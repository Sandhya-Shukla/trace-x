/*
  TRACE-X - Handheld Detection Pod
  Stage 2c - smooth buzzer ramp + manual SEND button

  - Buzzer behaviour is distinct beeps that scale with threat distance/confidence:
      no threat        -> silent
      far threat       -> slow beeps with 500ms gap
      near threat      -> rapid beeps with 50ms gap (always distinct beeps, never continuous)
      pitch            -> smoothly rises from 400 Hz to 2600 Hz as threat increases
  - OLED now shows, every refresh: overall STATUS, both sensors'
    live confidence %, which substance is currently dominant, and
    the current latitude/longitude.
  - New third push button (green, PIN_SEND_BTN) is a manual
    "SEND / SAVE" control: pressing it immediately logs the current
    reading to the SD card (temporary local record) and pushes it to
    ThingSpeak (the cloud platform) if WiFi is up - independent of
    whether an alert threshold has been crossed. The screen flashes
    "SAVED" briefly to confirm.
  - Automatic alert-edge logging (crossing ALERT_THRESHOLD) is kept
    as well, so nothing is missed even if the operator doesn't press
    SEND in time.
  - Red button: still ON/OFF only. Blue button: still language
    toggle.

  BEFORE FLASHING: replace THINGSPEAK_API_KEY below with your
  channel's own Write API Key from thingspeak.com.
*/

#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <SD.h>
#include <WiFi.h>
#include <HTTPClient.h>

// ---------- TFT Display (ILI9341 2.8" 320x240 Color SPI) ----------
const int PIN_TFT_CS = 14;
const int PIN_TFT_DC = 2;
Adafruit_ILI9341 tft = Adafruit_ILI9341(PIN_TFT_CS, PIN_TFT_DC);

// ---------- pins ----------
const int PIN_POT_NARCOTIC  = 34;  // dedicated "narcotic sensor" knob
const int PIN_POT_EXPLOSIVE = 35;  // dedicated "explosive sensor" knob
const int PIN_POT_HEADING   = 33;  // operator facing angle (0-360 deg sweep knob)
const int PIN_BUTTON    = 15;  // red button: ON/OFF only
const int PIN_LANG_BTN  = 4;   // blue button: language toggle
const int PIN_SEND_BTN  = 13;  // green button: manual save/send + sweep reset
const int PIN_LED_R     = 25;
const int PIN_LED_G     = 26;
const int PIN_LED_B     = 27;
const int PIN_BUZZER    = 32;
const int PIN_SD_CS     = 5;   // SD CS (SCK/DI/DO use ESP32 default VSPI pins: 18/23/19)

const char* WIFI_SSID = "Wokwi-GUEST";
const char* WIFI_PASS = "";
const char* THINGSPEAK_API_KEY = "U1NLA1LB385GCA4A"; // <-- replace with your channel's Write API Key

// ---------- tuning ----------
const int ALERT_THRESHOLD    = 60;   // auto-log/upload once dominant confidence crosses this
const int SILENT_BELOW       = 3;    // buzzer/blink stay fully off below this confidence

const int BLINK_MS_AT_0      = 900;  // LED blink period at 0% confidence (slow)
const int BLINK_MS_AT_100    = 120;  // LED blink period at 100% confidence (fast)

// buzzer beep timing:
// Always distinct beeps (never continuous tone).
// Gap between beeps is 500ms when threat is far, speeding up to 50ms when threat is near.
const int BEEP_DURATION_MS   = 60;   // ms, length of each distinct beep
const int BUZZ_GAP_AT_FAR    = 500;  // ms gap between beeps when threat is far (low confidence)
const int BUZZ_GAP_AT_NEAR   = 50;   // ms gap between beeps when threat is near (high confidence)
const int BUZZ_FREQ_AT_0     = 400;  // Hz at low confidence
const int BUZZ_FREQ_AT_100   = 2600; // Hz at high confidence

const unsigned long SAVED_MSG_MS = 1200; // how long "SAVED" shows after pressing SEND

bool sdReady = false;
bool wifiReady = false;
bool deviceOn = true;
int scanCount = 0;
int currentLang = 0;  // 0 = English, 1 = Hindi (Roman script)

enum ThreatLevel { CLEAR = 0, NARCOTIC = 1, EXPLOSIVE = 2 };
enum GuidanceDir { DIR_SCANNING = 0, DIR_AHEAD = 1, DIR_RIGHT = 2, DIR_LEFT = 3 };

// ---------- 12-Sector Directional Sweep Memory (30 deg each) ----------
const int NUM_SECTORS = 12;
const int SECTOR_SPAN = 30; // 360 / 12 = 30 degrees per sector
int sectorMaxConf[NUM_SECTORS] = {0};
ThreatLevel sectorThreat[NUM_SECTORS] = {CLEAR};

// Active locked threat target
int targetHeading = -1;  // exact angle where peak threat was detected (0-359 deg)
int targetConf = 0;      // peak threat confidence (0-100)
ThreatLevel targetThreat = CLEAR;
bool tftInitialized = false;

void clearSweepMemory() {
  for (int i = 0; i < NUM_SECTORS; i++) {
    sectorMaxConf[i] = 0;
    sectorThreat[i] = CLEAR;
  }
  targetHeading = -1;
  targetConf = 0;
  targetThreat = CLEAR;
  tftInitialized = false; // trigger UI refresh on clear
}

// ---------- RGB LED (PWM, common-anode wiring: 0 = fully on) ----------

void setColorRaw(uint8_t r, uint8_t g, uint8_t b) {
  analogWrite(PIN_LED_R, 255 - r);
  analogWrite(PIN_LED_G, 255 - g);
  analogWrite(PIN_LED_B, 255 - b);
}

void ledOff() {
  setColorRaw(0, 0, 0);
}

// green -> yellow -> red as confidence 0 -> 100, smooth (no zones)
void confidenceToColor(int conf, uint8_t &r, uint8_t &g, uint8_t &b) {
  conf = constrain(conf, 0, 100);
  if (conf <= 50) {
    float t = conf / 50.0f;
    r = (uint8_t)(255 * t);
    g = 255;
    b = 0;
  } else {
    float t = (conf - 50) / 50.0f;
    r = 255;
    g = (uint8_t)(255 * (1.0f - t));
    b = 0;
  }
}

// ---------- names / helpers ----------

const char* levelName(ThreatLevel level) {
  switch (level) {
    case CLEAR:     return "CLEAR";
    case NARCOTIC:  return "NARCOTIC";
    case EXPLOSIVE: return "EXPLOSIVE";
  }
  return "UNKNOWN";
}

// ---------- placeholder location (swap for a real GPS module later) ----------

void getLocation(float &lat, float &lon) {
  lat = 28.6430f + ((float)random(-50, 50) / 100000.0f);
  lon = 77.2190f + ((float)random(-50, 50) / 100000.0f);
}

// ---------- SD card event logging ----------

void logToSD(ThreatLevel level, int confidence, float lat, float lon, int heading) {
  if (!sdReady) return;
  File f = SD.open("/log.csv", FILE_APPEND);
  if (!f) return;
  f.printf("%d,%lu,%s,%d,%d,%.5f,%.5f\n",
           scanCount, (unsigned long)millis(), levelName(level),
           confidence, heading, lat, lon);
  f.close();
}


// ---------- cloud upload (ThingSpeak) ----------

void connectWiFi() {
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 8000) {
    delay(250);
  }
  wifiReady = (WiFi.status() == WL_CONNECTED);
  if (wifiReady) {
    Serial.print("WiFi connected, IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("WiFi connect failed - cloud upload disabled, everything else still works");
  }
}

struct PendingUpload {
  bool active;
  ThreatLevel level;
  int confidence;
  float lat;
  float lon;
  int peakHeading;
  int facingHeading;
  int scanNumber;
};
static PendingUpload pendingUpload = {false, CLEAR, 0, 0.0, 0.0, 0, -1, 0};
static unsigned long lastUploadTime = 0;

void executeCloudUpload(ThreatLevel level, int confidence, float lat, float lon, int peakHeading, int facingHeading, int scanNum) {
  if (!wifiReady || WiFi.status() != WL_CONNECTED) return;

  HTTPClient http;
  http.setConnectTimeout(1500); // 1.5s reliable connect timeout for Wokwi gateway
  http.setTimeout(1500);        // 1.5s read timeout
  String url = "http://api.thingspeak.com/update?api_key=" + String(THINGSPEAK_API_KEY) +
               "&field1=" + String(scanNum) +
               "&field2=" + String((int)level) +
               "&field3=" + String(confidence) +
               "&field4=" + String(lat, 5) +
               "&field5=" + String(lon, 5) +
               "&field6=" + String(peakHeading);
  if (facingHeading >= 0) {
    url += "&field7=" + String(facingHeading);
  }

  http.begin(url);
  int code = http.GET();
  http.end();

  lastUploadTime = millis();

  Serial.print("ThingSpeak upload HTTP code: ");
  Serial.print(code);
  Serial.print(" [Scan #");
  Serial.print(scanNum);
  Serial.print(" peakAngle=");
  Serial.print(peakHeading);
  if (facingHeading >= 0) {
    Serial.print(" facing=");
    Serial.print(facingHeading);
  }
  Serial.println("]");
}

void sendToCloud(ThreatLevel level, int confidence, float lat, float lon, int peakHeading, int facingHeading = -1) {
  if (!wifiReady || WiFi.status() != WL_CONNECTED) return;

  unsigned long now = millis();
  unsigned long elapsed = (lastUploadTime == 0) ? 999999 : (now - lastUploadTime);

  if (elapsed >= 15000) {
    // 15-second rate limit window open: upload immediately
    executeCloudUpload(level, confidence, lat, lon, peakHeading, facingHeading, scanCount);
    pendingUpload.active = false;
  } else {
    // Within 15-second ThingSpeak rate limit: queue for automatic transmission
    pendingUpload.active = true;
    pendingUpload.level = level;
    pendingUpload.confidence = confidence;
    pendingUpload.lat = lat;
    pendingUpload.lon = lon;
    pendingUpload.peakHeading = peakHeading;
    pendingUpload.facingHeading = facingHeading;
    pendingUpload.scanNumber = scanCount;

    int waitSec = (15000 - elapsed) / 1000 + 1;
    Serial.print("Cloud upload queued: ThingSpeak 15s cooldown active (");
    Serial.print(waitSec);
    Serial.println("s remaining). Telemetry will auto-transmit when cooldown finishes.");
  }
}

void processPendingUpload() {
  if (!pendingUpload.active) return;
  if (!wifiReady || WiFi.status() != WL_CONNECTED) return;

  unsigned long now = millis();
  if (now - lastUploadTime >= 15000) {
    Serial.print("Transmitting queued detection to Cloud #");
    Serial.println(pendingUpload.scanNumber);
    executeCloudUpload(pendingUpload.level, pendingUpload.confidence, pendingUpload.lat, pendingUpload.lon,
                       pendingUpload.peakHeading, pendingUpload.facingHeading, pendingUpload.scanNumber);
    pendingUpload.active = false;
  }
}


// ---------- TFT Display Rendering (320x240 Landscape) ----------

void drawStaticUI() {
  tft.fillScreen(ILI9341_BLACK);

  // 1. Top Status Header Bar
  tft.fillRect(0, 0, 320, 26, 0x0821);
  tft.drawFastHLine(0, 26, 320, ILI9341_CYAN);
  tft.setTextSize(2);
  tft.setTextColor(ILI9341_CYAN, 0x0821);
  tft.setCursor(6, 5);
  tft.print("TRACE-X");

  // 2. Directional Guidance Panel Frame
  tft.drawRoundRect(4, 30, 312, 54, 4, 0x4208);

  // 3. Live Threat Meter Frame
  tft.drawRect(8, 114, 304, 12, ILI9341_WHITE);

  // 4. 12-Sector Memory Title
  tft.setTextSize(1);
  tft.setTextColor(ILI9341_CYAN, ILI9341_BLACK);
  tft.setCursor(8, 150);
  tft.print("360");
  tft.print((char)247);
  tft.print(" SWEEP MEMORY (12 SECTORS):");

  // 5. Telemetry Footer
  tft.drawFastHLine(0, 198, 320, 0x4208);
  tft.fillRect(0, 200, 320, 40, 0x0008);
}

void showOff() {
  tftInitialized = false;
  tft.fillScreen(ILI9341_BLACK);
  tft.setTextSize(3);
  tft.setTextColor(ILI9341_RED, ILI9341_BLACK);
  tft.setCursor(65, 50);
  tft.println("TRACE-X");

  tft.setTextSize(2);
  tft.setTextColor(ILI9341_WHITE, ILI9341_BLACK);
  tft.setCursor(45, 110);
  tft.println(currentLang == 0 ? "DEVICE OFF" : "DEVICE BAND HAI");

  tft.setTextSize(1);
  tft.setTextColor(ILI9341_LIGHTGREY, ILI9341_BLACK);
  tft.setCursor(35, 170);
  tft.println(currentLang == 0 ? "Press RED button to power ON" : "Chalu karne ke liye Lal button dabaye");
}

void showMonitor(int confN, int confE, ThreatLevel dominant, int domConf,
                 int heading, int targetHeading, int turnAngle,
                 GuidanceDir guidance, int bestSector, int peakConf,
                 float lat, float lon, const char* statusText) {
  if (!tftInitialized) {
    drawStaticUI();
    tftInitialized = true;
  }

  // 1. Heading in Header (update only if changed)
  static int lastDrawnHeading = -999;
  if (heading != lastDrawnHeading) {
    tft.setTextSize(2);
    tft.setTextColor(ILI9341_WHITE, 0x0821);
    tft.setCursor(115, 5);
    tft.printf("HDG:%3d%c", heading, (char)247);
    lastDrawnHeading = heading;
  }

  // Status Badge (update only if changed)
  static String lastStatusText = "";
  if (String(statusText) != lastStatusText) {
    uint16_t badgeBg = ILI9341_DARKGREEN;
    uint16_t badgeFg = ILI9341_WHITE;
    if (strstr(statusText, "SAVE") != NULL) {
      badgeBg = ILI9341_YELLOW;
      badgeFg = ILI9341_BLACK;
    } else if (strstr(statusText, "ALERT") != NULL || strstr(statusText, "SAVDHAN") != NULL) {
      badgeBg = ILI9341_RED;
      badgeFg = ILI9341_WHITE;
    }
    tft.fillRoundRect(220, 3, 96, 20, 3, badgeBg);
    tft.setTextSize(1);
    tft.setTextColor(badgeFg, badgeBg);
    tft.setCursor(226, 7);
    tft.printf("%-12s", statusText);
    lastStatusText = String(statusText);
  }

  // 2. Guidance Panel (update only if changed)
  static GuidanceDir lastGuidance = (GuidanceDir)-1;
  static int lastTurnAngle = -999;
  static int lastTargetHeading = -999;
  static int lastTargetConf = -999;
  static int lastLang = -1;

  bool guidanceChanged = (guidance != lastGuidance || turnAngle != lastTurnAngle ||
                          targetHeading != lastTargetHeading || targetConf != lastTargetConf ||
                          currentLang != lastLang);
  if (guidanceChanged) {
    uint16_t cardBg = ILI9341_BLACK;
    uint16_t cardBorder = 0x4208;
    if (guidance == DIR_AHEAD) {
      cardBg = 0x0200;
      cardBorder = ILI9341_GREEN;
    } else if (guidance == DIR_RIGHT || guidance == DIR_LEFT) {
      cardBg = 0x2100;
      cardBorder = ILI9341_YELLOW;
    }

    if (guidance != lastGuidance) {
      tft.fillRoundRect(5, 31, 310, 52, 4, cardBg);
      tft.drawRoundRect(4, 30, 312, 54, 4, cardBorder);
    }

    tft.setTextSize(2);
    tft.setCursor(12, 36);
    char msg[32];
    if (guidance == DIR_AHEAD) {
      tft.setTextColor(ILI9341_GREEN, cardBg);
      snprintf(msg, sizeof(msg), "%-22s", currentLang == 0 ? "== TARGET AHEAD (0\367) ==" : "== TARGET SAMNE (0\367) ==");
    } else if (guidance == DIR_RIGHT) {
      tft.setTextColor(ILI9341_YELLOW, cardBg);
      snprintf(msg, sizeof(msg), currentLang == 0 ? "TURN RIGHT >> (+%d%c) " : "DAAYE MUDO >> (+%d%c) ", abs(turnAngle), (char)247);
    } else if (guidance == DIR_LEFT) {
      tft.setTextColor(ILI9341_YELLOW, cardBg);
      snprintf(msg, sizeof(msg), currentLang == 0 ? "<< TURN LEFT (-%d%c)  " : "<< BAAYE MUDO (-%d%c)  ", abs(turnAngle), (char)247);
    } else {
      tft.setTextColor(ILI9341_WHITE, cardBg);
      snprintf(msg, sizeof(msg), "%-22s", currentLang == 0 ? "SWEEP: SCANNING..." : "SWEEP: SCAN KARO...");
    }
    tft.print(msg);

    tft.setTextSize(1);
    tft.setCursor(12, 64);
    char subMsg[48];
    if (guidance == DIR_AHEAD) {
      tft.setTextColor(ILI9341_GREEN, cardBg);
      snprintf(subMsg, sizeof(subMsg), currentLang == 0 ? "Offset: 0%c | Target Ahead | Peak:%3d%%" : "Offset: 0%c | Samne Lakshya | Peak:%3d%%",
               (char)247, targetConf);
    } else if (guidance != DIR_SCANNING && targetHeading >= 0) {
      tft.setTextColor(ILI9341_WHITE, cardBg);
      snprintf(subMsg, sizeof(subMsg), currentLang == 0 ? "Offset:%3d%c away | Peak:%3d%% (%-5s)" : "Offset:%3d%c door | Peak:%3d%% (%-5s)",
               abs(turnAngle), (char)247, targetConf, levelName(targetThreat));
    } else {
      tft.setTextColor(ILI9341_LIGHTGREY, cardBg);
      snprintf(subMsg, sizeof(subMsg), "%-44s", currentLang == 0 ? "Sweep heading knob to scan 360 deg" : "Khatra khojne 360 deg sweep karein");
    }
    tft.print(subMsg);


    lastGuidance = guidance;
    lastTurnAngle = turnAngle;
    lastTargetHeading = targetHeading;
    lastTargetConf = targetConf;
    lastLang = currentLang;
  }

  // 3. Detection Text & Threat Bar (update only if changed)
  static ThreatLevel lastDom = (ThreatLevel)-1;
  static int lastDomConf = -1;
  static int lastConfN = -1;
  static int lastConfE = -1;

  if (dominant != lastDom || domConf != lastDomConf) {
    tft.setTextSize(2);
    tft.setCursor(8, 92);
    char detMsg[30];
    if (dominant == NARCOTIC) {
      tft.setTextColor(ILI9341_ORANGE, ILI9341_BLACK);
      snprintf(detMsg, sizeof(detMsg), "DETECT: NARCOTIC %3d%% ", domConf);
    } else if (dominant == EXPLOSIVE) {
      tft.setTextColor(ILI9341_RED, ILI9341_BLACK);
      snprintf(detMsg, sizeof(detMsg), "DETECT: EXPLOSIVE %3d%%", domConf);
    } else {
      tft.setTextColor(ILI9341_GREEN, ILI9341_BLACK);
      snprintf(detMsg, sizeof(detMsg), "DETECT: CLEAR    0%%   ");
    }
    tft.print(detMsg);

    // Update progress bar
    int newBarWidth = constrain(map(domConf, 0, 100, 0, 300), 0, 300);
    uint16_t barColor = (domConf < 40) ? ILI9341_GREEN : ((domConf < 70) ? ILI9341_YELLOW : ILI9341_RED);
    if (newBarWidth > 0) {
      tft.fillRect(10, 116, newBarWidth, 8, barColor);
    }
    if (newBarWidth < 300) {
      tft.fillRect(10 + newBarWidth, 116, 300 - newBarWidth, 8, ILI9341_BLACK);
    }

    lastDom = dominant;
    lastDomConf = domConf;
  }

  if (confN != lastConfN || confE != lastConfE) {
    tft.setTextSize(1);
    tft.setTextColor(ILI9341_LIGHTGREY, ILI9341_BLACK);
    tft.setCursor(8, 134);
    tft.printf("NARC:%3d%%   EXPL:%3d%%   DOMINANT:%-9s", confN, confE, levelName(dominant));
    lastConfN = confN;
    lastConfE = confE;
  }

  // 4. 12-Sector Memory Ribbon (update only if changed)
  static int lastSectorStates[NUM_SECTORS] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
  int currentSector = constrain(heading / SECTOR_SPAN, 0, NUM_SECTORS - 1);

  for (int i = 0; i < NUM_SECTORS; i++) {
    int sConf = sectorMaxConf[i];
    bool isCursor = (i == currentSector);
    bool isTarget = (guidance != DIR_SCANNING && targetHeading >= 0 && i == (targetHeading / SECTOR_SPAN));
    int stateHash = sConf + (isCursor ? 1000 : 0) + (isTarget ? 2000 : 0);

    if (stateHash != lastSectorStates[i]) {
      int boxX = 8 + i * 26;
      uint16_t boxColor = 0x2104;
      if (sConf >= 70) boxColor = ILI9341_RED;
      else if (sConf >= 40) boxColor = ILI9341_YELLOW;
      else if (sConf > 0) boxColor = ILI9341_DARKGREEN;

      tft.fillRect(boxX, 164, 22, 14, boxColor);
      uint16_t borderColor = isTarget ? ILI9341_RED : (isCursor ? ILI9341_WHITE : 0x4208);
      tft.drawRect(boxX, 164, 22, 14, borderColor);

      // Cursor ^ marker
      tft.setCursor(boxX + 8, 180);
      if (isCursor) {
        tft.setTextColor(ILI9341_WHITE, ILI9341_BLACK);
        tft.print("^");
      } else {
        tft.setTextColor(ILI9341_BLACK, ILI9341_BLACK);
        tft.print(" ");
      }
      lastSectorStates[i] = stateHash;
    }
  }

  // 5. Telemetry Footer
  static int lastScanCount = -1;
  if (scanCount != lastScanCount) {
    tft.setTextSize(1);
    tft.setCursor(8, 204);
    tft.setTextColor(ILI9341_CYAN, 0x0008);
    tft.printf("GPS: %.4f N, %.4f E     SCAN #%-5d", lat, lon, scanCount);

    tft.setCursor(8, 220);
    tft.setTextColor(ILI9341_LIGHTGREY, 0x0008);
    tft.printf("SD: %-3s  WIFI: %-3s  [GREEN BTN: SEND & RESET SWEEP]",
               sdReady ? "OK" : "NO", wifiReady ? "OK" : "OFF");
    lastScanCount = scanCount;
  }
}

// ---------- non-blocking blink + buzzer ramp state ----------

unsigned long lastBlinkToggle = 0;
bool blinkOn = true;

unsigned long buzzPhaseStart = 0;
bool buzzOn = false;
int lastBuzzFreq = -1;

void stopBuzzer() {
  if (buzzOn) {
    noTone(PIN_BUZZER);
    buzzOn = false;
  }
  buzzPhaseStart = 0;
  lastBuzzFreq = -1;
}

void updateLED(int domConf) {
  int blinkPeriod = map(domConf, 0, 100, BLINK_MS_AT_0, BLINK_MS_AT_100);
  unsigned long now = millis();
  if (now - lastBlinkToggle >= (unsigned long)blinkPeriod) {
    lastBlinkToggle = now;
    blinkOn = !blinkOn;
  }
  if (blinkOn) {
    uint8_t r, g, b;
    confidenceToColor(domConf, r, g, b);
    setColorRaw(r, g, b);
  } else {
    ledOff();
  }
}

// Distinct beeping with variable rate and pitch tracking:
// - Below SILENT_BELOW: fully silent
// - Threat far: beeps with 500ms gap
// - Threat near: beeps much faster (50ms gap)
// - Always distinct beeps with clear silence between them (never continuous)
// - Pitch scales from 400 Hz to 2600 Hz with threat intensity
void updateBuzzer(int domConf) {
  if (domConf < SILENT_BELOW) {
    if (buzzOn) {
      noTone(PIN_BUZZER);
      buzzOn = false;
    }
    buzzPhaseStart = 0;
    lastBuzzFreq = -1;
    return;
  }

  // Pitch tracks threat level (400 Hz -> 2600 Hz)
  int freq = map(constrain(domConf, 0, 100), 0, 100, BUZZ_FREQ_AT_0, BUZZ_FREQ_AT_100);

  // Gap between beeps: 500ms when threat is far -> 50ms when threat is near
  int gap = map(constrain(domConf, SILENT_BELOW, 100), SILENT_BELOW, 100, BUZZ_GAP_AT_FAR, BUZZ_GAP_AT_NEAR);

  unsigned long now = millis();

  if (buzzOn) {
    // Keep pitch tracking live if knob is adjusted during beep
    if (freq != lastBuzzFreq) {
      tone(PIN_BUZZER, freq);
      lastBuzzFreq = freq;
    }
    // Check if beep duration has finished
    if (now - buzzPhaseStart >= (unsigned long)BEEP_DURATION_MS) {
      noTone(PIN_BUZZER);
      buzzOn = false;
      buzzPhaseStart = now;
    }
  } else {
    // Check if gap duration has finished (or if initial trigger after silence)
    if (buzzPhaseStart == 0 || (now - buzzPhaseStart >= (unsigned long)gap)) {
      tone(PIN_BUZZER, freq);
      lastBuzzFreq = freq;
      buzzOn = true;
      buzzPhaseStart = now;
    }
  }
}

// ---------- setup / loop ----------

void setup() {
  Serial.begin(115200);
  randomSeed(analogRead(PIN_POT_NARCOTIC) + analogRead(PIN_POT_EXPLOSIVE));

  pinMode(PIN_BUTTON, INPUT_PULLUP);
  pinMode(PIN_LANG_BTN, INPUT_PULLUP);
  pinMode(PIN_SEND_BTN, INPUT_PULLUP);
  pinMode(PIN_POT_NARCOTIC, INPUT);
  pinMode(PIN_POT_EXPLOSIVE, INPUT);
  pinMode(PIN_POT_HEADING, INPUT);
  pinMode(PIN_LED_R, OUTPUT);
  pinMode(PIN_LED_G, OUTPUT);
  pinMode(PIN_LED_B, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  ledOff();

  pinMode(PIN_TFT_CS, OUTPUT);
  digitalWrite(PIN_TFT_CS, HIGH);
  pinMode(PIN_SD_CS, OUTPUT);
  digitalWrite(PIN_SD_CS, HIGH);

  tft.begin();
  tft.setRotation(1); // landscape 320x240
  tft.fillScreen(ILI9341_BLACK);

  clearSweepMemory();

  sdReady = SD.begin(PIN_SD_CS);
  if (!sdReady) {
    Serial.println("SD init failed - logging disabled, everything else still works");
  } else {
    File f = SD.open("/log.csv", FILE_APPEND);
    if (f) {
      f.println("scan,millis,level,confidence,heading,lat,lon");
      f.close();
    }
  }

  connectWiFi();

  showMonitor(0, 0, CLEAR, 0, 0, -1, 0, DIR_SCANNING, -1, 0, 0, 0, "MONITORING");
}

void loop() {
  static bool lastButtonState = HIGH;
  static bool lastLangState = HIGH;
  static bool lastSendState = HIGH;
  static bool lastAboveThreshold = false;
  static bool sweepResetPending = false;
  static unsigned long lastDisplayUpdate = 0;
  static unsigned long savedMsgUntil = 0;
  static float lastLat = 0, lastLon = 0;

  bool buttonState = digitalRead(PIN_BUTTON);
  bool langState = digitalRead(PIN_LANG_BTN);
  bool sendState = digitalRead(PIN_SEND_BTN);

  // on/off toggle - this button does nothing else
  if (lastButtonState == HIGH && buttonState == LOW) {
    delay(30);
    if (digitalRead(PIN_BUTTON) == LOW) {
      deviceOn = !deviceOn;
      if (!deviceOn) {
        ledOff();
        stopBuzzer();
        showOff();
      } else {
        tft.fillScreen(ILI9341_BLACK);
        showMonitor(0, 0, CLEAR, 0, 0, -1, 0, DIR_SCANNING, -1, 0, 0, 0, "MONITORING");
      }
    }
  }
  lastButtonState = buttonState;

  // language toggle
  if (lastLangState == HIGH && langState == LOW) {
    delay(30);
    if (digitalRead(PIN_LANG_BTN) == LOW) {
      currentLang = 1 - currentLang;
    }
  }
  lastLangState = langState;

  if (!deviceOn) {
    return; // fully idle, nothing else runs
  }

  processPendingUpload();

  // read both dedicated sensors directly
  int confN = map(analogRead(PIN_POT_NARCOTIC), 0, 4095, 0, 100);
  int confE = map(analogRead(PIN_POT_EXPLOSIVE), 0, 4095, 0, 100);

  // read operator facing heading (0-360 deg)
  int currentHeading = map(analogRead(PIN_POT_HEADING), 0, 4095, 0, 359);
  currentHeading = constrain(currentHeading, 0, 359);

  ThreatLevel dominant;
  int domConf;
  if (confE >= confN && confE > 0) {
    dominant = EXPLOSIVE;
    domConf = confE;
  } else if (confN > 0) {
    dominant = NARCOTIC;
    domConf = confN;
  } else {
    dominant = CLEAR;
    domConf = 0;
  }

  // Target tracking & directional sweep guidance
  int currentSector = constrain(currentHeading / SECTOR_SPAN, 0, NUM_SECTORS - 1);

  if (domConf >= SILENT_BELOW) {
    if (targetHeading < 0) {
      // 1. Initial target lock: threat detected while facing currentHeading
      targetHeading = currentHeading;
      targetConf = domConf;
      targetThreat = dominant;
      sectorMaxConf[currentSector] = domConf;
      sectorThreat[currentSector] = dominant;
    } else {
      // 2. Target already locked: check angular distance to target
      int angleDiff = (targetHeading - currentHeading + 540) % 360 - 180;
      if (abs(angleDiff) <= 25) {
        // Operator is facing target: update reading and fine-tune exact angle
        targetConf = domConf;
        targetThreat = dominant;
        targetHeading = currentHeading;
        sectorMaxConf[currentSector] = domConf;
        sectorThreat[currentSector] = dominant;
      } else if (domConf > targetConf) {
        // Operator swept to a new angle and found a stronger peak: re-latch to stronger peak
        targetHeading = currentHeading;
        targetConf = domConf;
        targetThreat = dominant;
        sectorMaxConf[currentSector] = domConf;
        sectorThreat[currentSector] = dominant;
      }
      // When turned away (abs(angleDiff) > 25 and domConf <= targetConf),
      // we preserve targetHeading & targetConf so guidance points back accurately
      // without other sectors being contaminated during the sweep.
    }
  } else {
    // Both threat pots are near 0 (no active signal)
    // Clear sweep memory when the operator zeroes out the threat sensors
    if (targetHeading >= 0 && domConf == 0) {
      targetHeading = -1;
      targetConf = 0;
      targetThreat = CLEAR;
      for (int i = 0; i < NUM_SECTORS; i++) {
        sectorMaxConf[i] = 0;
        sectorThreat[i] = CLEAR;
      }
    }
  }

  // Calculate shortest turn direction to locked target (-180 to +180 deg)
  int turnAngle = 0;
  GuidanceDir guidance = DIR_SCANNING;

  if (targetHeading >= 0 && targetConf >= SILENT_BELOW) {
    turnAngle = (targetHeading - currentHeading + 540) % 360 - 180;
    if (abs(turnAngle) <= 15) {
      guidance = DIR_AHEAD;
    } else if (turnAngle > 0) {
      guidance = DIR_RIGHT; // target is clockwise
    } else {
      guidance = DIR_LEFT;  // target is counter-clockwise
    }
  }

  updateLED(domConf);
  updateBuzzer(domConf);

  getLocation(lastLat, lastLon);

  // manual SEND / SAVE button - records peak threat telemetry while preserving sweep lock
  if (lastSendState == HIGH && sendState == LOW) {
    delay(30);
    if (digitalRead(PIN_SEND_BTN) == LOW) {
      scanCount++;

      // Determine angle: 0 if on target ahead, or exact angle away if turned away
      int saveAngle = (guidance == DIR_AHEAD || targetHeading < 0) ? 0 : abs(turnAngle);
      int saveConf = (targetHeading >= 0 && targetConf > domConf) ? targetConf : domConf;
      ThreatLevel saveThreat = (targetHeading >= 0 && targetConf > domConf) ? targetThreat : dominant;

      logToSD(saveThreat, saveConf, lastLat, lastLon, saveAngle);
      sendToCloud(saveThreat, saveConf, lastLat, lastLon, saveAngle, (targetHeading >= 0 ? targetHeading : currentHeading));
      savedMsgUntil = millis() + SAVED_MSG_MS;
      sweepResetPending = true;

      // Preserves targetHeading and guidance orientation during the 1.2s SAVED display
      // so saving while pointing at an angle cleanly shows SAVED(XX°) without flipping.
      // After 1.2s, sweep memory auto-resets so the next detection can be scanned fresh.

      Serial.print("Manual SEND #"); Serial.print(scanCount);
      Serial.print(" level="); Serial.print(levelName(saveThreat));
      Serial.print(" conf="); Serial.print(saveConf);
      Serial.print(" angle="); Serial.print(saveAngle);
      Serial.print(" (targetHeading="); Serial.print(targetHeading);
      Serial.print(" currentHeading="); Serial.print(currentHeading);
      Serial.println(")");
    }
  }
  lastSendState = sendState;

  // refresh the screen at ~20 FPS for instant knob response
  unsigned long now = millis();

  if (sweepResetPending && now >= savedMsgUntil) {
    clearSweepMemory();
    sweepResetPending = false;
    Serial.println("Sweep memory reset: ready for next detection scan");
  }

  if (now - lastDisplayUpdate >= 50) {
    lastDisplayUpdate = now;
    static char statusBuf[24];
    const char* status;
    if (now < savedMsgUntil) {
      int dispAngle = (guidance == DIR_AHEAD || targetHeading < 0) ? 0 : abs(turnAngle);
      if (currentLang == 0) {
        snprintf(statusBuf, sizeof(statusBuf), "SAVED (%d%c)", dispAngle, (char)247);
      } else {
        snprintf(statusBuf, sizeof(statusBuf), "SAVE (%d%c)", dispAngle, (char)247);
      }
      status = statusBuf;
    } else if (pendingUpload.active) {
      int waitSec = (15000 - (now - lastUploadTime)) / 1000 + 1;
      if (waitSec < 1) waitSec = 1;
      snprintf(statusBuf, sizeof(statusBuf), "SYNC (%ds)", waitSec);
      status = statusBuf;
    } else if (domConf >= ALERT_THRESHOLD) {
      status = (currentLang == 0) ? "ALERT" : "SAVDHAN";
    } else {
      status = (currentLang == 0) ? "MONITORING" : "NIGRANI";
    }
    int bestSector = (targetHeading >= 0) ? (targetHeading / SECTOR_SPAN) : -1;
    showMonitor(confN, confE, dominant, domConf,
                currentHeading, targetHeading, turnAngle,
                guidance, bestSector, targetConf,
                lastLat, lastLon, status);
  }

  // automatic log the moment we cross into an alert (in addition to manual SEND)
  bool aboveThreshold = domConf >= ALERT_THRESHOLD;
  if (aboveThreshold && !lastAboveThreshold) {
    scanCount++;
    int alertAngle = (guidance == DIR_AHEAD || targetHeading < 0) ? 0 : abs(turnAngle);
    Serial.print("AUTO ALERT #"); Serial.print(scanCount);
    Serial.print(" level="); Serial.print(levelName(dominant));
    Serial.print(" conf="); Serial.print(domConf);
    Serial.print(" angle="); Serial.print(alertAngle);
    Serial.print(" facingHdg="); Serial.print(currentHeading);
    Serial.print(" lat="); Serial.print(lastLat, 5);
    Serial.print(" lon="); Serial.println(lastLon, 5);

    logToSD(dominant, domConf, lastLat, lastLon, alertAngle);
    // Cloud upload intentionally omitted here to guarantee zero latency during sweep!
  }

  lastAboveThreshold = aboveThreshold;
}