# TRACE-X: Handheld Detection Pod & Central Threat Analytics Platform

**TRACE-X** is an embedded security and hazardous material detection system designed for railway security, perimeter defense, and counter-contraband operations. It combines an **ESP32-based handheld detection pod** with an **interactive Central Monitoring & Data Analytics Command Platform**.

---

## Key Features

### 1. Handheld Detection Pod (Firmware)
- **Dual Substance Detection**: Real-time detection of **Narcotics** (organic contraband) and **Explosives** (nitrates, peroxides, volatile vapors) with confidence grading (0–100%).
- **360° Directional Sweep Finder**:
  - Continuous facing angle tracking (0°–359°) divided into 12 sectors (30° each).
  - **Smart Target Latching**: Locks onto threat headings, shields against turn contamination, and guides the operator with shortest-turn directions:
    - `== TARGET AHEAD ==` (Green, within ±15°)
    - `TURN RIGHT >> (+deg)` (Yellow)
    - `<< TURN LEFT (-deg)` (Yellow)
  - Memory reset on green button press for sweeping fresh search sectors.
- **Dynamic Variable-Rate Buzzer**:
  - Emits crisp, distinct beeps (never a continuous unbroken tone).
  - Rate scaling: **500 ms gap** when threat is far/low $\rightarrow$ **50 ms gap** when threat is near/high.
  - Pitch tracking: Scales smoothly from **400 Hz** to **2600 Hz** with threat intensity.
- **2.8" Color TFT Display (`wokwi-ili9341`, 320x240)**:
  - Header with live heading in degrees and status badge.
  - Guidance panel card with directional arrows.
  - Live threat progress gauge and dual sensor telemetry.
  - 12-sector radar memory ribbon tracking past hits with active cursor (`^`).
- **Telemetry & Logging**:
  - Local CSV logging to **MicroSD card** (`/log.csv`).
  - Remote cloud synchronization to **ThingSpeak**.

### 2. Central Monitoring & Data Analytics Platform (Web)
- **Embedded SQLite Database (`data/tracex.db`)**: Persistent storage for scan numbers, timestamps, classifications, confidence levels, GPS coordinates, heading angles, and operator field notes.
- **Zero-Dependency Python Backend (`server.py`)**: Runs immediately using Python standard libraries (`http.server`, `sqlite3`, `json`, `csv`, `urllib`). Requires **no `pip install`**.
- **Defense C2 Telemetry Console**:
  - **Live Monitoring & GPS Deployment Map**: Dark-mode cartographic map (Leaflet.js) with color-coded incident classification markers and telemetry popups.
  - **Data Analytics & 360° Radar**: Polar Area radar chart visualizing threat concentrations by facing angle, incident timelines, and confidence histograms (Chart.js).
  - **Incident Comparison Matrix**: Select any two scans to compare side-by-side with compass dials, confidence deltas, angular divergence, and Haversine ground distance in meters.
  - **Audit Logs & Ingestion**: Searchable, filterable log grid with click-to-edit field notes, drag-and-drop SD Card CSV importer, and CSV/JSON export.
  - **Dual Online/Offline Mode**: Seamlessly works connected to `server.py` or standalone in any browser with localStorage fallback.

---

## Hardware Pinout (ESP32 DevKit V1)

| Peripheral / Component | Pin / Signal | ESP32 Pin | Details |
| :--- | :--- | :--- | :--- |
| **Narcotic Sensor Knob** | `SIG` | `D34` (ADC1_CH6) | 0–100% simulated narcotic vapor |
| **Explosive Sensor Knob** | `SIG` | `D35` (ADC1_CH7) | 0–100% simulated explosive vapor |
| **Heading / Sweep Knob** | `SIG` | `D33` (ADC1_CH5) | Operator facing angle (0°–359°) |
| **2.8" Color TFT (`ILI9341`)** | `CS` | `D14` | Chip Select (SPI) |
| | `D/C` | `D2` | Data/Command |
| | `MOSI` | `D23` | VSPI MOSI (shared) |
| | `SCK` | `D18` | VSPI Clock (shared) |
| | `LED` / `VCC` | `3V3` | Backlight & Logic |
| **MicroSD Card Module** | `CS` | `D5` | Chip Select (SPI) |
| | `DI` / `DO` / `SCK` | `D23` / `D19` / `D18` | Shared hardware VSPI bus |
| **RGB LED** (Common-Anode) | `R` / `G` / `B` | `D25` / `D26` / `D27` | Via 330Ω resistors (PWM color ramp) |
| **Piezo Buzzer** | `+` | `D32` | Variable rate & frequency tone |
| **Red Button** | `PIN_BUTTON` | `D15` | Power Toggle (ON / OFF) |
| **Blue Button** | `PIN_LANG_BTN`| `D4` | Language Toggle (English / Hindi) |
| **Green Button** | `PIN_SEND_BTN`| `D13` | Manual SAVE / SEND & Reset Sweep |

---

## Getting Started

### 1. Running the Simulation in Wokwi
1. Open the project in VS Code with the **Wokwi for VS Code** extension installed.
2. Open `diagram.json` or press `F1` $\rightarrow$ `Wokwi: Start Simulator`.
3. Interact with:
   - `pot_heading`: Sweep operator angle (0°–360°).
   - `pot_narcotic` / `pot_explosive`: Introduce threat levels.
   - Green push button: Save reading to SD card and reset sweep memory for the next sector.

### 2. Building and Flashing to Real Hardware
Using [PlatformIO](https://platformio.org/):
```bash
# Build firmware
pio run

# Flash to connected ESP32
pio run --target upload

# Open serial monitor
pio device monitor -b 115200
```

### 3. Launching the Web Monitoring & Analytics Platform
1. Open a terminal in the project directory:
   ```bash
   python server.py
   ```
2. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```
3. You can also drag and drop `/log.csv` extracted from your pod's SD card directly into the web interface.

---

## Project Structure

```
trace-x-detection-pod/
├── diagram.json         # Wokwi simulation wiring diagram (ESP32, TFT, SD, Pots, Buttons)
├── platformio.ini       # PlatformIO configuration & library dependencies
├── wokwi.toml           # Wokwi project settings & firmware binary path
├── server.py            # Python REST API & SQLite backend engine
├── index.html           # Central Command Station frontend dashboard
├── app.js               # Leaflet map, Chart.js analytics, comparison engine
├── style.css            # Dark-mode railway defense styling
├── train_model.py       # NumPy MLP classifier training script
├── include/             # C/C++ headers
├── src/
│   └── main.cpp         # Complete ESP32 firmware source code
└── data/
    └── .gitkeep         # Local SQLite database location (tracex.db)
```

---

## License
Educational and security research prototype. Developed for defense and transportation safety.
