/**
 * TRACE-X Central Monitoring & Data Analytics Platform (app.js)
 * Dual-Mode: Full SQLite REST API when server.py is running,
 * with graceful in-browser localStorage fallback if opened directly as index.html.
 */

// Global State
let isBackendOnline = false;
let allScans = [];
let filteredScans = [];
let mapInstance = null;
let mapMarkers = [];

// Chart Instances
let timelineChart = null;
let radarChart = null;
let ratioChart = null;
let confDistChart = null;

// Initial Demo Dataset for offline fallback
const FALLBACK_DEMO_SCANS = [
  { id: 1, scan_number: 1, timestamp: "2026-09-15 01:10:00", threat_level: "CLEAR", confidence: 0, heading: 15, lat: 28.6139, lon: 77.2090, is_alert: 0, operator_notes: "Routine perimeter scan - Platform 1", source: "demo" },
  { id: 2, scan_number: 2, timestamp: "2026-09-15 01:15:30", threat_level: "CLEAR", confidence: 2, heading: 45, lat: 28.6141, lon: 77.2092, is_alert: 0, operator_notes: "Luggage rack clear - Coach A1", source: "demo" },
  { id: 3, scan_number: 3, timestamp: "2026-09-15 01:25:10", threat_level: "NARCOTIC", confidence: 45, heading: 90, lat: 28.6145, lon: 77.2098, is_alert: 0, operator_notes: "Minor trace flagged near locker 12", source: "demo" },
  { id: 4, scan_number: 4, timestamp: "2026-09-15 01:28:45", threat_level: "NARCOTIC", confidence: 82, heading: 95, lat: 28.6146, lon: 77.2099, is_alert: 1, operator_notes: "STRONG NARCOTIC HIT - Locker 14 inspected", source: "demo" },
  { id: 5, scan_number: 5, timestamp: "2026-09-15 01:34:00", threat_level: "NARCOTIC", confidence: 88, heading: 92, lat: 28.6146, lon: 77.2099, is_alert: 1, operator_notes: "Secondary sweep confirmed narcotic presence", source: "demo" },
  { id: 6, scan_number: 6, timestamp: "2026-09-15 01:45:20", threat_level: "CLEAR", confidence: 0, heading: 180, lat: 28.6150, lon: 77.2105, is_alert: 0, operator_notes: "Waiting hall area scan clear", source: "demo" },
  { id: 7, scan_number: 7, timestamp: "2026-09-15 02:00:15", threat_level: "CLEAR", confidence: 0, heading: 210, lat: 28.6155, lon: 77.2110, is_alert: 0, operator_notes: "Platform 2 walkway inspection", source: "demo" },
  { id: 8, scan_number: 8, timestamp: "2026-09-15 02:12:40", threat_level: "EXPLOSIVE", confidence: 65, heading: 240, lat: 28.6160, lon: 77.2115, is_alert: 1, operator_notes: "ELEVATED VAPOR - Unattended duffle near Track 3", source: "demo" },
  { id: 9, scan_number: 9, timestamp: "2026-09-15 02:14:10", threat_level: "EXPLOSIVE", confidence: 94, heading: 245, lat: 28.6161, lon: 77.2116, is_alert: 1, operator_notes: "CRITICAL HAZARD: High nitrate compound detected!", source: "demo" },
  { id: 10, scan_number: 10, timestamp: "2026-09-15 02:18:00", threat_level: "EXPLOSIVE", confidence: 91, heading: 242, lat: 28.6161, lon: 77.2116, is_alert: 1, operator_notes: "Bomb squad perimeter established", source: "demo" },
  { id: 11, scan_number: 11, timestamp: "2026-09-15 02:30:00", threat_level: "CLEAR", confidence: 0, heading: 315, lat: 28.6135, lon: 77.2085, is_alert: 0, operator_notes: "South exit gate sweep clear", source: "demo" },
  { id: 12, scan_number: 12, timestamp: "2026-09-15 02:40:00", threat_level: "CLEAR", confidence: 0, heading: 0, lat: 28.6130, lon: 77.2080, is_alert: 0, operator_notes: "Ticketing counter routine check", source: "demo" }
];

// ---------- Initialization ----------

document.addEventListener("DOMContentLoaded", async () => {
  initTabs();
  initModals();
  initFilters();
  await checkBackendStatus();
  await loadData();
  initMap();
  initCharts();
  renderAllViews();

  // Polling every 6 seconds for fresh pod telemetry
  setInterval(async () => {
    await loadData(true);
  }, 6000);
});

// ---------- Backend Check & Data Loading ----------

async function checkBackendStatus() {
  const pill = document.getElementById("backend-status");
  try {
    const res = await fetch("/api/status", { cache: "no-store" });
    if (res.ok) {
      const json = await res.json();
      isBackendOnline = true;
      pill.className = "status-pill online";
      pill.innerHTML = '<span class="status-indicator-box"></span> DB: SQLITE CONNECTED';
      return;
    }
  } catch (e) {
    // server.py is not reachable
  }

  isBackendOnline = false;
  pill.className = "status-pill offline";
  pill.innerHTML = '<span class="status-indicator-box"></span> DB: BROWSER STORAGE';
}

async function loadData(isPolling = false) {
  if (isBackendOnline) {
    try {
      const res = await fetch("/api/scans?limit=200");
      const json = await res.json();
      allScans = json.scans || [];
    } catch (e) {
      console.warn("Failed to query backend, using local cache", e);
    }
  } else {
    // LocalStorage fallback
    const saved = localStorage.getItem("tracex_local_scans");
    if (saved) {
      try {
        allScans = JSON.parse(saved);
      } catch (e) {
        allScans = FALLBACK_DEMO_SCANS;
      }
    } else {
      allScans = [...FALLBACK_DEMO_SCANS];
      localStorage.setItem("tracex_local_scans", JSON.stringify(allScans));
    }
  }

  applyFilters();
  if (!isPolling) {
    showToast(`Loaded ${allScans.length} telemetry records.`);
  }
}

function saveLocalState() {
  if (!isBackendOnline) {
    localStorage.setItem("tracex_local_scans", JSON.stringify(allScans));
  }
}

// ---------- Tab Management ----------

function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add("active");
      }

      // If switching to map or analytics, trigger redraw
      if (targetId === "tab-monitor" && mapInstance) {
        setTimeout(() => mapInstance.invalidateSize(), 150);
      }
      if (targetId === "tab-analytics") {
        updateAnalyticsCharts();
      }
      if (targetId === "tab-compare") {
        renderComparisonView();
      }
    });
  });
}

// ---------- Filter & Search Handling ----------

function initFilters() {
  const searchInput = document.getElementById("search-input");
  const threatSelect = document.getElementById("filter-threat");
  const confSlider = document.getElementById("filter-conf");
  const confValLabel = document.getElementById("filter-conf-val");

  const applyChange = () => {
    applyFilters();
    renderAllViews();
  };

  if (searchInput) searchInput.addEventListener("input", applyChange);
  if (threatSelect) threatSelect.addEventListener("change", applyChange);
  if (confSlider) {
    confSlider.addEventListener("input", () => {
      if (confValLabel) confValLabel.innerText = `${confSlider.value}%`;
      applyChange();
    });
  }
}

function applyFilters() {
  const search = (document.getElementById("search-input")?.value || "").toLowerCase().trim();
  const threat = (document.getElementById("filter-threat")?.value || "ALL").toUpperCase();
  const minConf = parseInt(document.getElementById("filter-conf")?.value || "0", 10);

  filteredScans = allScans.filter(scan => {
    const sLevel = (scan.threat_level || "CLEAR").toUpperCase();
    const sConf = parseInt(scan.confidence || 0, 10);
    const sNotes = (scan.operator_notes || "").toLowerCase();
    const sNum = `#${scan.scan_number}`;

    if (threat !== "ALL" && sLevel !== threat) return false;
    if (sConf < minConf) return false;
    if (search && !sNotes.includes(search) && !sLevel.toLowerCase().includes(search) && !sNum.includes(search)) {
      return false;
    }
    return true;
  });
}

// ---------- Render All Views ----------

function renderAllViews() {
  renderKPIs();
  renderAlertBanner();
  renderLiveFeed();
  renderMapMarkers();
  renderLogTable();
  updateAnalyticsCharts();
  populateComparisonDropdowns();
}

// ---------- KPI Calculation & Render ----------

function renderKPIs() {
  const total = allScans.length;
  const explosive = allScans.filter(s => s.threat_level === "EXPLOSIVE").length;
  const narcotic = allScans.filter(s => s.threat_level === "NARCOTIC").length;
  const clear = allScans.filter(s => s.threat_level === "CLEAR").length;
  const alerts = allScans.filter(s => s.is_alert || s.confidence >= 60).length;

  const threats = allScans.filter(s => s.threat_level !== "CLEAR");
  const avgConf = threats.length > 0
    ? Math.round(threats.reduce((sum, s) => sum + (s.confidence || 0), 0) / threats.length)
    : 0;

  const clearRate = total > 0 ? Math.round((clear / total) * 100) : 100;

  setEl("kpi-total", total);
  setEl("kpi-expl", explosive);
  setEl("kpi-narc", narcotic);
  setEl("kpi-clear-rate", `${clearRate}%`);
  setEl("kpi-avg-conf", `${avgConf}%`);
  setEl("kpi-alerts", alerts);
}

function renderAlertBanner() {
  const banner = document.getElementById("alert-banner");
  if (!banner) return;

  // Find latest active threat scan
  const latestThreat = allScans.find(s => s.threat_level !== "CLEAR");
  if (!latestThreat || latestThreat.confidence < 60) {
    banner.className = "alert-banner secure";
    banner.innerHTML = `
      <span>STATUS: NOMINAL // ALL PODS OPERATIONAL // BACKGROUND CLEAR</span>
      <span style="font-size:11px; color:var(--text-dim)">LATEST SWEEP: CLEAR</span>
    `;
    return;
  }

  if (latestThreat.threat_level === "EXPLOSIVE") {
    banner.className = "alert-banner danger";
    banner.innerHTML = `
      <span>ALARM [EXP-01]: VOLATILE VAPOR THRESHOLD BREACH (${latestThreat.confidence}%) AT [${latestThreat.lat.toFixed(4)}, ${latestThreat.lon.toFixed(4)}] HEADING ${latestThreat.heading}°</span>
      <button class="btn btn-danger" onclick="inspectScan(${latestThreat.id})">Inspect Scan #${latestThreat.scan_number}</button>
    `;
  } else if (latestThreat.threat_level === "NARCOTIC") {
    banner.className = "alert-banner warning";
    banner.innerHTML = `
      <span>WARNING [NRC-01]: SUSPECT ORGANIC TRACE DETECTED (${latestThreat.confidence}%) AT [${latestThreat.lat.toFixed(4)}, ${latestThreat.lon.toFixed(4)}] HEADING ${latestThreat.heading}°</span>
      <button class="btn btn-primary" onclick="inspectScan(${latestThreat.id})">Inspect Scan #${latestThreat.scan_number}</button>
    `;
  }
}

// ---------- Live Feed & Threat Gauge ----------

function renderLiveFeed() {
  const latest = allScans[0] || null;
  const fill = document.getElementById("gauge-fill");
  const label = document.getElementById("gauge-label");
  const confVal = document.getElementById("gauge-conf");

  if (latest && fill && label && confVal) {
    const conf = latest.confidence || 0;
    fill.style.width = `${conf}%`;
    confVal.innerText = `${conf}%`;

    if (latest.threat_level === "EXPLOSIVE") {
      fill.className = "progress-bar-fill danger";
      label.innerText = `EXPLOSIVE DETECTED (${conf}%)`;
      label.style.color = "var(--threat-expl)";
    } else if (latest.threat_level === "NARCOTIC") {
      fill.className = "progress-bar-fill warning";
      label.innerText = `NARCOTIC FLAGGED (${conf}%)`;
      label.style.color = "var(--threat-narc)";
    } else {
      fill.className = "progress-bar-fill";
      label.innerText = `NORMAL MONITORING (0%)`;
      label.style.color = "var(--threat-clear)";
    }
  }

  // Telemetry list (top 8)
  const listEl = document.getElementById("feed-list");
  if (!listEl) return;
  listEl.innerHTML = "";

  allScans.slice(0, 8).forEach(scan => {
    const item = document.createElement("div");
    const lvl = (scan.threat_level || "CLEAR").toLowerCase();
    item.className = `feed-item ${lvl}`;
    item.innerHTML = `
      <div class="feed-top">
        <span class="feed-scan-id">SCAN #${scan.scan_number}</span>
        <span class="badge ${lvl}">${scan.threat_level}</span>
      </div>
      <div class="feed-details">
        <span>Conf: <strong>${scan.confidence}%</strong></span>
        <span>Heading: <strong>${scan.heading}°</strong></span>
        <span>${formatTime(scan.timestamp)}</span>
      </div>
    `;
    item.addEventListener("click", () => inspectScan(scan.id));
    listEl.appendChild(item);
  });
}

// ---------- Leaflet.js GPS Threat Map ----------

function initMap() {
  const mapEl = document.getElementById("gps-map");
  if (!mapEl || mapInstance) return;

  // Center on New Delhi station default or latest scan
  const initialLat = allScans[0]?.lat || 28.6139;
  const initialLon = allScans[0]?.lon || 77.2090;

  mapInstance = L.map("gps-map", {
    center: [initialLat, initialLon],
    zoom: 16,
    zoomControl: true
  });

  // Dark Matter tiles from CartoDB
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: '&copy; <a href="https://carto.com/">CARTO</a> | TRACE-X Security Grid',
    maxZoom: 19
  }).addTo(mapInstance);
}

function renderMapMarkers() {
  if (!mapInstance) return;

  // Clear existing markers
  mapMarkers.forEach(m => mapInstance.removeLayer(m));
  mapMarkers = [];

  allScans.forEach(scan => {
    if (!scan.lat || !scan.lon) return;

    let color = "#10b981"; // clear
    if (scan.threat_level === "EXPLOSIVE") color = "#ef4444";
    else if (scan.threat_level === "NARCOTIC") color = "#f59e0b";

    const radius = scan.threat_level === "CLEAR" ? 6 : 9;

    const marker = L.circleMarker([scan.lat, scan.lon], {
      radius: radius,
      fillColor: color,
      color: "#ffffff",
      weight: 1.5,
      opacity: 0.9,
      fillOpacity: 0.85
    });

    const popupHtml = `
      <div class="map-popup-title">SCAN #${scan.scan_number} - ${scan.threat_level}</div>
      <div class="map-popup-row">Confidence: <strong>${scan.confidence}%</strong></div>
      <div class="map-popup-row">Facing Angle: <strong>${scan.heading}°</strong></div>
      <div class="map-popup-row">GPS: ${scan.lat.toFixed(5)}, ${scan.lon.toFixed(5)}</div>
      <div class="map-popup-row">Time: ${formatTime(scan.timestamp)}</div>
      ${scan.operator_notes ? `<div class="map-popup-row" style="color:var(--accent-cyan)"><em>"${scan.operator_notes}"</em></div>` : ''}
    `;

    marker.bindPopup(popupHtml);
    marker.addTo(mapInstance);
    mapMarkers.push(marker);
  });
}

// ---------- Chart.js Analytics Visualizations ----------

function initCharts() {
  // 1. Timeline Chart
  const ctxTimeline = document.getElementById("chart-timeline")?.getContext("2d");
  if (ctxTimeline) {
    timelineChart = new Chart(ctxTimeline, {
      type: "line",
      data: { labels: [], datasets: [] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#94a3b8" } } },
        scales: {
          x: { ticks: { color: "#64748b" }, grid: { color: "#1e293b" } },
          y: { min: 0, max: 100, ticks: { color: "#64748b" }, grid: { color: "#1e293b" } }
        }
      }
    });
  }

  // 2. 360° Directional Polar Radar Chart
  const ctxRadar = document.getElementById("chart-radar")?.getContext("2d");
  if (ctxRadar) {
    radarChart = new Chart(ctxRadar, {
      type: "polarArea",
      data: {
        labels: ["0°", "30°", "60°", "90°", "120°", "150°", "180°", "210°", "240°", "270°", "300°", "330°"],
        datasets: [{
          data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
          backgroundColor: [
            "rgba(56, 189, 248, 0.4)", "rgba(56, 189, 248, 0.4)", "rgba(245, 158, 11, 0.5)",
            "rgba(245, 158, 11, 0.7)", "rgba(245, 158, 11, 0.5)", "rgba(56, 189, 248, 0.4)",
            "rgba(56, 189, 248, 0.4)", "rgba(239, 68, 68, 0.5)", "rgba(239, 68, 68, 0.8)",
            "rgba(239, 68, 68, 0.5)", "rgba(56, 189, 248, 0.4)", "rgba(56, 189, 248, 0.4)"
          ],
          borderColor: "#1f293d",
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            grid: { color: "#1e293b" },
            ticks: { color: "#64748b", backdropColor: "transparent" }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (item) => ` Sector ${item.label}: ${item.raw} threat detections`
            }
          }
        }
      }
    });
  }

  // 3. Threat Classification Ratio Doughnut
  const ctxRatio = document.getElementById("chart-ratio")?.getContext("2d");
  if (ctxRatio) {
    ratioChart = new Chart(ctxRatio, {
      type: "doughnut",
      data: {
        labels: ["Clear", "Narcotics", "Explosives"],
        datasets: [{
          data: [0, 0, 0],
          backgroundColor: ["#10b981", "#f59e0b", "#ef4444"],
          borderColor: "#111827",
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "right", labels: { color: "#94a3b8" } }
        }
      }
    });
  }

  // 4. Confidence Distribution Bar Chart
  const ctxConf = document.getElementById("chart-conf-dist")?.getContext("2d");
  if (ctxConf) {
    confDistChart = new Chart(ctxConf, {
      type: "bar",
      data: {
        labels: ["0-20%", "21-40%", "41-60%", "61-80%", "81-100%"],
        datasets: [
          { label: "Narcotics", data: [0, 0, 0, 0, 0], backgroundColor: "#f59e0b" },
          { label: "Explosives", data: [0, 0, 0, 0, 0], backgroundColor: "#ef4444" }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#94a3b8" } } },
        scales: {
          x: { ticks: { color: "#64748b" }, grid: { color: "#1e293b" } },
          y: { ticks: { color: "#64748b" }, grid: { color: "#1e293b" } }
        }
      }
    });
  }
}

function updateAnalyticsCharts() {
  if (!timelineChart || !radarChart || !ratioChart || !confDistChart) return;

  // Timeline (latest 15 in chronological order)
  const recent = [...allScans].slice(0, 15).reverse();
  timelineChart.data.labels = recent.map(s => `#${s.scan_number}`);
  timelineChart.data.datasets = [
    {
      label: "Confidence %",
      data: recent.map(s => s.confidence),
      borderColor: "#06b6d4",
      backgroundColor: "rgba(6, 182, 212, 0.1)",
      fill: true,
      tension: 0.3
    }
  ];
  timelineChart.update();

  // 360° Directional Radar (12 sectors: 30 deg each)
  const sectorCounts = new Array(12).fill(0);
  allScans.filter(s => s.threat_level !== "CLEAR").forEach(s => {
    const sec = Math.floor(((s.heading || 0) % 360) / 30);
    sectorCounts[sec]++;
  });
  radarChart.data.datasets[0].data = sectorCounts;
  radarChart.update();

  // Doughnut Ratio
  const clearCount = allScans.filter(s => s.threat_level === "CLEAR").length;
  const narcCount = allScans.filter(s => s.threat_level === "NARCOTIC").length;
  const explCount = allScans.filter(s => s.threat_level === "EXPLOSIVE").length;
  ratioChart.data.datasets[0].data = [clearCount, narcCount, explCount];
  ratioChart.update();

  // Confidence Distribution
  const narcDist = [0, 0, 0, 0, 0];
  const explDist = [0, 0, 0, 0, 0];

  allScans.forEach(s => {
    if (s.threat_level === "NARCOTIC") {
      const idx = Math.min(Math.floor(s.confidence / 20), 4);
      narcDist[idx]++;
    } else if (s.threat_level === "EXPLOSIVE") {
      const idx = Math.min(Math.floor(s.confidence / 20), 4);
      explDist[idx]++;
    }
  });

  confDistChart.data.datasets[0].data = narcDist;
  confDistChart.data.datasets[1].data = explDist;
  confDistChart.update();
}

// ---------- Incident Comparison Engine ----------

function populateComparisonDropdowns() {
  const selA = document.getElementById("compare-scan-a");
  const selB = document.getElementById("compare-scan-b");
  if (!selA || !selB) return;

  const currentA = selA.value;
  const currentB = selB.value;

  selA.innerHTML = "";
  selB.innerHTML = "";

  allScans.forEach((scan, idx) => {
    const optText = `Scan #${scan.scan_number} - ${scan.threat_level} (${scan.confidence}%)`;
    selA.appendChild(new Option(optText, scan.id));
    selB.appendChild(new Option(optText, scan.id));
  });

  // Default selection: pick highest explosive vs highest narcotic or scans 1 & 2
  if (currentA && allScans.some(s => s.id == currentA)) {
    selA.value = currentA;
  } else if (allScans.length > 0) {
    const expl = allScans.find(s => s.threat_level === "EXPLOSIVE");
    selA.value = expl ? expl.id : allScans[0].id;
  }

  if (currentB && allScans.some(s => s.id == currentB)) {
    selB.value = currentB;
  } else if (allScans.length > 1) {
    const narc = allScans.find(s => s.threat_level === "NARCOTIC");
    selB.value = narc ? narc.id : allScans[1].id;
  }

  selA.onchange = renderComparisonView;
  selB.onchange = renderComparisonView;
}

function renderComparisonView() {
  const idA = document.getElementById("compare-scan-a")?.value;
  const idB = document.getElementById("compare-scan-b")?.value;
  const scanA = allScans.find(s => s.id == idA);
  const scanB = allScans.find(s => s.id == idB);

  const container = document.getElementById("compare-matrix");
  const deltaContainer = document.getElementById("compare-deltas");
  if (!container || !deltaContainer) return;

  if (!scanA || !scanB) {
    container.innerHTML = "<p>Select two scans above to compute comparative data analytics.</p>";
    deltaContainer.innerHTML = "";
    return;
  }

  // Render cards for Scan A and Scan B
  container.innerHTML = `
    ${renderScanCard(scanA, "PRIMARY INCIDENT (A)")}
    ${renderScanCard(scanB, "COMPARISON INCIDENT (B)")}
  `;

  // Compute Analytics Deltas
  const confDelta = scanA.confidence - scanB.confidence;
  const confDeltaStr = confDelta > 0 ? `+${confDelta}%` : `${confDelta}%`;

  // Angular difference (-180 to +180)
  const angleDelta = (scanB.heading - scanA.heading + 540) % 360 - 180;
  const angleDeltaStr = Math.abs(angleDelta) <= 15
    ? "Aligned (±15°)"
    : `${Math.abs(angleDelta)}° ${angleDelta > 0 ? "Clockwise" : "Counter-Clockwise"}`;

  // Ground distance (Haversine formula in meters)
  const distanceMeters = haversineMeters(scanA.lat, scanA.lon, scanB.lat, scanB.lon);
  const distStr = distanceMeters < 1000 ? `${distanceMeters} m` : `${(distanceMeters / 1000).toFixed(2)} km`;

  deltaContainer.innerHTML = `
    <div class="panel-title">DELTA ANALYSIS MATRIX</div>
    <div class="delta-grid">
      <div class="delta-box">
        <div class="kpi-title">Confidence Delta (A vs B)</div>
        <div class="delta-val" style="color:${confDelta >= 0 ? 'var(--threat-expl)' : 'var(--threat-clear)'}">${confDeltaStr}</div>
      </div>
      <div class="delta-box">
        <div class="kpi-title">Directional Divergence</div>
        <div class="delta-val">${angleDeltaStr}</div>
      </div>
      <div class="delta-box">
        <div class="kpi-title">Ground Distance Delta</div>
        <div class="delta-val">${distStr}</div>
      </div>
      <div class="delta-box">
        <div class="kpi-title">Threat Classification Match</div>
        <div class="delta-val" style="font-size:16px; margin-top:8px; color:${scanA.threat_level === scanB.threat_level ? 'var(--threat-clear)' : 'var(--threat-narc)'}">
          ${scanA.threat_level === scanB.threat_level ? 'MATCH (' + scanA.threat_level + ')' : 'DIVERGENT CLUSTER'}
        </div>
      </div>
    </div>
  `;
}

function renderScanCard(scan, tag) {
  const lvl = (scan.threat_level || "CLEAR").toLowerCase();
  return `
    <div class="comp-card highlight">
      <div class="comp-header">
        <div>
          <span style="font-size:11px; color:var(--accent-cyan); font-weight:700;">${tag}</span>
          <div class="comp-title">SCAN #${scan.scan_number}</div>
        </div>
        <span class="badge ${lvl}">${scan.threat_level}</span>
      </div>

      <div class="compass-dial">
        <div class="compass-needle" style="transform: rotate(${scan.heading}deg);"></div>
      </div>
      <div style="text-align:center; font-size:12px; color:var(--text-muted); margin-bottom:12px;">Facing: <strong>${scan.heading}°</strong></div>

      <div class="comp-metric-row">
        <span class="comp-metric-label">Confidence</span>
        <span class="comp-metric-val">${scan.confidence}%</span>
      </div>
      <div class="comp-metric-row">
        <span class="comp-metric-label">Coordinates</span>
        <span class="comp-metric-val">${scan.lat.toFixed(4)}, ${scan.lon.toFixed(4)}</span>
      </div>
      <div class="comp-metric-row">
        <span class="comp-metric-label">Recorded At</span>
        <span class="comp-metric-val">${formatTime(scan.timestamp)}</span>
      </div>
      <div class="comp-metric-row">
        <span class="comp-metric-label">Data Source</span>
        <span class="comp-metric-val">${scan.source || 'pod'}</span>
      </div>
      <div style="margin-top:12px; font-size:12px; color:var(--text-muted)">
        <strong>Field Notes:</strong> ${scan.operator_notes || '<em>No notes added</em>'}
      </div>
    </div>
  `;
}

// Haversine formula
function haversineMeters(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const φ1 = (lat1 * Math.PI) / 180;
  const φ2 = (lat2 * Math.PI) / 180;
  const Δφ = ((lat2 - lat1) * Math.PI) / 180;
  const Δλ = ((lon2 - lon1) * Math.PI) / 180;

  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
            Math.cos(φ1) * Math.cos(φ2) *
            Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c);
}

// ---------- Audit Logs & In-Line Notes ----------

function renderLogTable() {
  const tbody = document.getElementById("log-table-body");
  if (!tbody) return;
  tbody.innerHTML = "";

  if (filteredScans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-dim); padding:24px;">No telemetry records matching filter criteria.</td></tr>`;
    return;
  }

  filteredScans.forEach(scan => {
    const tr = document.createElement("tr");
    const lvl = (scan.threat_level || "CLEAR").toLowerCase();
    tr.innerHTML = `
      <td>#${scan.scan_number}</td>
      <td><span class="badge ${lvl}">${scan.threat_level}</span></td>
      <td><strong>${scan.confidence}%</strong></td>
      <td>${scan.heading}°</td>
      <td>${scan.lat.toFixed(4)}, ${scan.lon.toFixed(4)}</td>
      <td>${formatTime(scan.timestamp)}</td>
      <td>
        <span class="notes-cell" title="Click to edit operator field notes" onclick="editNote(${scan.id}, this)">
          ${escapeHtml(scan.operator_notes || '')}
        </span>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function editNote(scanId, element) {
  const current = element.innerText.trim();
  const updated = prompt("Enter Operator Field Notes for Scan #" + scanId + ":", current);
  if (updated === null) return;

  const scan = allScans.find(s => s.id === scanId);
  if (scan) {
    scan.operator_notes = updated;
    element.innerText = updated;
    saveLocalState();
  }

  if (isBackendOnline) {
    try {
      await fetch(`/api/scans/${scanId}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: updated })
      });
      showToast(`Notes updated for Scan #${scanId}`);
    } catch (e) {
      showToast("Updated locally (offline mode).");
    }
  } else {
    showToast(`Notes saved to browser database.`);
  }
}

// ---------- Modals & Actions ----------

function initModals() {
  const modal = document.getElementById("csv-modal");
  const openBtn = document.getElementById("btn-open-csv");
  const closeBtn = document.getElementById("btn-close-csv");
  const dropZone = document.getElementById("csv-dropzone");
  const fileInput = document.getElementById("csv-file-input");

  if (openBtn && modal) {
    openBtn.addEventListener("click", () => modal.classList.add("open"));
  }
  if (closeBtn && modal) {
    closeBtn.addEventListener("click", () => modal.classList.remove("open"));
  }

  if (dropZone && fileInput) {
    dropZone.addEventListener("click", () => fileInput.click());

    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.classList.add("dragover");
    });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.classList.remove("dragover");
      if (e.dataTransfer.files.length > 0) {
        handleCsvFile(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener("change", () => {
      if (fileInput.files.length > 0) {
        handleCsvFile(fileInput.files[0]);
      }
    });
  }
}

function handleCsvFile(file) {
  const reader = new FileReader();
  reader.onload = async (e) => {
    const text = e.target.result;
    if (isBackendOnline) {
      try {
        const res = await fetch("/api/upload-csv", {
          method: "POST",
          headers: { "Content-Type": "text/csv" },
          body: text
        });
        const json = await res.json();
        showToast(`Successfully imported ${json.imported_count || 0} scans from SD card.`);
        document.getElementById("csv-modal")?.classList.remove("open");
        await loadData();
        return;
      } catch (err) {
        console.warn("Server import error, using local parser", err);
      }
    }

    // Client-side CSV Parser
    parseCsvClientSide(text);
  };
  reader.readAsText(file);
}

function parseCsvClientSide(text) {
  const lines = text.trim().split("\n").filter(l => l.trim().length > 0);
  let count = 0;
  lines.forEach((line, idx) => {
    if (idx === 0 && line.toLowerCase().includes("scan")) return; // header
    const p = line.split(",").map(s => s.trim());
    if (p.length >= 4) {
      const scanNum = parseInt(p[0]) || (allScans.length + 1);
      const lvlRaw = p.length >= 7 ? p[2] : p[1];
      const conf = parseInt(p.length >= 7 ? p[3] : p[2]) || 0;
      const heading = parseInt(p.length >= 7 ? p[4] : p[3]) || 0;
      const lat = parseFloat(p.length >= 7 ? p[5] : p[4]) || 28.6139;
      const lon = parseFloat(p.length >= 7 ? p[6] : p[5]) || 77.2090;

      let lvlStr = "CLEAR";
      if (lvlRaw === "2" || lvlRaw === "EXPLOSIVE") lvlStr = "EXPLOSIVE";
      else if (lvlRaw === "1" || lvlRaw === "NARCOTIC") lvlStr = "NARCOTIC";

      allScans.unshift({
        id: Date.now() + count,
        scan_number: scanNum,
        timestamp: new Date().toISOString(),
        threat_level: lvlStr,
        confidence: conf,
        heading: heading,
        lat: lat,
        lon: lon,
        is_alert: conf >= 60 ? 1 : 0,
        operator_notes: "Imported from SD Card log",
        source: "sd_import"
      });
      count++;
    }
  });

  saveLocalState();
  applyFilters();
  renderAllViews();
  document.getElementById("csv-modal")?.classList.remove("open");
  showToast(`Imported ${count} scans into browser database.`);
}

// Action: Sync from ThingSpeak Cloud
async function syncThingSpeak() {
  showToast("Syncing telemetry with ThingSpeak Cloud...");
  if (isBackendOnline) {
    try {
      const res = await fetch("/api/sync-thingspeak", { method: "POST" });
      const json = await res.json();
      showToast(`Cloud Sync Complete: ${json.synced_count || 0} new feeds added.`);
      await loadData();
      return;
    } catch (e) {}
  }

  // Direct Browser ThingSpeak Fetch
  try {
    const res = await fetch("https://api.thingspeak.com/channels/3492840/feeds.json?results=20");
    const json = await res.json();
    let newFeeds = 0;
    (json.feeds || []).forEach(f => {
      const scanNum = parseInt(f.field1 || 0);
      const lvlCode = f.field2;
      const conf = parseInt(f.field3 || 0);
      const lat = parseFloat(f.field4 || 28.6139);
      const lon = parseFloat(f.field5 || 77.2090);

      let lvlStr = "CLEAR";
      if (lvlCode === "2") lvlStr = "EXPLOSIVE";
      else if (lvlCode === "1") lvlStr = "NARCOTIC";

      // Deduplicate
      if (!allScans.some(s => s.scan_number === scanNum && s.source === "cloud_sync")) {
        allScans.unshift({
          id: Date.now() + Math.random(),
          scan_number: scanNum,
          timestamp: f.created_at,
          threat_level: lvlStr,
          confidence: conf,
          heading: 0,
          lat: lat,
          lon: lon,
          is_alert: conf >= 60 ? 1 : 0,
          operator_notes: "Synced from ThingSpeak",
          source: "cloud_sync"
        });
        newFeeds++;
      }
    });

    saveLocalState();
    applyFilters();
    renderAllViews();
    showToast(`Cloud Sync Complete: ${newFeeds} new records pulled.`);
  } catch (err) {
    showToast("Cloud sync failed. Check internet connection.");
  }
}

// Action: Seed Realistic Demo Inspection Data
async function seedDemoData() {
  if (isBackendOnline) {
    try {
      await fetch("/api/demo-data", { method: "POST" });
      await loadData();
      showToast("Added 12 realistic railway defense inspection scans.");
      return;
    } catch (e) {}
  }

  // Local fallback
  allScans = [...FALLBACK_DEMO_SCANS, ...allScans];
  saveLocalState();
  applyFilters();
  renderAllViews();
  showToast("Loaded 12 demo inspection scans into database.");
}

// Action: Export Data
function exportData(format = "csv") {
  if (isBackendOnline) {
    window.location.href = `/api/export?format=${format}`;
    return;
  }

  // Browser export fallback
  if (format === "json") {
    downloadFile(JSON.stringify(allScans, null, 2), "tracex_telemetry.json", "application/json");
  } else {
    const headers = ["scan_number", "timestamp", "threat_level", "confidence", "heading", "lat", "lon", "is_alert", "operator_notes"];
    const rows = allScans.map(s => [
      s.scan_number,
      s.timestamp,
      s.threat_level,
      s.confidence,
      s.heading,
      s.lat,
      s.lon,
      s.is_alert,
      `"${(s.operator_notes || '').replace(/"/g, '""')}"`
    ].join(","));
    const csvContent = [headers.join(","), ...rows].join("\n");
    downloadFile(csvContent, "tracex_telemetry.csv", "text/csv");
  }
}

function downloadFile(content, fileName, contentType) {
  const a = document.createElement("a");
  const file = new Blob([content], { type: contentType });
  a.href = URL.createObjectURL(file);
  a.download = fileName;
  a.click();
}

function inspectScan(scanId) {
  const scan = allScans.find(s => s.id === scanId);
  if (!scan) return;

  // Switch to comparison tab and set as Primary
  const compTabBtn = document.querySelector('[data-tab="tab-compare"]');
  if (compTabBtn) compTabBtn.click();

  const selA = document.getElementById("compare-scan-a");
  if (selA) {
    selA.value = scanId;
    renderComparisonView();
  }
}

// ---------- Helper Utilities ----------

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.innerText = val;
}

function formatTime(isoStr) {
  if (!isoStr) return "--";
  try {
    const d = new Date(isoStr);
    return isNaN(d.getTime()) ? isoStr : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) {
    return isoStr;
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function showToast(msg) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerText = msg;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}
