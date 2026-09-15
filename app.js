/**
 * TRACE-X Central Telemetry & Threat Analytics Platform (app.js)
 * High-legibility Defense & Industrial Monitoring Station Console
 * 
 * Key Functions:
 *  - Prominent Major Hero Alert Console for latest detection
 *  - Real-time continuous 3-second auto-poll against ThingSpeak channel 3492840
 *  - Dual-mode: SQLite REST API when server.py is running, with browser-native
 *    ThingSpeak fetch and localStorage caching when running standalone.
 *  - Zero emojis, clean SCADA C2 telemetry formatting.
 */

// Global State
let isBackendOnline = false;
let allScans = [];
let filteredScans = [];
let latestKnownEntryId = 0;
let mapInstance = null;
let mapMarkers = [];
let radarChart = null;
let currentSubview = "map";
let notesCache = {};

// Fallback demo scans if offline and no feeds available yet
const FALLBACK_DEMO_SCANS = [
  { id: 1, scan_number: 1, timestamp: "2026-09-15T01:10:00Z", threat_level: "CLEAR", confidence: 0, heading: 15, lat: 28.6430, lon: 77.2190, is_alert: 0, operator_notes: "Routine perimeter sweep - Platform 1", source: "demo" },
  { id: 2, scan_number: 2, timestamp: "2026-09-15T01:25:10Z", threat_level: "NARCOTIC", confidence: 45, heading: 90, lat: 28.6432, lon: 77.2194, is_alert: 0, operator_notes: "Minor organic trace near locker 12", source: "demo" },
  { id: 3, scan_number: 3, timestamp: "2026-09-15T01:28:45Z", threat_level: "NARCOTIC", confidence: 82, heading: 95, lat: 28.6433, lon: 77.2195, is_alert: 1, operator_notes: "STRONG NARCOTIC HIT - Locker 14 inspected", source: "demo" },
  { id: 4, scan_number: 4, timestamp: "2026-09-15T02:12:40Z", threat_level: "EXPLOSIVE", confidence: 65, heading: 240, lat: 28.6429, lon: 77.2188, is_alert: 1, operator_notes: "ELEVATED VAPOR - Unattended duffle near Track 3", source: "demo" },
  { id: 5, scan_number: 5, timestamp: "2026-09-15T02:14:10Z", threat_level: "EXPLOSIVE", confidence: 94, heading: 245, lat: 28.6428, lon: 77.2186, is_alert: 1, operator_notes: "CRITICAL HAZARD: High nitrate compound detected!", source: "demo" }
];

// ---------- Initialization ----------

document.addEventListener("DOMContentLoaded", async () => {
  loadNotesCache();
  initFilters();
  initModals();
  initMap();

  await checkBackendStatus();
  await syncThingSpeak(true); // initial silent load

  // If no scans loaded, fallback to demo
  if (allScans.length === 0) {
    allScans = [...FALLBACK_DEMO_SCANS];
    applyFilters();
    renderAllViews();
  }

  // Real-time continuous polling every 3 seconds
  setInterval(async () => {
    await syncThingSpeak(true);
  }, 3000);
});

// ---------- Local Notes Cache Management ----------

function loadNotesCache() {
  try {
    const raw = localStorage.getItem("tracex_notes_cache");
    if (raw) notesCache = JSON.parse(raw);
  } catch (e) {
    notesCache = {};
  }
}

function saveNotesCache() {
  try {
    localStorage.setItem("tracex_notes_cache", JSON.stringify(notesCache));
  } catch (e) {}
}

// ---------- Backend Check ----------

async function checkBackendStatus() {
  const pill = document.getElementById("backend-status");
  try {
    const res = await fetch("/api/status", { cache: "no-store" });
    if (res.ok) {
      isBackendOnline = true;
      if (pill) {
        pill.className = "status-pill online";
        pill.innerHTML = '<span class="status-indicator-box"></span> DB: SQLITE + LIVE SYNC (3s)';
      }
      return;
    }
  } catch (e) {
    // server.py is not reachable; standalone browser mode
  }

  isBackendOnline = false;
  if (pill) {
    pill.className = "status-pill online";
    pill.innerHTML = '<span class="status-indicator-box"></span> LIVE SYNC ACTIVE (3s)';
  }
}

// ---------- Real-Time ThingSpeak Cloud Sync & Telemetry Ingestion ----------

async function syncThingSpeak(silent = false) {
  if (!silent) {
    showToast("Connecting to ThingSpeak Cloud (Channel 3492840)...");
  }

  // If backend is online, notify server to sync to SQLite as well
  if (isBackendOnline) {
    try {
      fetch("/api/sync-thingspeak", { method: "POST" }).catch(() => {});
    } catch (e) {}
  }

  try {
    // Direct Browser Fetch from ThingSpeak (Public CORS supported)
    const url = "https://api.thingspeak.com/channels/3492840/feeds.json?results=50";
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const data = await res.json();
    const feeds = data.feeds || [];

    if (feeds.length > 0) {
      // Find highest entry_id
      const maxEntry = Math.max(...feeds.map(f => parseInt(f.entry_id) || 0));
      const isNewDetection = latestKnownEntryId > 0 && maxEntry > latestKnownEntryId;

      // Map feeds to standard scan objects, newest first
      const mappedScans = feeds.map(f => {
        const entryId = parseInt(f.entry_id) || 0;
        const scanNum = entryId;
        const lvlCode = String(f.field2 || "0");
        const conf = parseInt(f.field3) || 0;
        const lat = parseFloat(f.field4) || 28.6430;
        const lon = parseFloat(f.field5) || 77.2190;
        const heading = parseInt(f.field6) || 0;
        const timestamp = f.created_at;

        let lvlStr = "CLEAR";
        if (lvlCode === "2") lvlStr = "EXPLOSIVE";
        else if (lvlCode === "1") lvlStr = "NARCOTIC";

        const cachedNote = notesCache[scanNum] || notesCache[timestamp] || "";

        return {
          id: entryId,
          scan_number: scanNum,
          timestamp: timestamp,
          threat_level: lvlStr,
          confidence: conf,
          heading: heading,
          lat: lat,
          lon: lon,
          is_alert: conf >= 60 ? 1 : 0,
          operator_notes: cachedNote || "Live pod telemetry stream",
          source: "live_stream"
        };
      }).reverse(); // newest first

      allScans = mappedScans;

      if (isNewDetection) {
        const newest = allScans[0];
        showToast(`NEW TELEMETRY: Scan #${newest.scan_number} [${newest.threat_level}] - ${newest.confidence}%`);
      }

      latestKnownEntryId = maxEntry;

      // Save to local storage cache
      try {
        localStorage.setItem("tracex_local_scans", JSON.stringify(allScans));
      } catch (e) {}

      applyFilters();
      renderAllViews();

      if (!silent) {
        showToast(`Cloud Sync Complete: ${feeds.length} records verified.`);
      }
      return;
    }
  } catch (err) {
    if (!silent) {
      showToast("Cloud sync failed. Check internet connection.");
    }
  }

  // Fallback to local storage if network request failed
  if (allScans.length === 0) {
    const saved = localStorage.getItem("tracex_local_scans");
    if (saved) {
      try {
        allScans = JSON.parse(saved);
        applyFilters();
        renderAllViews();
      } catch (e) {}
    }
  }
}

// ---------- Filter & Search Handling ----------

function initFilters() {
  const searchInput = document.getElementById("search-input");
  const threatSelect = document.getElementById("filter-threat");
  const confSlider = document.getElementById("filter-conf");
  const confValLabel = document.getElementById("filter-conf-val");

  const applyChange = () => {
    applyFilters();
    renderFilteredViews();
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
  renderHeroAlert(allScans[0] || null);
  renderLogTable();
  renderMapMarkers();
  updateRadarChart();
  populateComparisonDropdowns();
}

function renderFilteredViews() {
  renderLogTable();
  renderMapMarkers();
  updateRadarChart();
}

// ---------- MAJOR HERO ALERT CONSOLE ----------

function renderHeroAlert(scan) {
  const card = document.getElementById("hero-alert-card");
  const title = document.getElementById("hero-status-title");
  const badge = document.getElementById("hero-status-badge");
  const timeEl = document.getElementById("hero-status-time");
  const confVal = document.getElementById("hero-conf-val");
  const meterFill = document.getElementById("hero-meter-fill");

  const scanNum = document.getElementById("hero-scan-num");
  const threatType = document.getElementById("hero-threat-type");
  const headingEl = document.getElementById("hero-heading");
  const coordsEl = document.getElementById("hero-coords");
  const levelDesc = document.getElementById("hero-level-desc");
  const sourceEl = document.getElementById("hero-source");
  const notesText = document.getElementById("hero-notes-text");

  if (!card) return;

  if (!scan) {
    card.className = "hero-alert-card nominal";
    if (title) title.innerText = "STATUS: NOMINAL // AWAITING TELEMETRY STREAM";
    if (badge) { badge.className = "hero-alert-badge nominal"; badge.innerText = "NOMINAL"; }
    if (timeEl) timeEl.innerText = "Awaiting pod signals...";
    if (confVal) { confVal.className = "hero-conf-value nominal"; confVal.innerText = "0%"; }
    if (meterFill) { meterFill.className = "hero-meter-fill"; meterFill.style.width = "0%"; }
    if (scanNum) scanNum.innerText = "SCAN #--";
    if (threatType) threatType.innerText = "CLEAR";
    if (headingEl) headingEl.innerText = "0° [N]";
    if (coordsEl) coordsEl.innerText = "28.6430, 77.2190";
    if (levelDesc) levelDesc.innerText = "SECURE";
    if (sourceEl) sourceEl.innerText = "LIVE STREAM";
    if (notesText) notesText.innerText = "No remarks attached to latest telemetry entry.";
    return;
  }

  const conf = Math.min(Math.max(scan.confidence || 0, 0), 100);
  const threat = (scan.threat_level || "CLEAR").toUpperCase();
  const heading = scan.heading || 0;
  const cardinal = getCardinal(heading);

  if (threat === "EXPLOSIVE") {
    card.className = "hero-alert-card critical";
    if (badge) {
      badge.className = "hero-alert-badge critical";
      badge.innerText = "CRITICAL HAZARD";
    }
    if (title) {
      title.innerText = `ALARM [EXP-01]: HIGH-CONFIDENCE EXPLOSIVE HAZARD DETECTED`;
    }
    if (confVal) {
      confVal.className = "hero-conf-value critical";
    }
    if (meterFill) {
      meterFill.className = "hero-meter-fill critical";
    }
    if (threatType) {
      threatType.innerHTML = `<span style="color:var(--col-critical);">EXPLOSIVE [CLASS-2]</span>`;
    }
    if (levelDesc) {
      levelDesc.innerHTML = `<span style="color:var(--col-critical); font-weight:800;">CRITICAL ALARM</span>`;
    }
  } else if (threat === "NARCOTIC") {
    card.className = "hero-alert-card warning";
    if (badge) {
      badge.className = "hero-alert-badge warning";
      badge.innerText = "WARNING";
    }
    if (title) {
      title.innerText = `WARNING [NRC-01]: ELEVATED NARCOTIC SIGNATURE FLAGGED`;
    }
    if (confVal) {
      confVal.className = "hero-conf-value warning";
    }
    if (meterFill) {
      meterFill.className = "hero-meter-fill warning";
    }
    if (threatType) {
      threatType.innerHTML = `<span style="color:var(--col-warning);">NARCOTIC [CLASS-1]</span>`;
    }
    if (levelDesc) {
      levelDesc.innerHTML = `<span style="color:var(--col-warning); font-weight:800;">CAUTION ACTIVE</span>`;
    }
  } else {
    card.className = "hero-alert-card nominal";
    if (badge) {
      badge.className = "hero-alert-badge nominal";
      badge.innerText = "NOMINAL";
    }
    if (title) {
      title.innerText = `STATUS: NOMINAL // ALL SENSORS STABLE // BACKGROUND CLEAR`;
    }
    if (confVal) {
      confVal.className = "hero-conf-value nominal";
    }
    if (meterFill) {
      meterFill.className = "hero-meter-fill";
    }
    if (threatType) {
      threatType.innerHTML = `<span style="color:var(--col-nominal);">CLEAR [ALL-OK]</span>`;
    }
    if (levelDesc) {
      levelDesc.innerHTML = `<span style="color:var(--col-nominal); font-weight:800;">SECURE</span>`;
    }
  }

  if (confVal) confVal.innerText = `${conf}%`;
  if (meterFill) meterFill.style.width = `${conf}%`;
  if (scanNum) scanNum.innerText = `SCAN #${scan.scan_number}`;
  if (headingEl) headingEl.innerText = `${heading}° [${cardinal}]`;
  if (coordsEl) coordsEl.innerText = `${Number(scan.lat).toFixed(4)}, ${Number(scan.lon).toFixed(4)}`;
  if (sourceEl) {
    sourceEl.innerText = scan.source === "live_stream" ? "POD STREAM (CH-3492840)" : (scan.source === "sd_import" ? "SD CARD LOG" : "LOCAL STORAGE");
  }
  if (timeEl) timeEl.innerText = formatRelativeTime(scan.timestamp);
  if (notesText) {
    notesText.innerText = scan.operator_notes || "No remarks attached to latest telemetry entry.";
  }

  // Rotate compass needle to target bearing
  const needle = document.getElementById("hero-compass-needle");
  if (needle) {
    needle.style.transform = `translateX(-50%) rotate(${heading}deg)`;
  }
  const cardinalEl = document.getElementById("hero-heading-cardinal");
  if (cardinalEl) {
    cardinalEl.innerText = `${cardinal} Vector (${heading}°)`;
  }
}

// ---------- Sample Demo Data Seeder ----------

function seedDemoData() {
  allScans = [...FALLBACK_DEMO_SCANS];
  latestKnownEntryId = 5;
  applyFilters();
  renderAllViews();
  showToast("Sample telemetry loaded into console.");
  if (isBackendOnline) {
    fetch("/api/demo-data", { method: "POST" }).catch(() => {});
  }
}


// ---------- Live Telemetry Incident Log Table ----------

function renderLogTable() {
  const tbody = document.getElementById("log-table-body");
  if (!tbody) return;
  tbody.innerHTML = "";

  if (filteredScans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-dim); padding:28px;">No telemetry records matching filter criteria.</td></tr>`;
    return;
  }

  filteredScans.forEach((scan, idx) => {
    const tr = document.createElement("tr");
    const lvl = (scan.threat_level || "CLEAR").toLowerCase();
    const isLatest = (idx === 0);

    if (isLatest) {
      tr.className = "latest-row";
    }

    const heading = scan.heading || 0;
    const cardinal = getCardinal(heading);

    tr.innerHTML = `
      <td>
        <strong>#${scan.scan_number}</strong>
        ${isLatest ? '<span class="badge-latest">LATEST</span>' : ''}
      </td>
      <td><span class="badge ${lvl}">${scan.threat_level}</span></td>
      <td><strong>${scan.confidence}%</strong></td>
      <td>${heading}° [${cardinal}]</td>
      <td>${Number(scan.lat).toFixed(4)}, ${Number(scan.lon).toFixed(4)}</td>
      <td>${formatTime(scan.timestamp)}</td>
      <td>
        <span class="notes-cell" title="Click to edit operator notes" onclick="editNote(${scan.id}, this)">
          ${escapeHtml(scan.operator_notes || '')}
        </span>
      </td>
    `;

    tr.addEventListener("click", (e) => {
      if (e.target.closest(".notes-cell")) return;
      focusScan(scan);
    });

    tbody.appendChild(tr);
  });
}

function focusScan(scan) {
  if (mapInstance && scan.lat && scan.lon) {
    mapInstance.setView([scan.lat, scan.lon], 17);
    showToast(`Focused on Map: Scan #${scan.scan_number}`);
  }
}

async function editNote(scanId, element) {
  const current = element.innerText.trim();
  const updated = prompt("Enter Operator Remarks for Scan #" + scanId + ":", current);
  if (updated === null) return;

  const scan = allScans.find(s => s.id === scanId);
  if (scan) {
    scan.operator_notes = updated;
    element.innerText = updated;
    notesCache[scan.scan_number] = updated;
    notesCache[scan.timestamp] = updated;
    saveNotesCache();

    if (allScans[0] && allScans[0].id === scanId) {
      const heroRemarks = document.getElementById("hero-notes-text");
      if (heroRemarks) heroRemarks.innerText = updated;
    }
  }

  if (isBackendOnline) {
    try {
      await fetch(`/api/scans/${scanId}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: updated })
      });
      showToast(`Remarks updated for Scan #${scanId}`);
    } catch (e) {
      showToast("Saved to local browser storage.");
    }
  } else {
    showToast(`Remarks saved for Scan #${scanId}`);
  }
}

// ---------- Leaflet.js GPS Threat Map ----------

function initMap() {
  const mapEl = document.getElementById("gps-map");
  if (!mapEl || mapInstance) return;

  const defaultLat = 28.6430;
  const defaultLon = 77.2190;

  mapInstance = L.map("gps-map", {
    center: [defaultLat, defaultLon],
    zoom: 16,
    zoomControl: true
  });

  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: '&copy; <a href="https://carto.com/">CARTO</a> | TRACE-X Defense Grid',
    maxZoom: 19
  }).addTo(mapInstance);
}

function renderMapMarkers() {
  if (!mapInstance) return;

  mapMarkers.forEach(m => mapInstance.removeLayer(m));
  mapMarkers = [];

  if (allScans.length === 0) return;

  const latest = allScans[0];
  if (latest && latest.lat && latest.lon) {
    mapInstance.setView([latest.lat, latest.lon], mapInstance.getZoom() || 16);
  }

  allScans.forEach((scan, idx) => {
    if (!scan.lat || !scan.lon) return;

    let color = "#10b981";
    if (scan.threat_level === "EXPLOSIVE") color = "#ef4444";
    else if (scan.threat_level === "NARCOTIC") color = "#f59e0b";

    const isLatest = (idx === 0);
    const radius = isLatest ? 10 : (scan.threat_level === "CLEAR" ? 6 : 8);

    const marker = L.circleMarker([scan.lat, scan.lon], {
      radius: radius,
      fillColor: color,
      color: isLatest ? "#38bdf8" : "#ffffff",
      weight: isLatest ? 3 : 1.5,
      opacity: 1.0,
      fillOpacity: 0.85
    });

    const cardinal = getCardinal(scan.heading || 0);

    const popupHtml = `
      <div style="font-family:var(--text-mono); font-size:13px; line-height:1.5;">
        <div style="font-weight:800; color:${color}; margin-bottom:4px;">
          SCAN #${scan.scan_number} &bull; ${scan.threat_level}
          ${isLatest ? ' [LATEST]' : ''}
        </div>
        <div>Confidence: <strong>${scan.confidence}%</strong></div>
        <div>Heading: <strong>${scan.heading || 0}° [${cardinal}]</strong></div>
        <div>GPS: ${Number(scan.lat).toFixed(5)}, ${Number(scan.lon).toFixed(5)}</div>
        <div>Time: ${formatTime(scan.timestamp)}</div>
        ${scan.operator_notes ? `<div style="color:#94a3b8; margin-top:4px;"><em>"${escapeHtml(scan.operator_notes)}"</em></div>` : ''}
      </div>
    `;

    marker.bindPopup(popupHtml);
    marker.addTo(mapInstance);
    mapMarkers.push(marker);
  });
}

// ---------- Subview Switching (Map / Radar / Compare) ----------

function switchSubview(mode) {
  currentSubview = mode;

  const btnMap = document.getElementById("btn-subview-map");
  const btnRadar = document.getElementById("btn-subview-radar");
  const btnComp = document.getElementById("btn-subview-compare");

  const viewMap = document.getElementById("subview-map");
  const viewRadar = document.getElementById("subview-radar");
  const viewComp = document.getElementById("subview-compare");
  const headerTitle = document.getElementById("subview-header-title");

  [btnMap, btnRadar, btnComp].forEach(b => b?.classList.remove("active"));
  if (viewMap) viewMap.style.display = "none";
  if (viewRadar) viewRadar.style.display = "none";
  if (viewComp) viewComp.style.display = "none";

  if (mode === "map") {
    btnMap?.classList.add("active");
    if (viewMap) viewMap.style.display = "block";
    if (headerTitle) headerTitle.innerText = "GEOGRAPHICAL DEPLOYMENT MAP";
    if (mapInstance) {
      setTimeout(() => mapInstance.invalidateSize(), 150);
    }
  } else if (mode === "radar") {
    btnRadar?.classList.add("active");
    if (viewRadar) viewRadar.style.display = "block";
    if (headerTitle) headerTitle.innerText = "360° DIRECTIONAL POLAR RADAR";
    initRadarChart();
    updateRadarChart();
  } else if (mode === "compare") {
    btnComp?.classList.add("active");
    if (viewComp) viewComp.style.display = "block";
    if (headerTitle) headerTitle.innerText = "INCIDENT COMPARISON MATRIX";
    populateComparisonDropdowns();
    renderComparisonView();
  }
}

// ---------- 360° Directional Polar Radar Chart ----------

function initRadarChart() {
  if (radarChart) return;
  const ctx = document.getElementById("chart-radar")?.getContext("2d");
  if (!ctx) return;

  radarChart = new Chart(ctx, {
    type: "polarArea",
    data: {
      labels: ["0° [N]", "30°", "60°", "90° [E]", "120°", "150°", "180° [S]", "210°", "240°", "270° [W]", "300°", "330°"],
      datasets: [{
        data: new Array(12).fill(0),
        backgroundColor: [
          "rgba(56, 189, 248, 0.45)", "rgba(56, 189, 248, 0.45)", "rgba(245, 158, 11, 0.55)",
          "rgba(245, 158, 11, 0.75)", "rgba(245, 158, 11, 0.55)", "rgba(56, 189, 248, 0.45)",
          "rgba(56, 189, 248, 0.45)", "rgba(239, 68, 68, 0.55)", "rgba(239, 68, 68, 0.85)",
          "rgba(239, 68, 68, 0.55)", "rgba(56, 189, 248, 0.45)", "rgba(56, 189, 248, 0.45)"
        ],
        borderColor: "#1e293b",
        borderWidth: 1.5
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          grid: { color: "#232c3f" },
          ticks: { color: "#94a3b8", backdropColor: "transparent", font: { family: "JetBrains Mono" } }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (item) => ` Sector ${item.label}: ${item.raw} active threat signals`
          }
        }
      }
    }
  });
}

function updateRadarChart() {
  if (!radarChart) return;

  const sectorCounts = new Array(12).fill(0);
  allScans.filter(s => s.threat_level !== "CLEAR").forEach(s => {
    const sec = Math.floor(((s.heading || 0) % 360) / 30);
    sectorCounts[sec]++;
  });

  radarChart.data.datasets[0].data = sectorCounts;
  radarChart.update();
}

// ---------- Incident Comparison Matrix ----------

function populateComparisonDropdowns() {
  const selA = document.getElementById("compare-scan-a");
  const selB = document.getElementById("compare-scan-b");
  if (!selA || !selB) return;

  const currentA = selA.value;
  const currentB = selB.value;

  selA.innerHTML = "";
  selB.innerHTML = "";

  allScans.forEach((scan) => {
    const optText = `Scan #${scan.scan_number} - ${scan.threat_level} (${scan.confidence}%)`;
    selA.appendChild(new Option(optText, scan.id));
    selB.appendChild(new Option(optText, scan.id));
  });

  if (currentA && allScans.some(s => String(s.id) === String(currentA))) {
    selA.value = currentA;
  } else if (allScans.length > 0) {
    selA.value = allScans[0].id;
  }

  if (currentB && allScans.some(s => String(s.id) === String(currentB))) {
    selB.value = currentB;
  } else if (allScans.length > 1) {
    selB.value = allScans[1].id;
  }

  selA.onchange = renderComparisonView;
  selB.onchange = renderComparisonView;
}

function renderComparisonView() {
  const idA = document.getElementById("compare-scan-a")?.value;
  const idB = document.getElementById("compare-scan-b")?.value;
  const scanA = allScans.find(s => String(s.id) === String(idA));
  const scanB = allScans.find(s => String(s.id) === String(idB));

  const matrixEl = document.getElementById("compare-matrix");
  const deltasEl = document.getElementById("compare-deltas");
  if (!matrixEl || !deltasEl) return;

  if (!scanA || !scanB) {
    matrixEl.innerHTML = `<p style="color:var(--text-dim); padding:20px; font-family:var(--text-mono);">Select two incident records above to compute comparative delta analytics.</p>`;
    deltasEl.innerHTML = "";
    return;
  }

  matrixEl.innerHTML = `
    ${renderScanCompareCard(scanA, "PRIMARY (A)")}
    ${renderScanCompareCard(scanB, "COMPARISON (B)")}
  `;

  // Compute Deltas
  const confDelta = (scanA.confidence || 0) - (scanB.confidence || 0);
  const confDeltaStr = confDelta >= 0 ? `+${confDelta}%` : `${confDelta}%`;

  const angleDelta = (((scanB.heading || 0) - (scanA.heading || 0) + 540) % 360) - 180;
  const angleDeltaStr = Math.abs(angleDelta) <= 10
    ? "Aligned (±10°)"
    : `${Math.abs(angleDelta)}° ${angleDelta > 0 ? "Clockwise" : "Counter-Clockwise"}`;

  const distMeters = haversineMeters(scanA.lat, scanA.lon, scanB.lat, scanB.lon);
  const distStr = distMeters < 1000 ? `${distMeters} m` : `${(distMeters / 1000).toFixed(2)} km`;

  const matchColor = scanA.threat_level === scanB.threat_level ? "var(--col-nominal)" : "var(--col-warning)";

  deltasEl.innerHTML = `
    <div class="panel-title" style="margin-bottom:10px;">ANALYTICAL DELTA METRICS</div>
    <div class="delta-grid">
      <div class="delta-box">
        <div class="kpi-title">Confidence Delta (A vs B)</div>
        <div class="delta-val" style="color:${confDelta >= 0 ? 'var(--col-critical)' : 'var(--col-nominal)'}">
          ${confDeltaStr}
        </div>
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
        <div class="kpi-title">Classification Correlation</div>
        <div class="delta-val" style="font-size:13px; color:${matchColor};">
          ${scanA.threat_level === scanB.threat_level ? 'MATCH (' + scanA.threat_level + ')' : 'DIVERGENT'}
        </div>
      </div>
    </div>
  `;
}

function renderScanCompareCard(scan, tag) {
  const lvl = (scan.threat_level || "CLEAR").toLowerCase();
  const cardinal = getCardinal(scan.heading || 0);

  return `
    <div class="comp-card">
      <div class="comp-header">
        <div>
          <span style="font-size:10px; color:var(--col-telemetry); font-weight:800; font-family:var(--text-mono);">${tag}</span>
          <div class="comp-title">SCAN #${scan.scan_number}</div>
        </div>
        <span class="badge ${lvl}">${scan.threat_level}</span>
      </div>

      <div class="comp-metric-row">
        <span class="comp-metric-label">Certainty</span>
        <span class="comp-metric-val">${scan.confidence}%</span>
      </div>
      <div class="comp-metric-row">
        <span class="comp-metric-label">Heading</span>
        <span class="comp-metric-val">${scan.heading || 0}° [${cardinal}]</span>
      </div>
      <div class="comp-metric-row">
        <span class="comp-metric-label">Coordinates</span>
        <span class="comp-metric-val">${Number(scan.lat).toFixed(4)}, ${Number(scan.lon).toFixed(4)}</span>
      </div>
      <div class="comp-metric-row">
        <span class="comp-metric-label">Recorded At</span>
        <span class="comp-metric-val">${formatTime(scan.timestamp)}</span>
      </div>
      <div style="margin-top:10px; font-size:12px; color:var(--text-muted); font-family:var(--text-mono);">
        <strong>Remarks:</strong> ${escapeHtml(scan.operator_notes || 'None')}
      </div>
    </div>
  `;
}

function haversineMeters(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const p1 = (lat1 * Math.PI) / 180;
  const p2 = (lat2 * Math.PI) / 180;
  const dp = ((lat2 - lat1) * Math.PI) / 180;
  const dl = ((lon2 - lon1) * Math.PI) / 180;

  const a = Math.sin(dp / 2) * Math.sin(dp / 2) +
            Math.cos(p1) * Math.cos(p2) *
            Math.sin(dl / 2) * Math.sin(dl / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c);
}

// ---------- SD Card CSV Import / Export ----------

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
  reader.onload = (e) => {
    const text = e.target.result;
    parseCsvClientSide(text);
  };
  reader.readAsText(file);
}

function parseCsvClientSide(text) {
  const lines = text.trim().split("\n").filter(l => l.trim().length > 0);
  let count = 0;
  lines.forEach((line, idx) => {
    if (idx === 0 && line.toLowerCase().includes("scan")) return;
    const p = line.split(",").map(s => s.trim());
    if (p.length >= 4) {
      const scanNum = parseInt(p[0]) || (allScans.length + 1);
      const lvlRaw = p.length >= 7 ? p[2] : p[1];
      const conf = parseInt(p.length >= 7 ? p[3] : p[2]) || 0;
      const heading = parseInt(p.length >= 7 ? p[4] : p[3]) || 0;
      const lat = parseFloat(p.length >= 7 ? p[5] : p[4]) || 28.6430;
      const lon = parseFloat(p.length >= 7 ? p[6] : p[5]) || 77.2190;

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
        operator_notes: "Imported from MicroSD log.csv",
        source: "sd_import"
      });
      count++;
    }
  });

  applyFilters();
  renderAllViews();
  document.getElementById("csv-modal")?.classList.remove("open");
  showToast(`Imported ${count} scan records from SD Card.`);
}

function exportData(format = "csv") {
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

// ---------- Helper Utilities ----------

function getCardinal(deg) {
  const directions = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE", "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"];
  const val = Math.round((((deg % 360) + 360) % 360) / 22.5);
  return directions[val % 16];
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

function formatRelativeTime(isoStr) {
  if (!isoStr) return "--";
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    const diffSec = Math.round((Date.now() - d.getTime()) / 1000);
    const dateStr = d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    if (diffSec < 15) return `${dateStr} ${timeStr} (Just now)`;
    if (diffSec < 60) return `${dateStr} ${timeStr} (${diffSec}s ago)`;
    if (diffSec < 3600) return `${dateStr} ${timeStr} (${Math.floor(diffSec / 60)}m ago)`;
    if (diffSec < 86400) return `${dateStr} ${timeStr} (${Math.floor(diffSec / 3600)}h ago)`;
    return `${dateStr} ${timeStr}`;
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
