"""
TRACE-X Central Monitoring & Data Analytics Backend
Zero external dependencies - uses Python standard library:
  - http.server for REST API and static file serving
  - sqlite3 for embedded database (data/tracex.db)
  - json, csv, urllib for telemetry ingestion and data processing

Run with: python server.py
Access at: http://localhost:5000
"""

import os
import sys
import json
import sqlite3
import urllib.request
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

PORT = 5000
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "tracex.db")
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------- Database Setup ----------

def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_number INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        threat_level TEXT NOT NULL,       -- 'CLEAR', 'NARCOTIC', 'EXPLOSIVE'
        confidence INTEGER NOT NULL,      -- 0-100%
        heading INTEGER DEFAULT 0,        -- 0-359 deg
        lat REAL DEFAULT 28.6139,
        lon REAL DEFAULT 77.2090,
        sensor_narc INTEGER DEFAULT 0,
        sensor_expl INTEGER DEFAULT 0,
        is_alert BOOLEAN DEFAULT 0,
        operator_notes TEXT DEFAULT '',
        source TEXT DEFAULT 'live'        -- 'live_pod', 'sd_import', 'cloud_sync', 'demo'
    );
    """)
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- Pre-seed Realistic Demo Data if DB is Empty ----------

DEMO_SCANS = [
    (1, "2026-09-15 01:10:00", "CLEAR", 0, 15, 28.6139, 77.2090, 0, 0, 0, "Routine perimeter scan - Platform 1", "demo"),
    (2, "2026-09-15 01:15:30", "CLEAR", 2, 45, 28.6141, 77.2092, 2, 0, 0, "Luggage rack clear - Coach A1", "demo"),
    (3, "2026-09-15 01:25:10", "NARCOTIC", 45, 90, 28.6145, 77.2098, 45, 0, 0, "Minor trace flagged near locker 12", "demo"),
    (4, "2026-09-15 01:28:45", "NARCOTIC", 82, 95, 28.6146, 77.2099, 82, 0, 1, "STRONG NARCOTIC HIT - Locker 14 inspected", "demo"),
    (5, "2026-09-15 01:34:00", "NARCOTIC", 88, 92, 28.6146, 77.2099, 88, 5, 1, "Secondary sweep confirmed narcotic presence", "demo"),
    (6, "2026-09-15 01:45:20", "CLEAR", 0, 180, 28.6150, 77.2105, 0, 0, 0, "Waiting hall area scan clear", "demo"),
    (7, "2026-09-15 02:00:15", "CLEAR", 0, 210, 28.6155, 77.2110, 0, 0, 0, "Platform 2 walkway inspection", "demo"),
    (8, "2026-09-15 02:12:40", "EXPLOSIVE", 65, 240, 28.6160, 77.2115, 0, 65, 1, "ELEVATED VAPOR - Unattended duffle near Track 3", "demo"),
    (9, "2026-09-15 02:14:10", "EXPLOSIVE", 94, 245, 28.6161, 77.2116, 0, 94, 1, "CRITICAL HAZARD: High nitrate compound detected!", "demo"),
    (10, "2026-09-15 02:18:00", "EXPLOSIVE", 91, 242, 28.6161, 77.2116, 12, 91, 1, "Bomb squad perimeter established", "demo"),
    (11, "2026-09-15 02:30:00", "CLEAR", 0, 315, 28.6135, 77.2085, 0, 0, 0, "South exit gate sweep clear", "demo"),
    (12, "2026-09-15 02:40:00", "CLEAR", 0, 0, 28.6130, 77.2080, 0, 0, 0, "Ticketing counter routine check", "demo")
]

def seed_demo_if_empty():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scans")
    count = cur.fetchone()[0]
    if count == 0:
        cur.executemany("""
            INSERT INTO scans (scan_number, timestamp, threat_level, confidence, heading, lat, lon, sensor_narc, sensor_expl, is_alert, operator_notes, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, DEMO_SCANS)
        conn.commit()
        print("[TRACE-X] Seeded database with initial demo telemetry.")
    conn.close()

# ---------- Request Handler ----------

class TraceXHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def _send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/api/status":
            self._send_json({"status": "online", "system": "TRACE-X Control Center", "database": "connected"})
            return

        elif path == "/api/scans":
            self._handle_get_scans(params)
            return

        elif path == "/api/analytics":
            self._handle_get_analytics()
            return

        elif path == "/api/compare":
            self._handle_compare(params)
            return

        elif path == "/api/export":
            self._handle_export(params)
            return

        # Fallback to serving static HTML/JS/CSS files
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        if path == "/api/scans":
            self._handle_create_scan(body)
            return

        elif path == "/api/upload-csv":
            self._handle_upload_csv(body)
            return

        elif path == "/api/sync-thingspeak":
            self._handle_sync_thingspeak()
            return

        elif path == "/api/demo-data":
            self._handle_reseed_demo()
            return

        elif path.startswith("/api/scans/") and path.endswith("/notes"):
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[1] == "scans" and parts[3] == "notes":
                scan_id = parts[2]
                self._handle_update_notes(scan_id, body)
                return

        self._send_json({"error": "Endpoint not found"}, 404)

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/scans":
            conn = get_db()
            cur = conn.cursor()
            cur.execute("DELETE FROM scans")
            conn.commit()
            conn.close()
            self._send_json({"success": True, "message": "All scans cleared"})
            return

        elif path.startswith("/api/scans/"):
            scan_id = path.split("/")[-1]
            conn = get_db()
            cur = conn.cursor()
            cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            conn.close()
            self._send_json({"success": True, "deleted_id": scan_id})
            return

        self._send_json({"error": "Endpoint not found"}, 404)

    # ---------- Handler Implementations ----------

    def _handle_get_scans(self, params):
        threat = params.get("threat", [None])[0]
        min_conf = params.get("min_conf", [None])[0]
        search = params.get("search", [None])[0]
        limit = int(params.get("limit", [100])[0])
        offset = int(params.get("offset", [0])[0])

        query = "SELECT * FROM scans WHERE 1=1"
        args = []

        if threat and threat.upper() != "ALL":
            query += " AND threat_level = ?"
            args.append(threat.upper())

        if min_conf is not None and min_conf != "":
            query += " AND confidence >= ?"
            args.append(int(min_conf))

        if search:
            query += " AND (operator_notes LIKE ? OR threat_level LIKE ? OR source LIKE ?)"
            s = f"%{search}%"
            args.extend([s, s, s])

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        args.extend([limit, offset])

        conn = get_db()
        cur = conn.cursor()
        cur.execute(query, args)
        rows = [dict(row) for row in cur.fetchall()]

        cur.execute("SELECT COUNT(*) FROM scans")
        total = cur.fetchone()[0]
        conn.close()

        self._send_json({"scans": rows, "total": total, "limit": limit, "offset": offset})

    def _handle_create_scan(self, body):
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception as e:
            self._send_json({"error": f"Invalid JSON: {str(e)}"}, 400)
            return

        scan_num = data.get("scan_number", 0)
        level = data.get("threat_level", "CLEAR").upper()
        confidence = int(data.get("confidence", 0))
        heading = int(data.get("heading", 0))
        lat = float(data.get("lat", 28.6139))
        lon = float(data.get("lon", 77.2090))
        narc = int(data.get("sensor_narc", confidence if level == "NARCOTIC" else 0))
        expl = int(data.get("sensor_expl", confidence if level == "EXPLOSIVE" else 0))
        is_alert = 1 if (data.get("is_alert", confidence >= 60)) else 0
        notes = data.get("operator_notes", "")
        source = data.get("source", "live_pod")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO scans (scan_number, threat_level, confidence, heading, lat, lon, sensor_narc, sensor_expl, is_alert, operator_notes, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_num, level, confidence, heading, lat, lon, narc, expl, is_alert, notes, source))
        conn.commit()
        new_id = cur.lastrowid
        conn.close()

        self._send_json({"success": True, "id": new_id, "message": "Scan recorded"})

    def _handle_upload_csv(self, body):
        try:
            text = body.decode("utf-8")
        except Exception as e:
            self._send_json({"error": f"Decoding error: {str(e)}"}, 400)
            return

        lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
        if not lines:
            self._send_json({"error": "Empty CSV file"}, 400)
            return

        imported = 0
        conn = get_db()
        cur = conn.cursor()

        start_idx = 1 if "scan" in lines[0].lower() else 0

        for line in lines[start_idx:]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue

            try:
                scan_num = int(parts[0])
                if len(parts) >= 7:
                    level_raw = parts[2]
                    conf = int(parts[3])
                    heading = int(parts[4])
                    lat = float(parts[5])
                    lon = float(parts[6])
                else:
                    level_raw = parts[1]
                    conf = int(parts[2])
                    heading = int(parts[3]) if len(parts) > 3 else 0
                    lat = float(parts[4]) if len(parts) > 4 else 28.6139
                    lon = float(parts[5]) if len(parts) > 5 else 77.2090

                level_str = "CLEAR"
                if level_raw in ("2", "EXPLOSIVE", "explosive"):
                    level_str = "EXPLOSIVE"
                elif level_raw in ("1", "NARCOTIC", "narcotic"):
                    level_str = "NARCOTIC"

                narc = conf if level_str == "NARCOTIC" else 0
                expl = conf if level_str == "EXPLOSIVE" else 0
                is_alert = 1 if conf >= 60 else 0

                cur.execute("""
                    INSERT INTO scans (scan_number, threat_level, confidence, heading, lat, lon, sensor_narc, sensor_expl, is_alert, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'sd_import')
                """, (scan_num, level_str, conf, heading, lat, lon, narc, expl, is_alert))
                imported += 1
            except Exception as row_err:
                print(f"Skipping bad CSV row: {line} ({row_err})")

        conn.commit()
        conn.close()
        self._send_json({"success": True, "imported_count": imported})

    def _handle_sync_thingspeak(self):
        channel_id = "3492840"
        url = f"https://api.thingspeak.com/channels/{channel_id}/feeds.json?results=50"

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TRACE-X-Server"})
            with urllib.request.urlopen(req, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as e:
            self._send_json({"error": f"Failed to contact ThingSpeak: {str(e)}"}, 502)
            return

        feeds = payload.get("feeds", [])
        if not feeds:
            self._send_json({"success": True, "synced_count": 0, "message": "No feeds found"})
            return

        conn = get_db()
        cur = conn.cursor()
        synced = 0

        for f in feeds:
            try:
                scan_num = int(f.get("field1", 0)) if f.get("field1") else 0
                lvl_code = str(f.get("field2", "0"))
                conf = int(f.get("field3", 0)) if f.get("field3") else 0
                lat = float(f.get("field4", 28.6139)) if f.get("field4") else 28.6139
                lon = float(f.get("field5", 77.2090)) if f.get("field5") else 77.2090
                created_at = f.get("created_at", datetime.now().isoformat())

                level_str = "CLEAR"
                if lvl_code == "2": level_str = "EXPLOSIVE"
                elif lvl_code == "1": level_str = "NARCOTIC"

                cur.execute("SELECT id FROM scans WHERE scan_number = ? AND timestamp = ?", (scan_num, created_at))
                if cur.fetchone():
                    continue

                is_alert = 1 if conf >= 60 else 0
                narc = conf if level_str == "NARCOTIC" else 0
                expl = conf if level_str == "EXPLOSIVE" else 0

                cur.execute("""
                    INSERT INTO scans (scan_number, timestamp, threat_level, confidence, heading, lat, lon, sensor_narc, sensor_expl, is_alert, source)
                    VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, 'cloud_sync')
                """, (scan_num, created_at, level_str, conf, lat, lon, narc, expl, is_alert))
                synced += 1
            except Exception as feed_err:
                print("Error parsing feed item:", feed_err)

        conn.commit()
        conn.close()
        self._send_json({"success": True, "synced_count": synced})

    def _handle_reseed_demo(self):
        conn = get_db()
        cur = conn.cursor()
        cur.executemany("""
            INSERT INTO scans (scan_number, timestamp, threat_level, confidence, heading, lat, lon, sensor_narc, sensor_expl, is_alert, operator_notes, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, DEMO_SCANS)
        conn.commit()
        conn.close()
        self._send_json({"success": True, "message": "Added 12 realistic inspection scans"})

    def _handle_update_notes(self, scan_id, body):
        try:
            data = json.loads(body.decode("utf-8"))
            notes = data.get("notes", "")
        except Exception:
            notes = ""

        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE scans SET operator_notes = ? WHERE id = ?", (notes, scan_id))
        conn.commit()
        conn.close()
        self._send_json({"success": True, "id": scan_id, "notes": notes})

    def _handle_get_analytics(self):
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM scans")
        total_scans = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM scans WHERE threat_level = 'EXPLOSIVE'")
        total_explosive = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM scans WHERE threat_level = 'NARCOTIC'")
        total_narcotic = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM scans WHERE threat_level = 'CLEAR'")
        total_clear = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM scans WHERE is_alert = 1")
        total_alerts = cur.fetchone()[0]

        cur.execute("SELECT AVG(confidence), MAX(confidence) FROM scans WHERE threat_level != 'CLEAR'")
        avg_row = cur.fetchone()
        avg_threat_conf = round(avg_row[0] or 0, 1) if avg_row else 0
        max_conf = avg_row[1] or 0 if avg_row else 0

        sector_counts = [0] * 12
        sector_peaks = [0] * 12
        cur.execute("SELECT heading, confidence FROM scans WHERE threat_level != 'CLEAR'")
        for row in cur.fetchall():
            hdg = (row[0] or 0) % 360
            sec = hdg // 30
            sector_counts[sec] += 1
            if (row[1] or 0) > sector_peaks[sec]:
                sector_peaks[sec] = row[1]

        conf_dist = {"narcotic": [0]*5, "explosive": [0]*5}
        cur.execute("SELECT threat_level, confidence FROM scans WHERE threat_level IN ('NARCOTIC', 'EXPLOSIVE')")
        for row in cur.fetchall():
            lvl = row[0].lower()
            conf = min(max(row[1], 0), 100)
            bucket = min(conf // 20, 4)
            conf_dist[lvl][bucket] += 1

        cur.execute("""
            SELECT id, scan_number, timestamp, threat_level, confidence, heading, lat, lon
            FROM scans ORDER BY id DESC LIMIT 15
        """)
        timeline = [dict(r) for r in reversed(cur.fetchall())]

        conn.close()

        self._send_json({
            "kpis": {
                "total_scans": total_scans,
                "explosive_count": total_explosive,
                "narcotic_count": total_narcotic,
                "clear_count": total_clear,
                "alert_count": total_alerts,
                "avg_threat_confidence": avg_threat_conf,
                "peak_confidence": max_conf
            },
            "sectors": {
                "labels": ["0°-29°", "30°-59°", "60°-89°", "90°-119°", "120°-149°", "150°-179°",
                           "180°-209°", "210°-239°", "240°-269°", "270°-299°", "300°-329°", "330°-359°"],
                "counts": sector_counts,
                "peaks": sector_peaks
            },
            "confidence_distribution": conf_dist,
            "timeline": timeline
        })

    def _handle_compare(self, params):
        ids_param = params.get("ids", [""])[0]
        id_list = [int(i.strip()) for i in ids_param.split(",") if i.strip().isdigit()]

        if not id_list:
            self._send_json({"error": "No scan IDs provided"}, 400)
            return

        placeholders = ",".join(["?"] * len(id_list))
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM scans WHERE id IN ({placeholders})", id_list)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        self._send_json({"items": rows})

    def _handle_export(self, params):
        fmt = params.get("format", ["csv"])[0].lower()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM scans ORDER BY id ASC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()

        if fmt == "json":
            self._send_json(rows)
            return

        header = ["id", "scan_number", "timestamp", "threat_level", "confidence", "heading", "lat", "lon", "is_alert", "operator_notes", "source"]
        lines = [",".join(header)]
        for r in rows:
            clean_notes = (r.get("operator_notes") or "").replace('"', '""')
            line = [
                str(r.get("id")),
                str(r.get("scan_number")),
                str(r.get("timestamp")),
                str(r.get("threat_level")),
                str(r.get("confidence")),
                str(r.get("heading")),
                str(r.get("lat")),
                str(r.get("lon")),
                str(r.get("is_alert")),
                f'"{clean_notes}"',
                str(r.get("source"))
            ]
            lines.append(",".join(line))

        csv_body = "\n".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", 'attachment; filename="tracex_telemetry.csv"')
        self.send_header("Content-Length", str(len(csv_body)))
        self.end_headers()
        self.wfile.write(csv_body)

# ---------- Main Execution ----------

if __name__ == "__main__":
    init_db()
    seed_demo_if_empty()

    print("=" * 65)
    print("  TRACE-X Railway Security & Detection Monitoring System")
    print(f"  Database : {DB_PATH}")
    print(f"  Listening: http://localhost:{PORT}")
    print("  Ready for telemetry ingestion, CSV import, and data analytics.")
    print("=" * 65)

    server = HTTPServer(("0.0.0.0", PORT), TraceXHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down TRACE-X server gracefully.")
        server.server_close()
