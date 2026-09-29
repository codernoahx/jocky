from __future__ import annotations

import argparse
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

DB = "jocky_reports.db"


def init_db() -> None:
    with sqlite3.connect(DB) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, hostname TEXT, profile TEXT, report_json TEXT NOT NULL)")
        conn.commit()


class Handler(BaseHTTPRequestHandler):
    server_version = "JOCKYCollector/0.1"

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/api/reports":
            self._json(404, {"error": "not_found"})
            return
        with sqlite3.connect(DB) as conn:
            rows = conn.execute("SELECT id, received_at, hostname, profile FROM reports ORDER BY id DESC LIMIT 100").fetchall()
        self._json(200, {"reports": [{"id": r[0], "received_at": r[1], "hostname": r[2], "profile": r[3]} for r in rows]})

    def do_POST(self) -> None:
        if self.path != "/api/reports":
            self._json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 20 * 1024 * 1024:
                self._json(400, {"error": "invalid_content_length"})
                return
            payload = json.loads(self.rfile.read(length))
            hostname = payload.get("host", {}).get("hostname")
            profile = payload.get("profile")
            with sqlite3.connect(DB) as conn:
                cur = conn.execute("INSERT INTO reports(hostname, profile, report_json) VALUES (?, ?, ?)", (hostname, profile, json.dumps(payload)))
                conn.commit()
                report_id = cur.lastrowid
            self._json(201, {"ok": True, "report_id": report_id})
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid_json"})
        except Exception as exc:
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[collector] {self.address_string()} - {fmt % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="JOCKY central report collector")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    init_db()
    server = HTTPServer((args.host, args.port), Handler)
    print(f"JOCKY collector listening on http://{args.host}:{args.port}")
    print("POST /api/reports to submit reports; GET /api/reports to list them.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping collector...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
