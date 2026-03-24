#!/usr/bin/env python3
"""
SOC-style Flask dashboard with Socket.IO live refresh (polls MariaDB).
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template
from flask_socketio import SocketIO

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except Exception:
    pass

from alert_service import list_recent_alerts
from db_connection import get_connection
from event_service import list_recent_events
from fsm_service import get_current_state, list_response_logs
from process_service import list_suspicious_processes


def _json_safe(obj):
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(x) for x in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def _alert_chart_series():
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT DATE_FORMAT(created_at, '%%H:%%i') AS bucket, COUNT(*) AS cnt
            FROM Alerts
            WHERE created_at >= NOW() - INTERVAL 60 MINUTE
            GROUP BY bucket
            ORDER BY bucket ASC
            LIMIT 30
            """
        )
        rows = cur.fetchall()
        cur.close()
    labels = [r["bucket"] for r in rows]
    data = [int(r["cnt"]) for r in rows]
    return {"labels": labels, "counts": data}


def _empty_snapshot(db_error: str) -> dict:
    return {
        "fsm": _json_safe(
            {
                "state_name": "NORMAL",
                "last_reason": "",
                "hardware_led": "GREEN",
            }
        ),
        "alerts": [],
        "events": [],
        "processes": [],
        "responses": [],
        "threat_level": 0,
        "hardware_led": "GREEN",
        "chart": {"labels": [], "counts": []},
        "db_error": db_error,
    }


def build_snapshot():
    try:
        fsm = get_current_state()
        state = fsm.get("state_name", "NORMAL")
        threat = 25
        if state == "WARNING":
            threat = 60
        elif state == "LOCKED":
            threat = 100
        return {
            "fsm": _json_safe(fsm),
            "alerts": _json_safe(list_recent_alerts(40)),
            "events": _json_safe(list_recent_events(25)),
            "processes": _json_safe(list_suspicious_processes(30)),
            "responses": _json_safe(list_response_logs(30)),
            "threat_level": threat,
            "hardware_led": fsm.get("hardware_led", "GREEN"),
            "chart": _alert_chart_series(),
        }
    except Exception as e:
        return _empty_snapshot(str(e))


app = Flask(__name__)
app.config["SECRET_KEY"] = "hidrs-dev-secret-change-me"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


@app.route("/")
def index():
    return render_template("dashboard.html", initial=build_snapshot())


def _background_poll():
    import time

    last_db_log = 0.0
    while True:
        snap = build_snapshot()
        try:
            socketio.emit("soc_update", snap)
        except Exception as ex:
            print(f"[dashboard] emit error: {ex}", flush=True)
        if snap.get("db_error"):
            now = time.time()
            if now - last_db_log > 30:
                print(f"[dashboard] DB offline: {snap['db_error']}", flush=True)
                last_db_log = now
        time.sleep(2)


@socketio.on("connect")
def on_connect():
    try:
        socketio.emit("soc_update", build_snapshot())
    except Exception as ex:
        print(f"[dashboard] socket connect push failed: {ex}", flush=True)


def main():
    import os
    import threading

    def _host() -> str:
        raw = os.environ.get("DASHBOARD_HOST")
        if raw is None or not str(raw).strip():
            return "127.0.0.1"
        return str(raw).strip()

    def _port() -> int:
        raw = os.environ.get("DASHBOARD_PORT")
        if raw is None or not str(raw).strip():
            return 5000
        return int(str(raw).strip())

    host = _host()
    port = _port()
    threading.Thread(target=_background_poll, daemon=True).start()
    print(f"[dashboard] repo root (load .env from here): {ROOT}", flush=True)
    print(f"[dashboard] open in Cursor preview: http://{host}:{port}", flush=True)
    socketio.run(
        app,
        host=host,
        port=port,
        allow_unsafe_werkzeug=True,
    )


if __name__ == "__main__":
    main()
