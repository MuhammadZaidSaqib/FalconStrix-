#!/usr/bin/env python3
"""
SOC-style Flask dashboard with Socket.IO live refresh (polls MariaDB).
"""
from __future__ import annotations

import os
import sys
import subprocess
import time
import json
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

_NET_STATE = {"ts": None, "rx": None, "tx": None}


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
        "concepts": {
            "procfs": {"status": "unknown", "summary": "No telemetry available."},
            "resource": {"status": "unknown", "summary": "No telemetry available."},
            "supervision": {"status": "unknown", "summary": "No telemetry available."},
        },
        "network": _network_telemetry(),
        "db_error": db_error,
    }


def _read_net_totals() -> Optional[tuple[int, int]]:
    try:
        import psutil  # type: ignore

        io = psutil.net_io_counters()
        if io is not None:
            return int(io.bytes_recv), int(io.bytes_sent)
    except Exception:
        pass
    if os.name == "nt":
        try:
            cmd = (
                "Get-NetAdapterStatistics | "
                "Select-Object -Property ReceivedBytes,SentBytes | "
                "ConvertTo-Json -Compress"
            )
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                raw = json.loads(proc.stdout)
                if isinstance(raw, dict):
                    rx = int(raw.get("ReceivedBytes", 0))
                    tx = int(raw.get("SentBytes", 0))
                    return rx, tx
                if isinstance(raw, list):
                    rx = sum(int(x.get("ReceivedBytes", 0)) for x in raw if isinstance(x, dict))
                    tx = sum(int(x.get("SentBytes", 0)) for x in raw if isinstance(x, dict))
                    return rx, tx
        except Exception:
            pass
    try:
        p = Path("/proc/net/dev")
        if not p.exists():
            return None
        rx_total = 0
        tx_total = 0
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()[2:]:
            if ":" not in line:
                continue
            _, rhs = line.split(":", 1)
            cols = rhs.split()
            if len(cols) < 9:
                continue
            rx_total += int(cols[0])
            tx_total += int(cols[8])
        return rx_total, tx_total
    except Exception:
        return None


def _network_telemetry() -> dict:
    totals = _read_net_totals()
    now = time.time()
    if totals is None:
        return {
            "status": "unavailable",
            "in_mbps": 0.0,
            "out_mbps": 0.0,
            "in_total_bytes": 0,
            "out_total_bytes": 0,
        }
    rx, tx = totals
    prev_ts = _NET_STATE["ts"]
    prev_rx = _NET_STATE["rx"]
    prev_tx = _NET_STATE["tx"]
    _NET_STATE["ts"] = now
    _NET_STATE["rx"] = rx
    _NET_STATE["tx"] = tx
    if prev_ts is None or prev_rx is None or prev_tx is None:
        return {
            "status": "live",
            "in_mbps": 0.0,
            "out_mbps": 0.0,
            "in_total_bytes": rx,
            "out_total_bytes": tx,
        }
    dt = max(0.001, now - float(prev_ts))
    drx = max(0, rx - int(prev_rx))
    dtx = max(0, tx - int(prev_tx))
    return {
        "status": "live",
        "in_mbps": round((drx * 8.0) / (dt * 1_000_000.0), 3),
        "out_mbps": round((dtx * 8.0) / (dt * 1_000_000.0), 3),
        "in_total_bytes": rx,
        "out_total_bytes": tx,
    }


def _build_concept_summary(events: list, processes: list, responses: list) -> dict:
    recent_resource = [e for e in events if str(e.get("event_type", "")).upper() == "RESOURCE_PRESSURE"]
    proc_with_cmdline = [p for p in processes if p.get("cmdline")]
    proc_status_seen = False
    for e in events:
        payload = e.get("payload")
        if isinstance(payload, dict):
            procs = payload.get("processes")
            if isinstance(procs, list) and any(isinstance(p, dict) and p.get("status") for p in procs):
                proc_status_seen = True
                break

    if proc_with_cmdline and proc_status_seen:
        procfs = {
            "status": "active",
            "summary": f"/proc process metadata captured for {len(proc_with_cmdline)} records (cmdline/status fields).",
        }
    elif proc_with_cmdline:
        procfs = {
            "status": "partial",
            "summary": f"/proc cmdline metadata captured for {len(proc_with_cmdline)} records; waiting for status field telemetry.",
        }
    else:
        procfs = {
            "status": "partial",
            "summary": "/proc monitoring is enabled but cmdline/status metadata has not been observed yet.",
        }

    if recent_resource:
        resource = {
            "status": "active",
            "summary": f"Resource monitoring active: {len(recent_resource)} RESOURCE_PRESSURE events in recent stream.",
        }
    else:
        resource = {
            "status": "partial",
            "summary": "Resource monitoring instrumentation is present; no recent pressure events have triggered.",
        }

    if any(str(r.get("action", "")).upper() == "FSM_LOCK_CMD" for r in responses):
        supervision = {
            "status": "active",
            "summary": "Supervision/response path is active (LOCKED command flow observed).",
        }
    else:
        supervision = {
            "status": "partial",
            "summary": "Auto-restart supervision is enabled in the Linux engine; no recent LOCKED supervision action observed.",
        }
    if os.name == "nt":
        supervision["summary"] += " Windows dashboard mode uses Python pipeline; C++ fork supervision is Linux-only."
    return {
        "procfs": procfs,
        "resource": resource,
        "supervision": supervision,
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
        alerts = _json_safe(list_recent_alerts(40))
        events = _json_safe(list_recent_events(25))
        processes = _json_safe(list_suspicious_processes(30))
        responses = _json_safe(list_response_logs(30))
        return {
            "fsm": _json_safe(fsm),
            "alerts": alerts,
            "events": events,
            "processes": processes,
            "responses": responses,
            "threat_level": threat,
            "hardware_led": fsm.get("hardware_led", "GREEN"),
            "chart": _alert_chart_series(),
            "concepts": _build_concept_summary(events, processes, responses),
            "network": _network_telemetry(),
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
