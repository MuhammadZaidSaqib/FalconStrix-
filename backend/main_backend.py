#!/usr/bin/env python3
"""
HIDRS backend: reads JSON lines from the OS engine / red team events sink,
persists to MariaDB, runs FSM escalation, and writes LOCKED-phase commands
to the command sink for the C++ response engine.

On Kali/Linux the default sink is a named pipe (FIFO) under /tmp. On Windows,
Python has no mkfifo, so defaults use repo-local var/*.jsonl file tailing.
Override paths with HIDRS_EVENTS_FIFO / HIDRS_CMD_FIFO (relative paths resolve
from the repository root).
"""
from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass
from typing import Any, Dict, List, Optional

# Allow running as script from repo root or backend/
_BACKEND_DIR = Path(__file__).resolve().parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from alert_service import create_alert
from event_service import insert_event
from fsm_service import (
    STATE_LOCKED,
    evaluate_after_event,
    get_current_state,
    log_response_action,
)
from process_service import record_bulk_from_payload


DEFAULT_EVENTS_FIFO = "/tmp/hidrs_events.fifo"
DEFAULT_CMD_FIFO = "/tmp/hidrs_cmd.fifo"

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Kali .env often sets /tmp/hidrs_*.fifo; on Windows that becomes C:\tmp\... (not a FIFO).
_WIN_TMP_HIDRS_MAP = {
    "hidrs_events.fifo": "hidrs_events.jsonl",
    "hidrs_cmd.fifo": "hidrs_cmd.jsonl",
    "hidrs_sim_auth.log": "hidrs_sim_auth.log",
    "hidrs_watch_file.txt": "hidrs_watch_file.txt",
}


def _remap_windows_drive_tmp_hidrs(path_str: str) -> str:
    if os.name != "nt":
        return path_str
    p = Path(path_str)
    try:
        rp = p.resolve()
    except OSError:
        rp = p
    if len(rp.parts) < 2:
        return path_str
    if rp.parts[-2].lower() != "tmp":
        return path_str
    name = rp.name
    mapped = _WIN_TMP_HIDRS_MAP.get(name.lower())
    if not mapped:
        return path_str
    var_dir = _REPO_ROOT / "var"
    var_dir.mkdir(parents=True, exist_ok=True)
    return str((var_dir / mapped).resolve())


def _resolved_hidrs_path(key: str, default: str) -> str:
    """Use env if set and non-empty; resolve repo-relative paths against repo root."""
    raw = os.environ.get(key)
    if raw is None or not str(raw).strip():
        p = Path(default)
    else:
        p = Path(str(raw).strip())
    if not p.is_absolute():
        p = _REPO_ROOT / p
    out = str(p.resolve())
    return _remap_windows_drive_tmp_hidrs(out)


def _wait_for_mysql(timeout_sec: int = 90) -> None:
    from db_connection import get_connection

    deadline = time.time() + timeout_sec
    last_err: Optional[BaseException] = None
    while time.time() < deadline:
        try:
            with get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT 1")
                cur.close()
            return
        except Exception as e:
            last_err = e
            time.sleep(2)
    print("[backend] Cannot connect to MySQL/MariaDB (check MYSQL_* in .env).", file=sys.stderr)
    print(f"[backend] Last error: {last_err}", file=sys.stderr)
    print("[backend] Start the database, then retry. For example:", file=sys.stderr)
    print("  docker compose up -d", file=sys.stderr)
    sys.exit(1)


def _default_event_cmd_paths() -> tuple[str, str]:
    if getattr(os, "mkfifo", None):
        return DEFAULT_EVENTS_FIFO, DEFAULT_CMD_FIFO
    var_dir = _REPO_ROOT / "var"
    var_dir.mkdir(parents=True, exist_ok=True)
    return str(var_dir / "hidrs_events.jsonl"), str(var_dir / "hidrs_cmd.jsonl")


def _prepare_event_sink(path: str) -> bool:
    """Return True if the reader should use blocking FIFO semantics; False for JSONL tail."""
    p = Path(path)
    if p.exists():
        if not stat.S_ISFIFO(p.stat().st_mode):
            return False
        return True
    p.parent.mkdir(parents=True, exist_ok=True)
    if getattr(os, "mkfifo", None):
        os.mkfifo(path, 0o666)
        return True
    p.touch()
    return False


def _prepare_cmd_sink(path: str, events_use_fifo: bool) -> None:
    p = Path(path)
    if p.exists():
        if events_use_fifo and not stat.S_ISFIFO(p.stat().st_mode):
            raise RuntimeError(f"{path} exists and is not a FIFO (expected FIFO with event FIFO mode)")
        if not events_use_fifo and stat.S_ISFIFO(p.stat().st_mode):
            raise RuntimeError(f"{path} is a FIFO but event sink is file mode; align HIDRS_* paths")
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    if events_use_fifo:
        os.mkfifo(path, 0o666)
    else:
        p.touch()


def _severity_from_payload(msg: Dict[str, Any]) -> str:
    sev = str(msg.get("severity", "MEDIUM")).upper()
    if sev not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return "MEDIUM"
    return sev


def _should_raise_alert(msg: Dict[str, Any]) -> bool:
    if msg.get("force_alert"):
        return True
    t = str(msg.get("type", ""))
    if t in ("PROCESS_SPIKE", "SUSPICIOUS_PROCESS", "LOGIN_ANOMALY", "FILE_TAMPER"):
        return True
    if str(msg.get("severity", "")).upper() in ("HIGH", "CRITICAL"):
        return True
    return msg.get("source") == "red_team"


def _extract_pids_for_response(msg: Dict[str, Any]) -> List[int]:
    out: List[int] = []
    pid = msg.get("pid")
    if pid is not None and int(pid) > 0:
        out.append(int(pid))
    for p in msg.get("processes") or []:
        try:
            v = int(p.get("pid", 0))
            if v > 1:
                out.append(v)
        except (TypeError, ValueError):
            continue
    # de-dupe preserving order
    seen = set()
    uniq = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq[:32]


def _write_cmd_fifo(cmd_path: str, obj: Dict[str, Any], *, fifo_cmd: bool) -> None:
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    mode = "w" if fifo_cmd else "a"
    try:
        with open(cmd_path, mode, encoding="utf-8") as w:
            w.write(line)
            w.flush()
    except OSError as e:
        print(f"[backend] cmd fifo write failed: {e}", file=sys.stderr)


def handle_message(raw: str, cmd_fifo: str, *, fifo_cmd: bool) -> None:
    raw = raw.strip()
    if not raw:
        return
    msg = json.loads(raw)
    event_type = str(msg.get("type", "GENERIC"))
    source = str(msg.get("source", "os_engine"))
    description = str(msg.get("detail", msg.get("description", "")))[:2000]
    payload = {k: v for k, v in msg.items() if k not in ("type", "source", "detail")}

    eid = insert_event(
        event_type=event_type,
        source=source,
        description=description,
        payload=payload,
    )

    if event_type == "RESPONSE_ACTION":
        try:
            log_response_action(
                "SIGTERM" if "SIGTERM" in description else "RESPONSE",
                int(msg["pid"]) if msg.get("pid") else None,
                description,
                event_id=eid,
            )
        except Exception as ex:
            print(f"[backend] response log: {ex}", file=sys.stderr)

    procs = msg.get("processes")
    if isinstance(procs, list) and procs:
        try:
            record_bulk_from_payload(eid, procs)
        except Exception as ex:
            print(f"[backend] process snapshot failed: {ex}", file=sys.stderr)

    alert_id = None
    if _should_raise_alert(msg):
        title = f"{event_type} from {source}"
        alert_id = create_alert(
            eid,
            _severity_from_payload(msg),
            title,
            description,
        )

    before, after = evaluate_after_event(event_type, source, alert_id)

    if after == STATE_LOCKED and before != STATE_LOCKED:
        targets = _extract_pids_for_response(msg)
        _write_cmd_fifo(
            cmd_fifo,
            {
                "cmd": "RESPOND_LOCKED",
                "targets": targets,
                "reason": "FSM_LOCK",
                "related_event_id": eid,
            },
            fifo_cmd=fifo_cmd,
        )
        # Audit trail even before C++ confirms kills
        log_response_action(
            "FSM_LOCK_CMD",
            None,
            json.dumps({"targets": targets, "event_id": eid}),
            event_id=eid,
        )

    print(
        f"[backend] event={eid} type={event_type} fsm {before}->{after}",
        flush=True,
    )


def _run_fifo_loop(events_fifo: str, cmd_fifo: str) -> None:
    while True:
        try:
            with open(events_fifo, "r", encoding="utf-8") as pipe:
                for line in pipe:
                    try:
                        handle_message(line, cmd_fifo, fifo_cmd=True)
                    except json.JSONDecodeError as je:
                        print(f"[backend] bad json: {je}", file=sys.stderr)
                    except Exception as ex:
                        print(f"[backend] handler error: {ex}", file=sys.stderr)
        except OSError as e:
            print(f"[backend] fifo error: {e}; retry in 2s", file=sys.stderr)
            time.sleep(2)


def _run_file_tail_loop(events_path: str, cmd_fifo: str) -> None:
    Path(events_path).parent.mkdir(parents=True, exist_ok=True)
    if not Path(events_path).exists():
        Path(events_path).write_text("", encoding="utf-8")
    while True:
        try:
            with open(events_path, "r", encoding="utf-8") as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.05)
                        continue
                    try:
                        handle_message(line, cmd_fifo, fifo_cmd=False)
                    except json.JSONDecodeError as je:
                        print(f"[backend] bad json: {je}", file=sys.stderr)
                    except Exception as ex:
                        print(f"[backend] handler error: {ex}", file=sys.stderr)
        except OSError as e:
            print(f"[backend] event file error: {e}; retry in 2s", file=sys.stderr)
            time.sleep(2)


def main() -> None:
    _wait_for_mysql()

    d_ev, d_cmd = _default_event_cmd_paths()
    events_fifo = _resolved_hidrs_path("HIDRS_EVENTS_FIFO", d_ev)
    cmd_fifo = _resolved_hidrs_path("HIDRS_CMD_FIFO", d_cmd)

    fifo_mode = _prepare_event_sink(events_fifo)
    _prepare_cmd_sink(cmd_fifo, fifo_mode)

    mode = "FIFO" if fifo_mode else "file-tail"
    print(f"[backend] Listening on {events_fifo} ({mode})", flush=True)
    print(f"[backend] Commands -> {cmd_fifo}", flush=True)
    print(f"[backend] FSM state: {get_current_state()}", flush=True)

    if fifo_mode:
        _run_fifo_loop(events_fifo, cmd_fifo)
    else:
        _run_file_tail_loop(events_fifo, cmd_fifo)


if __name__ == "__main__":
    main()
