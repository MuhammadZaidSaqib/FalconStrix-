"""
HIDRS paths shared by red team scripts.

- Kali/Linux: defaults use /tmp FIFOs and log files (matches hidrs_os_engine C++ defaults).
- Windows: Python has no mkfifo; defaults use <repo>/var/ JSONL and plain files.

Override any value with HIDRS_* in .env. Relative paths are resolved from the repository root.
"""
from __future__ import annotations

import os
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


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
    if len(rp.parts) < 2 or rp.parts[-2].lower() != "tmp":
        return path_str
    mapped = _WIN_TMP_HIDRS_MAP.get(rp.name.lower())
    if not mapped:
        return path_str
    d = repo_root() / "var"
    d.mkdir(parents=True, exist_ok=True)
    return str((d / mapped).resolve())


def _resolved(key: str, fallback: str) -> str:
    raw = os.environ.get(key)
    if raw is None or not str(raw).strip():
        p = Path(fallback)
    else:
        p = Path(str(raw).strip())
    if not p.is_absolute():
        p = repo_root() / p
    out = str(p.resolve())
    return _remap_windows_drive_tmp_hidrs(out)


def events_fifo() -> str:
    if os.name == "nt":
        d = repo_root() / "var"
        d.mkdir(parents=True, exist_ok=True)
        fb = str((d / "hidrs_events.jsonl").resolve())
    else:
        fb = "/tmp/hidrs_events.fifo"
    return _resolved("HIDRS_EVENTS_FIFO", fb)


def auth_sim_log() -> str:
    if os.name == "nt":
        d = repo_root() / "var"
        d.mkdir(parents=True, exist_ok=True)
        fb = str((d / "hidrs_sim_auth.log").resolve())
    else:
        fb = "/tmp/hidrs_sim_auth.log"
    return _resolved("HIDRS_AUTH_SIM_LOG", fb)


def watch_file() -> str:
    if os.name == "nt":
        d = repo_root() / "var"
        d.mkdir(parents=True, exist_ok=True)
        fb = str((d / "hidrs_watch_file.txt").resolve())
    else:
        fb = "/tmp/hidrs_watch_file.txt"
    return _resolved("HIDRS_WATCH_FILE", fb)
