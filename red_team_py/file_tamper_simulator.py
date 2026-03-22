#!/usr/bin/env python3
"""
Modify a monitored canary file so the OS engine's mtime watcher raises FILE_TAMPER.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

from env_paths import events_fifo, watch_file

WATCH_FILE = watch_file()


def _emit_fifo(obj: dict) -> None:
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    with open(events_fifo(), "a", encoding="utf-8") as w:
        w.write(line)
        w.flush()


def tamper() -> None:
    os.makedirs(os.path.dirname(WATCH_FILE) or ".", exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    with open(WATCH_FILE, "a", encoding="utf-8") as f:
        f.write(f"TAMPER {ts} red_team_canary\n")
        f.flush()
    time.sleep(0.1)
    _emit_fifo(
        {
            "type": "RED_TEAM_FILE",
            "source": "red_team",
            "severity": "MEDIUM",
            "detail": f"Canary file modified: {WATCH_FILE}",
            "path": WATCH_FILE,
            "force_alert": True,
        }
    )


if __name__ == "__main__":
    tamper()
