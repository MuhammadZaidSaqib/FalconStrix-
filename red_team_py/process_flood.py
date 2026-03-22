#!/usr/bin/env python3
"""
Spawn many short-lived processes to create a /proc-visible spike for the OS engine.
Also emits a RED_TEAM_FLOOD event on the HIDRS FIFO for guaranteed DB correlation.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

from env_paths import events_fifo


def _emit_fifo(obj: dict) -> None:
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    with open(events_fifo(), "a", encoding="utf-8") as w:
        w.write(line)
        w.flush()


def flood(count: int) -> None:
    procs = []
    for i in range(count):
        procs.append(
            subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(8)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )
        if i % 20 == 0:
            time.sleep(0.01)
    _emit_fifo(
        {
            "type": "RED_TEAM_FLOOD",
            "source": "red_team",
            "severity": "HIGH",
            "detail": f"Spawned {count} child python sleep processes",
            "child_pids": [p.pid for p in procs[:64]],
            "force_alert": True,
        }
    )
    time.sleep(2)
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    flood(n)
