#!/usr/bin/env python3
"""
Simulate repeated failed login attempts by appending to a watched auth log file
and emitting high-volume LOGIN_ANOMALY events on the HIDRS events FIFO.
Blue team (C++) tails line-rate; backend always ingests explicit events.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from env_paths import auth_sim_log, events_fifo

AUTH_SIM_PATH = auth_sim_log()
EVENTS_FIFO = events_fifo()


def _append_auth_failures(count: int, delay_sec: float) -> None:
    Path(AUTH_SIM_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(AUTH_SIM_PATH, "a", encoding="utf-8") as log:
        for i in range(count):
            log.write(f"FAIL ssh invalid user redteam_{i} from 203.0.113.10\n")
            log.flush()
            if delay_sec > 0:
                time.sleep(delay_sec)


def _emit_fifo(obj: dict) -> None:
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    with open(EVENTS_FIFO, "a", encoding="utf-8") as w:
        w.write(line)
        w.flush()


def simulate_failed_logins(count: int = 30, delay_sec: float = 0.02) -> None:
    _append_auth_failures(count, delay_sec)
    _emit_fifo(
        {
            "type": "RED_TEAM_LOGIN",
            "source": "red_team",
            "severity": "HIGH",
            "detail": f"Simulated {count} failed logins (auth sim log + FIFO)",
            "auth_log": AUTH_SIM_PATH,
            "force_alert": True,
        }
    )


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=25)
    ap.add_argument("--delay", type=float, default=0.02)
    a = ap.parse_args()
    simulate_failed_logins(a.count, a.delay)
