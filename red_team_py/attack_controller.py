#!/usr/bin/env python3
"""
Orchestrate red-team simulations (login noise, process flood, file tamper).
Uses HIDRS_EVENTS_FIFO so the blue pipeline records the same JSON schema as the OS engine.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _emit_fifo(obj: dict) -> None:
    from env_paths import events_fifo

    fifo = events_fifo()
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    with open(fifo, "a", encoding="utf-8") as w:
        w.write(line)
        w.flush()


def run_login_burst(count: int, delay: float) -> None:
    from login_simulator import simulate_failed_logins

    simulate_failed_logins(count=count, delay_sec=delay)


def run_flood(count: int) -> None:
    script = Path(__file__).resolve().parent / "process_flood.py"
    subprocess.run([sys.executable, str(script), str(count)], check=False)


def run_file_tamper() -> None:
    script = Path(__file__).resolve().parent / "file_tamper_simulator.py"
    subprocess.run([sys.executable, str(script)], check=False)


def run_full_sequence() -> None:
    print("[red_team] login burst", flush=True)
    run_login_burst(12, 0.05)
    time.sleep(0.5)
    print("[red_team] process flood", flush=True)
    run_flood(80)
    time.sleep(0.5)
    print("[red_team] file tamper", flush=True)
    run_file_tamper()


def main() -> None:
    p = argparse.ArgumentParser(description="HIDRS red team controller")
    p.add_argument(
        "mode",
        choices=["login", "flood", "file", "fifo_only", "full"],
        help="Attack mode",
    )
    p.add_argument("--count", type=int, default=20)
    p.add_argument("--delay", type=float, default=0.05)
    args = p.parse_args()

    os.chdir(_repo_root())

    if args.mode == "login":
        run_login_burst(args.count, args.delay)
    elif args.mode == "flood":
        run_flood(args.count)
    elif args.mode == "file":
        run_file_tamper()
    elif args.mode == "fifo_only":
        from env_paths import events_fifo

        _emit_fifo(
            {
                "type": "RED_TEAM_GENERIC",
                "source": "red_team",
                "severity": "MEDIUM",
                "detail": "Manual fifo probe from attack_controller",
            }
        )
        print(f"[red_team] wrote one event to {events_fifo()}", flush=True)
    elif args.mode == "full":
        run_full_sequence()


if __name__ == "__main__":
    main()
