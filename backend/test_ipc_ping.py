#!/usr/bin/env python3
"""Send one test JSON event through the same HIDRS pipe the backend reads.

Run while main_backend.py is running (or alone — creates the pipe on Windows).

Usage (from project root):
  python backend/test_ipc_ping.py
"""
from __future__ import annotations

import json
import os
import sys

# Ensure imports work when launched from repo root or backend/
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from ipc_config import PIPE_PATH, setup_named_pipe  # noqa: E402


def main() -> None:
    setup_named_pipe()
    payload = {
        "event_type": "IPC_TEST",
        "description": "test_ipc_ping.py handshake — pipe is writable",
        "source": "test_ipc_ping",
        "pid": os.getpid(),
        "process_name": "test_ipc_ping",
        "severity": 1,
    }
    line = json.dumps(payload) + "\n"
    with open(PIPE_PATH, "a", encoding="utf-8") as f:
        f.write(line)
    print(f"[OK] Wrote test event to: {PIPE_PATH}")
    print("     If main_backend.py is running, you should see [BACKEND] Recv Event: IPC_TEST")


if __name__ == "__main__":
    main()
