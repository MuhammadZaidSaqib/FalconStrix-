"""
Single source of truth for FalconStrix HIDRS event pipe paths.

- Windows: backend/hidrs_events.pipe (regular file; mkfifo is unavailable)
- Linux/macOS: /tmp/hidrs_events (FIFO created with os.mkfifo)

The C++ engine (behavior_detector.cpp) opens /tmp/hidrs_events on POSIX —
keep that path identical to PIPE_PATH here on non-Windows builds.
"""
from __future__ import annotations

import logging
import os
import stat as stat_mod
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)


def get_pipe_path() -> str:
    if os.name == "nt":
        return os.path.join(BACKEND_DIR, "hidrs_events.pipe")
    return "/tmp/hidrs_events"


PIPE_PATH = get_pipe_path()


def setup_named_pipe() -> None:
    """Create pipe or placeholder file; must run before readers/writers rely on path."""
    if os.name == "nt":
        if not os.path.exists(PIPE_PATH):
            with open(PIPE_PATH, "w", encoding="utf-8") as f:
                f.write("")
        logging.info("FalconStrix IPC: using %s (Windows file mode)", PIPE_PATH)
        return

    if not os.path.exists(PIPE_PATH):
        try:
            os.mkfifo(PIPE_PATH, 0o666)
        except OSError as e:
            logging.error("FalconStrix failed to create named pipe at %s: %s", PIPE_PATH, e)
            sys.exit(1)
    logging.info("FalconStrix IPC: FIFO ready at %s", PIPE_PATH)


def pipe_status() -> dict:
    """Metadata for health checks and the dashboard API."""
    out: dict = {
        "path": PIPE_PATH,
        "exists": False,
        "is_fifo": False,
        "readable": False,
        "writable": False,
        "platform": os.name,
    }
    try:
        if os.path.exists(PIPE_PATH):
            out["exists"] = True
            st = os.stat(PIPE_PATH)
            out["is_fifo"] = bool(stat_mod.S_ISFIFO(st.st_mode))
            out["readable"] = os.access(PIPE_PATH, os.R_OK)
            out["writable"] = os.access(PIPE_PATH, os.W_OK)
    except OSError:
        pass
    return out
