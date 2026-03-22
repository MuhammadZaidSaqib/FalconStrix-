"""
Store process observations tied to detection events.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from db_connection import get_connection


def insert_process_snapshot(
    event_id: int,
    pid: int,
    process_name: str,
    parent_pid: Optional[int] = None,
    cmdline: Optional[str] = None,
) -> int:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO Processes (event_id, pid, process_name, parent_pid, cmdline)
            VALUES (%s,%s,%s,%s,%s)
            """,
            (event_id, pid, process_name[:255], parent_pid, cmdline[:1024] if cmdline else None),
        )
        pid_row = cur.lastrowid
        conn.commit()
        cur.close()
        return int(pid_row)


def record_bulk_from_payload(event_id: int, processes: List[Dict[str, Any]]) -> int:
    n = 0
    for p in processes[:200]:
        insert_process_snapshot(
            event_id,
            int(p.get("pid", 0)),
            str(p.get("name", "unknown"))[:255],
            int(p["ppid"]) if p.get("ppid") is not None else None,
            str(p.get("cmdline", ""))[:1024] if p.get("cmdline") else None,
        )
        n += 1
    return n


def list_suspicious_processes(limit: int = 100):
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT p.process_id, p.pid, p.process_name, p.parent_pid, p.cmdline, p.detected_at,
                   e.event_type, e.source
            FROM Processes p
            JOIN Events e ON e.event_id = p.event_id
            ORDER BY p.detected_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        cur.close()
        return rows
