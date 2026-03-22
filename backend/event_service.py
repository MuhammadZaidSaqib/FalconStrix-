"""
Persist raw events from the OS engine FIFO, red team injectors, and responses.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from db_connection import get_connection


def _system_user_id(conn) -> int:
    cur = conn.cursor()
    cur.execute(
        "SELECT user_id FROM Users WHERE username=%s AND host=%s LIMIT 1",
        ("system", "localhost"),
    )
    row = cur.fetchone()
    cur.close()
    if row:
        return int(row[0])
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO Users (username, host, role) VALUES (%s,%s,%s)",
        ("system", "localhost", "system"),
    )
    uid = cur.lastrowid
    conn.commit()
    cur.close()
    return int(uid)


def insert_event(
    event_type: str,
    source: str,
    description: str,
    payload: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None,
) -> int:
    payload_json = json.dumps(payload) if payload is not None else None
    with get_connection() as conn:
        uid = user_id if user_id is not None else _system_user_id(conn)
        cur = conn.cursor()
        if payload_json is None:
            cur.execute(
                """
                INSERT INTO Events (user_id, event_type, source, description, payload)
                VALUES (%s,%s,%s,%s,NULL)
                """,
                (uid, event_type, source, description),
            )
        else:
            cur.execute(
                """
                INSERT INTO Events (user_id, event_type, source, description, payload)
                VALUES (%s,%s,%s,%s,CAST(%s AS JSON))
                """,
                (uid, event_type, source, description, payload_json),
            )
        eid = cur.lastrowid
        conn.commit()
        cur.close()
        return int(eid)


def list_recent_events(limit: int = 50):
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT event_id, user_id, event_type, source, description, payload, created_at
            FROM Events
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        cur.close()
        return rows
