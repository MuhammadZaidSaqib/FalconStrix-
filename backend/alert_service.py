"""
Create alerts linked to events and severity reference rows.
"""
from __future__ import annotations

from typing import Optional

from db_connection import get_connection


def severity_id_for_code(code: str) -> Optional[int]:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT severity_id FROM Severity WHERE code=%s LIMIT 1",
            (code.upper(),),
        )
        row = cur.fetchone()
        cur.close()
        return int(row[0]) if row else None


def create_alert(
    event_id: int,
    severity_code: str,
    title: str,
    details: str = "",
) -> int:
    sid = severity_id_for_code(severity_code)
    if sid is None:
        sid = severity_id_for_code("MEDIUM")
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO Alerts (event_id, severity_id, title, details)
            VALUES (%s,%s,%s,%s)
            """,
            (event_id, sid, title, details[:4000]),
        )
        aid = cur.lastrowid
        conn.commit()
        cur.close()
        return int(aid)


def list_recent_alerts(limit: int = 100):
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT a.alert_id, a.title, a.details, a.created_at, a.acknowledged,
                   s.code AS severity_code, s.numeric_level,
                   e.event_type, e.source
            FROM Alerts a
            JOIN Severity s ON s.severity_id = a.severity_id
            JOIN Events e ON e.event_id = a.event_id
            ORDER BY a.created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        cur.close()
        return rows
