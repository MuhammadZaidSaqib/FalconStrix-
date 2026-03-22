"""
Finite-state escalation: NORMAL → WARNING → LOCKED.
Maps states to conceptual hardware LEDs (GREEN / YELLOW / RED) for DLD integration.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from db_connection import get_connection

STATE_NORMAL = "NORMAL"
STATE_WARNING = "WARNING"
STATE_LOCKED = "LOCKED"

LED_MAP = {
    STATE_NORMAL: "GREEN",
    STATE_WARNING: "YELLOW",
    STATE_LOCKED: "RED",
}


def get_current_state() -> Dict[str, Any]:
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT state_name, last_reason, hardware_led, updated_at
            FROM FSM_Current_State WHERE id=1
            """
        )
        row = cur.fetchone()
        cur.close()
        return row or {
            "state_name": STATE_NORMAL,
            "last_reason": "",
            "hardware_led": "GREEN",
            "updated_at": None,
        }


def _set_state(
    conn,
    new_state: str,
    reason: str,
    alert_id: Optional[int] = None,
) -> None:
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT state_name FROM FSM_Current_State WHERE id=1")
    row = cur.fetchone()
    old = row["state_name"] if row else STATE_NORMAL
    if old == new_state:
        cur.close()
        return
    led = LED_MAP.get(new_state, "GREEN")
    cur.execute(
        """
        UPDATE FSM_Current_State
        SET state_name=%s, last_reason=%s, hardware_led=%s
        WHERE id=1
        """,
        (new_state, reason[:500], led),
    )
    cur.execute(
        """
        INSERT INTO FSM_State_History (alert_id, from_state, to_state, reason)
        VALUES (%s,%s,%s,%s)
        """,
        (alert_id, old, new_state, reason[:500]),
    )
    conn.commit()
    cur.close()


def _recent_suspicious_count(conn, window_sec: int) -> int:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT COUNT(*) FROM Events
        WHERE created_at >= NOW() - INTERVAL %s SECOND
          AND (
            event_type IN (
              'PROCESS_SPIKE','SUSPICIOUS_PROCESS','LOGIN_ANOMALY',
              'FILE_TAMPER','RED_TEAM_LOGIN','RED_TEAM_FLOOD','RED_TEAM_FILE'
            )
            OR source IN ('os_engine','red_team')
          )
        """,
        (window_sec,),
    )
    row = cur.fetchone()
    cur.close()
    return int(row[0]) if row else 0


def _recent_high_alerts(conn, window_sec: int) -> int:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT COUNT(*) FROM Alerts a
        JOIN Severity s ON s.severity_id = a.severity_id
        WHERE a.created_at >= NOW() - INTERVAL %s SECOND
          AND s.numeric_level >= 4
        """,
        (window_sec,),
    )
    row = cur.fetchone()
    cur.close()
    return int(row[0]) if row else 0


def evaluate_after_event(
    new_event_type: str,
    new_event_source: str,
    last_alert_id: Optional[int] = None,
) -> Tuple[str, str]:
    """
    Apply escalation rules after an event (and optional alert) is recorded.
    Returns (previous_state, new_state).
    """
    window = int(os.environ.get("FSM_WINDOW_SEC", "120"))
    warn_n = int(os.environ.get("FSM_WARN_THRESHOLD", "4"))
    lock_n = int(os.environ.get("FSM_LOCK_THRESHOLD", "10"))
    lock_high = int(os.environ.get("FSM_LOCK_HIGH_ALERTS", "3"))

    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT state_name FROM FSM_Current_State WHERE id=1")
        row = cur.fetchone()
        current = row["state_name"] if row else STATE_NORMAL

        if current == STATE_LOCKED:
            cur.close()
            return current, current

        sus = _recent_suspicious_count(conn, window)
        highs = _recent_high_alerts(conn, window)

        target = current
        reason = "steady"

        if sus >= lock_n or (current == STATE_WARNING and highs >= lock_high):
            target = STATE_LOCKED
            reason = f"Escalation: suspicious_events={sus}, high_alerts={highs}"
        elif sus >= warn_n or new_event_type in (
            "PROCESS_SPIKE",
            "LOGIN_ANOMALY",
            "FILE_TAMPER",
        ):
            target = STATE_WARNING
            reason = f"Elevated activity: suspicious_events={sus}, trigger={new_event_type}"

        if target != current:
            _set_state(conn, target, reason, last_alert_id)

        cur.close()
        return current, target


def log_response_action(
    action: str,
    target_pid: Optional[int],
    detail: str,
    event_id: Optional[int] = None,
) -> int:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO Response_Log (event_id, action, target_pid, detail)
            VALUES (%s,%s,%s,%s)
            """,
            (event_id, action[:64], target_pid, detail[:4000]),
        )
        lid = cur.lastrowid
        conn.commit()
        cur.close()
        return int(lid)


def list_response_logs(limit: int = 100) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT log_id, action, target_pid, detail, created_at, event_id
            FROM Response_Log
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        cur.close()
        return rows
