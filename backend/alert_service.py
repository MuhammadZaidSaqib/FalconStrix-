from db_connection import execute_query, fetch_query
from fsm_service import tick_fsm
import logging

def create_alert(event_id, severity_id, message):
    """
    Creates an alert based on an event, then triggers FSM tick to check
    if escalation is needed.
    Severity IDs: 1 (LOW), 2 (MEDIUM), 3 (HIGH), 4 (CRITICAL)
    """
    try:
        insert_alert = """
        INSERT INTO Alerts (event_id, severity_id, message)
        VALUES (%s, %s, %s)
        """
        alert_id = execute_query(insert_alert, (event_id, severity_id, message))
        
        # After inserting an alert, ask FSM to evaluate state
        tick_fsm()
        
        return alert_id
    except Exception as e:
        logging.error(f"Failed to create alert: {e}")
        return None

def get_active_alerts():
    query = """
    SELECT a.alert_id, s.level_name as severity, a.message, a.timestamp, e.event_type
    FROM Alerts a
    JOIN Severity s ON a.severity_id = s.severity_id
    JOIN Events e ON a.event_id = e.event_id
    WHERE a.is_resolved = FALSE
    ORDER BY a.timestamp DESC
    """
    return fetch_query(query)


def get_recent_alerts_for_dashboard(days=7, limit=5):
    """
    Time-bounded alerts for the dashboard 'Recent Alerts' column (includes resolved).
    """
    query = """
    SELECT a.alert_id, s.level_name as severity, a.message, a.timestamp, e.event_type, a.is_resolved
    FROM Alerts a
    JOIN Severity s ON a.severity_id = s.severity_id
    JOIN Events e ON a.event_id = e.event_id
    WHERE a.timestamp >= NOW() - INTERVAL %s DAY
    ORDER BY a.timestamp DESC
    LIMIT %s
    """
    return fetch_query(query, (days, limit))

def resolve_alert(alert_id):
    query = "UPDATE Alerts SET is_resolved = TRUE WHERE alert_id = %s"
    execute_query(query, (alert_id,))
