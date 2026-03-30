from db_connection import execute_query, fetch_query
import logging

def log_event(event_type, description, source, process_name=None, pid=None, user_id=None):
    """ Logs an event into the Events table, creating a Process entry if necessary. """
    try:
        process_id = None
        if process_name and pid:
            # Check or create process
            check_proc = "SELECT process_id FROM Processes WHERE pid = %s AND process_name = %s ORDER BY start_time DESC LIMIT 1"
            res = fetch_query(check_proc, (pid, process_name), fetchall=False)
            if res:
                process_id = res['process_id']
            else:
                insert_proc = "INSERT INTO Processes (pid, process_name) VALUES (%s, %s)"
                process_id = execute_query(insert_proc, (pid, process_name))

        if user_id is not None:
            insert_event = """
            INSERT INTO Events (event_type, description, source, process_id, user_id)
            VALUES (%s, %s, %s, %s, %s)
            """
            event_id = execute_query(
                insert_event, (event_type, description, source, process_id, user_id)
            )
        else:
            insert_event = """
            INSERT INTO Events (event_type, description, source, process_id)
            VALUES (%s, %s, %s, %s)
            """
            event_id = execute_query(insert_event, (event_type, description, source, process_id))
        return event_id
    except Exception as e:
        logging.error(f"Failed to log event {event_type}: {e}")
        return None

def get_recent_events(limit=50):
    query = """
    SELECT e.event_id, e.event_type, e.description, p.process_name, e.timestamp
    FROM Events e
    LEFT JOIN Processes p ON e.process_id = p.process_id
    ORDER BY e.timestamp DESC
    LIMIT %s
    """
    return fetch_query(query, (limit,))
