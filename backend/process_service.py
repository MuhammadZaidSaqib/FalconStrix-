import os
import signal
from db_connection import fetch_query, execute_query
import logging

def active_defense():
    """ 
    Invoked when State -> LOCKED. 
    Kills processes that triggered HIGH or CRITICAL level alerts.
    """
    query = """
    SELECT DISTINCT p.pid, p.process_name, e.event_id 
    FROM Processes p
    JOIN Events e ON p.process_id = e.process_id
    JOIN Alerts a ON e.event_id = a.event_id
    JOIN Severity s ON a.severity_id = s.severity_id
    WHERE a.is_resolved = FALSE AND s.level_name IN ('HIGH', 'CRITICAL', 'MEDIUM')
    """
    bad_procs = fetch_query(query)
    
    for proc in bad_procs:
        pid = proc['pid']
        name = proc['process_name']
        try:
            os.kill(pid, signal.SIGKILL)
            msg = f"Terminated malicious process {name} (PID: {pid})"
            print(f"[*] RESPONSE ENGINE: {msg}")
            
            # Log action
            ev_id = execute_query(
                "INSERT INTO Events (event_type, description, source) VALUES (%s, %s, %s)",
                ('RESPONSE_ACTION', msg, 'Response_Engine')
            )
            # Mark the alert as resolved since we killed the process
            execute_query("UPDATE Alerts SET is_resolved=TRUE WHERE event_id=%s", (proc['event_id'],))
        except ProcessLookupError:
            pass # Process already dead
        except PermissionError:
            print(f"[!] RESPONSE ENGINE: Permission denied to kill PID {pid}")
    
    # Check if system should de-escalate down from LOCKED
    from fsm_service import tick_fsm
    tick_fsm()
