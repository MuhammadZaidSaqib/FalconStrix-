import os
import signal
from db_connection import fetch_query, execute_query
import logging
from ipc_config import CMD_PIPE_PATH
from event_service import log_event

def active_defense():
    """ 
    Invoked when State -> LOCKED. 
    On Linux, sends a LOCKED response command to the C++ OS engine, which
    performs the actual termination and emits RESPONSE_ACTION events back.

    On Windows, where the C++ OS engine is not running, it falls back to
    direct process termination and logs RESPONSE_ACTION events.
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

    if not bad_procs:
        return

    # Resolve alerts immediately (we are taking response action now).
    for proc in bad_procs:
        execute_query("UPDATE Alerts SET is_resolved=TRUE WHERE event_id=%s", (proc["event_id"],))

    # Linux path: delegate kills to OS engine via command FIFO.
    if os.name != "nt":
        try:
            targets = sorted({int(p["pid"]) for p in bad_procs if p.get("pid") is not None})
            if targets:
                # Non-blocking open: if OS engine isn't reading yet, fall back.
                fd = os.open(CMD_PIPE_PATH, os.O_WRONLY | os.O_NONBLOCK)
                cmd_line = "RESPOND_LOCKED " + " ".join(str(t) for t in targets) + "\n"
                os.write(fd, cmd_line.encode("utf-8"))
                os.close(fd)

                msg = f"Sent RESPOND_LOCKED to OS engine for {len(targets)} targets"
                logging.info("[SOC] %s (cmd fifo: %s)", msg, CMD_PIPE_PATH)
                execute_query(
                    "INSERT INTO Events (event_type, description, source) VALUES (%s, %s, %s)",
                    ("RESPONSE_CMD_SENT", msg, "Response_Engine"),
                )

                # Let C++ emit RESPONSE_ACTION events after SIGKILL attempts.
                from fsm_service import tick_fsm, maybe_unlock_locked_state

                tick_fsm()
                # If defensive response has resolved all active cases, clear LOCKED -> NORMAL.
                maybe_unlock_locked_state(actor_username='system')
                return
        except OSError as oe:
            logging.warning("[SOC] Command FIFO send failed (%s). Falling back to direct kill.", oe)
        except Exception as ex:
            logging.warning("[SOC] Command FIFO send error (%s). Falling back to direct kill.", ex)

    # Windows fallback (or if OS engine command FIFO fails): direct kills + log.
    kill_sig = getattr(signal, 'SIGKILL', 9)  # 9 is SIGKILL on POSIX
    for proc in bad_procs:
        pid = proc["pid"]
        name = proc["process_name"]
        try:
            os.kill(int(pid), kill_sig)
            msg = f"Terminated malicious process {name} (PID: {pid})"
            print(f"[*] RESPONSE ENGINE: {msg}")
            execute_query(
                "INSERT INTO Events (event_type, description, source) VALUES (%s, %s, %s)",
                ("RESPONSE_ACTION", msg, "Response_Engine"),
            )
        except ProcessLookupError:
            pass
        except PermissionError:
            print(f"[!] RESPONSE ENGINE: Permission denied to kill PID {pid}")

    from fsm_service import tick_fsm
    tick_fsm()
    # If defensive response has resolved all active cases, clear LOCKED -> NORMAL.
    try:
        from fsm_service import maybe_unlock_locked_state
        maybe_unlock_locked_state(actor_username='system')
    except Exception:
        pass


def resolve_alert_case(alert_id, actor_username='unknown', actor_role='user', actor_user_id=None):
    """
    Resolve a single live alert case from dashboard workflow.
    - If possible, delegate response action to C++ response_engine via CMD FIFO.
    - Mark alert as resolved.
    - Log CASE_RESOLVED event.
    - Tick FSM, and if LOCKED + no unresolved alerts, allow admin-only unlock.
    """
    row = fetch_query(
        """
        SELECT a.alert_id, a.is_resolved, e.event_id, e.event_type, p.pid, p.process_name
        FROM Alerts a
        JOIN Events e ON e.event_id = a.event_id
        LEFT JOIN Processes p ON p.process_id = e.process_id
        WHERE a.alert_id = %s
        """,
        (alert_id,),
        fetchall=False,
    )
    if not row:
        return {'ok': False, 'status': 404, 'message': 'Alert case not found'}
    if row.get('is_resolved'):
        return {'ok': True, 'status': 200, 'message': 'Case already resolved'}

    from fsm_service import get_current_state, tick_fsm, maybe_unlock_locked_state

    current_state = get_current_state()
    pid = row.get('pid')
    pname = row.get('process_name') or 'unknown'
    response_detail = 'Manual case resolution'
    responded = False
    kill_sig = getattr(signal, 'SIGKILL', 9)  # 9 is SIGKILL on POSIX

    if pid is not None:
        # Prefer Linux FIFO command -> C++ response_engine does termination and audit.
        if os.name != "nt":
            try:
                fd = os.open(CMD_PIPE_PATH, os.O_WRONLY | os.O_NONBLOCK)
                cmd_line = f"RESPOND_LOCKED {int(pid)}\n"
                os.write(fd, cmd_line.encode("utf-8"))
                os.close(fd)
                response_detail = f"C++ response_engine command sent for PID {pid}"
                responded = True
            except Exception as ex:
                logging.warning("[SOC] Case resolve FIFO send failed for PID %s: %s", pid, ex)

        # Fallback direct termination if command delegation unavailable.
        if not responded:
            try:
                os.kill(int(pid), kill_sig)
                response_detail = f"Process terminated directly for PID {pid}"
                log_event(
                    "RESPONSE_ACTION",
                    f"Manual case response by {actor_username}: SIGKILL delivered pid={pid} name={pname}",
                    "SOC-Dashboard",
                    process_name=pname,
                    pid=int(pid),
                    user_id=actor_user_id,
                )
                responded = True
            except Exception as ex:
                response_detail = f"Case resolved without kill (PID action failed: {ex})"

    execute_query("UPDATE Alerts SET is_resolved=TRUE WHERE alert_id=%s", (alert_id,))
    log_event(
        "CASE_RESOLVED",
        f"Alert case {alert_id} resolved by {actor_username}. {response_detail}",
        "SOC-Dashboard",
        process_name=pname if pid else None,
        pid=int(pid) if pid else None,
        user_id=actor_user_id,
    )

    tick_fsm()
    unlock_result = {'changed': False, 'reason': 'No unlock attempt'}
    if actor_role == 'admin':
        unlock_result = maybe_unlock_locked_state(actor_username=actor_username)

    return {
        'ok': True,
        'status': 200,
        'message': 'Case resolved successfully',
        'response_detail': response_detail,
        'fsm_unlock': unlock_result,
    }
