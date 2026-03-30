import os
import signal
from db_connection import fetch_query, execute_query
import logging
from ipc_config import CMD_PIPE_PATH

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
                from fsm_service import tick_fsm

                tick_fsm()
                return
        except OSError as oe:
            logging.warning("[SOC] Command FIFO send failed (%s). Falling back to direct kill.", oe)
        except Exception as ex:
            logging.warning("[SOC] Command FIFO send error (%s). Falling back to direct kill.", ex)

    # Windows fallback (or if OS engine command FIFO fails): direct kills + log.
    for proc in bad_procs:
        pid = proc["pid"]
        name = proc["process_name"]
        try:
            os.kill(int(pid), signal.SIGKILL)
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
