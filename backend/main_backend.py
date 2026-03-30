import os
import sys
import time
import json
import logging
from pathlib import Path
from event_service import log_event
from alert_service import create_alert
from fsm_service import get_current_state, tick_fsm
from ipc_config import PIPE_PATH, setup_named_pipe

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

try:
    from dotenv import load_dotenv

    ROOT = Path(__file__).resolve().parent.parent
    load_dotenv(ROOT / ".env")
except Exception:
    pass

def process_message(msg):
    try:
        data = json.loads(msg)
        event_type = data.get("event_type", "UNKNOWN")
        desc = data.get("description", "")
        source = data.get("source", "OS_Engine")
        pid = data.get("pid", 0)
        pname = data.get("process_name", "unknown")
        severity = data.get("severity", 1)  # Default LOW
        
        # Log event
        event_id = log_event(event_type, desc, source, process_name=pname, pid=pid)
        print(f"[BACKEND] Recv Event: {event_type} - {desc}")

        # Don't treat response/audit events as new detections.
        # Otherwise, FSM may re-escalate based on its own response actions.
        if event_type in ("RESPONSE_ACTION", "RESPONSE_CMD_SENT", "PROCESS_KILLED"):
            return

        if event_id and severity > 1:
            # Create Alert 
            create_alert(event_id, severity, f"OS Engine Detection: {desc}")
            
    except json.JSONDecodeError:
        logging.error(f"Malformed JSON from named pipe: {msg}")

def main():
    setup_named_pipe()
    
    print("[*] Backend Server Running...")
    print(f"[*] Initial State: {get_current_state()}")
    
    while True:
        try:
            with open(PIPE_PATH, 'r') as fifo:
                while True:
                    data = fifo.readline()
                    if len(data) == 0:
                        if os.name == 'nt':
                            time.sleep(0.5)
                            continue
                        break # EOF, writer closed pipe
                    
                    line = data.strip()
                    if line:
                        process_message(line)
        except KeyboardInterrupt:
            print("\nShutting down backend...")
            break
        except Exception as e:
            logging.error(f"Pipe read error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
