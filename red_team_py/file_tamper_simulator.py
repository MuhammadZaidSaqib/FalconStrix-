import json
import os
import time
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'backend'))
from ipc_config import PIPE_PATH  # noqa: E402
TARGET_FILE = 'dummy_passwd.txt' if os.name == 'nt' else '/tmp/dummy_passwd'

def main():
    print("[RED TEAM] Simulating critical file tampering (/etc/passwd style)...")
    
    # We will simulate the attack by creating a dummy file, editing it rapidly, and sending events
    target = TARGET_FILE
    with open(target, 'w') as f:
        f.write("root:x:0:0:\n")
        
    time.sleep(1)
    
    with open(target, 'a') as f:
        f.write("hacker:x:0:0:\n")
        
    print(f"-> Modified {target}")
    
    event = {
        "event_type": "FILE_TAMPER",
        "description": f"Unauthorized modification of critical file {target}",
        "source": "File_System",
        "pid": os.getpid(),
        "process_name": "tamper_script",
        "severity": 4 # CRITICAL severity
    }
    
    try:
        with open(PIPE_PATH, 'a') as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass

if __name__ == "__main__":
    main()
