import json
import time
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'backend'))
from ipc_config import PIPE_PATH  # noqa: E402

def main():
    print("[RED TEAM] Starting process flood (Fork Bomb lite)...")
    
    # Note: Rather than actually spawning 100 processes which can freeze the user's Kali,
    # we emit event logs as if we did, and spawn a few benign sleepers to trigger OS engine.
    
    procs = []
    for i in range(10):
        cmd = ["timeout", "/t", "60"] if os.name == 'nt' else ["sleep", "60"]
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
        print(f"[-] Spawned useless process PID {p.pid}")
        
    # Send event summarizing flood (if OS Engine misses it)
    event = {
        "event_type": "PROCESS_SPAM",
        "description": "Rapid creation of 10 subprocesses detected",
        "source": "Process_Subsystem",
        "pid": os.getpid(),
        "process_name": "flood_malware.py",
        "severity": 3 # High severity
    }
    try:
        with open(PIPE_PATH, 'a') as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass
        
    print("[RED TEAM] Spawned processes, leaving them alive to be targeted by Blue Team response...")
    
    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()

if __name__ == "__main__":
    main()
