import json
import time
import random
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'backend'))
from ipc_config import PIPE_PATH  # noqa: E402

def send_to_blue_team(event_data):
    try:
        if not os.path.exists(PIPE_PATH):
            print("Pipe doesn't exist, is the backend running?")
            return
        with open(PIPE_PATH, 'a') as f:
            f.write(json.dumps(event_data) + "\n")
    except Exception as e:
        print(f"Failed to send event: {e}")

def run_simulation(attempts=5, delay=1):
    print(f"[RED TEAM] Starting login brute-force simulator ({attempts} attempts)...")
    for i in range(attempts):
        time.sleep(delay)
        event = {
            "event_type": "AUTH_FAILED",
            "description": f"Failed login attempt for user 'root' from 192.168.1.{random.randint(10, 50)}",
            "source": "Auth_Log",
            "pid": os.getpid(),
            "process_name": "ssh_login_sim",
            "severity": 2 # Medium severity
        }
        send_to_blue_team(event)
        print(f"-> Sent Login Failure {i+1}/{attempts}")
    
    print("[RED TEAM] Login Simulator complete.")

if __name__ == "__main__":
    run_simulation()
