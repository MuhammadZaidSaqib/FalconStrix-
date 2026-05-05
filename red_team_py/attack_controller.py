import os
import sys
import time
import subprocess
import argparse

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _run(script: str) -> None:
    path = os.path.join(_SCRIPT_DIR, script)
    try:
        cp = subprocess.run([sys.executable, path], check=False)
        if cp.returncode != 0:
            print(f"[!] {script} exited with code {cp.returncode}")
    except Exception as ex:
        print(f"[!] Failed to run {script}: {ex}")

def menu():
    print("="*40)
    print("  RED TEAM ATTACK CONTROLLER  ")
    print("="*40)
    print("1. Simulate Failed Logins (Brute Force)")
    print("2. Simulate Process Flooding")
    print("3. Simulate File Tampering")
    print("4. Launch Full Attack Suite")
    print("5. Exit")
    print("="*40)

def run_choice(choice: str) -> bool:
    """Run selected attack. Returns False when caller should exit."""
    if choice == '1':
        _run('login_simulator.py')
    elif choice == '2':
        _run('process_flood.py')
    elif choice == '3':
        _run('file_tamper_simulator.py')
    elif choice == '4':
        _run('login_simulator.py')
        _run('process_flood.py')
        _run('file_tamper_simulator.py')
    elif choice == '5':
        return False
    else:
        print("Invalid choice. Use 1, 2, 3, 4, or 5.")
    return True


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FalconStrix Red Team Attack Controller")
    parser.add_argument(
        "--choice",
        choices=["1", "2", "3", "4", "5"],
        help="Run a single menu choice non-interactively (1-5).",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Auto-run full attack suite (same as choice 4).",
    )
    return parser.parse_args()


def main():
    args = _parse_args()

    if args.auto:
        run_choice('4')
        return

    if args.choice:
        run_choice(args.choice)
        return

    # In non-interactive sessions (no stdin), avoid hanging on input().
    if not sys.stdin.isatty():
        print("[*] Non-interactive terminal detected. Auto-running full attack suite...")
        run_choice('4')
        return

    while True:
        menu()
        choice = input("Select an attack vector (1-5) and press Enter: ").strip()
        if not run_choice(choice):
            sys.exit(0)

if __name__ == "__main__":
    main()
