import os
import sys
import time

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _run(script: str) -> None:
    path = os.path.join(_SCRIPT_DIR, script)
    code = os.system(f'"{sys.executable}" "{path}"')
    if code != 0:
        print(f"[!] {script} exited with code {code}")

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

def main():
    while True:
        menu()
        choice = input("Select an attack vector: ")
        
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
            sys.exit(0)
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
