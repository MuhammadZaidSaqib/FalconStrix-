#!/usr/bin/env bash
set -euo pipefail

# Launch FalconStrix services in tmux panes on Linux/Kali.
# Usage:
#   ./run_all.sh
#   ./run_all.sh --with-red-team
#   ./run_all.sh --session falcon

SESSION_NAME="falconstrix"
WITH_RED_TEAM=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-red-team)
      WITH_RED_TEAM=1
      shift
      ;;
    --session)
      SESSION_NAME="${2:-falconstrix}"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1"
      echo "Usage: $0 [--with-red-team] [--session <name>]"
      exit 1
      ;;
  esac
done

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required. Install with:"
  echo "  sudo apt install -y tmux"
  exit 1
fi

if ! command -v mysql >/dev/null 2>&1; then
  echo "mysql client is missing. Install MariaDB client/server first."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="${ROOT_DIR}/.venv"
ENGINE_DIR="${ROOT_DIR}/os_engine_cpp"
ENGINE_BIN="${ENGINE_DIR}/os_engine"

if [[ ! -d "${VENV_PATH}" ]]; then
  echo "Python venv not found at ${VENV_PATH}"
  echo "Create it first:"
  echo "  python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi

if [[ ! -f "${ENGINE_BIN}" ]]; then
  echo "C++ engine binary not found. Building now..."
  (
    cd "${ENGINE_DIR}"
    g++ -pthread src/main.cpp src/process_monitor.cpp src/behavior_detector.cpp src/resource_monitor.cpp src/response_engine.cpp -I include -o os_engine
  )
fi

if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
  echo "tmux session '${SESSION_NAME}' already exists."
  echo "Attach with: tmux attach -t ${SESSION_NAME}"
  exit 1
fi

tmux new-session -d -s "${SESSION_NAME}" -n "falcon"

# Pane 0: backend
tmux send-keys -t "${SESSION_NAME}:falcon.0" "cd \"${ROOT_DIR}\" && source .venv/bin/activate && python3 backend/main_backend.py" C-m

# Pane 1: dashboard
tmux split-window -h -t "${SESSION_NAME}:falcon.0"
tmux send-keys -t "${SESSION_NAME}:falcon.1" "cd \"${ROOT_DIR}\" && source .venv/bin/activate && python3 gui_dashboard/app.py" C-m

# Pane 2: OS engine
tmux split-window -v -t "${SESSION_NAME}:falcon.0"
tmux send-keys -t "${SESSION_NAME}:falcon.2" "cd \"${ENGINE_DIR}\" && sudo ./os_engine" C-m

# Pane 3: utility shell (or red team)
tmux split-window -v -t "${SESSION_NAME}:falcon.1"
if [[ "${WITH_RED_TEAM}" -eq 1 ]]; then
  tmux send-keys -t "${SESSION_NAME}:falcon.3" "cd \"${ROOT_DIR}\" && source .venv/bin/activate && python3 red_team_py/attack_controller.py" C-m
else
  tmux send-keys -t "${SESSION_NAME}:falcon.3" "cd \"${ROOT_DIR}\" && source .venv/bin/activate && echo 'Ready. Run red team here if needed: python3 red_team_py/attack_controller.py'" C-m
fi

tmux select-layout -t "${SESSION_NAME}:falcon" tiled

echo "FalconStrix started in tmux session: ${SESSION_NAME}"
echo "Attach:"
echo "  tmux attach -t ${SESSION_NAME}"
echo
echo "Stop everything:"
echo "  tmux kill-session -t ${SESSION_NAME}"
