#!/usr/bin/env bash
# FalconStrix on Kali/Linux: venv, deps, optional Docker MariaDB.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

if command -v docker >/dev/null 2>&1; then
  docker compose -f "$ROOT/docker-compose.yml" up -d
  echo "Waiting for MariaDB on 127.0.0.1:3306 ..."
  for _ in {1..30}; do
    if (echo >/dev/tcp/127.0.0.1/3306) >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
else
  echo "Docker not found: use local MariaDB/MySQL and load database/schema.sql + sample_data.sql"
fi

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate
pip install -r requirements.txt

echo ""
echo "Ready. Start from repo root (order matters):"
echo "  1) python3 backend/main_backend.py"
echo "  2) python3 gui_dashboard/app.py   # http://127.0.0.1:5000"
echo "  3) cmake -S . -B build && cmake --build build   # optional OS engine"
echo "  4) ./build/os_engine_cpp/hidrs_os_engine        # optional, after backend"
echo "  5) python3 red_team_py/attack_controller.py fifo_only"
