# FalconStrix — HIDRS Prototype

Hybrid **Host-Based Intrusion Detection and Response (HIDRS)**-style stack: Red Team Python simulators, an optional **C++** Blue Team OS monitor (Linux: `fork` + **pthreads** + **mutex**-protected FIFO writes), a **Python** backend (events → **MariaDB/MySQL** → **FSM** escalation → command sink), and a **Flask + Socket.IO + Chart.js** SOC dashboard. FSM states map to conceptual **GREEN / YELLOW / RED** LEDs for future DLD hardware integration.

**Platforms:** **Kali Linux** is the full lab target (FIFOs + `hidrs_os_engine` + `/proc`). **Windows** runs the Python pipeline and dashboard using **file-based** event paths under `var/` (no `mkfifo`). The same repo and `.env.example` work on both; omit `HIDRS_*` in `.env` to use automatic per-OS defaults.

## Repository layout

| Path | Role |
|------|------|
| `database/` | `schema.sql`, `sample_data.sql`, `queries.sql` |
| `backend/` | DB services, FSM, `main_backend.py` event bridge |
| `red_team_py/` | Login, process flood, file tamper simulators + controller |
| `os_engine_cpp/` | `/proc` monitoring, behavioral heuristics, response engine (**Linux only**) |
| `gui_dashboard/` | Flask SOC UI (live Socket.IO feed) |
| `docker-compose.yml` | Optional MariaDB for local dev (Windows or Kali) |
| `scripts/dev-windows.ps1` | Windows: venv + pip + optional Docker |
| `scripts/dev-kali.sh` | Kali: venv + pip + optional Docker |
| `docs/PROJECT_TASKS.md` | Full build checklist (step-by-step) |

## Architecture (data flow)

1. **Red Team** and **OS engine** emit **JSON lines** on `HIDRS_EVENTS_FIFO`. **Kali default:** `/tmp/hidrs_events.fifo`. **Windows default:** `var/hidrs_events.jsonl` (appended lines; backend tails the file).
2. **`main_backend.py`** inserts **Events**, optional **Processes**, raises **Alerts**, runs **FSM** (`NORMAL` → `WARNING` → `LOCKED`), updates **`FSM_Current_State`** / **`FSM_State_History`**, and on **LOCKED** writes **`RESPOND_LOCKED`** JSON to **`HIDRS_CMD_FIFO`** (FIFO on Kali, append file on Windows).
3. **OS engine parent** (Linux only) reads the command FIFO and forwards lines to the **child** over an internal `pipe()`. The **response** path issues **`SIGTERM`** and emits **`RESPONSE_ACTION`** lines back on the events sink; the backend logs to **`Response_Log`**.

## Prerequisites

| | Windows | Kali Linux |
|---|---------|------------|
| Python | 3.10+ | 3.10+ |
| Database | MariaDB/MySQL or **Docker Desktop** + `docker compose` | MariaDB/MySQL or Docker |
| OS engine | Not supported natively; use WSL/VM for `hidrs_os_engine` | `g++`, `cmake`, `make`, pthreads |

## Quick setup

### Option A — Docker MariaDB (Windows or Kali)

From the repo root:

```bash
docker compose up -d
```

First start applies `database/schema.sql` and `database/sample_data.sql`. Then:

- **Windows:** `powershell -ExecutionPolicy Bypass -File scripts/dev-windows.ps1`
- **Kali:** `chmod +x scripts/dev-kali.sh && ./scripts/dev-kali.sh`

### Option B — Local MariaDB / MySQL (typical on Kali)

```bash
sudo mysql < database/schema.sql
mysql hidrs_db < database/sample_data.sql
```

Create a DB user if needed (see below), copy `.env.example` → `.env`, then:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Environment variables

Copy `.env.example` to `.env`. **MySQL** variables apply on both OSes.

**`HIDRS_*` paths:** Leave them commented for automatic defaults (Kali → `/tmp` FIFOs; Windows → `var/` files). Uncomment a block in `.env.example` to pin paths. **Relative paths** (e.g. `var/hidrs_events.jsonl`) resolve from the **repository root**, so scripts behave the same no matter your current working directory.

See `.env.example` for FSM thresholds and `DASHBOARD_PORT`.

## Run components (order matters)

**1 — Backend** (creates FIFOs on Kali or `var/` files on Windows):

```bash
# From repo root
python3 backend/main_backend.py
```

**2 — Dashboard**

```bash
python3 gui_dashboard/app.py
# http://127.0.0.1:5000
```

**3 — OS engine (Kali only)**

```bash
cmake -S . -B build && cmake --build build
./build/os_engine_cpp/hidrs_os_engine
```

**4 — Red Team**

```bash
python3 red_team_py/attack_controller.py full
# or: login | flood | file | fifo_only
```

On Windows, run **backend before** red team so the event file exists and is tailed.

## Modules (short)

- **`db_connection.py`** — connections via context manager; env-driven config.
- **`event_service.py`** — inserts **Events** (JSON payload column).
- **`alert_service.py`** — links **Alerts** to **Severity** reference data.
- **`process_service.py`** — persists **Processes** rows for suspicious/spike snapshots.
- **`fsm_service.py`** — escalation rules, **LED** mapping, **FSM_State_History**, **Response_Log** helper.
- **`main_backend.py`** — JSONL consumer (FIFO or file tail), FSM orchestration, LOCKED command emission.
- **`red_team_py/env_paths.py`** — cross-platform defaults for FIFO/file paths.
- **`hidrs_os_engine`** — Linux: `fork()`, pthread monitors, mutexed FIFO writer.
- **`gui_dashboard/app.py`** — polls DB every ~2s, pushes snapshots over Socket.IO.

## Security notice

This project runs real **`kill()`** signaling in **LOCKED** mode. Use only on **isolated lab VMs**. Tune PIDs and thresholds before any class demo.

## License

Educational / research prototype — use and modify at your own risk.
