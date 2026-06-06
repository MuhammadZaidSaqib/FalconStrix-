# FalconStrix

For a complete Kali Linux setup walkthrough, see `SETUP_KALI.md`.

**FalconStrix** is a host-based intrusion detection and response platform that combines:

- a Python backend for event ingestion, persistence, and FSM orchestration,
- a C++ engine for low-level monitoring and response workflows,
- a real-time SOC-style Flask dashboard for analysts,
- a modern marketing landing page with Clerk authentication,
- and red-team simulation scripts for end-to-end testing.

It is designed for practical security demos, academic projects, and SOC workflow experimentation on Windows/Linux labs.

---

## Core Capabilities

- Real-time alert ingestion and event logging
- Finite State Machine (FSM): `NORMAL`, `WARNING`, `LOCKED`
- Active defense and case resolution workflows
- Live Alerts, Resolved Cases, Terminated Processes, and User Activity visibility
- CSV and professional PDF report exports (dashboard + audit sections)
- Educational OS concept visualizations (process, threads, sync, IPC, signals, resources)
- **SIGKILL automated process termination** on critical threshold breach
- **Syscall monitoring** and IPC telemetry via named pipes
- **Zero-trust architecture** with Clerk-based authentication on the marketing site
- **Dark / Light mode** responsive landing page

---

## Architecture Overview

FalconStrix follows a layered architecture:

1. **Collectors / Simulators**
   - Red team scripts and engine components emit structured events.
2. **Backend Services**
   - Python services process, classify, persist, and trigger FSM transitions.
3. **Response Layer**
   - Response logic performs containment/termination based on policy/state.
4. **Dashboard Layer**
   - Flask + Socket.IO provides real-time monitoring and analyst controls.
5. **Marketing / Auth Layer**
   - A public-facing hero page with problem/solution overview, pricing, tech stack,
     and Clerk-powered sign-in that gates access to the SOC dashboard.

High-level flow:

`Event Source -> Backend Ingestion -> DB -> FSM Evaluation -> Dashboard + Response`

---

## Tech Stack

- **Backend**: Python 3, Flask, Flask-SocketIO
- **Engine**: C++17 (Linux-focused runtime path)
- **Data**: MySQL/MariaDB
- **Frontend**: HTML/CSS/JavaScript (real-time updates + visualizations)
- **Auth**: Clerk (JWT-based, marketing site gate)
- **Reporting**: CSV + PDF (ReportLab)
- **IPC**: Named pipes + Linux signals (SIGKILL, SIGTERM)

---

## Prerequisites

- **OS**: Windows 10/11 or Linux (Linux recommended for full C++ engine workflow)
- **Python**: 3.10+
- **Database**: MySQL/MariaDB server
- **Compiler** (Linux/C++ path): `g++` with pthread support
- **Terminal multiplexer** (Linux quick-start): `tmux`
- **Clerk account** (optional, for marketing site auth): https://clerk.com

---

## Setup

### 1) Database

Create your database (example: `hidrs_db`) and import SQL files:

```bash
mysql -u root -p < database/schema.sql
mysql -u root -p hidrs_db < database/sample_data.sql
mysql -u root -p hidrs_db < database/backfill_incident_trends.sql
```

Update DB credentials/environment in backend configuration as needed.

### 2) Python Environment

```powershell
# Windows
python -m venv .venv
.\.venv\Scripts\activate
.\.venv\Scripts\python -m pip install -r requirements.txt
```

```bash
# Linux
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 3) Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Key variables:
- `CLERK_PUBLISHABLE_KEY` — your Clerk frontend API key (for marketing site auth)
- `FALCON_SECRET_KEY` — Flask session secret

### 4) C++ Engine Build (Linux path)

```bash
cd os_engine_cpp
g++ -pthread src/main.cpp src/process_monitor.cpp src/behavior_detector.cpp src/resource_monitor.cpp src/response_engine.cpp -I include/ -o os_engine
```

---

## Run FalconStrix

### Linux quick start (recommended)

After first-time setup (DB + venv + dependencies), run everything with one command:

```bash
chmod +x run_all.sh
./run_all.sh
```

Optional (auto-start Red Team pane):

```bash
./run_all.sh --with-red-team
```

Attach / stop tmux session:

```bash
tmux attach -t falconstrix
tmux kill-session -t falconstrix
```

---

Use separate terminals:

### A) Backend Ingestion Service

```bash
# Windows
python backend\main_backend.py

# Linux
python3 backend/main_backend.py
```

### B) Dashboard Service

```bash
# Windows
python gui_dashboard\app.py

# Linux
python3 gui_dashboard/app.py
```

URLs:
- **Landing page**: `http://127.0.0.1:5001`
- **SOC Dashboard**: `http://127.0.0.1:5001/dashboard`
- **Demo page**: `http://127.0.0.1:5001/demo`

### C) C++ Engine (Optional / Linux)

```bash
cd os_engine_cpp
sudo ./os_engine
```

---

## Red-Team Simulation

```bash
cd red_team_py
python attack_controller.py
```

This drives test events (e.g., auth failures, process spam, tamper scenarios) to validate:

- event ingestion,
- FSM escalation/de-escalation,
- dashboard updates,
- and response handling.

---

## FSM Behavior (Operational)

- `NORMAL` -> stable operation
- `WARNING` -> elevated suspicious activity
- `LOCKED` -> critical posture; analyst intervention required

Return to `NORMAL` occurs when lock conditions are cleared according to backend/DB state and FSM re-evaluation.

---

## Reports

FalconStrix supports:

- CSV exports for operational tables
- PDF reports for dashboard, user activity, incident summary, resolved cases, and terminated processes

PDF reports include structured sections and severity-aware coloring for quick triage readability.

---

## Troubleshooting

- If dependencies fail in Windows venv, prefer:
  - `.\.venv\Scripts\python -m pip install -r requirements.txt`
- If dashboard JS changes do not appear:
  - hard refresh (`Ctrl+F5`)
  - ensure dashboard service restarted
- If API route returns 404 after code changes:
  - stop old `gui_dashboard\app.py` process and restart
- If Clerk auth buttons do not appear on the landing page:
  - ensure `CLERK_PUBLISHABLE_KEY` is set in your `.env` file

---

## Project Status

FalconStrix is an actively evolving SOC-style platform.
Contributions and hardening improvements are welcome.
