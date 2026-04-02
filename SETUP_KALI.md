# FalconStrix Setup Guide (Kali Linux)

This guide is a complete, practical walkthrough to run FalconStrix on Kali from zero to fully working services.

It covers:
- system dependencies,
- database setup,
- Python environment setup,
- C++ engine build,
- one-command startup with `run_all.sh`,
- and troubleshooting common Kali issues.

---

## 1) Overview: What Runs in FalconStrix

FalconStrix is multi-process by design. For full functionality, these components run together:

1. **MariaDB/MySQL** - persistent storage (`Events`, `Alerts`, FSM tables)
2. **Python Backend** - ingests events and applies FSM logic (`backend/main_backend.py`)
3. **Dashboard** - web UI + socket updates (`gui_dashboard/app.py`)
4. **C++ OS Engine** - low-level process/resource detection + response (`os_engine_cpp/os_engine`)
5. *(Optional)* **Red Team scripts** - generate simulation events (`red_team_py/`)

---

## 2) First-Time System Setup (Kali)

Run once:

```bash
sudo apt update
sudo apt install -y \
  python3 python3-venv python3-pip \
  mariadb-server mariadb-client \
  g++ make build-essential \
  tmux git
```

Enable/start MariaDB:

```bash
sudo systemctl enable --now mariadb
sudo systemctl status mariadb --no-pager
```

---

## 3) Get Project on Kali

If not already cloned:

```bash
git clone https://github.com/MuhammadZaidSaqib/FalconStrix-.git
cd FalconStrix-
```

If already present:

```bash
cd ~/FalconStrix-
```

Confirm you are in the right folder:

```bash
ls
```

You should see folders like `backend`, `gui_dashboard`, `database`, `os_engine_cpp`, `red_team_py`.

---

## 4) Database Setup (Recommended user-based auth)

### 4.1 Create DB and app user

Open MariaDB as system root:

```bash
sudo mysql
```

Inside SQL prompt:

```sql
CREATE DATABASE IF NOT EXISTS hidrs_db;
CREATE USER IF NOT EXISTS 'falcon'@'localhost' IDENTIFIED BY 'Falcon@123';
GRANT ALL PRIVILEGES ON hidrs_db.* TO 'falcon'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 4.2 Import schema + seed data

From project root:

```bash
mysql -u falcon -p hidrs_db < database/schema.sql
mysql -u falcon -p hidrs_db < database/sample_data.sql
mysql -u falcon -p hidrs_db < database/backfill_incident_trends.sql
```

### 4.3 Verify tables and data

```bash
mysql -u falcon -p -e "USE hidrs_db; SHOW TABLES;"
mysql -u falcon -p -e "USE hidrs_db; SELECT COUNT(*) AS alerts FROM Alerts;"
mysql -u falcon -p -e "USE hidrs_db; SELECT COUNT(*) AS events FROM Events;"
```

---

## 5) Configure Environment

Create `.env` (repo root):

```bash
cp .env.example .env
```

Edit it:

```bash
nano .env
```

Set at least:

```env
MYSQL_HOST=127.0.0.1
MYSQL_USER=falcon
MYSQL_PASSWORD=Falcon@123
MYSQL_DATABASE=hidrs_db
PORT=5001
FALCON_SECRET_KEY=change_this_in_production
```

Save and exit.

---

## 6) Python Environment Setup

From project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Check:

```bash
python --version
pip --version
```

---

## 7) Build C++ Engine

```bash
cd os_engine_cpp
g++ -pthread src/main.cpp src/process_monitor.cpp src/behavior_detector.cpp src/resource_monitor.cpp src/response_engine.cpp -I include -o os_engine
cd ..
```

Verify binary:

```bash
ls -l os_engine_cpp/os_engine
```

---

## 8) Run FalconStrix (Recommended: one command)

Use launcher script:

```bash
chmod +x run_all.sh
./run_all.sh
```

With red-team auto pane:

```bash
./run_all.sh --with-red-team
```

Attach tmux session:

```bash
tmux attach -t falconstrix
```

Stop all services started by launcher:

```bash
tmux kill-session -t falconstrix
```

---

## 9) Manual Run (if you prefer separate terminals)

Terminal 1:

```bash
cd ~/FalconStrix-
source .venv/bin/activate
python3 backend/main_backend.py
```

Terminal 2:

```bash
cd ~/FalconStrix-
source .venv/bin/activate
python3 gui_dashboard/app.py
```

Terminal 3:

```bash
cd ~/FalconStrix-/os_engine_cpp
sudo ./os_engine
```

Terminal 4 (optional simulation):

```bash
cd ~/FalconStrix-
source .venv/bin/activate
python3 red_team_py/attack_controller.py
```

Dashboard URL:
- `http://127.0.0.1:5001` (or whichever port is shown in terminal)

---

## 10) Backend-Level Verification Checklist (OS Concepts)

If all are healthy, these concepts are truly running in backend/engine (not only UI):

- **Process Management**: `fork()` + `waitpid()` supervision in C++ engine logs
- **Multithreading**: monitor/detector/resource/response threads alive
- **Synchronization**: mutex-protected reads in process monitor path
- **IPC Pipes**: `/tmp/hidrs_events` and `/tmp/hidrs_cmd` active
- **Signal Handling**: graceful handling of SIGINT/SIGTERM
- **Resource Monitor**: `/proc/stat`, `/proc/meminfo` sampling loop
- **/proc Filesystem**: `/proc/[pid]/comm`, `cmdline`, `status` reads
- **Concurrency Design**: process + thread + service fanout
- **Fault Tolerance**: child restart path when abnormal exit occurs
- **Response Engine**: LOCKED response path with `kill(pid, SIGKILL)` logic

Quick API checks:

```bash
curl -s http://127.0.0.1:5001/api/ipc/status
curl -s http://127.0.0.1:5001/api/dashboard_snapshot | head
```

---

## 11) Common Kali Troubleshooting

### A) `ERROR 1698 (28000): Access denied for user 'root'@'localhost'`

Use `sudo mysql` for root socket auth, or use your app user (`falcon`) as shown above.

### B) Dashboard says DB unavailable / mock behavior appears

Check `.env` credentials and restart backend + dashboard.

### C) `tmux: command not found`

```bash
sudo apt install -y tmux
```

### D) Engine build fails

Install build chain:

```bash
sudo apt install -y g++ make build-essential
```

### E) Engine binary missing

Rebuild in `os_engine_cpp` and verify `os_engine` exists.

### F) Permission denied for process kill actions

Run engine with sudo:

```bash
cd os_engine_cpp
sudo ./os_engine
```

### G) UI changes not visible

Hard refresh browser (`Ctrl+F5`) and ensure dashboard process restarted.

---

## 12) Daily Workflow (After First-Time Setup)

From project root:

```bash
./run_all.sh
```

Then open dashboard and operate normally.

That is the shortest reliable daily path on Kali.

