# Host-Based Intrusion Detection and Response System (HIDRS)

This project implements a layered cybersecurity monitoring and response framework designed to run on **Kali Linux** or **Windows** environments.

## Pre-requisites

- **OS**: Windows or Kali Linux (Linux recommended for low-level features).
- **Database**: MariaDB / MySQL Server.
- **Python 3.8+**: Essential for the backend and dashboard.
- **Compiler**: `g++` (for C++ engine on Linux).

## Installation & Setup

### 1. Database Setup
1. Create a database named `hidrs_db`.
2. Import the schema and sample data:
   ```bash
   mysql -u root -p hidrs_db < database/schema.sql
   mysql -u root -p hidrs_db < database/sample_data.sql
   ```
   > Note: Ensure DB credentials in `backend/db_connection.py` match your setup.

### 2. Environment & Dependencies
We recommend using a virtual environment and the provided `requirements.txt`.
```powershell
# On Windows
python -m venv .venv
& .venv/Scripts/Activate.ps1
pip install -r requirements.txt

# On Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Compile OS Engine (Blue Team Engine - Linux Only)
```bash
cd os_engine_cpp
g++ -pthread src/main.cpp src/process_monitor.cpp src/behavior_detector.cpp src/response_engine.cpp -I include/ -o os_engine
```

## Running the Architecture

To see the system work end-to-end, you need three terminal windows:

### 1. Start the Python Backend
The Python backend listens for OS events, logs to the database, and processes FSM logic.
```bash
# Windows
python backend\main_backend.py

# Linux
python3 backend/main_backend.py
```

### 2. Start the SOC Dashboard
The Flask interface provides a real-time SOC-style overview.
```bash
# Windows
cd gui_dashboard
python app.py

# Linux
cd gui_dashboard
python3 app.py
```
Open your browser to: **[http://localhost:5000](http://localhost:5000)**

### 3. Start the OS Engine (Linux Only)
Monitors the system and feeds data to the backend via named pipe.
```bash
cd os_engine_cpp
sudo ./os_engine
```

## Running Attacks (Red Team)
Open a separate terminal to simulate attacks and trigger the Blue Team defense.
```bash
cd red_team_py
python attack_controller.py
```

Select any of the options (1-4).
- C++ engine (if running) will catch the malicious activity.
- Python Backend logs event ingestion and **FSM State Changes**.
- Browser SOC Dashboard will turn red, reflecting the `LOCKED` state.
- Response Engine will automatically terminate malicious processes.
