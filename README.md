# FalconStrix

**The Ultimate Linux Host Intrusion Detection Engine**

FalconStrix provides real-time, low-level process monitoring and automated threat response through a high-performance C++ engine and an intelligent Python backend. It bridges the Linux security gap by protecting infrastructure against modern, fileless adversaries and living-off-the-land techniques.

## Features

- **C++17 OS Engine**: Provides microsecond-level visibility into process creation, resource usage, and tree hierarchy by monitoring `/proc` without requiring complex kernel modifications or eBPF.
- **Python 3 FSM (Finite State Machine)**: Continuously ingests telemetry via fast IPC and intelligently evaluates behaviors to transition between `NORMAL`, `ELEVATED`, and `LOCKED` threat states.
- **Automated Mitigation**: When critical behavioral thresholds are breached, the FSM escalates and issues immediate `SIGKILL` commands to neutralize rogue processes.
- **Modern Web Dashboard**: Built with Flask and Socket.IO, pushing live process metrics and security alerts instantly to your browser.
- **Premium Marketing Pages**: A beautiful, responsive landing page highlighting the project's capabilities, integrated with **Clerk Authentication** for seamless onboarding.
- **MariaDB Storage**: Persistent database backend to store FSM state history, real-time alerts, process logs, and SOC operator activity.

## Technologies Used

✦ C++17 Engine ✦ Python 3 FSM ✦ MariaDB Storage ✦ Flask & WebSockets ✦ IPC Telemetry ✦ SIGKILL Defense ✦ Syscall Monitoring ✦ Clerk Authentication ✦ Zero-Trust Architecture ✦ Threat Hunting ✦ Incident Forensics ✦ Real-Time Dashboards ✦

## Setup & Installation

Please refer to [SETUP_KALI.md](SETUP_KALI.md) for detailed instructions on configuring the environment, installing dependencies, and running the FalconStrix multi-process architecture on Linux/Kali.

## Running the Application

1. Make sure your virtual environment is active.
2. Ensure you have your `.env` configured (including `CLERK_PUBLISHABLE_KEY` if you intend to use the authentication on the marketing site).
3. Start the application:
   ```bash
   ./run_all.sh
   ```
   Or to just start the dashboard:
   ```bash
   python gui_dashboard/app.py
   ```
4. Access the web interface at `http://127.0.0.1:5001`.

## License

MIT License
