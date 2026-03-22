# HIDRS — project task checklist (build order)

Use this as the master to-do list for the prototype.

## Database

- [ ] Generate `database/schema.sql` (tables, FKs, `Response_Log`, FSM + LED mapping).
- [ ] Load schema: `sudo mysql < database/schema.sql`
- [ ] Generate `database/sample_data.sql` — run: `mysql hidrs_db < database/sample_data.sql`
- [ ] Create DB user and grants (see README).
- [ ] Review `database/queries.sql` in any SQL client.

## Backend (Python)

- [ ] Generate `backend/db_connection.py`
- [ ] Generate `backend/event_service.py`
- [ ] Generate `backend/alert_service.py`
- [ ] Generate `backend/process_service.py`
- [ ] Generate `backend/fsm_service.py` (NORMAL → WARNING → LOCKED, LED mapping)
- [ ] Generate `backend/main_backend.py` (FIFO → DB → FSM → command FIFO)

## Red team (Python)

- [ ] `red_team_py/login_simulator.py`
- [ ] `red_team_py/process_flood.py`
- [ ] `red_team_py/file_tamper_simulator.py`
- [ ] `red_team_py/attack_controller.py`

## Blue team OS engine (C++ / Kali)

- [ ] Write `os_engine_cpp/include/*.h`
- [ ] Write `process_monitor.cpp` (/proc, suspicious comm)
- [ ] Write `behavior_detector.cpp` (spike, auth sim log, canary file)
- [ ] Write `response_engine.cpp` (SIGTERM + RESPONSE_ACTION JSONL)
- [ ] Write `main.cpp` (fork, pthreads, mutex-protected FIFO writer)
- [ ] Build: `cmake -S . -B build && cmake --build build`

## Named pipes

- [ ] Start `main_backend.py` first (creates `/tmp/hidrs_events.fifo` and `/tmp/hidrs_cmd.fifo`).
- [ ] Start `hidrs_os_engine` (opens events FIFO for write).
- [ ] Confirm JSON lines appear in DB (`Events` table).

## FSM & response

- [ ] Run red-team `full` sequence; verify `FSM_Current_State` moves toward WARNING/LOCKED.
- [ ] On LOCKED, verify backend writes `RESPOND_LOCKED` to cmd FIFO and C++ emits `RESPONSE_ACTION`.

## SOC dashboard

- [ ] Build Flask SOC dashboard (`gui_dashboard/app.py`)
- [ ] Verify Chart.js graph + Socket.IO updates
- [ ] Confirm LOCKED turns UI red and shows defensive banner

## Hardware (conceptual)

- [ ] Map FSM → `hardware_led` (GREEN/YELLOW/RED) in DB and dashboard LED strip.

## Done when

Red Team → OS engine detects / co-injects → Events/Alerts in DB → FSM escalates → Dashboard live → LOCKED triggers response path.
