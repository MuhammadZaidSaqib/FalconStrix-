USE hidrs_db;

-- Insert initial users
INSERT IGNORE INTO Users (username, role) VALUES 
('admin', 'administrator'),
('root', 'superuser'),
('testuser', 'user'),
('guest', 'guest');

-- Insert severity levels
INSERT IGNORE INTO Severity (severity_id, level_name, description) VALUES 
(1, 'LOW', 'Minor anomaly, typical noise'),
(2, 'MEDIUM', 'Suspicious activity, requires monitoring'),
(3, 'HIGH', 'Definite attack or serious policy violation'),
(4, 'CRITICAL', 'System compromise or locked state triggered');

-- Insert sample processes
INSERT IGNORE INTO Processes (pid, process_name, command_line, user_id) VALUES 
(1, 'systemd', '/sbin/init splash', 2),
(1024, 'bash', '/bin/bash', 3),
(2048, 'python3', 'python3 my_script.py', 3);

-- Insert sample events
INSERT IGNORE INTO Events (event_type, description, source, process_id, user_id) VALUES 
('LOGIN_SUCCESS', 'User logged in successfully', 'Auth', 1, 3),
('PROCESS_CREATE', 'New bash process created', 'OS_Engine', 2, 3),
('SUSPICIOUS_EXEC', 'Python script executing rapid file operations', 'OS_Engine', 3, 3);

-- Insert sample alerts
INSERT IGNORE INTO Alerts (event_id, severity_id, message) VALUES 
(3, 2, 'Rapid file operations detected from python3 process');

-- Insert sample FSM history
INSERT IGNORE INTO FSM_State_History (previous_state, new_state, reason) VALUES 
('NORMAL', 'WARNING', 'Multiple medium severity alerts detected');

-- ---------------------------------------------------------------------------
-- Extra dataset for Resolved Cases + Terminated Processes dashboard pages
-- ---------------------------------------------------------------------------

-- Additional demo processes
INSERT IGNORE INTO Processes (pid, process_name, command_line, user_id) VALUES
(3184, 'netcat.exe', 'nc -lvp 4444', 2),
(4550, 'powershell.exe', 'powershell -nop -w hidden -enc <redacted>', 1),
(6022, 'cmd.exe', 'cmd /c whoami', 4);

-- Detection events (these are linked to alerts)
INSERT INTO Events (event_type, description, source, process_id, user_id)
SELECT 'SUSPICIOUS_PROCESS', 'Reverse-shell listener behavior detected', 'OS_Engine', p.process_id, 2
FROM Processes p
WHERE p.pid = 3184
  AND NOT EXISTS (
    SELECT 1 FROM Events e
    WHERE e.event_type = 'SUSPICIOUS_PROCESS'
      AND e.description = 'Reverse-shell listener behavior detected'
  );

INSERT INTO Events (event_type, description, source, process_id, user_id)
SELECT 'PROCESS_SPIKE', 'Abnormal command spawn burst detected', 'OS_Engine', p.process_id, 1
FROM Processes p
WHERE p.pid = 4550
  AND NOT EXISTS (
    SELECT 1 FROM Events e
    WHERE e.event_type = 'PROCESS_SPIKE'
      AND e.description = 'Abnormal command spawn burst detected'
  );

-- Response / termination events (shown in Terminated Processes page)
INSERT INTO Events (event_type, description, source, process_id, user_id)
SELECT 'RESPONSE_ACTION', 'Active defense executed: kill(pid=3184)', 'SOC-Dashboard', p.process_id, 1
FROM Processes p
WHERE p.pid = 3184
  AND NOT EXISTS (
    SELECT 1 FROM Events e
    WHERE e.event_type = 'RESPONSE_ACTION'
      AND e.description = 'Active defense executed: kill(pid=3184)'
  );

INSERT INTO Events (event_type, description, source, process_id, user_id)
SELECT 'PROCESS_KILLED', 'User manually terminated suspicious process: powershell.exe (PID: 4550)', 'SOC-Dashboard', p.process_id, 1
FROM Processes p
WHERE p.pid = 4550
  AND NOT EXISTS (
    SELECT 1 FROM Events e
    WHERE e.event_type = 'PROCESS_KILLED'
      AND e.description = 'User manually terminated suspicious process: powershell.exe (PID: 4550)'
  );

-- Resolved alerts linked to the detection events above
INSERT INTO Alerts (event_id, severity_id, message, is_resolved)
SELECT e.event_id, 3, 'Reverse-shell process was contained and terminated', TRUE
FROM Events e
WHERE e.event_type = 'SUSPICIOUS_PROCESS'
  AND e.description = 'Reverse-shell listener behavior detected'
  AND NOT EXISTS (
    SELECT 1 FROM Alerts a
    WHERE a.event_id = e.event_id
      AND a.message = 'Reverse-shell process was contained and terminated'
  );

INSERT INTO Alerts (event_id, severity_id, message, is_resolved)
SELECT e.event_id, 2, 'Process burst investigated and remediated', TRUE
FROM Events e
WHERE e.event_type = 'PROCESS_SPIKE'
  AND e.description = 'Abnormal command spawn burst detected'
  AND NOT EXISTS (
    SELECT 1 FROM Alerts a
    WHERE a.event_id = e.event_id
      AND a.message = 'Process burst investigated and remediated'
  );
