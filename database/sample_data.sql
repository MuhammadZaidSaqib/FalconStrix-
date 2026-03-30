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
