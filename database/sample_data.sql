-- Sample reference data and demo user (run after schema.sql)
USE hidrs_db;

INSERT INTO Severity (code, label, numeric_level) VALUES
    ('INFO',    'Informational', 1),
    ('LOW',     'Low',           2),
    ('MEDIUM',  'Medium',        3),
    ('HIGH',    'High',          4),
    ('CRITICAL','Critical',      5);

INSERT INTO Users (username, host, role) VALUES
    ('system', 'localhost', 'system'),
    ('demo_user', 'kali-host', 'user'),
    ('svc_backup', 'kali-host', 'service');

INSERT INTO FSM_Current_State (id, state_name, last_reason, hardware_led) VALUES
    (1, 'NORMAL', 'Initial bootstrap', 'GREEN');
