-- Alert analysis and SOC-oriented queries (hidrs_db)

USE hidrs_db;

-- Recent alerts with severity and originating event
SELECT a.alert_id, a.title, a.created_at,
       s.code AS severity, s.numeric_level,
       e.event_type, e.source, e.description
FROM Alerts a
JOIN Severity s ON s.severity_id = a.severity_id
JOIN Events e ON e.event_id = a.event_id
ORDER BY a.created_at DESC
LIMIT 100;

-- Alert volume by severity (last 24h)
SELECT s.code, COUNT(*) AS cnt
FROM Alerts a
JOIN Severity s ON s.severity_id = a.severity_id
WHERE a.created_at >= NOW() - INTERVAL 1 DAY
GROUP BY s.code, s.severity_id
ORDER BY s.numeric_level DESC;

-- Suspicious process-related events
SELECT e.event_id, e.event_type, e.source, e.created_at, e.payload
FROM Events e
WHERE e.event_type IN ('PROCESS_SPIKE','SUSPICIOUS_PROCESS','PROCESS_ANOMALY')
   OR JSON_UNQUOTE(JSON_EXTRACT(e.payload, '$.type')) IN ('PROCESS_SPIKE','SUSPICIOUS_PROCESS')
ORDER BY e.created_at DESC
LIMIT 200;

-- FSM transition audit trail
SELECT h.history_id, h.from_state, h.to_state, h.reason, h.created_at,
       a.alert_id, a.title
FROM FSM_State_History h
LEFT JOIN Alerts a ON a.alert_id = h.alert_id
ORDER BY h.created_at DESC
LIMIT 100;

-- Current FSM + hardware mapping (conceptual LEDs)
SELECT state_name, hardware_led, last_reason, updated_at
FROM FSM_Current_State
WHERE id = 1;

-- Response actions after LOCKED / kill operations
SELECT r.log_id, r.action, r.target_pid, r.detail, r.created_at, e.event_type
FROM Response_Log r
LEFT JOIN Events e ON e.event_id = r.event_id
ORDER BY r.created_at DESC
LIMIT 100;
