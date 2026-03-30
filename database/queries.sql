USE hidrs_db;

-- 1. Get all unresolved alerts with their event details and severity
SELECT 
    a.alert_id,
    s.level_name AS severity,
    a.message,
    e.event_type,
    e.description AS event_description,
    p.process_name,
    u.username,
    a.timestamp
FROM Alerts a
JOIN Events e ON a.event_id = e.event_id
JOIN Severity s ON a.severity_id = s.severity_id
LEFT JOIN Processes p ON e.process_id = p.process_id
LEFT JOIN Users u ON e.user_id = u.user_id
WHERE a.is_resolved = FALSE
ORDER BY s.severity_id DESC, a.timestamp DESC;

-- 2. Count alerts by severity in the last 24 hours
SELECT 
    s.level_name,
    COUNT(a.alert_id) AS alert_count
FROM Alerts a
JOIN Severity s ON a.severity_id = s.severity_id
WHERE a.timestamp >= NOW() - INTERVAL 1 DAY
GROUP BY s.level_name;

-- 3. Review FSM State History
SELECT 
    previous_state,
    new_state,
    reason,
    changed_at
FROM FSM_State_History
ORDER BY changed_at DESC
LIMIT 10;

-- 4. Find potential process floods (processes grouped by name in recent events)
SELECT 
    p.process_name,
    COUNT(*) as execution_count
FROM Events e
JOIN Processes p ON e.process_id = p.process_id
WHERE e.event_type = 'PROCESS_CREATE'
  AND e.timestamp >= NOW() - INTERVAL 1 HOUR
GROUP BY p.process_name
HAVING execution_count > 10;
