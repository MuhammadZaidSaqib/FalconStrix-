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

-- 5. Resolved Cases audit view (what/when/how + process metadata)
SELECT
    a.alert_id,
    s.level_name AS severity,
    e.event_type AS trigger_event,
    a.timestamp AS detected_at,
    p.process_name,
    p.pid,
    p.start_time AS process_created_at,
    (
        SELECT re.timestamp
        FROM Events re
        WHERE re.event_type IN ('RESPONSE_ACTION', 'PROCESS_KILLED')
          AND (
            (e.process_id IS NOT NULL AND re.process_id = e.process_id)
            OR (re.description LIKE CONCAT('%%PID: ', p.pid, '%%'))
            OR (re.description LIKE CONCAT('%%pid=', p.pid, '%%'))
          )
        ORDER BY re.timestamp DESC
        LIMIT 1
    ) AS resolved_at,
    (
        SELECT re.description
        FROM Events re
        WHERE re.event_type IN ('RESPONSE_ACTION', 'PROCESS_KILLED')
          AND (
            (e.process_id IS NOT NULL AND re.process_id = e.process_id)
            OR (re.description LIKE CONCAT('%%PID: ', p.pid, '%%'))
            OR (re.description LIKE CONCAT('%%pid=', p.pid, '%%'))
          )
        ORDER BY re.timestamp DESC
        LIMIT 1
    ) AS resolution_detail
FROM Alerts a
JOIN Severity s ON s.severity_id = a.severity_id
JOIN Events e ON e.event_id = a.event_id
LEFT JOIN Processes p ON p.process_id = e.process_id
WHERE a.is_resolved = TRUE
ORDER BY a.timestamp DESC
LIMIT 250;

-- 6. Terminated Processes audit view (who/when/action/process created)
SELECT
    e.timestamp AS terminated_at,
    COALESCE(NULLIF(TRIM(u.username), ''), 'system') AS terminated_by,
    e.event_type AS action_type,
    p.process_name,
    p.pid,
    p.start_time AS process_created_at,
    e.source,
    COALESCE(NULLIF(TRIM(e.description), ''), 'Process termination event') AS details
FROM Events e
LEFT JOIN Users u ON u.user_id = e.user_id
LEFT JOIN Processes p ON p.process_id = e.process_id
WHERE e.event_type IN ('PROCESS_KILLED', 'RESPONSE_ACTION')
ORDER BY e.timestamp DESC
LIMIT 250;
