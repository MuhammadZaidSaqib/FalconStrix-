USE hidrs_db;



INSERT INTO Events (event_type, description, source, process_id, user_id, timestamp)
WITH RECURSIVE seq AS (
  SELECT 0 AS n
  UNION ALL
  SELECT n + 1 FROM seq WHERE n < 83
),
series AS (
  SELECT
    DATE_SUB(CURRENT_DATE, INTERVAL n DAY) AS d,
    CASE
      WHEN MOD(n, 17) = 0 THEN 4
      WHEN MOD(n, 9) = 0 THEN 3
      WHEN MOD(n, 4) = 0 THEN 2
      ELSE 1
    END AS sev_id
  FROM seq
)
SELECT
  'TREND_SEED' AS event_type,
  CONCAT('Trend seed event ', DATE_FORMAT(s.d, '%Y-%m-%d')) AS description,
  'Backfill' AS source,
  NULL AS process_id,
  NULL AS user_id,
  TIMESTAMP(s.d, '10:00:00') AS timestamp
FROM series s
WHERE NOT EXISTS (
  SELECT 1
  FROM Events e
  WHERE e.event_type = 'TREND_SEED'
    AND e.description = CONCAT('Trend seed event ', DATE_FORMAT(s.d, '%Y-%m-%d'))
);

INSERT INTO Alerts (event_id, severity_id, message, is_resolved, timestamp)
SELECT
  e.event_id,
  CASE
    WHEN MOD(DAYOFYEAR(e.timestamp), 17) = 0 THEN 4
    WHEN MOD(DAYOFYEAR(e.timestamp), 9) = 0 THEN 3
    WHEN MOD(DAYOFYEAR(e.timestamp), 4) = 0 THEN 2
    ELSE 1
  END AS severity_id,
  CONCAT('Trend seed alert for ', e.description) AS message,
  CASE WHEN MOD(DAY(e.timestamp), 3) = 0 THEN TRUE ELSE FALSE END AS is_resolved,
  e.timestamp
FROM Events e
WHERE e.event_type = 'TREND_SEED'
  AND e.timestamp >= DATE_SUB(CURRENT_DATE, INTERVAL 84 DAY)
  AND NOT EXISTS (
    SELECT 1
    FROM Alerts a
    WHERE a.event_id = e.event_id
      AND a.message = CONCAT('Trend seed alert for ', e.description)
  );
