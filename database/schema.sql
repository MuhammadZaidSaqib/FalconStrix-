-- HIDRS Hybrid Behavioral Monitoring — core schema (MySQL/MariaDB)
-- Run: mysql -u root -p < schema.sql

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

DROP DATABASE IF EXISTS hidrs_db;
CREATE DATABASE hidrs_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE hidrs_db;

-- ---------------------------------------------------------------------------
-- Reference: severity levels for alerts
-- ---------------------------------------------------------------------------
CREATE TABLE Severity (
    severity_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    code        VARCHAR(32)  NOT NULL,
    label       VARCHAR(64)  NOT NULL,
    numeric_level TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT '1=low ... 5=critical',
    PRIMARY KEY (severity_id),
    UNIQUE KEY uq_severity_code (code)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Users (logical actors / hosts); system user for non-user-bound events
-- ---------------------------------------------------------------------------
CREATE TABLE Users (
    user_id     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username    VARCHAR(128) NOT NULL,
    host        VARCHAR(255) NOT NULL DEFAULT 'localhost',
    role        VARCHAR(64)  NOT NULL DEFAULT 'user',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_users_username_host (username, host)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Events: raw observations from OS engine, red team injectors, responses
-- ---------------------------------------------------------------------------
CREATE TABLE Events (
    event_id    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     BIGINT UNSIGNED NULL COMMENT 'NULL for system-wide events',
    event_type  VARCHAR(64)  NOT NULL,
    source      VARCHAR(64)  NOT NULL COMMENT 'os_engine, red_team, fsm, response',
    description TEXT,
    payload     JSON NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (event_id),
    KEY idx_events_created (created_at),
    KEY idx_events_type (event_type),
    CONSTRAINT fk_events_user
        FOREIGN KEY (user_id) REFERENCES Users (user_id)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Alerts: correlated events with severity
-- ---------------------------------------------------------------------------
CREATE TABLE Alerts (
    alert_id    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    event_id    BIGINT UNSIGNED NOT NULL,
    severity_id INT UNSIGNED NOT NULL,
    title       VARCHAR(255) NOT NULL,
    details     TEXT,
    acknowledged TINYINT(1) NOT NULL DEFAULT 0,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (alert_id),
    KEY idx_alerts_created (created_at),
    CONSTRAINT fk_alerts_event
        FOREIGN KEY (event_id) REFERENCES Events (event_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_alerts_severity
        FOREIGN KEY (severity_id) REFERENCES Severity (severity_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- FSM: single current row + history (history links to optional alert)
-- ---------------------------------------------------------------------------
CREATE TABLE FSM_Current_State (
    id                  TINYINT UNSIGNED NOT NULL DEFAULT 1,
    state_name          ENUM('NORMAL','WARNING','LOCKED') NOT NULL DEFAULT 'NORMAL',
    last_reason         VARCHAR(512) NULL,
    hardware_led        ENUM('GREEN','YELLOW','RED') NOT NULL DEFAULT 'GREEN'
        COMMENT 'Conceptual LED mapping for DLD integration',
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB COMMENT 'Singleton row id must remain 1';

CREATE TABLE FSM_State_History (
    history_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    alert_id     BIGINT UNSIGNED NULL,
    from_state   ENUM('NORMAL','WARNING','LOCKED') NOT NULL,
    to_state     ENUM('NORMAL','WARNING','LOCKED') NOT NULL,
    reason       VARCHAR(512) NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (history_id),
    KEY idx_fsm_hist_created (created_at),
    CONSTRAINT fk_fsm_hist_alert
        FOREIGN KEY (alert_id) REFERENCES Alerts (alert_id)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Processes linked to originating detection event
-- ---------------------------------------------------------------------------
CREATE TABLE Processes (
    process_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    event_id     BIGINT UNSIGNED NOT NULL,
    pid          INT NOT NULL,
    process_name VARCHAR(255) NOT NULL,
    parent_pid   INT NULL,
    cmdline      VARCHAR(1024) NULL,
    detected_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (process_id),
    KEY idx_processes_pid (pid),
    CONSTRAINT fk_processes_event
        FOREIGN KEY (event_id) REFERENCES Events (event_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Response actions (Blue Team automated response audit trail)
-- ---------------------------------------------------------------------------
CREATE TABLE Response_Log (
    log_id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    event_id    BIGINT UNSIGNED NULL COMMENT 'Optional link to triggering event',
    action      VARCHAR(64)  NOT NULL,
    target_pid  INT NULL,
    detail      TEXT,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (log_id),
    KEY idx_response_created (created_at),
    CONSTRAINT fk_response_event
        FOREIGN KEY (event_id) REFERENCES Events (event_id)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

SET FOREIGN_KEY_CHECKS = 1;
