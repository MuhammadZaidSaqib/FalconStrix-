CREATE DATABASE IF NOT EXISTS hidrs_db;
USE hidrs_db;

CREATE TABLE IF NOT EXISTS Users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    role VARCHAR(20) DEFAULT 'user',
    password_hash VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Processes (
    process_id INT AUTO_INCREMENT PRIMARY KEY,
    pid INT NOT NULL,
    process_name VARCHAR(255) NOT NULL,
    command_line TEXT,
    user_id INT,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS Events (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    description TEXT,
    source VARCHAR(50) NOT NULL,
    process_id INT,
    user_id INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (process_id) REFERENCES Processes(process_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS Severity (
    severity_id INT PRIMARY KEY,
    level_name VARCHAR(20) NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS Alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    severity_id INT NOT NULL,
    message TEXT NOT NULL,
    is_resolved BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES Events(event_id) ON DELETE CASCADE,
    FOREIGN KEY (severity_id) REFERENCES Severity(severity_id)
);

CREATE TABLE IF NOT EXISTS FSM_Current_State (
    state_id INT PRIMARY KEY DEFAULT 1,
    current_state VARCHAR(20) NOT NULL DEFAULT 'NORMAL',  -- NORMAL, WARNING, LOCKED
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS FSM_State_History (
    history_id INT AUTO_INCREMENT PRIMARY KEY,
    previous_state VARCHAR(20) NOT NULL,
    new_state VARCHAR(20) NOT NULL,
    reason TEXT NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Initialize the FSM State
INSERT IGNORE INTO FSM_Current_State (state_id, current_state) VALUES (1, 'NORMAL');
