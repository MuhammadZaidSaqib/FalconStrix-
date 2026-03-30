-- Run once if Users table has no password_hash (dashboard login)
USE hidrs_db;
ALTER TABLE Users ADD COLUMN password_hash VARCHAR(255) NULL;
