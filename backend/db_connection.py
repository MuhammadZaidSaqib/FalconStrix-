"""
MySQL/MariaDB connection helper for HIDRS backend.
Uses environment variables for deployment on Kali without hard-coded secrets.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

import mysql.connector
from mysql.connector import MySQLConnection


def _env_str(key: str, default: str) -> str:
    v = os.environ.get(key)
    if v is None or not str(v).strip():
        return default
    return str(v).strip()


def get_db_config() -> Dict[str, Any]:
    return {
        "host": _env_str("MYSQL_HOST", "127.0.0.1"),
        "port": int(_env_str("MYSQL_PORT", "3306")),
        "user": _env_str("MYSQL_USER", "hidrs"),
        "password": _env_str("MYSQL_PASSWORD", "hidrs_secret"),
        "database": _env_str("MYSQL_DATABASE", "hidrs_db"),
        "autocommit": True,
        "charset": "utf8mb4",
        "use_unicode": True,
    }


@contextmanager
def get_connection() -> Iterator[MySQLConnection]:
    cfg = get_db_config()
    conn = mysql.connector.connect(**cfg)
    try:
        yield conn
    finally:
        conn.close()


def execute(
    sql: str,
    params: Optional[tuple] = None,
    fetch_one: bool = False,
    fetch_all: bool = False,
):
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params or ())
        if fetch_one:
            row = cur.fetchone()
            cur.close()
            return row
        if fetch_all:
            rows = cur.fetchall()
            cur.close()
            return rows
        last_id = cur.lastrowid
        cur.close()
        return last_id
