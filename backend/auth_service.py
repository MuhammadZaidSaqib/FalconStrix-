"""
Dashboard login: Users table + password hashes (Werkzeug).
Default admin password from env FALCON_ADMIN_PASSWORD or 'admin123'.
"""
import logging
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash

from db_connection import execute_query, fetch_query

DEFAULT_ADMIN = 'admin'
DEFAULT_PASSWORD_ENV = 'FALCON_ADMIN_PASSWORD'

# In-memory users when MySQL is unavailable (signup + login still work)
_mock_users_by_key = {}
_mock_next_user_id = 2


def _mock_users_init():
    global _mock_users_by_key
    if _mock_users_by_key:
        return
    ph = generate_password_hash(_default_password())
    _mock_users_by_key[DEFAULT_ADMIN.lower()] = {
        'user_id': 1,
        'username': DEFAULT_ADMIN,
        'role': 'admin',
        'password_hash': ph,
    }


def _mock_allocate_id():
    global _mock_next_user_id
    uid = _mock_next_user_id
    _mock_next_user_id += 1
    return uid


def _default_password():
    return os.environ.get(DEFAULT_PASSWORD_ENV, 'admin123')


def ensure_password_column():
    """Add password_hash to Users if missing (idempotent)."""
    row = fetch_query("SHOW COLUMNS FROM Users LIKE 'password_hash'", fetchall=False)
    if row:
        return
    try:
        execute_query("ALTER TABLE Users ADD COLUMN password_hash VARCHAR(255) NULL")
        logging.info("[auth] Added Users.password_hash column")
    except Exception as e:
        logging.error(f"[auth] Could not add password_hash: {e}")


def ensure_dashboard_accounts():
    """Create or upgrade admin account for SOC dashboard login."""
    ensure_password_column()
    admin = fetch_query(
        "SELECT user_id, username, password_hash FROM Users WHERE username = %s",
        (DEFAULT_ADMIN,),
        fetchall=False,
    )
    pwd = _default_password()
    ph = generate_password_hash(pwd)
    if not admin:
        execute_query(
            "INSERT INTO Users (username, role, password_hash) VALUES (%s, %s, %s)",
            (DEFAULT_ADMIN, 'admin', ph),
        )
        logging.info(f"[auth] Created dashboard user '{DEFAULT_ADMIN}' (set {DEFAULT_PASSWORD_ENV} to change password)")
        return
    if not admin.get('password_hash'):
        execute_query(
            "UPDATE Users SET password_hash = %s WHERE user_id = %s",
            (ph, admin['user_id']),
        )
        logging.info(f"[auth] Set password for '{DEFAULT_ADMIN}' (set {DEFAULT_PASSWORD_ENV} in production)")


def register_user(username, password, db_connected=True):
    """
    Create a dashboard account (role 'user'). Returns (user_dict, None) or (None, error_message).
    """
    username = (username or '').strip()
    if len(username) < 3 or len(username) > 32:
        return None, 'Username must be between 3 and 32 characters.'
    if not re.fullmatch(r'[\w.-]+', username, flags=re.ASCII):
        return None, 'Username may only use letters, numbers, underscore, hyphen, or dot.'
    if len(password or '') < 8:
        return None, 'Password must be at least 8 characters.'
    pw = str(password or '')
    uname_lower = username.lower()
    if uname_lower and uname_lower in pw.lower():
        return None, 'Password must not contain your username.'
    if not re.search(r'\d', pw):
        return None, 'Password must include at least one number.'
    if not re.search(r'[^A-Za-z0-9]', pw):
        return None, 'Password must include at least one symbol.'
    if username.lower() == DEFAULT_ADMIN.lower():
        return None, 'That username is reserved.'

    ph = generate_password_hash(pw)

    if db_connected:
        ensure_password_column()
        existing = fetch_query(
            "SELECT user_id FROM Users WHERE LOWER(username) = LOWER(%s)",
            (username,),
            fetchall=False,
        )
        if existing:
            return None, 'That username is already registered.'
        new_id = execute_query(
            "INSERT INTO Users (username, role, password_hash) VALUES (%s, %s, %s)",
            (username, 'user', ph),
        )
        if not new_id:
            return None, 'Could not create account. Try again.'
        return {'user_id': int(new_id), 'username': username, 'role': 'user'}, None

    _mock_users_init()
    key = username.lower()
    if key in _mock_users_by_key:
        return None, 'That username is already registered.'
    uid = _mock_allocate_id()
    _mock_users_by_key[key] = {
        'user_id': uid,
        'username': username,
        'role': 'user',
        'password_hash': ph,
    }
    return {'user_id': uid, 'username': username, 'role': 'user'}, None


def verify_login(username, password):
    """
    Returns dict with user_id, username, role or None (database only).
    """
    if not username or not password:
        return None
    row = fetch_query(
        """SELECT user_id, username, role, password_hash
           FROM Users WHERE username = %s""",
        (username.strip(),),
        fetchall=False,
    )
    if not row or not row.get('password_hash'):
        return None
    if check_password_hash(row['password_hash'], password):
        return {
            'user_id': row['user_id'],
            'username': row['username'],
            'role': row.get('role') or 'user',
        }
    return None


def verify_login_dashboard(username, password, db_connected=True):
    """Use DB when available; otherwise in-memory users (admin + signups)."""
    if db_connected:
        return verify_login(username, password)
    _mock_users_init()
    u = (username or '').strip()
    key = u.lower()
    row = _mock_users_by_key.get(key)
    if not row or not row.get('password_hash'):
        return None
    if check_password_hash(row['password_hash'], password):
        return {
            'user_id': row['user_id'],
            'username': row['username'],
            'role': row.get('role') or 'user',
        }
    return None


def check_username_availability(username, db_connected=True):
    """
    Returns tuple: (available: bool, message: str)
    """
    username = (username or '').strip()
    if len(username) < 3 or len(username) > 32:
        return False, 'Username must be between 3 and 32 characters.'
    if not re.fullmatch(r'[\w.-]+', username, flags=re.ASCII):
        return False, 'Only letters, numbers, underscore, hyphen, or dot allowed.'
    if username.lower() == DEFAULT_ADMIN.lower():
        return False, "Username 'admin' is reserved."

    if db_connected:
        existing = fetch_query(
            "SELECT user_id FROM Users WHERE LOWER(username) = LOWER(%s)",
            (username,),
            fetchall=False,
        )
        if existing:
            return False, 'Username is already taken.'
        return True, 'Username is available.'

    _mock_users_init()
    if username.lower() in _mock_users_by_key:
        return False, 'Username is already taken.'
    return True, 'Username is available.'
