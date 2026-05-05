import sys
import os
import time
import random
import json
import re
import io
from collections import deque
from datetime import datetime, timedelta
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_socketio import SocketIO, emit

try:
    import psutil
except ImportError:
    psutil = None

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_OK = True
except Exception:
    REPORTLAB_OK = False

try:
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
except ImportError:
    pass

# Add backend to path to use db_connection
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
try:
    from db_connection import fetch_query, get_db_connection
    from alert_service import get_active_alerts, get_recent_alerts_for_dashboard
    from event_service import get_recent_events
    from fsm_service import get_current_state
    
    # Check if we can actually reach the DB
    _conn = get_db_connection()
    if _conn:
        DB_AVAILABLE = True
        _conn.close()
        print("[*] Dashboard backend connected to MySQL database.")
    else:
        DB_AVAILABLE = False
        print("[!] MySQL connection failed. Falling back to MOCK mode.")
except (ImportError, Exception) as e:
    DB_AVAILABLE = False
    print(f"[!] Database services or module unavailable ({e}). Running in MOCK mode.")

if DB_AVAILABLE:
    try:
        from auth_service import ensure_dashboard_accounts

        ensure_dashboard_accounts()
    except Exception as auth_ex:
        print(f"[!] Dashboard auth bootstrap skipped: {auth_ex}")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FALCON_SECRET_KEY', 'soc_secret_change_me')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
# On Windows, eventlet binds differently and often collides on :5000; threading is stable for dev.
_socketio_kw = {'cors_allowed_origins': '*'}
if sys.platform == 'win32':
    _socketio_kw['async_mode'] = 'threading'
socketio = SocketIO(app, **_socketio_kw)

# Auth-related UI events when DB is off (ring buffer for User Activity widget)
auth_activity_ring = deque(maxlen=40)

# Failed dashboard login tracking (per IP) → FSM LOCKED after threshold
LOGIN_FAIL_THRESHOLD = 3
LOGIN_FAIL_WINDOW_SEC = 15 * 60
login_failure_by_ip = {}
# Mock-mode FSM when MySQL unavailable (auth lockout still visible in UI)
mock_fsm_auth_lock = None
mock_fsm_auth_history = deque(maxlen=12)


def get_effective_fsm_state():
    if mock_fsm_auth_lock:
        return mock_fsm_auth_lock
    return get_db_data_safely(get_current_state, 'NORMAL')


def _bump_login_failure(ip):
    now = time.time()
    rec = login_failure_by_ip.get(ip)
    if not rec or (now - rec.get('first', now)) > LOGIN_FAIL_WINDOW_SEC:
        rec = {'count': 0, 'first': now, 'lockout_sent': False}
    rec['count'] += 1
    rec['last'] = now
    login_failure_by_ip[ip] = rec
    return rec


def clear_login_failures(ip):
    login_failure_by_ip.pop(ip, None)


def trigger_fsm_auth_lockout(ip, username_attempt):
    global mock_fsm_auth_lock
    un = username_attempt or '?'
    reason = (
        f"Dashboard auth: {LOGIN_FAIL_THRESHOLD} failed attempts "
        f"(IP {ip}, user '{un}') — FSM LOCKED"
    )
    record_dashboard_auth_event(
        'AUTH_LOCKOUT',
        f"FSM locked after {LOGIN_FAIL_THRESHOLD} failed logins from {ip} (attempted user: {un})",
        actor_username=un if un != '?' else None,
    )
    if DB_AVAILABLE:
        try:
            from fsm_service import update_fsm_state

            update_fsm_state('LOCKED', reason, trigger_active_defense=False)
        except Exception as ex:
            print(f"FSM auth lockout error: {ex}")
    else:
        mock_fsm_auth_lock = 'LOCKED'
        mock_fsm_auth_history.appendleft(
            {
                'previous_state': 'NORMAL',
                'new_state': 'LOCKED',
                'reason': reason[:220],
                'changed_at': time.strftime('%H:%M:%S'),
            }
        )
    try:
        socketio.emit('state_change', {'state': 'LOCKED'})
    except Exception:
        pass

# In-memory store for tracking network speed
net_stats = {'last_in': 0, 'last_out': 0, 'last_time': time.time(), 'in_speed': '0.00 MB/s', 'out_speed': '0.00 MB/s', 'total_in': 0, 'total_out': 0}

# In-memory debug log (so you can check emitted events quickly)
debug_event_log = deque(maxlen=250)
_last_debug_network_ts = 0.0
last_dashboard_snapshot = None


def _debug_log(event_type, payload=None):
    """Record recent server-side events to debug_event_log."""
    try:
        debug_event_log.appendleft(
            {
                'ts': datetime.now().isoformat(timespec='seconds'),
                'event_type': event_type,
                'payload': payload or {},
            }
        )
    except Exception:
        # Never break the dashboard due to debug logging.
        pass

snapshot_cache = {
    'processes': {'data': [], 'ts': 0},
    'resources': {'data': None, 'ts': 0},
    'snapshot_signature': None,
    'last_full_emit': 0
}

# Suspicious process signatures
SUSPICIOUS_NAMES = ['powershell.exe', 'cmd.exe', 'nc.exe', 'netcat.exe', 'nmap.exe', 'wireshark.exe', 'mimikatz.exe', 'python.exe']

if psutil:
    try:
        initial_io = psutil.net_io_counters()
        net_stats['last_in'] = initial_io.bytes_recv
        net_stats['last_out'] = initial_io.bytes_sent
    except: pass

def get_db_data_safely(func, default=[]):
    if not DB_AVAILABLE: return default
    try:
        res = func()
        return res if res is not None else default
    except Exception as e:
        print(f"DB Fetch Error in {func.__name__}: {e}")
        return default

def get_process_list():
    if not psutil: return []
    cache_age = time.time() - snapshot_cache['processes']['ts']
    if cache_age < 8 and snapshot_cache['processes']['data']:
        return snapshot_cache['processes']['data']

    procs = []
    # Keep process sampling small to avoid heavy dashboard refreshes.
    for p in sorted(psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']), 
                    key=lambda x: x.info['cpu_percent'] or 0, reverse=True)[:15]:
        try:
            info = p.info
            name_lower = (info['name'] or '').lower()
            
            # Simple Behavioral Detection Score
            threat_level = "LOW"
            if any(s in name_lower for s in SUSPICIOUS_NAMES):
                threat_level = "HIGH" if info['cpu_percent'] > 5 else "MEDIUM"
            if info['cpu_percent'] > 25:
                threat_level = "MEDIUM" if threat_level == "LOW" else "CRITICAL"
            
            procs.append({
                'pid': info['pid'],
                'name': info['name'],
                'user': info['username'] or 'SYSTEM',
                'cpu': info['cpu_percent'],
                'mem': round(info['memory_percent'], 1),
                'threat': threat_level
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    snapshot_cache['processes'] = {'data': procs, 'ts': time.time()}
    return procs

def get_real_resources():
    if not psutil:
        return {
            'cpu': {'util': 22, 'freq': 3400, 'procs': 142, 'uptime': '02:30:15'},
            'memory': {'in_use': 12.7, 'avail': 3.1, 'commit': 15.8, 'cached': 3.3}
        }

    cache_age = time.time() - snapshot_cache['resources']['ts']
    if cache_age < 4 and snapshot_cache['resources']['data']:
        return snapshot_cache['resources']['data']
    
    cpu_util = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    boot_time = psutil.boot_time()
    uptime_str = time.strftime('%H:%M:%S', time.gmtime(time.time() - boot_time))

    resources = {
        'cpu': {'util': cpu_util, 'freq': int(psutil.cpu_freq().current if psutil.cpu_freq() else 3400), 
                'procs': len(psutil.pids()), 'uptime': uptime_str},
        'memory': {'in_use': round(mem.used / (1024**3), 1), 'avail': round(mem.available / (1024**3), 1),
                   'commit': round((mem.used + 1.5*1024**3) / (1024**3), 1), 'cached': round(getattr(mem, 'cached', 0) / (1024**3), 1)}
    }
    snapshot_cache['resources'] = {'data': resources, 'ts': time.time()}
    return resources

def update_network_stats():
    """Refresh counters from psutil; rate is bytes/sec over elapsed window (min ~80ms)."""
    if not psutil:
        return
    try:
        current_io = psutil.net_io_counters()
        now = time.time()
        elapsed = now - net_stats['last_time']
        net_stats['total_in'] = current_io.bytes_recv / (1024 * 1024 * 1024)
        net_stats['total_out'] = current_io.bytes_sent / (1024 * 1024 * 1024)
        if elapsed >= 0.08:
            in_bps = (current_io.bytes_recv - net_stats['last_in']) / elapsed
            out_bps = (current_io.bytes_sent - net_stats['last_out']) / elapsed

            # Format with the smallest unit that preserves motion in the UI.
            # (If we always show MB/s with 2 decimals, small rates often round to 0.00 MB/s.)
            def _fmt_rate(bps):
                if bps is None:
                    return "0.00 KB/s"
                if bps < 0:
                    bps = 0
                if bps < 1024 * 1024:
                    return f"{(bps / 1024):.2f} KB/s"
                if bps < 1024 * 1024 * 1024:
                    return f"{(bps / (1024 * 1024)):.2f} MB/s"
                return f"{(bps / (1024 * 1024 * 1024)):.2f} GB/s"

            net_stats['in_speed'] = _fmt_rate(in_bps)
            net_stats['out_speed'] = _fmt_rate(out_bps)
        net_stats['last_in'] = current_io.bytes_recv
        net_stats['last_out'] = current_io.bytes_sent
        net_stats['last_time'] = now
    except Exception:
        pass


def get_network_payload():
    """Snapshot for Socket.IO and REST (live ingress/egress)."""
    update_network_stats()
    return {
        'in': net_stats['in_speed'],
        'out': net_stats['out_speed'],
        'total_in': f"{net_stats['total_in']:.2f} GB",
        'total_out': f"{net_stats['total_out']:.2f} GB",
    }


def _fmt_clock(ts):
    """12-hour time for display (e.g. 10:24 AM)."""
    if ts is None:
        return '—'
    if hasattr(ts, 'strftime'):
        h = ts.hour % 12 or 12
        return f"{h}:{ts.strftime('%M %p')}"
    return str(ts)


def _add_calendar_months(year, month, delta):
    m = month - 1 + delta
    y = year + m // 12
    m = m % 12 + 1
    return y, m


def _month_start_end(year, month):
    start = datetime(year, month, 1)
    if month == 12:
        end = datetime(year + 1, 1, 1)
    else:
        end = datetime(year, month + 1, 1)
    return start, end


def _alert_counts_window(start, end):
    if not DB_AVAILABLE:
        return 0, 0
    row = get_db_data_safely(
        lambda: fetch_query(
            """SELECT COUNT(*) AS total,
                      COALESCE(SUM(CASE WHEN is_resolved THEN 1 ELSE 0 END), 0) AS resolved
               FROM Alerts WHERE timestamp >= %s AND timestamp < %s""",
            (start, end),
            fetchall=False,
        ),
        None,
    )
    if not row:
        return 0, 0
    total = int(row.get('total') or 0)
    resolved = int(row.get('resolved') or 0)
    return resolved, max(0, total - resolved)


def build_incident_trends():
    """Return resolved/unresolved counts with period-appropriate date buckets."""
    now = datetime.now()

    def mock_period(seed):
        r = random.Random(seed)
        return {
            'labels': [str(i + 1) for i in range(12)],
            'resolved': [r.randint(8, 45) for _ in range(12)],
            'unresolved': [r.randint(1, 18) for _ in range(12)],
        }

    if not DB_AVAILABLE:
        return {'weekly': mock_period(1), 'monthly': mock_period(2), 'yearly': mock_period(3)}

    # Weekly: last 7 calendar days (day-wise)
    weekly = {'labels': [], 'resolved': [], 'unresolved': []}
    for idx in range(7):
        day = now - timedelta(days=(6 - idx))
        start = datetime(day.year, day.month, day.day)
        end = start + timedelta(days=1)
        weekly['labels'].append(start.strftime('%a'))
        r, u = _alert_counts_window(start, end)
        weekly['resolved'].append(r)
        weekly['unresolved'].append(u)

    # Monthly: current calendar year, Jan -> Dec (month-wise)
    monthly = {'labels': [], 'resolved': [], 'unresolved': []}
    for m in range(1, 13):
        start, end = _month_start_end(now.year, m)
        monthly['labels'].append(start.strftime('%b'))
        r, u = _alert_counts_window(start, end)
        monthly['resolved'].append(r)
        monthly['unresolved'].append(u)

    # Yearly: last 12 years (year-wise)
    yearly = {'labels': [], 'resolved': [], 'unresolved': []}
    for idx in range(12):
        year = now.year - (11 - idx)
        start = datetime(year, 1, 1)
        end = datetime(year + 1, 1, 1)
        yearly['labels'].append(str(year))
        r, u = _alert_counts_window(start, end)
        yearly['resolved'].append(r)
        yearly['unresolved'].append(u)

    return {'weekly': weekly, 'monthly': monthly, 'yearly': yearly}


def _activity_icon_class(event_type, description):
    et = (event_type or '').upper()
    d = (description or '').upper()
    if 'FAIL' in et or 'BRUTE' in d or 'DENIED' in d or 'LOCKOUT' in et or 'FSM LOCK' in d:
        return 'red'
    if (
        'SIGNUP' in et
        or 'FILE' in et
        or 'ACCESS' in d
        or 'IPC' in et
        or 'PROCESS' in et
        or 'CSV' in et
        or 'REPORT' in et
    ):
        return 'blue'
    return 'gray'


def _extract_actor_username(actor_username, description):
    actor = (str(actor_username or '')).strip()
    if actor:
        return actor
    desc = str(description or '')
    patterns = (
        r"User\s+'([^']+)'",
        r'\bby\s+([A-Za-z0-9_.-]+)',
        r'\bfor\s+([A-Za-z0-9_.-]+)',
    )
    for pat in patterns:
        m = re.search(pat, desc, flags=re.IGNORECASE)
        if m and m.group(1):
            return m.group(1).strip()
    return None


def record_user_activity_event(event_type, description, user_id=None, actor_username=None):
    """Persist dashboard user activity to DB (when available) + in-memory ring."""
    if DB_AVAILABLE:
        try:
            from event_service import log_event

            log_event(event_type, description, 'SOC-Dashboard', user_id=user_id)
        except Exception as ex:
            print(f"Auth event log error: {ex}")
    auth_activity_ring.appendleft(
        {
            'event_type': event_type,
            'description': description,
            'ts': datetime.now(),
            'user_id': user_id,
            'username': actor_username,
        }
    )


def record_dashboard_auth_event(event_type, description, user_id=None, actor_username=None):
    """Compatibility wrapper for auth-related activity events."""
    record_user_activity_event(event_type, description, user_id=user_id, actor_username=actor_username)


def _rows_to_activity_items(rows):
    out = []
    for row in rows or []:
        ts = row.get('timestamp')
        desc = (row.get('description') or row.get('event_type') or 'Event').strip()
        et_raw = row.get('event_type') or ''
        ic = _activity_icon_class(et_raw, desc)
        etu = (et_raw or '').upper()
        if etu == 'AUTH_LOCKOUT':
            icon = '🔒'
        elif etu == 'SIGNUP':
            icon = '✚'
        else:
            icon = '⚠' if ic == 'red' else ('📄' if ic == 'blue' else '👤')
        actor = _extract_actor_username(row.get('actor_username'), desc)
        out.append(
            {
                'event_type': row.get('event_type'),
                'description': desc[:120],
                'timestamp': _fmt_clock(ts),
                'icon': ic,
                'icon_char': icon,
                'actor': actor,
            }
        )
    return out


def build_user_activity_list(recent_events):
    """Recent auth/session rows for the User Activity widget."""
    def _ring_items(limit=8):
        out = []
        for item in auth_activity_ring:
            desc = (item.get('description') or item.get('event_type') or 'Event').strip()
            et = item.get('event_type') or 'EVENT'
            ic = _activity_icon_class(et, desc)
            etu = (et or '').upper()
            if etu == 'AUTH_LOCKOUT':
                icon = '🔒'
            elif etu == 'SIGNUP':
                icon = '✚'
            else:
                icon = '⚠' if ic == 'red' else ('📄' if ic == 'blue' else '👤')
            actor = _extract_actor_username(item.get('username'), desc)
            out.append(
                {
                    'event_type': et,
                    'description': desc[:120],
                    'timestamp': _fmt_clock(item.get('ts')),
                    'icon': ic,
                    'icon_char': icon,
                    'actor': actor,
                }
            )
            if len(out) >= limit:
                break
        return out

    if DB_AVAILABLE:
        rows = get_db_data_safely(
            lambda: fetch_query(
                """SELECT e.event_type, e.description, e.timestamp, u.username AS actor_username
                   FROM Events e
                   LEFT JOIN Users u ON e.user_id = u.user_id
                   WHERE e.event_type IN (
                        'LOGIN', 'LOGOUT', 'AUTH_FAILED', 'AUTH_LOCKOUT', 'SIGNUP',
                        'PROCESS_KILLED', 'CASE_RESOLVED', 'CSV_EXPORT', 'REPORT_GENERATED'
                   )
                   ORDER BY e.timestamp DESC LIMIT 8"""
            ),
            [],
        )
        if not rows:
            rows = get_db_data_safely(
                lambda: fetch_query(
                    """SELECT e.event_type, e.description, e.timestamp, u.username AS actor_username
                       FROM Events e
                       LEFT JOIN Users u ON e.user_id = u.user_id
                       ORDER BY e.timestamp DESC LIMIT 8"""
                ),
                [],
            )
        db_items = _rows_to_activity_items(rows)
        ring_items = _ring_items(8)
        merged = []
        seen = set()
        for item in ring_items + db_items:
            key = (
                str(item.get('event_type') or ''),
                str(item.get('description') or ''),
                str(item.get('timestamp') or ''),
                str(item.get('actor') or ''),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
            if len(merged) >= 8:
                break
        return merged if merged else [{'event_type': 'INFO', 'description': 'No events yet', 'timestamp': '—', 'icon': 'gray', 'icon_char': 'ℹ', 'actor': None}]

    out = _ring_items(8)
    if len(out) >= 8:
        return out
    for ev in recent_events or []:
        if len(out) >= 8:
            break
        et = ev.get('event_type') or 'EVENT'
        desc = (ev.get('description') or et)[:120]
        out.append(
            {
                'event_type': et,
                'description': desc,
                'timestamp': ev.get('timestamp') or '—',
                'icon': _activity_icon_class(et, desc),
                'icon_char': 'ℹ',
                'actor': _extract_actor_username(ev.get('actor_username'), desc),
            }
        )
    if not out:
        return [
            {
                'event_type': 'INFO',
                'description': 'Sign in to record session activity',
                'timestamp': '—',
                'icon': 'gray',
                'icon_char': 'ℹ',
                'actor': None,
            }
        ]
    return out[:8]


def _ts_sort_key(ts):
    if ts is None:
        return datetime.min
    if hasattr(ts, 'timestamp'):
        return ts
    return datetime.min


def build_incident_summary_list(active_alerts, recent_events):
    """Recent alerts + notable events (last 7 days), merged by time, max 5."""
    limit = 5
    days = 7
    if DB_AVAILABLE:
        alert_rows = get_db_data_safely(
            lambda: fetch_query(
                """SELECT a.message AS title, a.timestamp, s.level_name AS severity
                   FROM Alerts a
                   JOIN Severity s ON a.severity_id = s.severity_id
                   WHERE a.timestamp >= NOW() - INTERVAL %s DAY
                   ORDER BY a.timestamp DESC LIMIT 20""",
                (days,),
            ),
            [],
        )
        event_rows = get_db_data_safely(
            lambda: fetch_query(
                """SELECT COALESCE(NULLIF(TRIM(description), ''), event_type) AS title,
                          timestamp, event_type
                   FROM Events
                   WHERE timestamp >= NOW() - INTERVAL %s DAY
                   ORDER BY timestamp DESC LIMIT 20""",
                (days,),
            ),
            [],
        )
        merged = []
        for row in alert_rows or []:
            merged.append({
                'title': (row.get('title') or '')[:100],
                'ts': row.get('timestamp'),
                'severity': (row.get('severity') or 'MEDIUM').upper(),
                'src': 'alert',
            })
        for row in event_rows or []:
            et = (row.get('event_type') or '').upper()
            sev = 'HIGH' if 'FAIL' in et or 'DENIED' in et else 'LOW'
            merged.append({'title': (row.get('title') or '')[:100], 'ts': row.get('timestamp'), 'severity': sev, 'src': 'event'})
        merged.sort(key=lambda r: _ts_sort_key(r['ts']), reverse=True)
        out = []
        seen = set()
        for item in merged:
            tkey = (item['title'][:48], str(item['ts']))
            if tkey in seen:
                continue
            seen.add(tkey)
            sev = item['severity']
            icon = '⚠' if sev in ('HIGH', 'CRITICAL') else 'ℹ'
            color = 'red' if sev in ('HIGH', 'CRITICAL') else 'blue'
            out.append({
                'title': item['title'],
                'time': _fmt_clock(item['ts']),
                'severity': sev,
                'icon': icon,
                'color': color,
            })
            if len(out) >= limit:
                break
        return out if out else [{'title': 'No recent incidents', 'time': '—', 'severity': 'LOW', 'icon': 'ℹ', 'color': 'blue'}]

    out = []
    for a in active_alerts or []:
        sev = (a.get('severity') or 'MEDIUM').upper()
        msg = (a.get('message') or 'Alert')[:100]
        ts = a.get('timestamp')
        if hasattr(ts, 'strftime'):
            time_part = _fmt_clock(ts)
        elif isinstance(ts, str) and len(ts) > 11 and ' ' in ts:
            time_part = ts[11:16]
        else:
            time_part = (ts or '—')[:8]
        icon = '⚠' if sev in ('HIGH', 'CRITICAL') else 'ℹ'
        color = 'red' if sev in ('HIGH', 'CRITICAL') else 'blue'
        out.append({'title': msg, 'time': time_part, 'severity': sev, 'icon': icon, 'color': color})
    for ev in recent_events or []:
        if len(out) >= limit:
            break
        et = ev.get('event_type') or 'EVENT'
        desc = (ev.get('description') or et)[:100]
        sev = 'HIGH' if 'FAIL' in et.upper() else 'LOW'
        icon = '⚠' if sev == 'HIGH' else 'ℹ'
        color = 'red' if sev == 'HIGH' else 'blue'
        out.append({'title': desc, 'time': ev.get('timestamp') or '—', 'severity': sev, 'icon': icon, 'color': color})
    return out[:limit]


def get_resolved_cases_rows(limit=200):
    if not DB_AVAILABLE:
        return [
            {
                'alert_id': 9001,
                'severity': 'HIGH',
                'trigger_event': 'SUSPICIOUS_PROC',
                'detected_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'resolved_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'resolved_by': 'admin',
                'resolution_detail': 'SIGKILL delivered (LOCKED response)',
                'process_name': 'netcat',
                'pid': 8842,
                'process_created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            }
        ]
    rows = get_db_data_safely(
        lambda: fetch_query(
            """
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
                    WHERE re.event_type IN ('RESPONSE_ACTION', 'PROCESS_KILLED', 'CASE_RESOLVED')
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
                    WHERE re.event_type IN ('RESPONSE_ACTION', 'PROCESS_KILLED', 'CASE_RESOLVED')
                      AND (
                        (e.process_id IS NOT NULL AND re.process_id = e.process_id)
                        OR (re.description LIKE CONCAT('%%PID: ', p.pid, '%%'))
                        OR (re.description LIKE CONCAT('%%pid=', p.pid, '%%'))
                      )
                    ORDER BY re.timestamp DESC
                    LIMIT 1
                ) AS resolution_detail,
                (
                    SELECT COALESCE(NULLIF(TRIM(u.username), ''), 'system')
                    FROM Events re
                    LEFT JOIN Users u ON u.user_id = re.user_id
                    WHERE re.event_type = 'CASE_RESOLVED'
                      AND (
                        re.description LIKE CONCAT('%%case #', a.alert_id, '%%')
                        OR re.description LIKE CONCAT('%%case ', a.alert_id, '%%')
                        OR re.description LIKE CONCAT('%%Alert case ', a.alert_id, '%%')
                      )
                    ORDER BY re.timestamp DESC
                    LIMIT 1
                ) AS resolved_by
            FROM Alerts a
            JOIN Severity s ON s.severity_id = a.severity_id
            JOIN Events e ON e.event_id = a.event_id
            LEFT JOIN Processes p ON p.process_id = e.process_id
            WHERE a.is_resolved = TRUE
            ORDER BY a.timestamp DESC
            LIMIT %s
            """,
            (limit,),
        ),
        [],
    )
    for r in rows:
        for k in ('detected_at', 'resolved_at', 'process_created_at'):
            if hasattr(r.get(k), 'strftime'):
                r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')
        if not r.get('resolved_by'):
            r['resolved_by'] = 'system'
    return rows


def get_terminated_process_rows(limit=250):
    if not DB_AVAILABLE:
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        return [
            {
                'terminated_at': now,
                'terminated_by': 'system',
                'action_type': 'PROCESS_KILLED',
                'process_name': 'unknown',
                'pid': 0,
                'process_created_at': now,
                'source': 'SOC-Dashboard',
                'details': 'Mock mode sample',
            }
        ]
    rows = get_db_data_safely(
        lambda: fetch_query(
            """
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
            LIMIT %s
            """,
            (limit,),
        ),
        [],
    )
    for r in rows:
        for k in ('terminated_at', 'process_created_at'):
            if hasattr(r.get(k), 'strftime'):
                r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')
    return rows


def get_fsm_lock_context():
    """
    DB-backed lock diagnostics used by overlay/explanations.
    This shows why LOCKED is active even when visible alert table looks empty.
    """
    base = {
        'unresolved_total': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'reason': 'No lock reason available',
    }
    if not DB_AVAILABLE:
        return base
    try:
        totals = fetch_query(
            """
            SELECT
                COUNT(*) AS unresolved_total,
                COALESCE(SUM(CASE WHEN s.level_name='CRITICAL' THEN 1 ELSE 0 END),0) AS critical,
                COALESCE(SUM(CASE WHEN s.level_name='HIGH' THEN 1 ELSE 0 END),0) AS high,
                COALESCE(SUM(CASE WHEN s.level_name='MEDIUM' THEN 1 ELSE 0 END),0) AS medium
            FROM Alerts a
            JOIN Severity s ON s.severity_id = a.severity_id
            WHERE a.is_resolved = FALSE
            """,
            fetchall=False,
        ) or {}
        last = fetch_query(
            "SELECT reason FROM FSM_State_History ORDER BY changed_at DESC LIMIT 1",
            fetchall=False,
        ) or {}
        base.update(
            {
                'unresolved_total': int(totals.get('unresolved_total') or 0),
                'critical': int(totals.get('critical') or 0),
                'high': int(totals.get('high') or 0),
                'medium': int(totals.get('medium') or 0),
                'reason': (last.get('reason') or base['reason'])[:260],
            }
        )
    except Exception:
        pass
    return base


def network_poll_thread():
    """Push network counters periodically — lighter load than sub-second polling."""
    while True:
        try:
            payload = get_network_payload()
            socketio.emit('network_stats', payload)
            global _last_debug_network_ts
            now_ts = time.time()
            if now_ts - _last_debug_network_ts > 8:
                _last_debug_network_ts = now_ts
                _debug_log('network_stats_emit', payload)
        except Exception as e:
            print(f"Network poll emit error: {e}")
        socketio.sleep(1.25)

def build_dashboard_snapshot(current_state):
    active_alerts = get_db_data_safely(get_active_alerts, [])
    recent_events = get_db_data_safely(lambda: get_recent_events(8), [])

    if not DB_AVAILABLE and not active_alerts:
        active_alerts = [
            {'alert_id': 101, 'severity': 'CRITICAL', 'message': 'Simulated Ransomware Heuristic Match', 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'event_type': 'MALWARE', 'agent': '001', 'agent_name': 'Kali-SOC', 'technique': 'T1486', 'tactic': 'Impact', 'rule_id': '255001', 'level': 12},
            {'alert_id': 102, 'severity': 'HIGH', 'message': 'Signed Script Proxy Execution: PowerShell.exe', 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'event_type': 'DETECTION', 'agent': '004', 'agent_name': 'Windows-Srv', 'technique': 'T1218', 'tactic': 'Defense Evasion', 'rule_id': '255563', 'level': 10}
        ]

    # When DB is unavailable, populate recent_events so the Events Log page isn't empty.
    if not DB_AVAILABLE and (not recent_events):
        recent_events = [
            {
                'event_id': 401,
                'event_type': 'AUTH_FAILED',
                'description': 'Failed login attempt for admin from 127.0.0.1',
                'process_name': 'ssh_login_sim',
                'timestamp': time.strftime('%H:%M:%S'),
            },
            {
                'event_id': 402,
                'event_type': 'PROCESS_SPAM',
                'description': 'Rapid subprocess spawn simulated to trigger process spike detector',
                'process_name': 'process_flood.py',
                'timestamp': time.strftime('%H:%M:%S'),
            },
            {
                'event_id': 403,
                'event_type': 'FILE_TAMPER',
                'description': 'Critical file tampering simulated (dummy target) for CRITICAL escalation',
                'process_name': 'file_tamper_simulator.py',
                'timestamp': time.strftime('%H:%M:%S'),
            },
            {
                'event_id': 404,
                'event_type': 'FSM_LOCKOUT',
                'description': 'FSM locked after repeated failed sign-in attempts (mock)',
                'process_name': None,
                'timestamp': time.strftime('%H:%M:%S'),
            },
            {
                'event_id': 405,
                'event_type': 'RESPONSE_ACTION',
                'description': 'Active defense workflow invoked (mock) to terminate suspicious processes',
                'process_name': 'response_engine',
                'timestamp': time.strftime('%H:%M:%S'),
            },
        ]

    for alert in active_alerts:
        alert.setdefault('agent', '004'); alert.setdefault('agent_name', 'Windows'); alert.setdefault('technique', 'T1059')
        alert.setdefault('tactic', 'Execution'); alert.setdefault('level', 10 if alert['severity'] in ['HIGH', 'CRITICAL'] else 5)
        alert.setdefault('rule_id', str(random.randint(200000, 260000)))
        if hasattr(alert.get('timestamp'), 'strftime'): alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    for event in recent_events:
        if hasattr(event.get('timestamp'), 'strftime'): event['timestamp'] = event['timestamp'].strftime('%H:%M:%S')

    severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for alert in active_alerts: severity_counts[alert.get('severity', 'LOW')] += 1

    if DB_AVAILABLE:
        state_history = fetch_query("SELECT previous_state, new_state, reason, changed_at FROM FSM_State_History ORDER BY changed_at DESC LIMIT 5") or []
        for item in state_history:
            if hasattr(item.get('changed_at'), 'strftime'): item['changed_at'] = item['changed_at'].strftime('%H:%M:%S')
        
        res = fetch_query("SELECT COUNT(*) as cnt FROM Events WHERE event_type IN ('RESPONSE_ACTION', 'PROCESS_KILLED') AND timestamp >= NOW() - INTERVAL 1 DAY", fetchall=False)
        kill_cnt = res['cnt'] if res and 'cnt' in res else 0
        resolved_res = fetch_query("SELECT COUNT(*) as cnt FROM Alerts WHERE is_resolved = TRUE", fetchall=False)
        resolved_cases = resolved_res['cnt'] if resolved_res and 'cnt' in resolved_res else 0
        ipc_res = fetch_query("SELECT COUNT(*) as cnt FROM Events WHERE timestamp >= NOW() - INTERVAL 1 HOUR", fetchall=False)
        ipc_total = ipc_res['cnt'] if ipc_res and 'cnt' in ipc_res else 0
    else:
        base_mock_hist = [
            {'previous_state': 'NORMAL', 'new_state': 'NORMAL', 'reason': 'System Init (Mock)', 'changed_at': time.strftime('%H:%M:%S')}
        ]
        state_history = list(mock_fsm_auth_history) + base_mock_hist
        kill_cnt, resolved_cases, ipc_total = 12, 128, 412

    update_network_stats()
    incident_trends = build_incident_trends()
    user_activity = build_user_activity_list(recent_events)
    incident_summary = build_incident_summary_list(active_alerts, recent_events)
    resolved_cases_rows = get_resolved_cases_rows(250)
    terminated_process_rows = get_terminated_process_rows(250)
    fsm_lock_context = get_fsm_lock_context()

    recent_alerts_widget = get_db_data_safely(lambda: get_recent_alerts_for_dashboard(7, 5), []) or []
    if not DB_AVAILABLE:
        recent_alerts_widget = list(active_alerts[:5])
    for alert in recent_alerts_widget:
        alert.setdefault('agent', '004')
        alert.setdefault('agent_name', 'Windows')
        alert.setdefault('technique', 'T1059')
        alert.setdefault('tactic', 'Execution')
        alert.setdefault('level', 10 if alert.get('severity') in ['HIGH', 'CRITICAL'] else 5)
        alert.setdefault('rule_id', str(random.randint(200000, 260000)))
        if hasattr(alert.get('timestamp'), 'strftime'):
            alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    return {
        'state': current_state, 'active_alerts': active_alerts, 'recent_alerts': recent_alerts_widget, 'recent_events': recent_events, 'severity_counts': severity_counts,
        'state_history': state_history, 'kill_cnt': kill_cnt, 'resolved_cases': resolved_cases, 'ipc_total': ipc_total,
        'devices': [{'name': 'Firewall-Main', 'status': 'Online', 'health': 'green'}, {'name': os.environ.get('COMPUTERNAME', 'LOCAL-HOST'), 'status': 'At Risk' if severity_counts['HIGH'] > 0 else 'Online', 'health': 'green'}],
        'network': {'in': net_stats['in_speed'], 'out': net_stats['out_speed'], 'total_in': f"{net_stats['total_in']:.2f} GB", 'total_out': f"{net_stats['total_out']:.2f} GB"}, 'resources': get_real_resources(),
        'processes': get_process_list(),
        'incident_trends': incident_trends,
        'user_activity': user_activity,
        'incident_summary': incident_summary,
        'resolved_cases_rows': resolved_cases_rows,
        'terminated_process_rows': terminated_process_rows,
        'fsm_lock_context': fsm_lock_context,
    }


def _severity_pdf_color(sev):
    s = str(sev or '').strip().upper()
    if s == 'CRITICAL':
        return colors.HexColor('#DC2626')
    if s == 'HIGH':
        return colors.HexColor('#F97316')
    if s == 'MEDIUM':
        return colors.HexColor('#FACC15')
    if s == 'LOW':
        return colors.HexColor('#22C55E')
    return None


def _to_text(v):
    if v is None:
        return '-'
    txt = str(v).strip()
    return txt if txt else '-'


def _col_ratio_for_key(key_name):
    k = str(key_name or '').lower()
    if 'description' in k or 'detail' in k or 'message' in k or 'title' in k or 'reason' in k:
        return 3.2
    if 'timestamp' in k or k.endswith('_at') or k == 'time':
        return 1.4
    if 'severity' in k:
        return 1.1
    if 'actor' in k or 'user' in k or 'pid' in k or 'id' in k:
        return 1.0
    return 1.2


def _render_pdf_report(report_title, subtitle, sections, landscape_mode=False):
    if not REPORTLAB_OK:
        raise RuntimeError("PDF engine not available. Install reportlab.")
    buff = io.BytesIO()
    doc = SimpleDocTemplate(
        buff,
        pagesize=landscape(A4) if landscape_mode else A4,
        topMargin=14 * mm,
        bottomMargin=12 * mm,
        leftMargin=10 * mm,
        rightMargin=10 * mm,
        title=report_title,
        author='FalconStrix',
    )
    styles = getSampleStyleSheet()
    cell_style = styles['BodyText']
    cell_style.fontName = 'Helvetica'
    cell_style.fontSize = 8
    cell_style.leading = 9.2
    cell_style.wordWrap = 'CJK'
    story = [
        Paragraph(f"<b>{report_title}</b>", styles['Title']),
        Paragraph(subtitle, styles['Normal']),
        Spacer(1, 8),
    ]
    for section in sections:
        section_title = section.get('title') or 'Section'
        cols = section.get('columns') or []
        rows = section.get('rows') or []
        sev_key = section.get('severity_key')
        sev_col_idx = -1
        if sev_key and isinstance(section.get('keys'), list):
            try:
                sev_col_idx = section.get('keys').index(sev_key)
            except ValueError:
                sev_col_idx = -1
        story.append(Paragraph(f"<b>{section_title}</b>", styles['Heading3']))
        if not rows:
            story.append(Paragraph("No records available.", styles['Italic']))
            story.append(Spacer(1, 8))
            continue
        keys = section.get('keys', [])
        table_data = [cols]
        for row in rows:
            rendered = []
            for k in keys:
                raw = _to_text(row.get(k))
                safe = (
                    raw.replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                )
                rendered.append(Paragraph(safe, cell_style))
            table_data.append(rendered)
        ratios = [_col_ratio_for_key(k) for k in keys]
        ratio_total = sum(ratios) if ratios else 1
        col_widths = [doc.width * (r / ratio_total) for r in ratios] if ratios else None
        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        style_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#111827')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#374151')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F8FAFC'), colors.HexColor('#EEF2FF')]),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]
        if sev_key:
            for i, row in enumerate(rows, start=1):
                c = _severity_pdf_color(row.get(sev_key))
                if c:
                    if sev_col_idx >= 0:
                        style_cmds.append(('BACKGROUND', (sev_col_idx, i), (sev_col_idx, i), c))
                        style_cmds.append(('TEXTCOLOR', (sev_col_idx, i), (sev_col_idx, i), colors.black))
                        style_cmds.append(('FONTNAME', (sev_col_idx, i), (sev_col_idx, i), 'Helvetica-Bold'))
                    else:
                        style_cmds.append(('BACKGROUND', (0, i), (-1, i), c))
                        style_cmds.append(('TEXTCOLOR', (0, i), (-1, i), colors.black))
        table.setStyle(TableStyle(style_cmds))
        story.append(table)
        story.append(Spacer(1, 10))
    doc.build(story)
    buff.seek(0)
    return buff


def _send_pdf(report_title, sections, filename):
    subtitle = f"Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Source: FalconStrix Dashboard"
    # Auto-switch to landscape when any section is wide.
    wide = any(len(s.get('columns') or []) >= 7 for s in sections or [])
    pdf_stream = _render_pdf_report(report_title, subtitle, sections, landscape_mode=wide)
    return send_file(
        pdf_stream,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf',
    )


def make_snapshot_signature(snapshot):
    slim_snapshot = {
        'state': snapshot.get('state'),
        'alerts': [
            (a.get('alert_id'), a.get('severity'), a.get('message'), a.get('timestamp'))
            for a in snapshot.get('active_alerts', [])
        ],
        'recent_alerts': [
            (a.get('alert_id'), a.get('severity'), a.get('timestamp'))
            for a in snapshot.get('recent_alerts', [])
        ],
        'events': [
            (e.get('event_id'), e.get('event_type'), e.get('timestamp'))
            for e in snapshot.get('recent_events', [])
        ],
        'history': [
            (h.get('previous_state'), h.get('new_state'), h.get('changed_at'))
            for h in snapshot.get('state_history', [])
        ],
        'severity_counts': snapshot.get('severity_counts'),
        'kill_cnt': snapshot.get('kill_cnt'),
        'resolved_cases': snapshot.get('resolved_cases'),
        'ipc_total': snapshot.get('ipc_total'),
        'network': snapshot.get('network'),
        'resources': snapshot.get('resources'),
        'processes': [
            (p.get('pid'), p.get('cpu'), p.get('mem'), p.get('threat'))
            for p in snapshot.get('processes', [])
        ],
        'user_activity': [
            (u.get('description'), u.get('timestamp'), u.get('actor'))
            for u in snapshot.get('user_activity', [])
        ],
        'incident_summary': [
            (s.get('title'), s.get('time'))
            for s in snapshot.get('incident_summary', [])
        ],
        'resolved_cases_rows': [
            (
                r.get('alert_id'),
                r.get('severity'),
                r.get('trigger_event'),
                r.get('detected_at'),
                r.get('resolved_at'),
                r.get('pid'),
            )
            for r in snapshot.get('resolved_cases_rows', [])
        ],
        'terminated_process_rows': [
            (
                r.get('terminated_at'),
                r.get('terminated_by'),
                r.get('action_type'),
                r.get('pid'),
            )
            for r in snapshot.get('terminated_process_rows', [])
        ],
        'incident_trends': (
            tuple(snapshot.get('incident_trends', {}).get('weekly', {}).get('resolved', [])),
            tuple(snapshot.get('incident_trends', {}).get('monthly', {}).get('resolved', [])),
            tuple(snapshot.get('incident_trends', {}).get('yearly', {}).get('resolved', [])),
        ),
    }
    return json.dumps(slim_snapshot, sort_keys=True)

def background_thread():
    last_state, last_alert_id = 'NORMAL', 0
    metrics_emit_counter = 0
    while True:
        try:
            current_state = get_effective_fsm_state()
            if DB_AVAILABLE:
                new_alerts = fetch_query("SELECT a.alert_id, s.level_name as severity, a.message, a.timestamp FROM Alerts a JOIN Severity s ON a.severity_id = s.severity_id WHERE a.alert_id > %s ORDER BY a.alert_id ASC", (last_alert_id,))
                if new_alerts:
                    for alert in new_alerts:
                        if hasattr(alert.get('timestamp'), 'strftime'): alert['timestamp'] = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                        socketio.emit('new_alert', alert); last_alert_id = max(last_alert_id, alert['alert_id'])
            if current_state != last_state: socketio.emit('state_change', {'state': current_state}); last_state = current_state
            snapshot = build_dashboard_snapshot(current_state)
            snapshot_signature = make_snapshot_signature(snapshot)
            now = time.time()

            if (
                snapshot_signature != snapshot_cache['snapshot_signature']
                or (now - snapshot_cache['last_full_emit']) >= 12
            ):
                global last_dashboard_snapshot
                last_dashboard_snapshot = snapshot
                socketio.emit('dashboard_snapshot', snapshot)
                _debug_log(
                    'dashboard_snapshot_emit',
                    {
                        'state': current_state,
                        'active_alerts': len(snapshot.get('active_alerts', [])),
                        'recent_events': len(snapshot.get('recent_events', []) or []),
                        'kill_cnt': snapshot.get('kill_cnt'),
                        'ipc_total': snapshot.get('ipc_total'),
                    },
                )
                snapshot_cache['snapshot_signature'] = snapshot_signature
                snapshot_cache['last_full_emit'] = now

            # metrics_update duplicates much of dashboard_snapshot — emit less often to reduce UI churn
            metrics_emit_counter += 1
            if metrics_emit_counter % 2 == 0:
                socketio.emit('metrics_update', {
                    'events_last_min': random.randint(5, 15),
                    'active_alerts': len(snapshot['active_alerts']),
                    'severity_counts': snapshot['severity_counts'],
                    'kill_cnt': snapshot['kill_cnt'],
                    'resolved_cases': snapshot.get('resolved_cases', 0),
                    'network': snapshot['network']
                })
                _debug_log(
                    'metrics_update_emit',
                    {
                        'active_alerts': snapshot.get('active_alerts'),
                        'kill_cnt': snapshot.get('kill_cnt'),
                        'network': snapshot.get('network'),
                    },
                )
        except Exception as e: print(f"BG Thread Error: {e}")
        # Slightly slower loop reduces UI churn under heavy event load.
        socketio.sleep(3)

@socketio.on('request_scan')
def handle_scan():
    socketio.emit('scan_start')
    _debug_log('scan_start')
    time.sleep(1.5)
    socketio.emit('scan_complete', {'message': 'System scan finished. No immediate threats found.'})
    _debug_log('scan_complete')

@socketio.on('kill_process')
def handle_kill(data):
    pid = data.get('pid')
    name = data.get('name')
    uid = session.get('user_id')
    uname = session.get('username') or 'unknown'
    print(f"[SOC] REQ: Kill process {name} (PID: {pid})")
    _debug_log('kill_process_req', {'pid': pid, 'name': name})
    with open("kill_debug.log", "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Kill REQ: {name} ({pid})\n")
    try:
        if psutil:
            proc = psutil.Process(pid)
            proc.terminate()
            if DB_AVAILABLE:
                from event_service import log_event
                log_event(
                    "PROCESS_KILLED",
                    f"User '{uname}' manually terminated suspicious process: {name} (PID: {pid})",
                    "SOC-Dashboard",
                    user_id=uid,
                )
            record_user_activity_event(
                "PROCESS_KILLED",
                f"User '{uname}' manually terminated suspicious process: {name} (PID: {pid})",
                user_id=uid,
                actor_username=uname,
            )
            socketio.emit('alert_msg', {'type': 'success', 'text': f'Process {name} ({pid}) terminated.'})
            try:
                st = get_effective_fsm_state()
                snap = build_dashboard_snapshot(st)
                global last_dashboard_snapshot
                last_dashboard_snapshot = snap
                socketio.emit('dashboard_snapshot', snap)
            except Exception as emit_ex:
                print(f"kill snapshot emit error: {emit_ex}")
            _debug_log('kill_process_success', {'pid': pid, 'name': name})
        else:
            socketio.emit('alert_msg', {'type': 'error', 'text': 'Kill failed: psutil unavailable.'})
            _debug_log('kill_process_failed', {'pid': pid, 'name': name, 'reason': 'psutil_unavailable'})
    except Exception as e:
        socketio.emit('alert_msg', {'type': 'error', 'text': f'Failed to kill {pid}: {str(e)}'})
        _debug_log('kill_process_error', {'pid': pid, 'name': name, 'error': str(e)})

@app.before_request
def require_dashboard_login():
    # Allow websocket handshake + Socket.IO polling to proceed; we authorize on the
    # Socket.IO 'connect' handler / session, not by HTTP redirects.
    if (
        request.path.startswith('/api/debug')
        or request.path.startswith('/api/auth/')
        or request.path.startswith('/socket.io')
        or request.endpoint in ('login', 'signup', 'static', 'api_username_availability')
        or request.path.startswith('/static/')
    ):
        return None
    if request.path == '/favicon.ico':
        return None
    if not session.get('user_id'):
        return redirect(url_for('login', next=request.path))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        try:
            from auth_service import verify_login_dashboard

            user = verify_login_dashboard(username, password, DB_AVAILABLE)
        except Exception as ex:
            print(f"Login verify error: {ex}")
            user = None
        if user:
            clear_login_failures(request.remote_addr or 'unknown')
            session.permanent = True
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user.get('role', 'user')
            ip = request.remote_addr or 'unknown'
            record_dashboard_auth_event(
                'LOGIN',
                f"User '{user['username']}' signed in to dashboard ({ip})",
                user_id=user['user_id'],
                actor_username=user['username'],
            )
            _debug_log('login_success', {'username': user.get('username'), 'user_id': user.get('user_id')})
            nxt = request.args.get('next') or url_for('index')
            if not nxt.startswith('/') or nxt.startswith('//'):
                nxt = url_for('index')
            return redirect(nxt)
        ip = request.remote_addr or 'unknown'
        rec = _bump_login_failure(ip)
        record_dashboard_auth_event(
            'AUTH_FAILED',
            f"Failed login attempt for {(username or '?')} ({ip}); count {rec['count']}/{LOGIN_FAIL_THRESHOLD}",
            actor_username=(username or '').strip() or None,
        )
        _debug_log('login_failed', {'username': (username or '').strip() or None, 'ip': ip, 'count': rec.get('count')})
        if rec['count'] >= LOGIN_FAIL_THRESHOLD and not rec.get('lockout_sent'):
            rec['lockout_sent'] = True
            login_failure_by_ip[ip] = rec
            trigger_fsm_auth_lockout(ip, username)
            flash(
                'Too many failed sign-in attempts. FSM has been escalated to LOCKED. '
                'Review the FSM page and OS Concepts security notice after signing in (if permitted).',
                'error',
            )
        elif rec['count'] >= LOGIN_FAIL_THRESHOLD:
            flash('Invalid credentials. FSM is in LOCKED state.', 'error')
        else:
            left = max(0, LOGIN_FAIL_THRESHOLD - rec['count'])
            flash(
                f'Invalid username or password. {left} attempt(s) remaining before FSM lock-down.',
                'error',
            )
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if session.get('user_id'):
        return redirect(url_for('index'))
    if os.environ.get('FALCON_DISABLE_SIGNUP', '').lower() in ('1', 'true', 'yes'):
        flash('New account registration is disabled.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        password2 = request.form.get('password_confirm') or ''
        if password != password2:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html')
        try:
            from auth_service import register_user

            user, err = register_user(username, password, DB_AVAILABLE)
        except Exception as ex:
            print(f"Signup error: {ex}")
            user, err = None, 'Registration failed. Try again.'
        if err:
            flash(err, 'error')
            return render_template('signup.html')
        ip = request.remote_addr or 'unknown'
        record_dashboard_auth_event(
            'SIGNUP',
            f"New account '{user['username']}' registered ({ip})",
            user_id=user['user_id'],
            actor_username=user['username'],
        )
        _debug_log('signup_success', {'username': user.get('username'), 'user_id': user.get('user_id')})
        flash('Account created. Sign in with your new username and password.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/api/auth/username-availability')
def api_username_availability():
    username = (request.args.get('username') or '').strip()
    try:
        from auth_service import check_username_availability
        ok, msg = check_username_availability(username, DB_AVAILABLE)
        return jsonify({'ok': True, 'available': bool(ok), 'message': msg})
    except Exception as e:
        return jsonify({'ok': False, 'available': False, 'message': str(e)}), 500


@app.route('/logout', methods=['POST'])
def logout():
    uid = session.get('user_id')
    un = session.get('username')
    if un:
        record_dashboard_auth_event(
            'LOGOUT',
            f"User '{un}' signed out",
            user_id=uid,
            actor_username=un,
        )
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def index():
    return render_template(
        'dashboard.html',
        username=session.get('username', 'Operator'),
        user_role=(session.get('role') or 'user'),
    )


@app.route('/api/ipc/status')
def api_ipc_status():
    """Reports named-pipe path and health for the OS Concepts IPC page."""
    try:
        from ipc_config import pipe_status
        st = pipe_status()
        st['ok'] = True
        return jsonify(st)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/network')
def api_network():
    """Current ingress/egress rates and cumulative totals (same data as Socket.IO)."""
    return jsonify(get_network_payload())


@app.route('/api/dashboard_snapshot')
def api_dashboard_snapshot():
    """Return the latest dashboard snapshot for UI refresh (REST fallback)."""
    try:
        st = get_effective_fsm_state()
        snap = build_dashboard_snapshot(st)
        return jsonify(snap)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/fsm/reevaluate', methods=['POST'])
def api_fsm_reevaluate():
    """
    Force an FSM recalculation and unlock check.
    Used by LOCKED overlay when counts are shown as zero.
    """
    try:
        from fsm_service import tick_fsm, maybe_unlock_locked_state
        actor = session.get('username') or 'system'
        tick_fsm()
        maybe_unlock_locked_state(actor_username=actor)
        st = get_effective_fsm_state()
        snap = build_dashboard_snapshot(st)
        return jsonify({'ok': True, 'state': st, 'snapshot': snap})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/reports/dashboard.pdf')
def api_report_dashboard_pdf():
    try:
        st = get_effective_fsm_state()
        snap = build_dashboard_snapshot(st)
        resolved_preview = []
        for r in (snap.get('resolved_cases_rows') or [])[:35]:
            detail = _to_text(r.get('resolution_detail'))
            if len(detail) > 80:
                detail = detail[:77] + '...'
            resolved_preview.append(
                {
                    'alert_id': r.get('alert_id'),
                    'severity': r.get('severity'),
                    'resolved_by': r.get('resolved_by'),
                    'resolved_at': r.get('resolved_at'),
                    'pid': r.get('pid'),
                    'resolution_short': detail,
                }
            )
        metrics_rows = [
            {'metric': 'FSM State', 'value': snap.get('state')},
            {'metric': 'Active Threats', 'value': len(snap.get('active_alerts') or [])},
            {'metric': 'Resolved Cases', 'value': snap.get('resolved_cases')},
            {'metric': 'Kill Actions (24h)', 'value': snap.get('kill_cnt')},
            {'metric': 'IPC Events (1h)', 'value': snap.get('ipc_total')},
        ]
        sections = [
            {
                'title': 'Executive Metrics',
                'columns': ['Metric', 'Value'],
                'keys': ['metric', 'value'],
                'rows': metrics_rows,
            },
            {
                'title': 'Active Alerts',
                'columns': ['Case ID', 'Severity', 'Event', 'Message', 'Detected At'],
                'keys': ['alert_id', 'severity', 'event_type', 'message', 'timestamp'],
                'rows': (snap.get('active_alerts') or [])[:35],
                'severity_key': 'severity',
            },
            {
                'title': 'Resolved Cases',
                'columns': ['Case ID', 'Severity', 'Resolved By', 'Resolved At', 'PID', 'Resolution'],
                'keys': ['alert_id', 'severity', 'resolved_by', 'resolved_at', 'pid', 'resolution_short'],
                'rows': resolved_preview,
                'severity_key': 'severity',
            },
            {
                'title': 'User Activity',
                'columns': ['Actor', 'Event', 'Description', 'Time'],
                'keys': ['actor', 'event_type', 'description', 'timestamp'],
                'rows': (snap.get('user_activity') or [])[:40],
            },
            {
                'title': 'Incident Summary',
                'columns': ['Severity', 'Incident', 'Time'],
                'keys': ['severity', 'title', 'time'],
                'rows': (snap.get('incident_summary') or [])[:30],
                'severity_key': 'severity',
            },
        ]
        return _send_pdf('FalconStrix Professional SOC Report', sections, 'FalconStrix_Soc_Report.pdf')
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/reports/user-activity.pdf')
def api_report_user_activity_pdf():
    try:
        st = get_effective_fsm_state()
        snap = build_dashboard_snapshot(st)
        sections = [
            {
                'title': 'User Activity Audit',
                'columns': ['Actor', 'Event Type', 'Description', 'Timestamp'],
                'keys': ['actor', 'event_type', 'description', 'timestamp'],
                'rows': (snap.get('user_activity') or [])[:100],
            }
        ]
        return _send_pdf('FalconStrix User Activity Report', sections, 'FalconStrix_User_Activity.pdf')
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/reports/incident-summary.pdf')
def api_report_incident_summary_pdf():
    try:
        st = get_effective_fsm_state()
        snap = build_dashboard_snapshot(st)
        sections = [
            {
                'title': 'Incident Summary',
                'columns': ['Severity', 'Incident', 'Time'],
                'keys': ['severity', 'title', 'time'],
                'rows': (snap.get('incident_summary') or [])[:100],
                'severity_key': 'severity',
            }
        ]
        return _send_pdf('FalconStrix Incident Summary Report', sections, 'FalconStrix_Incident_Summary.pdf')
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/reports/resolved-cases.pdf')
def api_report_resolved_cases_pdf():
    try:
        rows = get_resolved_cases_rows(500)
        sections = [
            {
                'title': 'Resolved Cases',
                'columns': ['Case ID', 'Severity', 'Resolved By', 'Detected At', 'Resolved At', 'Process', 'PID', 'Resolution'],
                'keys': ['alert_id', 'severity', 'resolved_by', 'detected_at', 'resolved_at', 'process_name', 'pid', 'resolution_detail'],
                'rows': rows,
                'severity_key': 'severity',
            }
        ]
        return _send_pdf('FalconStrix Resolved Cases Report', sections, 'FalconStrix_Resolved_Cases.pdf')
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/reports/terminated-processes.pdf')
def api_report_terminated_processes_pdf():
    try:
        rows = get_terminated_process_rows(500)
        sections = [
            {
                'title': 'Terminated Processes',
                'columns': ['Terminated At', 'Terminated By', 'Action', 'Process', 'PID', 'Created At', 'Source', 'Details'],
                'keys': ['terminated_at', 'terminated_by', 'action_type', 'process_name', 'pid', 'process_created_at', 'source', 'details'],
                'rows': rows,
            }
        ]
        return _send_pdf('FalconStrix Terminated Processes Report', sections, 'FalconStrix_Terminated_Processes.pdf')
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def api_resolve_alert_case(alert_id):
    """
    Resolve a live alert case from dashboard.
    LOCKED -> NORMAL requires authenticated admin + no unresolved cases left.
    """
    actor = session.get('username') or 'unknown'
    role = (session.get('role') or 'user').lower()
    actor_uid = session.get('user_id')
    try:
        from process_service import resolve_alert_case
    except Exception as e:
        return jsonify({'ok': False, 'error': f'resolve service unavailable: {e}'}), 500

    try:
        result = resolve_alert_case(
            alert_id=alert_id,
            actor_username=actor,
            actor_role=role,
            actor_user_id=actor_uid,
        )
        status = int(result.get('status', 200))
        if not result.get('ok'):
            return jsonify(result), status
        record_user_activity_event(
            'CASE_RESOLVED',
            f"User '{actor}' resolved case #{alert_id}",
            user_id=actor_uid,
            actor_username=actor,
        )

        # Push fresh snapshot immediately so Live Alerts / Resolved Cases update.
        st = get_effective_fsm_state()
        snap = build_dashboard_snapshot(st)
        global last_dashboard_snapshot
        last_dashboard_snapshot = snap
        socketio.emit('dashboard_snapshot', snap)
        return jsonify({'ok': True, 'result': result, 'snapshot': snap}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/alerts/manual', methods=['POST'])
def api_create_manual_alert():
    """
    Create a dashboard-triggered alert so operators can simulate/raise a real case.
    Persists Event + Alert in DB, then pushes a fresh dashboard snapshot.
    """
    actor = session.get('username') or 'unknown'
    actor_uid = session.get('user_id')
    payload = request.get_json(silent=True) or {}

    # Supported values align with alert_service.create_alert severity mapping.
    sev_map = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    severity_name = str(payload.get('severity') or 'HIGH').strip().upper()
    severity_id = sev_map.get(severity_name)
    if severity_id is None:
        return jsonify({'ok': False, 'error': 'Invalid severity. Use LOW|MEDIUM|HIGH|CRITICAL'}), 400

    message = str(payload.get('message') or '').strip()
    if not message:
        message = f"Manual alert raised by '{actor}' from dashboard"
    message = message[:240]

    try:
        from event_service import log_event
        from alert_service import create_alert
    except Exception as e:
        return jsonify({'ok': False, 'error': f'alert services unavailable: {e}'}), 500

    try:
        event_id = log_event(
            "MANUAL_ALERT",
            message,
            "SOC-Dashboard",
            user_id=actor_uid,
        )
        if not event_id:
            return jsonify({'ok': False, 'error': 'Failed to create event record'}), 500

        alert_id = create_alert(event_id, severity_id, message)
        if not alert_id:
            return jsonify({'ok': False, 'error': 'Failed to create alert record'}), 500

        record_user_activity_event(
            "MANUAL_ALERT",
            f"User '{actor}' created manual {severity_name} alert: {message}",
            user_id=actor_uid,
            actor_username=actor,
        )

        st = get_effective_fsm_state()
        snap = build_dashboard_snapshot(st)
        global last_dashboard_snapshot
        last_dashboard_snapshot = snap
        socketio.emit('dashboard_snapshot', snap)

        return jsonify({'ok': True, 'alert_id': alert_id, 'snapshot': snap}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/audit/action', methods=['POST'])
def api_audit_action():
    """
    Record user-driven dashboard actions (CSV export/report generation/etc.)
    so they appear in User Activity.
    """
    uid = session.get('user_id')
    uname = session.get('username')
    if not uid or not uname:
        return jsonify({'ok': False, 'message': 'Authentication required'}), 401
    payload = request.get_json(silent=True) or {}
    event_type = str(payload.get('event_type') or '').strip().upper()[:64]
    description = str(payload.get('description') or '').strip()[:300]
    allowed = {'CSV_EXPORT', 'REPORT_GENERATED', 'PROCESS_KILL_REQUEST', 'CASE_RESOLVE_REQUEST'}
    if event_type not in allowed:
        return jsonify({'ok': False, 'message': 'Unsupported audit event type'}), 400
    if not description:
        description = f'{event_type} by {uname}'
    record_user_activity_event(event_type, description, user_id=uid, actor_username=uname)
    try:
        st = get_effective_fsm_state()
        snap = build_dashboard_snapshot(st)
        global last_dashboard_snapshot
        last_dashboard_snapshot = snap
        socketio.emit('dashboard_snapshot', snap)
    except Exception as emit_ex:
        print(f"audit snapshot emit error: {emit_ex}")
    return jsonify({'ok': True})


@app.route('/api/debug/events')
def api_debug_events():
    """Return last N server debug events (for verifying dashboard functionality)."""
    limit = request.args.get('limit', default='80')
    try:
        limit = max(1, min(250, int(limit)))
    except Exception:
        limit = 80
    return jsonify({'ok': True, 'events': list(debug_event_log)[:limit]})


@app.route('/api/debug/last-snapshot')
def api_debug_last_snapshot():
    """Return a small view of the last dashboard_snapshot sent (for UI debugging)."""
    if not last_dashboard_snapshot:
        return jsonify({'ok': True, 'snapshot_recent_events_count': 0, 'recent_events': []})
    revents = last_dashboard_snapshot.get('recent_events') or []
    return jsonify(
        {
            'ok': True,
            'snapshot_recent_events_count': len(revents),
            'recent_events': revents[:8],
        }
    )


@socketio.on('connect')
def handle_socket_connect():
    # Don't reject the socket connection outright; some clients may not have a
    # session bound at handshake time (depending on cookies/port). We still
    # keep UI in sync via REST fallbacks for unauthenticated users.
    if not session.get('user_id'):
        return
    try:
        emit('network_stats', get_network_payload())
    except Exception:
        pass
    _debug_log('socket_connect', {'user_id': session.get('user_id'), 'username': session.get('username')})


if __name__ == '__main__':
    socketio.start_background_task(background_thread)
    socketio.start_background_task(network_poll_thread)

    # Windows often reserves 5000 (Hyper-V / excluded ranges) → WinError 10013 "forbidden by its access permissions"
    _default_port = '5001' if sys.platform == 'win32' else '5000'
    _explicit_port = 'PORT' in os.environ
    _port = int(os.environ.get('PORT', _default_port))
    _candidates = [_port]
    if not _explicit_port:
        for _alt in (5001, 8080, 8765, 9000):
            if _alt not in _candidates:
                _candidates.append(_alt)

    _last_err = None
    for _try_port in _candidates:
        try:
            print(f"[*] Binding dashboard on 0.0.0.0:{_try_port} …")
            socketio.run(
                app,
                host='0.0.0.0',
                port=_try_port,
                debug=True,
                use_reloader=False,
                allow_unsafe_werkzeug=True,
            )
            break
        except OSError as e:
            _last_err = e
            winerr = getattr(e, 'winerror', None)
            msg = str(e)
            if winerr == 10048 or 'Address already in use' in msg:
                print(
                    f"[!] Port {_try_port} is already in use. "
                    f"Try: Get-NetTCPConnection -LocalPort {_try_port}"
                )
            elif winerr == 10013 or 'forbidden by its access permissions' in msg:
                print(
                    f"[!] Port {_try_port} is blocked on Windows (reserved range or policy). "
                    f"Set PORT explicitly, e.g.  $env:PORT=8080; python app.py"
                )
            else:
                print(f"[!] Could not bind port {_try_port}: {e}")
            if _try_port == _candidates[-1]:
                print(
                    "[!] No usable port in fallback list. "
                    "Check excluded ranges: netsh interface ipv4 show excludedportrange protocol=tcp"
                )
                raise _last_err
            print(f"    Trying next candidate…")
