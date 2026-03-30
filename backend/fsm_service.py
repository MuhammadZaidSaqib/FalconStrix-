from db_connection import execute_query, fetch_query
import logging
from process_service import active_defense

def get_current_state():
    query = "SELECT current_state FROM FSM_Current_State WHERE state_id = 1"
    res = fetch_query(query, fetchall=False)
    if res:
        return res['current_state']
    return 'NORMAL'

def update_fsm_state(new_state, reason, trigger_active_defense=True):
    """
    Transition FSM. For auth-only lockouts (e.g. failed logins), pass
    trigger_active_defense=False to avoid killing processes.
    """
    curr_state = get_current_state()
    if curr_state == new_state:
        return  # No change

    # Update current state
    update_q = "UPDATE FSM_Current_State SET current_state = %s WHERE state_id = 1"
    execute_query(update_q, (new_state,))

    # Log history
    hist_q = """
    INSERT INTO FSM_State_History (previous_state, new_state, reason)
    VALUES (%s, %s, %s)
    """
    execute_query(hist_q, (curr_state, new_state, reason))
    logging.info(f"FSM State changed: {curr_state} -> {new_state}. Reason: {reason}")
    print(f"[+] FSM STATE ESCALATION: {curr_state} -> {new_state} | {reason}")

    # Physical Conceptual representation
    hardware_led_indicator(new_state)

    if new_state == 'LOCKED' and trigger_active_defense:
        print("[!] Defensive Response Activated!")
        active_defense()
    elif new_state == 'LOCKED':
        print("[!] FSM LOCKED (no active_defense — policy / auth lockout)")

def tick_fsm():
    """ Evaluate conditions to see if FSM must escalate or de-escalate """
    # Count unresolved high/critical alerts in last 10 minutes
    q = """
    SELECT COUNT(*) as cnt FROM Alerts a
    JOIN Severity s ON a.severity_id = s.severity_id
    WHERE a.is_resolved = FALSE AND s.level_name IN ('HIGH', 'CRITICAL')
    """
    res = fetch_query(q, fetchall=False)
    high_alerts = res['cnt'] if res else 0

    # Count recent medium alerts
    q2 = """
    SELECT COUNT(*) as cnt FROM Alerts a
    JOIN Severity s ON a.severity_id = s.severity_id
    WHERE a.is_resolved = FALSE AND s.level_name = 'MEDIUM'
    """
    res2 = fetch_query(q2, fetchall=False)
    med_alerts = res2['cnt'] if res2 else 0

    current_state = get_current_state()

    if high_alerts >= 2:
        update_fsm_state('LOCKED', 'Repeated abnormal behaviors/critical alerts detected')
    elif high_alerts == 1 or med_alerts >= 3:
        update_fsm_state('WARNING', 'Multiple suspicious events detected')
    elif high_alerts == 0 and med_alerts < 3 and current_state != 'NORMAL':
        # De-escalation can be manual or automatic over time. Let's make it automatic if 0 alerts
        pass

def hardware_led_indicator(state):
    """ Simulates physical FSM hardware LEDs via print statements """
    if state == 'NORMAL':
        print("[LED] GREEN: ON | YELLOW: OFF | RED: OFF")
    elif state == 'WARNING':
        print("[LED] GREEN: OFF | YELLOW: ON | RED: OFF")
    elif state == 'LOCKED':
        print("[LED] GREEN: OFF | YELLOW: OFF | RED: ON")
