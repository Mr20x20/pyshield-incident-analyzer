"""
rules/new_account.py — PyShield Incident Analyzer
Detects suspicious account creation patterns.

Patterns we detect:
  1. New account created shortly after a successful login
     → attacker creates a backdoor account
  2. New account created during off-hours (outside 08:00-18:00)
     → suspicious timing
  3. New account immediately used for login
     → account created and used in same session
"""

import logging
from datetime import datetime

from config import NEW_ACCOUNT_WINDOW

logger = logging.getLogger("incident.rules.new_account")

RULE_ID   = "RULE-003"
RULE_NAME = "Suspicious Account Creation"

# Off-hours definition
WORK_HOUR_START = 8
WORK_HOUR_END   = 18


def run(timeline: list[dict]) -> list[dict]:
    """Scan timeline for suspicious account creation."""
    alerts = []

    alerts.extend(_check_account_after_login(timeline))
    alerts.extend(_check_off_hours_creation(timeline))
    alerts.extend(_check_immediate_use(timeline))

    logger.info("%s: %d alert(s) generated", RULE_NAME, len(alerts))
    return alerts


def _check_account_after_login(timeline: list[dict]) -> list[dict]:
    """
    Detect new account created shortly after a successful login.
    This is a classic attacker persistence technique — create a
    backdoor account before the original vulnerability is patched.
    """
    alerts  = []
    logins  = [e for e in timeline
               if e.get("event_type") in
               ("successful_login", "accepted_password")]
    creations = [e for e in timeline
                 if e.get("event_type") in ("user_created", "new_user")]

    for login in logins:
        try:
            login_dt = datetime.strptime(
                login["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue

        for creation in creations:
            try:
                create_dt = datetime.strptime(
                    creation["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
                delta = (create_dt - login_dt).total_seconds()
                if 0 <= delta <= NEW_ACCOUNT_WINDOW:
                    alerts.append({
                        "rule_id":    RULE_ID,
                        "rule_name":  RULE_NAME,
                        "alert_type": "account_after_login",
                        "severity":   "CRITICAL",
                        "timestamp":  creation["timestamp"],
                        "src_ip":     login.get("src_ip", ""),
                        "username":   creation.get("username", ""),
                        "description": (
                            f"New account '{creation.get('username')}' "
                            f"created {int(delta)}s after login by "
                            f"'{login.get('username')}' — "
                            f"possible backdoor"
                        ),
                        "evidence": {
                            "login_event":    login,
                            "creation_event": creation,
                            "seconds":        int(delta),
                        },
                    })
            except ValueError:
                continue

    return alerts


def _check_off_hours_creation(timeline: list[dict]) -> list[dict]:
    """
    Detect accounts created outside business hours.
    Legitimate IT staff rarely create accounts at 3am.
    """
    alerts = []
    creations = [e for e in timeline
                 if e.get("event_type") in ("user_created", "new_user")]

    for event in creations:
        try:
            dt   = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
            hour = dt.hour
            if not (WORK_HOUR_START <= hour < WORK_HOUR_END):
                alerts.append({
                    "rule_id":    RULE_ID,
                    "rule_name":  RULE_NAME,
                    "alert_type": "off_hours_account",
                    "severity":   "HIGH",
                    "timestamp":  event["timestamp"],
                    "src_ip":     event.get("src_ip", ""),
                    "username":   event.get("username", ""),
                    "description": (
                        f"Account '{event.get('username')}' created "
                        f"at {dt.strftime('%H:%M')} — outside business hours"
                    ),
                    "evidence": {
                        "creation_event": event,
                        "hour":           hour,
                    },
                })
        except ValueError:
            continue

    return alerts


def _check_immediate_use(timeline: list[dict]) -> list[dict]:
    """
    Detect a newly created account being used for login immediately.
    Legitimate accounts usually have a delay before first use.
    """
    alerts    = []
    creations = [e for e in timeline
                 if e.get("event_type") in ("user_created", "new_user")]
    logins    = [e for e in timeline
                 if e.get("event_type") in
                 ("successful_login", "accepted_password")]

    for creation in creations:
        new_user = creation.get("username", "")
        if not new_user:
            continue

        try:
            create_dt = datetime.strptime(
                creation["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue

        for login in logins:
            if login.get("username") != new_user:
                continue
            try:
                login_dt = datetime.strptime(
                    login["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
                delta = (login_dt - create_dt).total_seconds()
                if 0 <= delta <= NEW_ACCOUNT_WINDOW:
                    alerts.append({
                        "rule_id":    RULE_ID,
                        "rule_name":  RULE_NAME,
                        "alert_type": "immediate_account_use",
                        "severity":   "HIGH",
                        "timestamp":  login["timestamp"],
                        "src_ip":     login.get("src_ip", ""),
                        "username":   new_user,
                        "description": (
                            f"Newly created account '{new_user}' "
                            f"used for login within {int(delta)}s "
                            f"of creation"
                        ),
                        "evidence": {
                            "creation_event": creation,
                            "login_event":    login,
                            "seconds":        int(delta),
                        },
                    })
                    break
            except ValueError:
                continue

    return alerts
