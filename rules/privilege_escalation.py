"""
rules/privilege_escalation.py — PyShield Incident Analyzer
Detects privilege escalation attempts.

Patterns we detect:
  1. Login → admin privileges assigned within PRIV_ESC_WINDOW seconds
  2. User added to Administrators group (Windows Event 4732)
  3. Sudo command executed shortly after login (Linux)
"""

import logging
from datetime import datetime

from config import PRIV_ESC_WINDOW

logger = logging.getLogger("incident.rules.privilege_escalation")

RULE_ID   = "RULE-002"
RULE_NAME = "Privilege Escalation Detection"


def run(timeline: list[dict]) -> list[dict]:
    """Scan timeline for privilege escalation patterns."""
    alerts = []

    alerts.extend(_check_admin_group_add(timeline))
    alerts.extend(_check_priv_after_login(timeline))
    alerts.extend(_check_sudo_after_login(timeline))

    logger.info("%s: %d alert(s) generated", RULE_NAME, len(alerts))
    return alerts


def _check_admin_group_add(timeline: list[dict]) -> list[dict]:
    """
    Detect user added to Administrators group.
    Windows Event 4732 — direct privilege escalation.
    """
    alerts = []
    for event in timeline:
        if event.get("event_type") == "admin_group_member_added":
            alerts.append({
                "rule_id":     RULE_ID,
                "rule_name":   RULE_NAME,
                "alert_type":  "admin_group_add",
                "severity":    "CRITICAL",
                "timestamp":   event["timestamp"],
                "src_ip":      event.get("src_ip", ""),
                "username":    event.get("username", ""),
                "description": (
                    f"User '{event.get('username')}' added to "
                    f"Administrators group on {event.get('hostname')}"
                ),
                "evidence": {"event": event},
            })
    return alerts


def _check_priv_after_login(timeline: list[dict]) -> list[dict]:
    """
    Detect special privileges assigned shortly after login.
    Windows: Event 4624 (login) → Event 4672 (special privileges)
    within PRIV_ESC_WINDOW seconds — same user.
    """
    alerts  = []
    logins  = [e for e in timeline if e.get("event_type") == "successful_login"]
    privs   = [e for e in timeline if e.get("event_type") == "privilege_assigned"]

    for login in logins:
        username = login.get("username", "")
        if not username:
            continue

        try:
            login_dt = datetime.strptime(
                login["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue

        for priv in privs:
            if priv.get("username") != username:
                continue
            try:
                priv_dt = datetime.strptime(
                    priv["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
                delta = (priv_dt - login_dt).total_seconds()
                if 0 <= delta <= PRIV_ESC_WINDOW:
                    alerts.append({
                        "rule_id":    RULE_ID,
                        "rule_name":  RULE_NAME,
                        "alert_type": "priv_after_login",
                        "severity":   "HIGH",
                        "timestamp":  login["timestamp"],
                        "src_ip":     login.get("src_ip", ""),
                        "username":   username,
                        "description": (
                            f"Special privileges assigned to '{username}' "
                            f"within {int(delta)}s of login"
                        ),
                        "evidence": {
                            "login_event": login,
                            "priv_event":  priv,
                            "seconds":     int(delta),
                        },
                    })
                    break
            except ValueError:
                continue

    return alerts


def _check_sudo_after_login(timeline: list[dict]) -> list[dict]:
    """
    Detect sudo execution shortly after SSH login — Linux.
    Pattern: session_opened → sudo_command within PRIV_ESC_WINDOW seconds.
    """
    alerts  = []
    logins  = [e for e in timeline
               if e.get("event_type") in
               ("session_opened", "accepted_password", "accepted_publickey")]
    sudos   = [e for e in timeline
               if e.get("event_type") == "sudo_command"]

    for login in logins:
        username = login.get("username", "")
        if not username:
            continue

        try:
            login_dt = datetime.strptime(
                login["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue

        for sudo in sudos:
            if sudo.get("username") != username:
                continue
            try:
                sudo_dt = datetime.strptime(
                    sudo["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
                delta = (sudo_dt - login_dt).total_seconds()
                if 0 <= delta <= PRIV_ESC_WINDOW:
                    alerts.append({
                        "rule_id":    RULE_ID,
                        "rule_name":  RULE_NAME,
                        "alert_type": "sudo_after_login",
                        "severity":   "HIGH",
                        "timestamp":  login["timestamp"],
                        "src_ip":     login.get("src_ip", ""),
                        "username":   username,
                        "description": (
                            f"Sudo command by '{username}' within "
                            f"{int(delta)}s of SSH login"
                        ),
                        "evidence": {
                            "login_event": login,
                            "sudo_event":  sudo,
                            "seconds":     int(delta),
                        },
                    })
                    break
            except ValueError:
                continue

    return alerts
