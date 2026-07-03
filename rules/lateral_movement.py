"""
rules/lateral_movement.py — PyShield Incident Analyzer
Detects lateral movement patterns.

Lateral movement is when an attacker moves from one system to another
after gaining initial access — trying to reach higher-value targets.

Patterns we detect:
  1. Same user logging in from multiple different IPs in short timeframe
     → credential reuse across systems
  2. Login from an IP that was previously seen in failed attempts
     → attacker succeeded after earlier reconnaissance
  3. Multiple different usernames tried from same IP then one succeeds
     → credential stuffing that worked
"""

import logging
from collections import defaultdict
from datetime import datetime

from config import LATERAL_MOVEMENT_WINDOW

logger = logging.getLogger("incident.rules.lateral_movement")

RULE_ID   = "RULE-004"
RULE_NAME = "Lateral Movement Detection"


def run(timeline: list[dict]) -> list[dict]:
    """Scan timeline for lateral movement patterns."""
    alerts = []

    alerts.extend(_check_multi_ip_login(timeline))
    alerts.extend(_check_recon_then_success(timeline))
    alerts.extend(_check_credential_stuffing_success(timeline))

    logger.info("%s: %d alert(s) generated", RULE_NAME, len(alerts))
    return alerts


def _check_multi_ip_login(timeline: list[dict]) -> list[dict]:
    """
    Detect same username logging in from multiple IPs in short window.
    Legitimate users don't usually log in from 3 different IPs in 1 hour.
    """
    alerts  = []
    logins  = [e for e in timeline
               if e.get("event_type") in
               ("successful_login", "accepted_password", "accepted_publickey")
               and e.get("src_ip") and e.get("username")]

    # Group successful logins by username
    by_user = defaultdict(list)
    for event in logins:
        by_user[event["username"]].append(event)

    for username, user_logins in by_user.items():
        if len(user_logins) < 2:
            continue

        # Check for multiple IPs within window
        for i, anchor in enumerate(user_logins):
            try:
                anchor_dt = datetime.strptime(
                    anchor["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                continue

            window_logins = []
            for login in user_logins[i:]:
                try:
                    login_dt = datetime.strptime(
                        login["timestamp"], "%Y-%m-%d %H:%M:%S"
                    )
                    delta = (login_dt - anchor_dt).total_seconds()
                    if 0 <= delta <= LATERAL_MOVEMENT_WINDOW:
                        window_logins.append(login)
                    elif delta > LATERAL_MOVEMENT_WINDOW:
                        break
                except ValueError:
                    continue

            unique_ips = list({e["src_ip"] for e in window_logins
                               if e.get("src_ip")})

            if len(unique_ips) >= 3:
                alerts.append({
                    "rule_id":    RULE_ID,
                    "rule_name":  RULE_NAME,
                    "alert_type": "multi_ip_login",
                    "severity":   "HIGH",
                    "timestamp":  anchor["timestamp"],
                    "src_ip":     unique_ips[0],
                    "username":   username,
                    "description": (
                        f"User '{username}' logged in from "
                        f"{len(unique_ips)} different IPs within "
                        f"{LATERAL_MOVEMENT_WINDOW // 60} minutes — "
                        f"possible credential reuse"
                    ),
                    "evidence": {
                        "unique_ips":      unique_ips,
                        "login_count":     len(window_logins),
                        "window_minutes":  LATERAL_MOVEMENT_WINDOW // 60,
                    },
                })
                break

    return alerts


def _check_recon_then_success(timeline: list[dict]) -> list[dict]:
    """
    Detect an IP that had failed logins earlier then succeeded.
    Pattern: failed_login from IP X → successful_login from IP X
    This means the attacker's reconnaissance paid off.
    """
    alerts = []

    # Group by IP
    by_ip  = defaultdict(lambda: {"failed": [], "success": []})
    for event in timeline:
        ip = event.get("src_ip", "")
        if not ip:
            continue
        if event.get("event_type") in (
            "failed_login", "failed_password", "invalid_user"
        ):
            by_ip[ip]["failed"].append(event)
        elif event.get("event_type") in (
            "successful_login", "accepted_password", "accepted_publickey"
        ):
            by_ip[ip]["success"].append(event)

    for ip, events in by_ip.items():
        if not events["failed"] or not events["success"]:
            continue

        # Check if any success came after a failed attempt
        for success in events["success"]:
            try:
                success_dt = datetime.strptime(
                    success["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                continue

            prior_fails = [
                e for e in events["failed"]
                if _is_before(e["timestamp"], success["timestamp"])
            ]

            if prior_fails:
                alerts.append({
                    "rule_id":    RULE_ID,
                    "rule_name":  RULE_NAME,
                    "alert_type": "recon_then_success",
                    "severity":   "CRITICAL",
                    "timestamp":  success["timestamp"],
                    "src_ip":     ip,
                    "username":   success.get("username", ""),
                    "description": (
                        f"IP {ip} had {len(prior_fails)} failed attempt(s) "
                        f"then successfully logged in as "
                        f"'{success.get('username')}' — "
                        f"attacker succeeded after reconnaissance"
                    ),
                    "evidence": {
                        "failed_count":  len(prior_fails),
                        "first_fail":    prior_fails[0]["timestamp"],
                        "success_event": success,
                    },
                })
                break

    return alerts


def _check_credential_stuffing_success(timeline: list[dict]) -> list[dict]:
    """
    Detect credential stuffing — many different usernames tried from
    one IP, then one succeeds.
    """
    alerts = []
    by_ip  = defaultdict(lambda: {"tried_users": set(), "success": []})

    for event in timeline:
        ip       = event.get("src_ip", "")
        username = event.get("username", "")
        if not ip or not username:
            continue

        if event.get("event_type") in (
            "failed_login", "failed_password", "invalid_user"
        ):
            by_ip[ip]["tried_users"].add(username)
        elif event.get("event_type") in (
            "successful_login", "accepted_password"
        ):
            by_ip[ip]["success"].append(event)

    for ip, data in by_ip.items():
        # More than 5 unique usernames tried = credential stuffing
        if len(data["tried_users"]) >= 5 and data["success"]:
            for success in data["success"]:
                alerts.append({
                    "rule_id":    RULE_ID,
                    "rule_name":  RULE_NAME,
                    "alert_type": "credential_stuffing_success",
                    "severity":   "CRITICAL",
                    "timestamp":  success["timestamp"],
                    "src_ip":     ip,
                    "username":   success.get("username", ""),
                    "description": (
                        f"Credential stuffing from IP {ip} — "
                        f"{len(data['tried_users'])} usernames tried, "
                        f"'{success.get('username')}' succeeded"
                    ),
                    "evidence": {
                        "unique_usernames_tried": len(data["tried_users"]),
                        "success_event":          success,
                    },
                })
            break

    return alerts


# ── Helper ────────────────────────────────────────────────────────────────────
def _is_before(ts_a: str, ts_b: str) -> bool:
    """Return True if timestamp A is before timestamp B."""
    try:
        a = datetime.strptime(ts_a, "%Y-%m-%d %H:%M:%S")
        b = datetime.strptime(ts_b, "%Y-%m-%d %H:%M:%S")
        return a < b
    except ValueError:
        return False
