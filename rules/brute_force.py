"""
rules/brute_force.py — PyShield Incident Analyzer
Detects brute force login attempts.

Pattern:
  N failed logins from the same IP within TIME_WINDOW seconds
  → flag as brute force attack

If a successful login follows the failed attempts:
  → escalate to "brute_force_success" — attacker got in
"""

import logging
from collections import defaultdict
from datetime import datetime

from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW

logger = logging.getLogger("incident.rules.brute_force")

RULE_ID   = "RULE-001"
RULE_NAME = "Brute Force Login Detection"


def run(timeline: list[dict]) -> list[dict]:
    """
    Scan timeline for brute force patterns.
    Returns list of alert dicts.
    """
    alerts    = []
    # Group failed logins by source IP
    by_ip     = defaultdict(list)

    for event in timeline:
        if event.get("event_type") in ("failed_login", "failed_password",
                                        "invalid_user"):
            ip = event.get("src_ip", "")
            if ip:
                by_ip[ip].append(event)

    for ip, failed_events in by_ip.items():
        alerts.extend(_check_ip(ip, failed_events, timeline))

    logger.info("%s: %d alert(s) generated", RULE_NAME, len(alerts))
    return alerts


def _check_ip(ip: str, failed_events: list[dict],
              full_timeline: list[dict]) -> list[dict]:
    """Check if one IP's failed logins constitute a brute force."""
    alerts = []

    # Sliding window — check each group of consecutive failures
    for i, anchor in enumerate(failed_events):
        try:
            anchor_dt = datetime.strptime(
                anchor["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue

        # Count failures within window from this anchor
        window_failures = []
        for event in failed_events[i:]:
            try:
                event_dt = datetime.strptime(
                    event["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
                delta = (event_dt - anchor_dt).total_seconds()
                if 0 <= delta <= BRUTE_FORCE_WINDOW:
                    window_failures.append(event)
                elif delta > BRUTE_FORCE_WINDOW:
                    break
            except ValueError:
                continue

        if len(window_failures) >= BRUTE_FORCE_THRESHOLD:
            # Check if a successful login followed
            success = _find_success_after(
                ip, anchor["timestamp"], full_timeline
            )

            severity    = "CRITICAL" if success else "HIGH"
            alert_type  = "brute_force_success" if success else "brute_force"
            description = (
                f"Brute force SUCCESS — attacker logged in after "
                f"{len(window_failures)} failed attempts"
                if success else
                f"Brute force attempt — {len(window_failures)} failed "
                f"logins within {BRUTE_FORCE_WINDOW}s"
            )

            usernames = list({
                e.get("username", "") for e in window_failures
                if e.get("username")
            })

            alerts.append({
                "rule_id":     RULE_ID,
                "rule_name":   RULE_NAME,
                "alert_type":  alert_type,
                "severity":    severity,
                "timestamp":   anchor["timestamp"],
                "src_ip":      ip,
                "username":    usernames[0] if len(usernames) == 1
                               else str(usernames),
                "description": description,
                "evidence": {
                    "failed_count":   len(window_failures),
                    "window_seconds": BRUTE_FORCE_WINDOW,
                    "usernames_tried":usernames,
                    "success_event":  success,
                },
            })
            break   # one alert per IP per window

    return alerts


def _find_success_after(ip: str, after_ts: str,
                        timeline: list[dict]) -> dict | None:
    """
    Look for a successful login from the same IP after the brute force.
    Returns the success event or None.
    """
    try:
        after_dt = datetime.strptime(after_ts, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    for event in timeline:
        if event.get("src_ip") != ip:
            continue
        if event.get("event_type") not in (
            "successful_login", "accepted_password", "accepted_publickey"
        ):
            continue
        try:
            event_dt = datetime.strptime(
                event["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
            if event_dt > after_dt:
                return event
        except ValueError:
            continue

    return None
