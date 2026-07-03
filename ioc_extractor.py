"""
ioc_extractor.py — PyShield Incident Analyzer
Extracts Indicators of Compromise (IOCs) from the timeline and alerts.

IOCs are specific artifacts that indicate malicious activity:
  - IP addresses seen in attacks
  - Usernames used in attacks
  - Timestamps of key events

These are what incident responders use to:
  - Block attacker IPs in firewall
  - Disable compromised accounts
  - Search other systems for the same indicators
"""

import logging
from collections import defaultdict

logger = logging.getLogger("incident.ioc_extractor")


# ── Public API ────────────────────────────────────────────────────────────────
def extract(timeline: list[dict], alerts: list[dict]) -> dict:
    """
    Extract all IOCs from timeline and alerts.

    Returns:
    {
        "malicious_ips":   [{"ip": "1.2.3.4", "count": 14, "type": "brute_force"}],
        "targeted_users":  [{"username": "admin", "failed": 10, "success": 1}],
        "attack_timeline": [{"timestamp": "...", "event": "..."}],
        "summary":         {"total_ips": 3, "total_users": 2}
    }
    """
    malicious_ips  = _extract_ips(timeline, alerts)
    targeted_users = _extract_users(timeline, alerts)
    attack_timeline = _build_attack_timeline(timeline, alerts)

    result = {
        "malicious_ips":   malicious_ips,
        "targeted_users":  targeted_users,
        "attack_timeline": attack_timeline,
        "summary": {
            "total_malicious_ips":  len(malicious_ips),
            "total_targeted_users": len(targeted_users),
            "total_attack_events":  len(attack_timeline),
        }
    }

    logger.info(
        "IOC extraction: %d IPs, %d users, %d attack events",
        len(malicious_ips),
        len(targeted_users),
        len(attack_timeline),
    )
    return result


# ── Internal ──────────────────────────────────────────────────────────────────
def _extract_ips(timeline: list[dict], alerts: list[dict]) -> list[dict]:
    """
    Extract malicious IP addresses with activity counts.
    Combines evidence from timeline events and rule alerts.
    """
    ip_data = defaultdict(lambda: {
        "failed_logins":    0,
        "successful_logins": 0,
        "http_probes":      0,
        "alert_types":      set(),
    })

    # Count activity from timeline
    for event in timeline:
        ip = event.get("src_ip", "")
        if not ip:
            continue

        etype = event.get("event_type", "")
        if etype in ("failed_login", "failed_password", "invalid_user"):
            ip_data[ip]["failed_logins"] += 1
        elif etype in ("successful_login", "accepted_password",
                       "accepted_publickey"):
            ip_data[ip]["successful_logins"] += 1
        elif etype == "honeypot_http_probe":
            ip_data[ip]["http_probes"] += 1

    # Add alert types from rules
    for alert in alerts:
        ip = alert.get("src_ip", "")
        if ip:
            ip_data[ip]["alert_types"].add(alert.get("alert_type", ""))

    # Build result list — only IPs with suspicious activity
    result = []
    for ip, data in ip_data.items():
        total_activity = (
            data["failed_logins"] +
            data["successful_logins"] +
            data["http_probes"]
        )

        # Only include IPs with failed logins or alerts
        if data["failed_logins"] > 0 or data["alert_types"]:
            result.append({
                "ip":               ip,
                "failed_logins":    data["failed_logins"],
                "successful_logins":data["successful_logins"],
                "http_probes":      data["http_probes"],
                "total_activity":   total_activity,
                "alert_types":      list(data["alert_types"]),
                "compromised":      data["successful_logins"] > 0,
            })

    # Sort by total activity descending
    result.sort(key=lambda x: x["total_activity"], reverse=True)
    return result


def _extract_users(timeline: list[dict], alerts: list[dict]) -> list[dict]:
    """
    Extract targeted usernames with activity counts.
    """
    user_data = defaultdict(lambda: {
        "failed":   0,
        "success":  0,
        "sources":  set(),
        "alerts":   set(),
    })

    for event in timeline:
        username = event.get("username", "")
        if not username or username in ("SYSTEM", "-", ""):
            continue

        etype = event.get("event_type", "")
        if etype in ("failed_login", "failed_password", "invalid_user"):
            user_data[username]["failed"] += 1
        elif etype in ("successful_login", "accepted_password",
                       "accepted_publickey"):
            user_data[username]["success"] += 1

        user_data[username]["sources"].add(event.get("source", ""))

    for alert in alerts:
        username = alert.get("username", "")
        if username:
            user_data[username]["alerts"].add(alert.get("alert_type", ""))

    result = []
    for username, data in user_data.items():
        if data["failed"] > 0 or data["alerts"]:
            result.append({
                "username":    username,
                "failed":      data["failed"],
                "success":     data["success"],
                "sources":     list(data["sources"]),
                "alerts":      list(data["alerts"]),
                "compromised": data["success"] > 0,
            })

    result.sort(key=lambda x: x["failed"], reverse=True)
    return result


def _build_attack_timeline(timeline: list[dict],
                           alerts: list[dict]) -> list[dict]:
    """
    Build a condensed attack timeline showing only
    significant events — not every INFO-level event.
    """
    significant = []

    # Include HIGH and CRITICAL events from timeline
    for event in timeline:
        if event.get("severity") in ("HIGH", "CRITICAL", "MEDIUM"):
            significant.append({
                "timestamp":   event["timestamp"],
                "type":        "event",
                "severity":    event["severity"],
                "description": event["description"],
                "src_ip":      event.get("src_ip", ""),
                "username":    event.get("username", ""),
                "source":      event.get("source", ""),
            })

    # Include all rule alerts
    for alert in alerts:
        significant.append({
            "timestamp":   alert["timestamp"],
            "type":        "alert",
            "severity":    alert["severity"],
            "description": alert["description"],
            "src_ip":      alert.get("src_ip", ""),
            "username":    alert.get("username", ""),
            "rule":        alert.get("rule_name", ""),
        })

    # Sort chronologically
    significant.sort(key=lambda x: x.get("timestamp", ""))
    return significant
