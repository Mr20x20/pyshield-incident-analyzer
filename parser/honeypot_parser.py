"""
parser/honeypot_parser.py — PyShield Incident Analyzer
Reads honeypot_report.json from project7 (PyShield Honeypot)
and converts it into normalized event dicts.

This is the connection point between project7 and project10.
The honeypot has already collected attacker behavior —
we just need to normalize it into our common schema.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger("incident.parser.honeypot")


# ── Public API ────────────────────────────────────────────────────────────────
def parse(report_path: str) -> list[dict]:
    """
    Parse honeypot_report.json into normalized events.

    Args:
        report_path: path to honeypot_report.json from project7

    Returns:
        List of normalized event dicts.
    """
    path = Path(report_path)
    if not path.exists():
        logger.error("Honeypot report not found: %s", report_path)
        return []

    logger.info("Parsing honeypot report: %s", report_path)

    try:
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        logger.error("Failed to read honeypot report: %s", e)
        return []

    events = []

    # Parse recent_events list from honeypot report
    for raw_event in report.get("recent_events", []):
        event = _normalize_honeypot_event(raw_event)
        if event:
            events.append(event)

    logger.info(
        "Parsed %d honeypot events from %s",
        len(events), report_path
    )
    return events


# ── Internal ──────────────────────────────────────────────────────────────────
def _normalize_honeypot_event(raw: dict) -> dict | None:
    """Convert a single honeypot event dict to normalized schema."""
    try:
        service    = raw.get("service", "")
        event_type = raw.get("event_type", "")
        src_ip     = raw.get("attacker_ip", "")
        timestamp  = raw.get("timestamp", "")
        username   = raw.get("username", "")
        password   = raw.get("password", "")
        http_path  = raw.get("http_path", "")
        user_agent = raw.get("user_agent", "")

        # Map honeypot event types to normalized types
        if service == "ssh" and event_type == "auth_attempt":
            norm_type   = "failed_login"
            category    = "auth"
            severity    = "MEDIUM"
            description = f"Honeypot SSH attempt: user='{username}'"

        elif service == "http" and event_type == "http_request":
            norm_type   = "honeypot_http_probe"
            category    = "auth"
            severity    = "LOW"
            description = f"Honeypot HTTP probe: {http_path} (UA: {user_agent[:40]})"

        else:
            norm_type   = "honeypot_event"
            category    = "auth"
            severity    = "LOW"
            description = f"Honeypot event: {service} {event_type}"

        return {
            "timestamp":   timestamp,
            "source":      "honeypot",
            "event_id":    None,
            "event_type":  norm_type,
            "category":    category,
            "severity":    severity,
            "username":    username,
            "src_ip":      src_ip,
            "hostname":    "honeypot",
            "description": description,
            "raw":         str(raw)[:200],
        }

    except Exception as e:
        logger.debug("Failed to normalize honeypot event: %s", e)
        return None
