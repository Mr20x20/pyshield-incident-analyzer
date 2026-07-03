"""
normalizer.py — PyShield Incident Analyzer
Takes raw events from all three parsers and ensures they all
conform to the same schema before the timeline and rules run.

Why normalization matters:
  Windows says "TargetUserName" for the username field.
  Linux says the username is captured by regex group 1.
  Honeypot says "attacker_ip" for the source IP.

  After normalization, every event has the same keys.
  The timeline, rules, and IOC extractor never need to know
  which parser produced an event — they just work.
"""

import logging
from datetime import datetime

logger = logging.getLogger("incident.normalizer")

# Required fields every normalized event must have
_REQUIRED_FIELDS = [
    "timestamp",
    "source",
    "event_id",
    "event_type",
    "category",
    "severity",
    "username",
    "src_ip",
    "hostname",
    "description",
    "raw",
]

# Valid severity values
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# Valid source values
_VALID_SOURCES = {"windows", "linux", "honeypot"}


# ── Public API ────────────────────────────────────────────────────────────────
def normalize_all(raw_events: list[dict]) -> list[dict]:
    """
    Normalize and validate a list of raw events from any parser.

    Args:
        raw_events: combined output from all parsers

    Returns:
        List of validated, normalized event dicts.
        Invalid events are dropped with a debug log.
    """
    normalized = []
    skipped    = 0

    for event in raw_events:
        clean = _normalize_one(event)
        if clean:
            normalized.append(clean)
        else:
            skipped += 1

    logger.info(
        "Normalization complete: %d valid events, %d skipped",
        len(normalized), skipped
    )
    return normalized


# ── Internal ──────────────────────────────────────────────────────────────────
def _normalize_one(event: dict) -> dict | None:
    """
    Normalize and validate a single event dict.
    Returns None if the event is invalid or missing critical fields.
    """
    if not isinstance(event, dict):
        return None

    # Ensure all required fields exist — fill missing with defaults
    clean = {}
    for field in _REQUIRED_FIELDS:
        clean[field] = event.get(field, "")

    # ── Validate and clean timestamp ──────────────────────────────────────────
    clean["timestamp"] = _clean_timestamp(clean["timestamp"])
    if not clean["timestamp"]:
        logger.debug("Dropping event with invalid timestamp: %s", event)
        return None

    # ── Validate source ───────────────────────────────────────────────────────
    if clean["source"] not in _VALID_SOURCES:
        clean["source"] = "unknown"

    # ── Validate severity ─────────────────────────────────────────────────────
    if clean["severity"] not in _VALID_SEVERITIES:
        clean["severity"] = "INFO"

    # ── Clean string fields ───────────────────────────────────────────────────
    clean["username"]    = _clean_str(clean["username"])
    clean["src_ip"]      = _clean_ip(clean["src_ip"])
    clean["hostname"]    = _clean_str(clean["hostname"])
    clean["description"] = _clean_str(clean["description"])
    clean["event_type"]  = _clean_str(clean["event_type"]) or "unknown"

    # ── Ensure event_id is int or None ────────────────────────────────────────
    try:
        clean["event_id"] = int(clean["event_id"]) if clean["event_id"] else None
    except (ValueError, TypeError):
        clean["event_id"] = None

    return clean


def _clean_timestamp(ts: str) -> str:
    """
    Validate and standardize timestamp to "YYYY-MM-DD HH:MM:SS".
    Returns empty string if timestamp cannot be parsed.
    """
    if not ts:
        return ""

    # Already in correct format
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(ts[:19], fmt[:len(ts[:19])])
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

    return ""


def _clean_str(value: str) -> str:
    """Strip whitespace and remove null bytes from string fields."""
    if not isinstance(value, str):
        return str(value) if value else ""
    return value.strip().replace("\x00", "")


def _clean_ip(ip: str) -> str:
    """
    Clean and validate IP address string.
    Returns empty string for placeholder values Windows uses.
    """
    if not ip:
        return ""
    ip = ip.strip()
    # Windows placeholder values
    if ip in ("-", "::1", "127.0.0.1", "LOCAL", "0.0.0.0"):
        return ""
    return ip
