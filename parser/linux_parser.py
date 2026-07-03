"""
parser/linux_parser.py — PyShield Incident Analyzer
Parses Linux auth.log / syslog format into normalized event dicts.

Linux auth.log format:
  Jun 27 10:00:00 hostname sshd[1234]: Failed password for admin from 192.168.1.100 port 44562 ssh2
  Jun 27 10:00:01 hostname sshd[1234]: Accepted password for user from 192.168.1.100 port 44563 ssh2
  Jun 27 10:00:02 hostname sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash

This is the same format as existing in  real_auth.log from project6.
The difference here is we extract more fields and normalize to the
common schema instead of just counting failed attempts.
"""

import logging
import re
from datetime import datetime
from pathlib import Path

from config import LINUX_EVENT_TYPES

logger = logging.getLogger("incident.parser.linux")

# ── Regex patterns for each event type ───────────────────────────────────────
_PATTERNS = [
    # Failed password: "Failed password for [invalid user] admin from 1.2.3.4"
    (
        re.compile(
            r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
        ),
        "failed_password",
    ),

    # Accepted password: "Accepted password for user from 1.2.3.4"
    (
        re.compile(
            r"Accepted password for (\S+) from ([\d.]+)"
        ),
        "accepted_password",
    ),

    # Accepted public key
    (
        re.compile(
            r"Accepted publickey for (\S+) from ([\d.]+)"
        ),
        "accepted_publickey",
    ),

    # Invalid user: "Invalid user admin from 1.2.3.4"
    (
        re.compile(
            r"Invalid user (\S+) from ([\d.]+)"
        ),
        "invalid_user",
    ),

    # Sudo command: "user : TTY=... ; COMMAND=/bin/bash"
    (
        re.compile(
            r"(\S+)\s*:.*COMMAND=(.*)"
        ),
        "sudo_command",
    ),

    # New user created: "new user: name=username"
    (
        re.compile(
            r"new user: name=(\S+)"
        ),
        "new_user",
    ),

    # Session opened: "session opened for user admin"
    (
        re.compile(
            r"session opened for user (\S+)"
        ),
        "session_opened",
    ),

    # Session closed: "session closed for user admin"
    (
        re.compile(
            r"session closed for user (\S+)"
        ),
        "session_closed",
    ),
]

# Timestamp pattern: "Jun 27 10:00:00" or "2026-06-27T10:00:00"
_TIMESTAMP_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
_ISO_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
)


# ── Public API ────────────────────────────────────────────────────────────────
def parse(log_path: str, year: int = None) -> list[dict]:
    """
    Parse a Linux auth.log file into normalized events.

    Args:
        log_path: path to auth.log or similar syslog file
        year    : year to use for timestamps (auth.log omits the year)
                  defaults to current year

    Returns:
        List of normalized event dicts.
    """
    path = Path(log_path)
    if not path.exists():
        logger.error("Linux log file not found: %s", log_path)
        return []

    if year is None:
        year = datetime.now().year

    logger.info("Parsing Linux auth log: %s", log_path)

    events = []
    with open(log_path, encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            event = _parse_line(line, year)
            if event:
                events.append(event)

    logger.info("Parsed %d Linux events from %s", len(events), log_path)
    return events


# ── Internal ──────────────────────────────────────────────────────────────────
def _parse_line(line: str, year: int) -> dict | None:
    """Parse one log line into a normalized event dict."""
    # Extract timestamp
    timestamp = _extract_timestamp(line, year)
    if not timestamp:
        return None

    # Extract hostname (second token after timestamp)
    parts    = line.split()
    hostname = parts[3] if len(parts) > 3 else ""
    # Remove process name from hostname if present (hostname sshd[123]:)
    hostname = hostname.split("[")[0].rstrip(":")

    # Try each pattern
    for pattern, event_type in _PATTERNS:
        match = pattern.search(line)
        if match:
            groups   = match.groups()
            username = groups[0] if len(groups) > 0 else ""
            src_ip   = groups[1] if len(groups) > 1 else ""

            # For sudo_command the second group is the command, not IP
            if event_type == "sudo_command":
                src_ip = ""

            category, description, severity = LINUX_EVENT_TYPES.get(
                event_type,
                ("auth", event_type, "INFO")
            )

            return {
                "timestamp":   timestamp,
                "source":      "linux",
                "event_id":    None,
                "event_type":  event_type,
                "category":    category,
                "severity":    severity,
                "username":    username.strip(),
                "src_ip":      src_ip.strip(),
                "hostname":    hostname,
                "description": description,
                "raw":         line[:200],
            }

    return None


def _extract_timestamp(line: str, year: int) -> str:
    """
    Extract and normalize timestamp from log line.

    Handles two formats:
      "Jun 27 10:00:00 ..." → "2026-06-27 10:00:00"
      "2026-06-27T10:00:00" → "2026-06-27 10:00:00"
    """
    # Try ISO format first
    iso_match = _ISO_TIMESTAMP.match(line)
    if iso_match:
        return iso_match.group(1).replace("T", " ")

    # Try syslog format: "Jun 27 10:00:00"
    ts_match = _TIMESTAMP_PATTERN.match(line)
    if ts_match:
        raw = ts_match.group(1)
        try:
            dt = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            try:
                # Handle single-digit day with extra space: "Jun  7"
                dt = datetime.strptime(f"{year} {raw}", "%Y %b  %d %H:%M:%S")
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                return ""

    return ""
