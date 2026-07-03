"""
timeline.py — PyShield Incident Analyzer
Sorts normalized events chronologically and builds
a structured timeline for analysis and reporting.

The timeline is the foundation everything else builds on:
  - Rules engine queries the timeline to detect patterns
  - IOC extractor walks the timeline to find indicators
  - Reporter renders the timeline as a visual graph
"""

import logging
from datetime import datetime

logger = logging.getLogger("incident.timeline")


# ── Public API ────────────────────────────────────────────────────────────────
def build(normalized_events: list[dict]) -> list[dict]:
    """
    Sort events chronologically and add sequence numbers.

    Args:
        normalized_events: output from normalizer.normalize_all()

    Returns:
        Same list sorted oldest → newest, with "seq" field added.
        Events with unparseable timestamps go to the end.
    """
    if not normalized_events:
        logger.warning("No events to build timeline from")
        return []

    # Sort by timestamp — events without timestamps go last
    def sort_key(event: dict):
        ts = event.get("timestamp", "")
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.max

    sorted_events = sorted(normalized_events, key=sort_key)

    # Add sequence numbers for easy reference in reports
    for i, event in enumerate(sorted_events, 1):
        event["seq"] = i

    logger.info(
        "Timeline built: %d events | %s → %s",
        len(sorted_events),
        sorted_events[0]["timestamp"] if sorted_events else "?",
        sorted_events[-1]["timestamp"] if sorted_events else "?",
    )

    return sorted_events


def get_events_in_window(timeline: list[dict],
                         anchor_ts: str,
                         window_seconds: int,
                         before: bool = False) -> list[dict]:
    """
    Get all events within a time window relative to an anchor timestamp.

    Used by detection rules to find related events.
    Example: "find all events within 5 minutes after this failed login"

    Args:
        timeline       : sorted event list
        anchor_ts      : reference timestamp string
        window_seconds : how many seconds to look forward (or back)
        before         : if True, look backward instead of forward

    Returns:
        List of events within the window.
    """
    try:
        anchor = datetime.strptime(anchor_ts, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return []

    result = []
    for event in timeline:
        try:
            event_dt = datetime.strptime(
                event["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
            if before:
                delta = (anchor - event_dt).total_seconds()
            else:
                delta = (event_dt - anchor).total_seconds()

            if 0 <= delta <= window_seconds:
                result.append(event)
        except ValueError:
            continue

    return result


def get_events_by_ip(timeline: list[dict], ip: str) -> list[dict]:
    """Return all events from a specific source IP."""
    return [e for e in timeline if e.get("src_ip") == ip]


def get_events_by_user(timeline: list[dict], username: str) -> list[dict]:
    """Return all events involving a specific username."""
    return [e for e in timeline if e.get("username") == username]


def get_events_by_type(timeline: list[dict],
                       event_type: str) -> list[dict]:
    """Return all events of a specific type."""
    return [e for e in timeline if e.get("event_type") == event_type]


def render_ascii(timeline: list[dict], max_events: int = 30) -> str:
    """
    Render a visual ASCII timeline for terminal output and reports.

    Example output:
      [001] 2026-06-27 10:00:00  MEDIUM  [linux   ] Failed SSH password   user=admin ip=1.2.3.4
      [002] 2026-06-27 10:00:05  MEDIUM  [linux   ] Failed SSH password   user=admin ip=1.2.3.4
      [003] 2026-06-27 10:00:10  INFO    [linux   ] Accepted SSH password  user=admin ip=1.2.3.4
      [004] 2026-06-27 10:00:15  HIGH    [linux   ] Sudo command executed  user=admin
    """
    if not timeline:
        return "  No events in timeline."

    lines = []
    events_to_show = timeline[:max_events]

    for event in events_to_show:
        seq      = event.get("seq", "?")
        ts       = event.get("timestamp", "")[:19]
        severity = event.get("severity", "INFO")[:8].ljust(8)
        source   = event.get("source", "")[:8].ljust(8)
        desc     = event.get("description", "")[:40].ljust(40)
        username = event.get("username", "")
        src_ip   = event.get("src_ip", "")

        # Build context string
        context = ""
        if username:
            context += f"user={username} "
        if src_ip:
            context += f"ip={src_ip}"

        lines.append(
            f"  [{seq:03}] {ts}  {severity}  [{source}] {desc}  {context}"
        )

    if len(timeline) > max_events:
        lines.append(
            f"\n  ... and {len(timeline) - max_events} more events "
            f"(see incident_report.json for full timeline)"
        )

    return "\n".join(lines)
