"""
parser/windows_parser.py — PyShield Incident Analyzer
Parses Windows Event Log XML format into normalized event dicts.

Windows Event Logs are stored as .evtx files but can be exported
to XML format. Each event looks like:

<Event>
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-06-27T10:00:00.000000000Z"/>
    <Computer>WORKSTATION-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="IpAddress">192.168.1.100</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>

How to export Windows Event Logs to XML:
  1. Open Event Viewer (eventvwr.msc)
  2. Right-click a log → Save All Events As → save as .xml
  Or use PowerShell:
  Get-WinEvent -LogName Security | Export-Clixml security.xml
"""

import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from config import WINDOWS_EVENT_IDS

logger = logging.getLogger("incident.parser.windows")

# XML namespace used in Windows Event Log exports
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


# ── Public API ────────────────────────────────────────────────────────────────
def parse(log_path: str) -> list[dict]:
    """
    Parse a Windows Event Log XML file into normalized events.

    Args:
        log_path: path to .xml exported Windows Event Log

    Returns:
        List of normalized event dicts matching config schema.
    """
    path = Path(log_path)
    if not path.exists():
        logger.error("Windows log file not found: %s", log_path)
        return []

    logger.info("Parsing Windows Event Log: %s", log_path)

    try:
        tree = ET.parse(log_path)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error("XML parse error in %s: %s", log_path, e)
        return []

    events   = []
    # Handle both wrapped (<Events>) and unwrapped root formats
    elements = root.findall(".//e:Event", _NS) or root.findall(".//Event")

    for element in elements:
        event = _parse_event(element)
        if event:
            events.append(event)

    logger.info("Parsed %d Windows events from %s", len(events), log_path)
    return events


# ── Internal ──────────────────────────────────────────────────────────────────
def _parse_event(element: ET.Element) -> dict | None:
    """Parse a single <Event> XML element into a normalized dict."""
    try:
        # ── System section ────────────────────────────────────────────────────
        system = (
            element.find("e:System", _NS) or
            element.find("System")
        )
        if system is None:
            return None

        event_id_el = (
            system.find("e:EventID", _NS) or
            system.find("EventID")
        )
        if event_id_el is None:
            return None

        event_id = int(event_id_el.text.strip())

        # Only process Event IDs we care about
        if event_id not in WINDOWS_EVENT_IDS:
            return None

        category, description, severity = WINDOWS_EVENT_IDS[event_id]

        # Timestamp
        time_el = (
            system.find("e:TimeCreated", _NS) or
            system.find("TimeCreated")
        )
        timestamp = ""
        if time_el is not None:
            raw_time = time_el.get("SystemTime", "")
            timestamp = _parse_timestamp(raw_time)

        # Hostname
        computer_el = (
            system.find("e:Computer", _NS) or
            system.find("Computer")
        )
        hostname = computer_el.text.strip() if computer_el is not None else ""

        # ── EventData section ─────────────────────────────────────────────────
        event_data = (
            element.find("e:EventData", _NS) or
            element.find("EventData")
        )
        data = _extract_event_data(event_data)

        # Extract common fields from EventData
        username = (
            data.get("TargetUserName") or
            data.get("SubjectUserName") or
            data.get("AccountName") or
            ""
        )
        src_ip = (
            data.get("IpAddress") or
            data.get("WorkstationName") or
            ""
        )

        # Clean up placeholder values Windows uses
        if username in ("-", "SYSTEM", ""):
            username = data.get("SubjectUserName", "")
        if src_ip in ("-", "::1", "127.0.0.1"):
            src_ip = ""

        return {
            "timestamp":   timestamp,
            "source":      "windows",
            "event_id":    event_id,
            "event_type":  _get_event_type(event_id),
            "category":    category,
            "severity":    severity,
            "username":    username.strip(),
            "src_ip":      src_ip.strip(),
            "hostname":    hostname,
            "description": description,
            "raw":         ET.tostring(element, encoding="unicode")[:200],
        }

    except Exception as e:
        logger.debug("Failed to parse event element: %s", e)
        return None


def _extract_event_data(event_data: ET.Element | None) -> dict:
    """
    Extract all <Data Name="...">value</Data> pairs into a dict.
    Returns empty dict if EventData is missing.
    """
    if event_data is None:
        return {}

    result = {}
    for data_el in event_data:
        name  = data_el.get("Name", "")
        value = (data_el.text or "").strip()
        if name:
            result[name] = value
    return result


def _parse_timestamp(raw: str) -> str:
    """
    Convert Windows event timestamp to standard format.
    Input:  "2026-06-27T10:00:00.000000000Z"
    Output: "2026-06-27 10:00:00"
    """
    try:
        # Trim nanoseconds — Python only handles microseconds
        raw = raw[:26].rstrip("Z").replace("T", " ")
        dt  = datetime.fromisoformat(raw)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return raw[:19].replace("T", " ")


def _get_event_type(event_id: int) -> str:
    """Map Event ID to a normalized event_type string."""
    mapping = {
        4624: "successful_login",
        4625: "failed_login",
        4634: "logoff",
        4648: "explicit_credential_logon",
        4672: "privilege_assigned",
        4688: "process_created",
        4698: "scheduled_task_created",
        4720: "user_created",
        4722: "user_enabled",
        4724: "password_reset",
        4728: "group_member_added",
        4732: "admin_group_member_added",
        4756: "universal_group_member_added",
        7045: "service_installed",
    }
    return mapping.get(event_id, f"event_{event_id}")
