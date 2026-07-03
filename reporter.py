"""
reporter.py — PyShield Incident Analyzer
Writes incident_report.json and prints terminal summary
including the visual ASCII timeline graph.
"""

import json
import logging

from config import INCIDENT_REPORT, TIMELINE_FILE
from timeline import render_ascii

logger = logging.getLogger("incident.reporter")


def write(report: dict) -> None:
    """Write full incident report to JSON."""
    try:
        with open(INCIDENT_REPORT, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, default=str)
        logger.info("Incident report saved to %s", INCIDENT_REPORT)
    except Exception as e:
        logger.error("Failed to write report: %s", e)


def write_timeline(timeline: list[dict]) -> None:
    """Write timeline separately for easy reading."""
    try:
        with open(TIMELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(timeline, f, indent=4, default=str)
        logger.info("Timeline saved to %s", TIMELINE_FILE)
    except Exception as e:
        logger.error("Failed to write timeline: %s", e)


def print_summary(report: dict) -> None:
    """Print clean terminal summary with visual timeline."""
    counts = report.get("alert_counts", {})
    iocs   = report.get("iocs", {})

    print("\n" + "=" * 65)
    print("  PyShield Incident Analyzer — Report")
    print("=" * 65)
    print(f"  Timestamp   : {report['timestamp']}")
    print(f"  Log Sources : {', '.join(report.get('log_sources', []))}")
    print(f"  Events      : {report['total_events']} analyzed")
    print(f"  Risk Score  : {report['total_score']}")
    print(f"  Risk Level  : {report['risk_level']}")
    print("-" * 65)
    print(
        f"  Alerts      : {report['total_alerts']} total | "
        f"CRITICAL:{counts.get('CRITICAL',0)} "
        f"HIGH:{counts.get('HIGH',0)} "
        f"MEDIUM:{counts.get('MEDIUM',0)} "
        f"LOW:{counts.get('LOW',0)}"
    )
    print("-" * 65)

    # IOC summary
    mal_ips = iocs.get("malicious_ips", [])
    users   = iocs.get("targeted_users", [])
    if mal_ips:
        print(f"  Malicious IPs   : {len(mal_ips)}")
        for ip in mal_ips[:3]:
            comp = " ← COMPROMISED" if ip["compromised"] else ""
            print(
                f"    {ip['ip']:18} failed={ip['failed_logins']} "
                f"success={ip['successful_logins']}{comp}"
            )
    if users:
        print(f"  Targeted Users  : {len(users)}")
        for u in users[:3]:
            comp = " ← COMPROMISED" if u["compromised"] else ""
            print(
                f"    {u['username']:18} failed={u['failed']} "
                f"success={u['success']}{comp}"
            )
    print("-" * 65)

    # Summary lines
    print("  SUMMARY:")
    for line in report.get("summary", []):
        print(f"  {line}")
    print("-" * 65)

    # Alerts
    print("  ALERTS:")
    for alert in report.get("alerts", [])[:10]:
        sev  = alert.get("severity", "")
        desc = alert.get("description", "")[:55]
        print(f"  [{sev:8}] {desc}")
    print("-" * 65)

    # Visual timeline
    print("  ATTACK TIMELINE:")
    print(render_ascii(report.get("timeline", []), max_events=20))
    print("=" * 65)
    print(f"  Full report : {INCIDENT_REPORT}")
    print(f"  Timeline    : {TIMELINE_FILE}\n")
