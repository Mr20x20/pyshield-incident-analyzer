"""
run.py — PyShield Incident Analyzer
Entry point. Accepts log files as arguments and runs the full pipeline.

Usage:
    python run.py --linux real_auth.log
    python run.py --windows security.xml
    python run.py --honeypot honeypot_report.json
    python run.py --linux auth.log --honeypot honeypot_report.json

Pipeline:
    1. Parse      → read log files into raw events
    2. Normalize  → enforce common schema
    3. Timeline   → sort chronologically
    4. Rules      → run all detection rules
    5. IOC        → extract indicators of compromise
    6. Risk       → score and assess
    7. Report     → write JSON + print summary
"""

import argparse
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("incident.run")

from parser import windows_parser, linux_parser, honeypot_parser
from normalizer import normalize_all
from timeline import build as build_timeline, render_ascii
from rules import ALL_RULES
from ioc_extractor import extract as extract_iocs
import risk_engine
import reporter


def run(linux_logs: list = None,
        windows_logs: list = None,
        honeypot_logs: list = None) -> dict:
    """
    Run full incident analysis pipeline.

    Args:
        linux_logs   : list of Linux auth.log paths
        windows_logs : list of Windows Event XML paths
        honeypot_logs: list of honeypot_report.json paths

    Returns:
        Full incident report dict
    """
    linux_logs    = linux_logs    or []
    windows_logs  = windows_logs  or []
    honeypot_logs = honeypot_logs or []

    sources = []
    logger.info("=" * 55)
    logger.info("  PyShield Incident Analyzer")
    logger.info("=" * 55)

    # ── Step 1: Parse all log sources ────────────────────────────────────────
    logger.info("[1/6] Parsing log files...")
    raw_events = []

    for path in linux_logs:
        events = linux_parser.parse(path)
        raw_events.extend(events)
        sources.append(f"linux:{path}")
        logger.info("  Linux: %d events from %s", len(events), path)

    for path in windows_logs:
        events = windows_parser.parse(path)
        raw_events.extend(events)
        sources.append(f"windows:{path}")
        logger.info("  Windows: %d events from %s", len(events), path)

    for path in honeypot_logs:
        events = honeypot_parser.parse(path)
        raw_events.extend(events)
        sources.append(f"honeypot:{path}")
        logger.info("  Honeypot: %d events from %s", len(events), path)

    if not raw_events:
        logger.error("No events parsed — check log file paths")
        return {}

    logger.info("Total raw events: %d", len(raw_events))

    # ── Step 2: Normalize ─────────────────────────────────────────────────────
    logger.info("[2/6] Normalizing events...")
    normalized = normalize_all(raw_events)

    # ── Step 3: Build timeline ────────────────────────────────────────────────
    logger.info("[3/6] Building timeline...")
    timeline = build_timeline(normalized)

    # ── Step 4: Run detection rules ───────────────────────────────────────────
    logger.info("[4/6] Running detection rules...")
    all_alerts = []
    for rule_module in ALL_RULES:
        alerts = rule_module.run(timeline)
        all_alerts.extend(alerts)
        logger.info(
            "  %s: %d alert(s)",
            rule_module.RULE_NAME,
            len(alerts)
        )

    logger.info("Total alerts: %d", len(all_alerts))

    # ── Step 5: Extract IOCs ──────────────────────────────────────────────────
    logger.info("[5/6] Extracting IOCs...")
    iocs = extract_iocs(timeline, all_alerts)

    # ── Step 6: Risk assessment ───────────────────────────────────────────────
    logger.info("[6/6] Calculating risk score...")
    target_info = {"sources": sources}
    report      = risk_engine.assess(
        target_info, all_alerts, iocs, timeline
    )

    # ── Write reports ─────────────────────────────────────────────────────────
    reporter.write(report)
    reporter.write_timeline(timeline)
    reporter.print_summary(report)

    return report


# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PyShield Incident Analyzer"
    )
    parser.add_argument(
        "--linux", nargs="+", metavar="FILE",
        help="Linux auth.log file(s)"
    )
    parser.add_argument(
        "--windows", nargs="+", metavar="FILE",
        help="Windows Event XML file(s)"
    )
    parser.add_argument(
        "--honeypot", nargs="+", metavar="FILE",
        help="Honeypot report JSON file(s)"
    )

    args = parser.parse_args()

    if not any([args.linux, args.windows, args.honeypot]):
        parser.print_help()
        print("\nExamples:")
        print("  python run.py --linux real_auth.log")
        print("  python run.py --windows security.xml")
        print("  python run.py --honeypot honeypot_report.json")
        print("  python run.py --linux auth.log --honeypot honeypot.json")
        sys.exit(1)

    run(
        linux_logs    = args.linux,
        windows_logs  = args.windows,
        honeypot_logs = args.honeypot,
    )
