"""
risk_engine.py — PyShield Incident Analyzer
Scores all alerts and produces a final incident risk assessment.
"""

import logging
from datetime import datetime

from config import SEVERITY_SCORES, RISK_LEVELS

logger = logging.getLogger("incident.risk_engine")


def assess(target_info: dict, alerts: list[dict],
           iocs: dict, timeline: list[dict]) -> dict:
    """
    Score all alerts and build the final incident report structure.

    Args:
        target_info: dict with log sources and metadata
        alerts     : combined alerts from all rules
        iocs       : output from ioc_extractor.extract()
        timeline   : full sorted event list

    Returns full assessment dict.
    """
    total_score = 0
    counts      = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for alert in alerts:
        severity     = alert.get("severity", "LOW")
        total_score += SEVERITY_SCORES.get(severity, 0)
        if severity in counts:
            counts[severity] += 1

    # Bonus score for compromised accounts and IPs
    compromised_ips   = sum(
        1 for ip in iocs.get("malicious_ips", [])
        if ip.get("compromised")
    )
    compromised_users = sum(
        1 for u in iocs.get("targeted_users", [])
        if u.get("compromised")
    )
    total_score += compromised_ips * 20
    total_score += compromised_users * 15

    risk_level = _get_risk_level(total_score)
    summary    = _build_summary(
        total_score, risk_level, alerts, counts, iocs, timeline
    )

    # Sort alerts: CRITICAL first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(
        key=lambda x: severity_order.get(x.get("severity", "LOW"), 3)
    )

    report = {
        "timestamp":        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "log_sources":      target_info.get("sources", []),
        "total_events":     len(timeline),
        "total_alerts":     len(alerts),
        "total_score":      total_score,
        "risk_level":       risk_level,
        "alert_counts":     counts,
        "summary":          summary,
        "alerts":           alerts,
        "iocs":             iocs,
        "timeline":         timeline,
    }

    logger.info(
        "Assessment: score=%d level=%s alerts=%d "
        "(C:%d H:%d M:%d L:%d)",
        total_score, risk_level, len(alerts),
        counts["CRITICAL"], counts["HIGH"],
        counts["MEDIUM"], counts["LOW"],
    )
    return report


def _get_risk_level(score: int) -> str:
    for threshold, level in RISK_LEVELS:
        if score <= threshold:
            return level
    return "CRITICAL"


def _build_summary(score: int, level: str, alerts: list[dict],
                   counts: dict, iocs: dict,
                   timeline: list[dict]) -> list[str]:
    summary = []

    summary.append(
        f"• Incident Risk Score: {score} | Level: {level}"
    )
    summary.append(
        f"• {len(timeline)} events analyzed, "
        f"{len(alerts)} alert(s) generated."
    )
    summary.append(
        f"• Alerts: {counts['CRITICAL']} CRITICAL, "
        f"{counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, "
        f"{counts['LOW']} LOW"
    )

    # Compromised accounts
    comp_users = [
        u["username"] for u in iocs.get("targeted_users", [])
        if u.get("compromised")
    ]
    if comp_users:
        summary.append(
            f"• 🔥 COMPROMISED accounts: {', '.join(comp_users)}"
        )

    # Malicious IPs
    mal_ips = [
        ip["ip"] for ip in iocs.get("malicious_ips", [])
    ]
    if mal_ips:
        summary.append(
            f"• Malicious IPs detected: {', '.join(mal_ips[:5])}"
        )

    # Top alerts
    crit_alerts = [a for a in alerts if a.get("severity") == "CRITICAL"]
    for alert in crit_alerts[:3]:
        summary.append(f"• 🔥 {alert['description']}")

    return summary
