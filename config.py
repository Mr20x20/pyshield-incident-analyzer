"""
config.py — PyShield Incident Analyzer
Central configuration. All other modules import from here.

Windows Event IDs reference:
  4624 — Successful logon
  4625 — Failed logon
  4634 — Logoff
  4648 — Logon with explicit credentials
  4672 — Special privileges assigned (admin logon)
  4688 — New process created
  4698 — Scheduled task created
  4720 — User account created
  4722 — User account enabled
  4724 — Password reset attempt
  4728 — Member added to security-enabled global group
  4732 — Member added to local security group (Administrators)
  4756 — Member added to universal security group
  7045 — New service installed
"""

from pathlib import Path

# ── Project root ──────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent.resolve()
LOGS_DIR     = BASE_DIR / "logs"
REPORTS_DIR  = BASE_DIR / "reports"

LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# ── Output ────────────────────────────────────────────────────────────────────
INCIDENT_REPORT = REPORTS_DIR / "incident_report.json"
TIMELINE_FILE   = REPORTS_DIR / "timeline.json"

# ── Windows Event IDs ─────────────────────────────────────────────────────────
# Maps Event ID → (category, description, severity)
WINDOWS_EVENT_IDS = {
    4624: ("auth",      "Successful logon",                    "INFO"),
    4625: ("auth",      "Failed logon",                        "MEDIUM"),
    4634: ("auth",      "Logoff",                              "INFO"),
    4648: ("auth",      "Logon with explicit credentials",     "MEDIUM"),
    4672: ("privilege", "Special privileges assigned to logon","HIGH"),
    4688: ("process",   "New process created",                 "INFO"),
    4698: ("persist",   "Scheduled task created",              "HIGH"),
    4720: ("account",   "User account created",                "HIGH"),
    4722: ("account",   "User account enabled",                "MEDIUM"),
    4724: ("account",   "Password reset attempt",              "MEDIUM"),
    4728: ("account",   "Member added to global group",        "HIGH"),
    4732: ("account",   "Member added to Administrators group","CRITICAL"),
    4756: ("account",   "Member added to universal group",     "HIGH"),
    7045: ("persist",   "New service installed",               "CRITICAL"),
}

# ── Linux log patterns ────────────────────────────────────────────────────────
# These are the event types we extract from Linux auth.log
LINUX_EVENT_TYPES = {
    "failed_password":   ("auth",      "Failed SSH password",   "MEDIUM"),
    "accepted_password": ("auth",      "Accepted SSH password", "INFO"),
    "accepted_publickey":("auth",      "Accepted SSH key",      "INFO"),
    "invalid_user":      ("auth",      "Invalid user attempt",  "MEDIUM"),
    "sudo_command":      ("privilege", "Sudo command executed", "HIGH"),
    "new_user":          ("account",   "New user created",      "HIGH"),
    "session_opened":    ("auth",      "Session opened",        "INFO"),
    "session_closed":    ("auth",      "Session closed",        "INFO"),
}

# ── Detection thresholds ──────────────────────────────────────────────────────
# Brute force: N failed logins within TIME_WINDOW seconds
BRUTE_FORCE_THRESHOLD   = 5
BRUTE_FORCE_WINDOW      = 300    # 5 minutes

# Privilege escalation: admin privileges within N seconds of login
PRIV_ESC_WINDOW         = 60     # 1 minute

# New account: account created within N seconds of suspicious activity
NEW_ACCOUNT_WINDOW      = 600    # 10 minutes

# Lateral movement: login from new IP within N seconds of first login
LATERAL_MOVEMENT_WINDOW = 3600   # 1 hour

# ── Risk scoring ──────────────────────────────────────────────────────────────
SEVERITY_SCORES = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    7,
    "LOW":       2,
    "INFO":      0,
}

RISK_LEVELS = [
    (0,   "CLEAN"),
    (15,  "LOW"),
    (40,  "MEDIUM"),
    (80,  "HIGH"),
    (999999, "CRITICAL"),
]

# ── Normalized event schema ───────────────────────────────────────────────────
# Every parser produces events matching this structure:
# {
#     "timestamp":  "2026-06-27 10:00:00",  # ISO format
#     "source":     "windows" | "linux" | "honeypot",
#     "event_id":   4625,                   # Windows ID or None
#     "event_type": "failed_password",      # normalized type
#     "category":   "auth",                 # auth/privilege/account/process/persist
#     "severity":   "MEDIUM",
#     "username":   "admin",
#     "src_ip":     "192.168.1.100",
#     "hostname":   "WORKSTATION-01",
#     "description":"Failed logon attempt",
#     "raw":        "...",                  # original log line
# }
