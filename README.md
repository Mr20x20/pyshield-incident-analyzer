# 🔎 PyShield Incident Analyzer

A rule-based incident analysis engine that parses log files from multiple sources, builds a chronological attack timeline, detects threat patterns, and extracts Indicators of Compromise (IOCs). Part of the **PyShield** security ecosystem.

---

## 📸 Example Output

```
=================================================================
  PyShield Incident Analyzer — Report
=================================================================
  Timestamp   : 2026-06-27 10:05:00
  Log Sources : linux:auth.log, honeypot:honeypot_report.json
  Events      : 47 analyzed
  Risk Score  : 95
  Risk Level  : CRITICAL
-----------------------------------------------------------------
  Alerts      : 4 total | CRITICAL:2 HIGH:2 MEDIUM:0 LOW:0
-----------------------------------------------------------------
  Malicious IPs   : 1
    192.168.1.100  failed=5 success=1  ← COMPROMISED
  Targeted Users  : 2
    admin          failed=5 success=1  ← COMPROMISED
    backdoor       failed=0 success=1
-----------------------------------------------------------------
  ATTACK TIMELINE:
  [001] 2026-06-27 10:00:01  MEDIUM  [linux   ] Failed SSH password   user=admin ip=192.168.1.100
  [002] 2026-06-27 10:00:06  INFO    [linux   ] Accepted SSH password  user=admin ip=192.168.1.100
  [003] 2026-06-27 10:00:15  HIGH    [linux   ] Sudo command executed  user=admin
  [004] 2026-06-27 10:01:00  HIGH    [linux   ] New user created       user=backdoor
  [005] 2026-06-27 10:01:30  INFO    [linux   ] Accepted SSH password  user=backdoor
=================================================================
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   PyShield Incident Analyzer                    │
│                                                                 │
│  Log Sources                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐     │
│  │ windows.xml  │  │ linux.log    │  │ honeypot.json      │     │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬──────────┘     │
│         └─────────────────┼──────────────────────┘              │
│                           ▼                                     │
│                  ┌─────────────────┐                            │
│                  │  Parser Layer   │  protocol-specific         │
│                  │  windows_parser │  parsing per source        │
│                  │  linux_parser   │                            │
│                  │  honeypot_parser│                            │
│                  └────────┬────────┘                            │
│                           │ raw events                          │
│                           ▼                                     │
│                  ┌─────────────────┐                            │
│                  │  normalizer.py  │  enforces common schema    │
│                  └────────┬────────┘                            │
│                           │ normalized events                   │
│                           ▼                                     │
│                  ┌─────────────────┐                            │
│                  │  timeline.py    │  chronological sort        │
│                  └────────┬────────┘                            │
│                           │ sorted timeline                     │
│                           ▼                                     │
│              ┌────────────────────────┐                         │
│              │     rules/             │  modular detection      │
│              │  brute_force.py        │                         │
│              │  privilege_escalation  │                         │
│              │  new_account.py        │                         │
│              │  lateral_movement.py   │                         │
│              └────────────┬───────────┘                         │
│                           │ alerts                              │
│                           ▼                                     │
│                  ┌─────────────────┐                            │
│                  │ ioc_extractor   │  IPs, users, timeline      │
│                  └────────┬────────┘                            │
│                           ▼                                     │
│                  ┌─────────────────┐                            │
│                  │  risk_engine    │  scoring + assessment      │
│                  └────────┬────────┘                            │
│                           ▼                                     │ 
│                  ┌─────────────────┐                            │
│                  │   reporter.py   │  JSON + terminal output    │
│                  └────────┬────────┘                            │
│                           │                                     │
└───────────────────────────┼──────────────────────────────────── ┘
                            ▼
               incident_report.json + timeline.json
                            │
                            ▼
               PyShield Dashboard (SIEM)
```

---

## 🔍 Detection Rules

| Rule | ID | Pattern Detected | Severity |
|---|---|---|---|
| Brute Force | RULE-001 | 5+ failed logins from same IP in 5 minutes | HIGH |
| Brute Force Success | RULE-001 | Brute force followed by successful login | CRITICAL |
| Admin Group Add | RULE-002 | User added to Administrators group | CRITICAL |
| Priv After Login | RULE-002 | Special privileges within 60s of login | HIGH |
| Sudo After Login | RULE-002 | Sudo command within 60s of SSH login | HIGH |
| Backdoor Account | RULE-003 | New account created after suspicious login | CRITICAL |
| Off-Hours Account | RULE-003 | Account created outside business hours | HIGH |
| Immediate Account Use | RULE-003 | New account used within 10 minutes of creation | HIGH |
| Multi-IP Login | RULE-004 | Same user from 3+ IPs within 1 hour | HIGH |
| Recon Then Success | RULE-004 | Failed logins from IP then successful login | CRITICAL |
| Credential Stuffing | RULE-004 | 5+ usernames tried then one succeeds | CRITICAL |

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Mr20x20/pyshield-incident-analyzer.git
cd pyshield-incident-analyzer
```

### 2. Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run analysis

```bash
# Analyze Linux auth log
python run.py --linux logs/auth.log

# Analyze Windows Event Log (exported as XML)
python run.py --windows logs/security.xml

# Analyze honeypot report from PyShield Honeypot
python run.py --honeypot logs/honeypot_report.json

# Combine multiple sources
python run.py --linux logs/auth.log --honeypot logs/honeypot_report.json
```

### 5. Export Windows Event Logs

```powershell
# In PowerShell as Administrator
Get-WinEvent -LogName Security -MaxEvents 1000 |
    Export-Clixml security.xml
```

---

## 📁 Project Structure

```
pyshield-incident-analyzer/
├── run.py                    # Entry point — CLI argument parser + pipeline
├── normalizer.py             # Enforces common event schema
├── timeline.py               # Chronological sort + query helpers
├── ioc_extractor.py          # Extracts IPs, users, attack timeline
├── risk_engine.py            # Scoring + risk level assessment
├── reporter.py               # JSON report + visual terminal output
├── config.py                 # Event IDs, thresholds, scoring rules
├── parser/
│   ├── windows_parser.py     # Windows Event Log XML parser
│   ├── linux_parser.py       # Linux auth.log regex parser
│   └── honeypot_parser.py    # PyShield Honeypot JSON parser
├── rules/
│   ├── brute_force.py        # RULE-001: Brute force detection
│   ├── privilege_escalation.py # RULE-002: Privilege escalation
│   ├── new_account.py        # RULE-003: Suspicious account creation
│   └── lateral_movement.py   # RULE-004: Lateral movement
├── logs/                     # Place log files here
└── reports/                  # Auto-created output directory
    ├── incident_report.json
    └── timeline.json
```

---

## 🧠 Design Decisions

**Why is the Parser layer separate from Normalizer?**
Each log source has a completely different format — Windows uses XML with namespaces, Linux uses regex-matched plaintext, Honeypot uses JSON. Separating parsing from normalization means each parser focuses on one job: reading its format. The normalizer focuses on one job: enforcing the schema. Mixing them would make both harder to maintain.

**Why is rules/ a package with modular files?**
Adding a new detection rule means creating one new file in `rules/` and adding it to `ALL_RULES` in `__init__.py`. Nothing else changes. This is the same pattern used in real SIEM products like Sigma rules — rules are data, not hardcoded logic. It also means rules can be tested independently without running the full pipeline.

**Why does the Timeline exist as its own module?**
The timeline is queried by multiple consumers — every rule uses `get_events_in_window()`, `get_events_by_ip()`, and `get_events_by_user()`. Centralizing these queries means rules never sort or filter raw events themselves. If the query logic needs to change, it changes in one place.

**Why are IOCs extracted separately from risk scoring?**
IOCs (malicious IPs, compromised users) are operational artifacts — security teams use them to block IPs in firewalls and disable accounts. Risk scoring is a management metric. Keeping them separate means each can evolve independently. An analyst might want raw IOCs without a risk score; a manager might want only the score.

**Why does normalizer clean placeholder values like `-` and `::1`?**
Windows Event Log uses `-` for "not applicable" and `::1` for localhost when no remote IP exists. Without cleaning these, the rules engine would flag localhost as an attacker and generate false positives on every system event.

---

## ⚙️ Configuration

All settings in `config.py`:

| Setting | Default | Description |
|---|---|---|
| `BRUTE_FORCE_THRESHOLD` | 5 | Failed logins before brute force alert |
| `BRUTE_FORCE_WINDOW` | 300s | Time window for brute force detection |
| `PRIV_ESC_WINDOW` | 60s | Window for privilege escalation detection |
| `NEW_ACCOUNT_WINDOW` | 600s | Window for backdoor account detection |
| `LATERAL_MOVEMENT_WINDOW` | 3600s | Window for lateral movement detection |

---

## 🔗 PyShield Ecosystem Integration

```
PyShield Honeypot (project7)
    │
    └── honeypot_report.json
              │
              ▼
PyShield Incident Analyzer (project10)  ← you are here
              │
              └── incident_report.json
                          │
                          ▼
        PyShield Dashboard (project6)
```

---

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **Log Parsing:** `xml.etree.ElementTree`, `re` (standard library)
- **Detection:** Custom rule engine with sliding window algorithms
- **Output:** JSON + ASCII timeline visualization

---

## 🔐 Legal & Ethical Notice

Only analyze logs from systems you own or have explicit permission to investigate. This tool is designed for authorized incident response and security operations.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Mr20x20** — Network & Security Enthusiast
GitHub: [github.com/Mr20x20](https://github.com/Mr20x20)

---

## 🔗 Related Projects

- [PyShield Dashboard](https://github.com/Mr20x20/PyShield_Dashboard) — Real-time SIEM dashboard
- [PyShield Honeypot](https://github.com/Mr20x20/pyshield-honeypot) — Attacker profiler
- [PyShield Threat Intel](https://github.com/Mr20x20/pyshield-threat-intel) — CVE vulnerability scanner
- [PyShield Web Scanner](https://github.com/Mr20x20/pyshield-web-scanner) — Web misconfiguration scanner
