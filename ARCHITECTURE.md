# ARCHITECTURE.md — PyShield Incident Analyzer

This document explains the purpose of every component, the threat models
each detection rule addresses, the sequence of execution, and what breaks
if any part is removed.

---

## Threat Models

Understanding WHY each component exists requires understanding the attacks
it defends against. Here are the real-world threat scenarios this tool detects:

---

### Threat Model 1 — Brute Force to Full Compromise

```
Attacker
    │
    ▼
Tries 100 passwords against SSH
    │
    ▼
Finds correct password (admin:password123)
    │
    ▼
Logs in successfully
    │
    ▼
Runs sudo -i to get root
    │
    ▼
Creates backdoor account
    │
    ▼
Full system compromise
```

**What detects this:**
- `RULE-001` fires on the 5th failed login → HIGH alert
- `RULE-001` escalates to CRITICAL when success follows
- `RULE-002` fires on sudo execution after login
- `RULE-003` fires on backdoor account creation

**Without this tool:** The attack appears as noise in raw logs.
**With this tool:** The full attack chain is reconstructed in the timeline.

---

### Threat Model 2 — Credential Stuffing

```
Attacker has leaked credential database
    │
    ▼
Tries 1000 username:password combinations
    │
    ▼
One combination works (john:Summer2024!)
    │
    ▼
Attacker logs in as legitimate user
    │
    ▼
Moves laterally to other systems
    │
    ▼
Data exfiltration
```

**What detects this:**
- `RULE-004` detects 5+ unique usernames tried from same IP
- `RULE-004` escalates to CRITICAL when one succeeds
- IOC extractor flags the attacker IP and compromised username

---

### Threat Model 3 — Insider Privilege Escalation

```
Legitimate employee logs in
    │
    ▼
Creates new admin account for themselves
    │
    ▼
Adds account to Administrators group
    │
    ▼
Exfiltrates sensitive data using new account
    │
    ▼
Deletes logs (but we already captured them)
```

**What detects this:**
- `RULE-003` fires on off-hours account creation
- `RULE-002` fires immediately on admin group membership change (Event 4732)
- Timeline shows the full sequence clearly

---

### Threat Model 4 — Lateral Movement

```
Attacker compromises workstation-01
    │
    ▼
Finds domain credentials in memory
    │
    ▼
Uses same credentials on server-01
    │
    ▼
Uses same credentials on server-02
    │
    ▼
Reaches domain controller
    │
    ▼
Full domain compromise
```

**What detects this:**
- `RULE-004` detects same username from 3+ different IPs in 1 hour
- IOC extractor shows which systems were accessed
- Timeline reveals the movement pattern

---

## Sequence Diagram

Full execution flow from user command to report output:

```
User
  │
  │  python run.py --linux auth.log --honeypot honeypot.json
  ▼
run.py (entry point)
  │
  ├── argparse reads --linux, --windows, --honeypot flags
  │
  ├── [Step 1] Parser Layer
  │     ├── linux_parser.parse("auth.log")
  │     │     └── regex per line → raw event dicts
  │     └── honeypot_parser.parse("honeypot.json")
  │           └── JSON fields → raw event dicts
  │
  ├── [Step 2] normalizer.normalize_all(raw_events)
  │     ├── validates required fields
  │     ├── cleans timestamps → "YYYY-MM-DD HH:MM:SS"
  │     ├── removes Windows placeholder values (-, ::1)
  │     └── ensures severity is valid enum value
  │
  ├── [Step 3] timeline.build(normalized_events)
  │     ├── sorts by timestamp oldest → newest
  │     └── adds seq number to each event
  │
  ├── [Step 4] rules.ALL_RULES loop
  │     ├── brute_force.run(timeline) → alerts[]
  │     ├── privilege_escalation.run(timeline) → alerts[]
  │     ├── new_account.run(timeline) → alerts[]
  │     └── lateral_movement.run(timeline) → alerts[]
  │
  ├── [Step 5] ioc_extractor.extract(timeline, alerts)
  │     ├── counts failed/success per IP
  │     ├── counts failed/success per username
  │     └── builds condensed attack timeline
  │
  ├── [Step 6] risk_engine.assess(target_info, alerts, iocs, timeline)
  │     ├── sums SEVERITY_SCORES per alert
  │     ├── adds bonus for compromised IPs and users
  │     ├── sorts alerts CRITICAL first
  │     └── builds summary lines
  │
  └── reporter.write(report) + reporter.print_summary(report)
        ├── incident_report.json → PyShield Dashboard
        ├── timeline.json
        └── terminal output with ASCII timeline
```

---

## Component Reference

---

### `config.py`
**Purpose:** Single source of truth for all settings and constants.

**Key contents:**
- `WINDOWS_EVENT_IDS` — maps Event ID → (category, description, severity)
- `LINUX_EVENT_TYPES` — maps event type string → (category, description, severity)
- Detection thresholds: `BRUTE_FORCE_THRESHOLD`, `PRIV_ESC_WINDOW` etc.
- `SEVERITY_SCORES` — numeric weight per severity level
- Normalized event schema documented as a comment

**What breaks if removed:**
Everything — all modules import from here.

**What breaks if `WINDOWS_EVENT_IDS` is incomplete:**
Unknown Event IDs are silently dropped by `windows_parser.py`. A gap
in this dict means missed detections — for example, removing Event 4732
means no admin group addition alerts ever fire.

---

### `parser/windows_parser.py`
**Purpose:** Parse Windows Event Log XML exports into normalized dicts.

**Key functions:**

`parse(log_path)` → list[dict]
- Loads XML file using `xml.etree.ElementTree`
- Finds all `<Event>` elements
- Filters to only Event IDs in `WINDOWS_EVENT_IDS`

`_parse_event(element)`
- Extracts `<System>` section: EventID, timestamp, hostname
- Extracts `<EventData>` section: username, IP, logon type
- Handles both namespaced (`e:EventID`) and plain XML

`_extract_event_data_robust(event_data)`
- Strips namespace prefix from all child tags using `tag.split("}")[-1]`
- Parses all <Data Name="...">value</Data> pairs into a dict
- Handles both namespaced and plain XML formats automatically

`_parse_timestamp(raw)`
- Converts `"2026-06-27T10:00:00.000000000Z"` → `"2026-06-27 10:00:00"`
- Trims nanoseconds Python cannot handle

`find_tag(parent, tag)` — internal helper
- Tries three lookup strategies in order:
  1. Namespaced: `e:TagName` with _NS dict
  2. Plain: `TagName` without namespace
  3. Clark notation: `{namespace-url}TagName`
- This makes the parser compatible with all Windows XML export formats

**Why three-strategy namespace lookup matters:**
Windows exports XML with `xmlns='...'` (single quotes) or `xmlns="..."`
(double quotes) depending on the export method. PowerShell `ConvertTo-Xml`
and `wevtutil` produce different formats. The three-strategy approach
handles all variants — without it, single-quote namespace exports return
0 events silently.

**What breaks if removed:**
Windows log analysis disappears completely.

---

### `parser/linux_parser.py`
**Purpose:** Parse Linux auth.log syslog format into normalized dicts.

**Key functions:**

`parse(log_path, year)` → list[dict]
- Reads file line by line
- Tries each regex pattern in `_PATTERNS` against each line
- First match wins — returns normalized event

`_extract_timestamp(line, year)`
- Handles syslog format `"Jun 27 10:00:00"` — note: no year in auth.log
- Year is injected from `datetime.now().year` or caller parameter
- Also handles ISO format `"2026-06-27T10:00:00"`

**Why year injection matters:**
Linux auth.log omits the year. Without injecting it, timestamps become
`"Jun 27 10:00:00"` which cannot be parsed or sorted correctly. This
is the most common surprise when working with real Linux logs.

**What breaks if a regex is missing from `_PATTERNS`:**
That event type is silently ignored. For example, removing the sudo
pattern means `RULE-002` (sudo after login) never fires.

---

### `parser/honeypot_parser.py`
**Purpose:** Convert PyShield Honeypot JSON reports into normalized events.

**Key function:**

`_normalize_honeypot_event(raw)`
- Maps `service=ssh, event_type=auth_attempt` → `event_type=failed_login`
- Maps `service=http, event_type=http_request` → `event_type=honeypot_http_probe`
- This translation is what makes honeypot data compatible with detection rules

**Ecosystem connection:**
This is the bridge between project7 (Honeypot) and project10.
Honeypot SSH attempts are treated as failed logins — so if an attacker
hits the honeypot 5 times, `RULE-001` brute force detection fires.

**What breaks if removed:**
Honeypot data cannot be analyzed. The ecosystem connection is lost.

---

### `normalizer.py`
**Purpose:** Validate and enforce the common event schema after parsing.

**Key functions:**

`normalize_all(raw_events)` → list[dict]
- Iterates all raw events from all parsers
- Drops invalid events (missing timestamp, unknown source)
- Fills missing optional fields with empty strings

`_clean_ip(ip)`
- Removes Windows placeholder values: `-`, `::1`, `LOCAL`, `0.0.0.0`
- Without this: localhost appears as an attacker in every system event

`_clean_timestamp(ts)`
- Tries multiple timestamp formats
- Returns empty string if unparseable → event gets dropped

**Why normalization is a separate step:**
Parsers focus on reading their format. Normalizer focuses on schema
enforcement. Without this separation, every parser would need its own
validation logic — duplicated and inconsistent.

**What breaks if removed:**
Rules receive inconsistent event dicts. Missing fields cause KeyError
crashes in detection logic. The pipeline stops working.

---

### `timeline.py`
**Purpose:** Sort events chronologically and provide query utilities.

**Key functions:**

`build(normalized_events)` → list[dict]
- Sorts by timestamp oldest → newest
- Adds `seq` field for easy reference

`get_events_in_window(timeline, anchor_ts, window_seconds, before)`
- Returns all events within N seconds of a reference timestamp
- Core utility used by every detection rule
- `before=True` looks backward, `before=False` looks forward

`get_events_by_ip(timeline, ip)`
- Returns all events from a specific IP
- Used by lateral movement rule and IOC extractor

`render_ascii(timeline, max_events)`
- Produces the visual terminal timeline
- Format: `[seq] timestamp  severity  [source]  description  user= ip=`

**Why timeline queries are centralized:**
Rules need to ask "what happened near this event?" frequently.
Centralizing this logic means rules don't sort or filter raw lists
themselves. If the query needs optimization (e.g. binary search for
large log files), it changes in one place.

**What breaks if removed:**
All detection rules break — they all import from timeline.py.

---

### `rules/` package

**Architecture:**
Each rule is an independent module with two mandatory exports:
- `RULE_ID` — unique identifier string (e.g. "RULE-001")
- `RULE_NAME` — human-readable name
- `run(timeline)` → list[dict] — takes timeline, returns alerts

`rules/__init__.py` exports `ALL_RULES` — a list of all rule modules.
`run.py` loops through `ALL_RULES` and calls `.run(timeline)` on each.

**Adding a new rule:**
1. Create `rules/new_rule.py` with `RULE_ID`, `RULE_NAME`, `run()`
2. Add to `ALL_RULES` in `rules/__init__.py`
3. Nothing else changes

**What breaks if a rule is removed from `ALL_RULES`:**
That rule's alerts are never generated. The rule file still exists
but is never called — silent gap in detection coverage.

**What breaks if `run()` signature changes:**
The `run.py` loop breaks for that rule. All rules must accept exactly
one argument: the timeline list.

---

### `ioc_extractor.py`
**Purpose:** Extract actionable security artifacts from the analysis.

**Key outputs:**
- `malicious_ips` — IPs with attack activity, sorted by volume
- `targeted_users` — usernames under attack, with compromise flag
- `attack_timeline` — condensed view of HIGH/CRITICAL events + all alerts

**Why `compromised` flag matters:**
An IP with only failed logins is a threat. An IP with failed logins
AND a successful login is a confirmed breach. The `compromised` flag
is what makes IOCs actionable — security teams block all flagged IPs
but immediately disable accounts marked as compromised.

**What breaks if removed:**
`risk_engine.py` crashes (imports `extract`). Compromise bonus scoring
disappears. IOC section missing from report.

---

### `risk_engine.py`
**Purpose:** Convert alerts into a single risk score and level.

**Scoring logic:**
- Base: sum of `SEVERITY_SCORES` per alert
- Bonus: +20 per compromised IP, +15 per compromised user
- Result mapped to: CLEAN / LOW / MEDIUM / HIGH / CRITICAL

**Why compromise bonuses exist:**
A brute force attempt that fails is serious. A brute force that
succeeds is catastrophic. The bonus scoring ensures a confirmed
breach always scores higher than a failed attempt of equal volume.

**What breaks if removed:**
`run.py` crashes. No risk assessment produced.

---

### `reporter.py`
**Purpose:** Write output files and print terminal summary.

**Key functions:**

`write(report)` → `reports/incident_report.json`
- Full report with all events, alerts, IOCs
- Consumed by PyShield Dashboard as a sensor source

`write_timeline(timeline)` → `reports/timeline.json`
- Clean timeline for separate review

`print_summary(report)`
- Terminal output with IOC table, alert list, ASCII timeline

**What breaks if `write()` is removed:**
Dashboard integration breaks. No persistent output.

**What breaks if `render_ascii()` is removed from timeline.py:**
Terminal timeline visualization disappears from reporter output.

---

## Data Flow Summary

```
Log Files
    │
    ▼  [parser layer — format-specific]
Raw Events (inconsistent schema)
    │
    ▼  [normalizer — schema enforcement]
Normalized Events (consistent schema)
    │
    ▼  [timeline — chronological sort]
Sorted Timeline
    │
    ├──▶ [rules — pattern detection]──▶ Alerts
    │
    ├──▶ [ioc_extractor]──────────────▶ IOCs
    │
    ▼
risk_engine (score + level)
    │
    ▼
reporter (JSON + terminal)
    │
    ├──▶ incident_report.json
    ├──▶ timeline.json
    └──▶ Terminal output with ASCII timeline
```

---

## Key Design Principles

**1. Schema contract between parsers and pipeline**
The normalized event schema defined in `config.py` is the contract.
Every parser must produce events matching this schema. Everything
downstream depends on it. Violating the schema in one parser breaks
all rules for that source.

**2. Rules are data, not hardcoded logic**
`ALL_RULES` is a list. Adding a rule is adding a file and one list entry.
This mirrors how real SIEM products like Splunk handle detection rules.

**3. Fail safe over fail loud**
Invalid events are silently dropped by the normalizer rather than
crashing the pipeline. A single malformed log line should never stop
analysis of the other 10,000 lines.

**4. Each module has one job**
Parser reads. Normalizer validates. Timeline sorts. Rules detect.
IOC extractor extracts. Risk engine scores. Reporter outputs.
No module does two jobs. This makes each one testable independently.
