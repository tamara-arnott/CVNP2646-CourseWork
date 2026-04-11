# Week 11: Configuration Drift Checker
**CVNP2646 – Python/JSON**
**Tamara Arnott**

---

## Overview

This tool compares two JSON configuration files to detect "configuration drift" — 
the term used when a system's actual settings no longer match its approved baseline. 
In a Security Operations Center (SOC), this matters because unauthorized or accidental 
changes to firewall rules, logging settings, and access controls are among the most 
common causes of security vulnerabilities.

A helpful way to think about this outside of an IT context: imagine comparing ATCC's 
approved organizational chart to what the true structure has become a year later. 
Positions may have been added or eliminated, roles may have moved under new supervisory 
authority, entire divisions may have been reorganized, or new reporting structures may 
have appeared under existing lines of authority. When the Higher Learning Commission 
visits campus and compares the published chart to the actual structure, peer reviewers 
will flag every discrepancy and try to determine whether proper procedures were followed. 
This tool performs that same review for firewall configurations.

| Org Chart Change | What It Maps To | Drift Type |
|---|---|---|
| A position was eliminated without approval | Expected setting is gone | `missing` |
| A new position added that wasn't on the approved chart | Unexpected setting appeared | `extra` |
| A position moved to a different supervisor | Setting still exists, value changed | `changed` |
| A whole new division added under an existing VP | Nested structure added | `extra` at a deeper level |
| Reporting lines reorganized under a new hierarchy | Nested structure changed | `changed` recursively |

According to course materials for CVNP2646, configuration drift is responsible for an 
estimated 60% of security incidents. This drift checker detects drift regardless of 
whether changes were unauthorized or simply authorized but never reflected in the 
baseline — both create the same vulnerabilities: disabled logging, opened firewall 
ports, and escalated permissions.

---

## Usage

Make sure `baseline.json` and `current.json` are in the same folder as `drift_checker.py`, 
then run:

```bash
python drift_checker.py
```

The program will print a formatted drift report to the screen and save detailed results 
to `drift_report.json`.

---

## Drift Types

The checker detects three types of differences between configurations:

| Type | Icon | Meaning | Example |
|------|------|---------|---------|
| **Missing** | `[-]` | A setting exists in the baseline but is gone from current | Logging destination removed |
| **Extra** | `[+]` | A setting exists in current but was never in the baseline | Unauthorized firewall rule added |
| **Changed** | `[~]` | A setting exists in both but the value is different | Port changed from 443 to 8080 |

---

## DriftResult Class

The `DriftResult` class is the blueprint for every drift finding. Think of it like a 
standardized incident report form — every finding gets its own filled-out copy with 
the same fields and the same built-in actions.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `path` | str | Where in the config the drift was found (e.g. `logging.enabled`) |
| `drift_type` | str | Type of drift: `"missing"`, `"extra"`, or `"changed"` |
| `baseline_value` | any | The approved value from the baseline config |
| `current_value` | any | The actual value found in the current config |
| `severity` | str | Calculated severity: `"high"`, `"medium"`, or `"low"` |

### Methods

| Method | Description |
|--------|-------------|
| `__init__()` | Runs automatically at creation — stores all attributes and calculates severity |
| `_calculate_severity()` | Private helper — determines severity based on path keywords and drift type |
| `__str__()` | Returns a formatted one-line summary for printing (e.g. `[~] logging.enabled (high)`) |
| `to_dict()` | Converts the finding to a dictionary for saving to a JSON file |
| `is_critical()` | Returns True if severity is "high", False otherwise |

---

## Severity Calculation

Severity is assigned automatically the moment a DriftResult is created:

- **High** — the config path contains a critical keyword: `password`, `secret`, `admin`, 
  `root`, or `enabled`. These paths are high-stakes because changes to them often have 
  immediate security impact.
- **Medium** — a setting is missing from the current config. Something that should be 
  there isn't — like required financial aid paperwork that disappeared from a student file.
- **Low** — everything else. The change is real and worth noting, but doesn't trigger 
  an immediate escalation.

---

## How Recursion Works

The `compare_configs()` function uses recursion — meaning it calls itself — to handle 
JSON configurations that are nested at unknown depths.

The function applies the same three rules at every level it encounters:

1. **If both values are dictionaries** — compare the keys, then call itself on each 
   matching value inside. This is how it gets from the top level all the way down to 
   individual settings like `rules[0].port`.

2. **If both values are lists** — compare each item by index number, then call itself 
   on each item. This is how it catches the extra `temp-debug` rule added at `rules[2]`.

3. **If the value is a plain value** (a number, True/False, a string) — just compare 
   them directly and stop. This is called the "base case" — the stopping point that 
   prevents the function from calling itself forever.

The `path` parameter works like breadcrumbs, tracking exactly where we are in the 
config at each level. That's how the report can say `rules[1].source` instead of 
just "something changed somewhere."

Without recursion, we would need to write separate code for every possible level of 
nesting. With recursion, one function handles any depth automatically.

---

## Test Results

Running `drift_checker.py` against the provided test files detected all six expected 
drift findings:

```
============================================================
CONFIGURATION DRIFT REPORT
============================================================

Summary:
  Total Drift Findings: 6
  By Type     - Missing: 1, Extra: 1, Changed: 4
  By Severity - High: 1, Medium: 1, Low: 4

Detailed Findings:
------------------------------------------------------------
[-] logging.destination (medium)
    Expected: siem
[~] logging.level (low)
    Baseline: info
    Current:  debug
[~] logging.enabled (high)
    Baseline: True
    Current:  False
[~] rules[0].port (low)
    Baseline: 443
    Current:  8080
[~] rules[1].source (low)
    Baseline: 10.0.0.0/8
    Current:  0.0.0.0/0
[+] rules[2] (low)
    Found:    {'name': 'temp-debug', 'port': 9999, 'protocol': 'tcp', 
               'source': '0.0.0.0/0', 'action': 'allow', 'enabled': True}

✓ Report saved to drift_report.json
```

---

## Challenges and What I Learned

The two concepts that required the most effort to understand were recursion and 
Object-Oriented Programming (OOP) — both of which were new territory for me.

Recursion clicked when I stopped thinking about it as code and started thinking about 
it as searching for a document on the M drive. When I know I generated a file but 
can't remember exactly where I saved it, I start at the top level folder and work my 
way down — opening each subfolder, checking what's inside, and if there are more 
folders inside that one, opening those too. I apply the same rule at every level: 
open it, check it, and if there is something else inside, go deeper. That continues 
until I finally land on an actual file I can look at directly. The search function 
speeds this up by focusing on a particular word, date, or concept — which is exactly 
what the path string does in compare_configs(). Instead of manually tracking where we 
are in the nested structure, the path builds itself automatically at each level, so 
every finding can report its exact location — like a search result that tells you not 
just the file name but the full folder path where it lives.

OOP was a new concept for me, and the way I understand it connects directly to the 
adjunct hiring process at ATCC. Every time we hire an adjunct, the same intake 
procedure runs automatically the moment the file is opened — the position is advertised, 
applications are reviewed against established criteria, interviews are scheduled, and 
once a candidate is selected, HR processing begins. Credentials are recorded, transcripts 
are verified, and the system calculates pay level without anyone having to reinvent the 
process for each new hire. That is exactly what __init__ does in the DriftResult class. 
Before learning about classes, I would have stored each drift finding as a plain 
dictionary — like a pile of sticky notes, each one holding a piece of information with 
no built-in instructions for what to do with it. Using a class instead is like switching 
to a standardized HR form that already knows what fields it needs, how to calculate a 
rating, and how to export itself to the state system. The DriftResult class bundles the 
data fields (path, drift type, values) together with the operating instructions (how to 
print itself, how to calculate severity, how to export to JSON) in one place. Every 
finding automatically knows what it is and what it can do — without anyone having to 
manage those things separately for each one.

---

## Security Impact

This tool detects the exact kinds of changes that create real-world vulnerabilities:

- **Disabled logging** (`logging.enabled: True → False`) — an attacker disabling audit 
  trails to cover their tracks is one of the first signs of compromise.
- **Opened firewall ports** (`rules[0].port: 443 → 8080`) — redirecting traffic through 
  unexpected ports bypasses security controls.
- **SSH opened to the world** (`rules[1].source: 10.0.0.0/8 → 0.0.0.0/0`) — exposing 
  SSH to all IP addresses dramatically increases attack surface.
- **Unauthorized rules** (`rules[2]: temp-debug added`) — temporary rules added during 
  troubleshooting that are never removed become permanent vulnerabilities.
- **Lost SIEM integration** (`logging.destination: siem → missing`) — without logs 
  flowing to the security information system, incidents go undetected.

Configuration baseline monitoring is required by SOC 2, ISO 27001, and PCI-DSS 
compliance frameworks for exactly these reasons.
