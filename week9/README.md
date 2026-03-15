# Week 9: System Inventory & Patch Status Tracker

## What This Tool Does
This script is a homegrown patch compliance tracker. It reads a list of computers from a JSON file, scores each one based on how risky it is to leave unpatched, and generates reports that tells the IT team exactly which computers to fix first and how quickly this fix needs to happen. 

Important: this tool does not create patches. Patches are written and released by software vendors like Microsoft or Apple when they discover security vulnerabilities. This tool is more like a building inspection report — the inspector (this script) does not fix the plumbing. It walks through the building, identifies which problems are most dangerous, and hands the landlord (the IT team) a prioritized list of what needs fixing first. The actual repair work is done by IT staff installing the patches the vendors already released.

## Why You Need Prioritization
Because we cannot patch everything at once, deciding which to patch in order of importance is essential. Because patches require restarting computers, this entails scheduling downtime, which must be planned in advance, additionally, some patches can accidentally break other software and need to be tested first. Some patches are more important than. others -- a patch fixing a minor cosmetic annoyance is very different from one fixing a critical security hole being actively exploited. 

This tool makes prioritization of the patching schedule objective and measurable. A computer that handles sensitive data, is visible to the internet, and hasn't been patched in six months is a much bigger risk than a developer's laptop patched last week. 

## Why This Matters in Higher Education
In a college or university environment, this tool would be especially valuable for protecting systems that hold sensitive student and institutional data. like FERPA-protected systems — Computers that store student records, grades, enrollment data, or financial aid information.  In the same way this tool uses a `hipaa` tag to flag health data systems, a college could add a `ferpa` tag to automatically surface student records systems as high priority.

At a college like Alexandria Technical & Community College, this tool could be adapted to tag systems with `ferpa`, `pci-scope`, and `internet-facing` to automatically surface the highest-priority computers for the IT team each week.

## How It Works
The script follows a straightforward pipeline:

1. Load the computer inventory from `host_inventory.json`
2. Calculate how many days since each computer was last patched
3. Score each computer from 0 to 100 based on six risk factors
4. Assign a risk level (critical, high, medium, or low)
5. Filter and sort by highest risk
6. Generate two output reports

## Risk Scoring Algorithm
Each computer is scored from 0 to 100 based on six factors. Scores are capped at 100 because once a system reaches maximum risk, the exact number no longer matters — the action is the same regardless. Whether a computer scores 100 or would have scored 120, it gets patched in the next 48 hours. 

| Factor | Condition | Points |
|---|---|---|
| Criticality | critical / high / medium / low | 40 / 25 / 10 / 5 |
| Patch Age | >90 days / >60 days / >30 days | 30 / 20 / 10 |
| Environment | production / staging / development | 15 / 8 / 3 |
| PCI Scope | pci-scope tag present | +10 |
| HIPAA | hipaa tag present | +10 |
| Internet Facing | internet-facing tag present | +15 |

**Important note on patch age:** The code checks patch age from most severe to least severe — greater than 90 days first, then greater than 60, then greater than 30. This order is critical. Python stops at the first condition that is true. If you checked greater than 30 days first, a computer that hasn't been patched in 120 days would match that first condition and only get 10 points instead of 30. Always check the most severe condition first.

## Risk Level Thresholds
| Level | Score Range | Action Required |
|---|---|---|
| Critical | >= 70 | Patch within 48 hours |
| High | 50-69 | Patch this week |
| Medium | 25-49 | Patch this month |
| Low | 0-24 | Normal patch cycle |

## CIS Control 7 Alignment
This tool implements CIS Critical Security Control 7 — Continuous Vulnerability Management. CIS Control 7 defines specific patch timelines based on vulnerability severity. The scoring thresholds and remediation timelines in this tool are built directly around those standards. This is also important for auditing purposes - it allows IT staff to demonstrate that they are following a structured, documented patch management program.

## A Note on Handling Missing Data
The script uses Python's `.get()` method when checking tags on each computer. This is important because not every computer in the inventory has a tags field. If the code tried to read a tags field that didn't exist, Python would crash with an error. Using `.get('tags', [])` tells Python: "look for the tags field, but if it doesn't exist, just return an empty list and keep going." This makes the script robust enough to handle real-world data that isn't always complete or consistent.

## Functions
- `load_inventory()` — Loads host data from the JSON file
- `calculate_days_since_patch()` — Calculates how many days since each computer was last patched
- `filter_by_os()` — Filters computers by operating system
- `filter_by_criticality()` — Filters computers by criticality level
- `filter_by_environment()` — Filters computers by environment (production, staging, development)
- `filter_critical_production()` — Returns only critical production computers
- `calculate_risk_score()` — Calculates the 0-100 risk score using all six factors
- `get_risk_level()` — Converts the numeric score to a plain English label
- `get_high_risk_hosts()` — Returns computers above the risk threshold, sorted highest first
- `analyze_inventory()` — Runs the full analysis pipeline on all computers
- `generate_json_report()` — Saves a structured JSON report for automation use
- `generate_text_summary()` — Saves a plain-language summary for managers

## Sample Output
```
Total Systems Analyzed:        20
High-Risk Systems Identified:  13 (65.0%)
Critical Priority Systems:     10
Immediate Action Required:     12 systems >90 days unpatched
```

## How to Run
Make sure `host_inventory.json` is in the same folder as the script, then run:
```
python3 patch_tracker.py
```
This will generate `high_risk_report.json` and `patch_summary.txt` in the same folder.

## Test Results
Running the tracker against the 20-host inventory produced the following results:

- Total systems analyzed: 20
- High-risk systems identified: 13 (65%)
- Critical priority systems: 10
- Systems unpatched more than 90 days: 12

**Top 3 Highest Risk Systems:**
| Rank | Hostname | Score | Risk Level | Days Since Patch |
|---|---|---|---|---|
| 1 | IT-SRV-DC01 | 100 | Critical | 670+ days |
| 2 | WEB-SRV-001 | 100 | Critical | 690+ days |
| 3 | DB-SRV-001 | 95 | Critical | 600+ days |

Both IT-SRV-DC01 and WEB-SRV-001 scored 100 — the maximum — because they are critical production systems that are internet-facing, in PCI scope, and have not been patched in nearly two years.

## AI Usage
I used Claudeai as my AI tool throughout this project. Rather than generating the entire script at once, I built it one function at a time, testing each piece before moving on. This approach helped me understand what each part was doing rather than just copying a finished product.

Claude helped me work through the logic of the risk scoring algorithm, understand why patch age order matters in if/elif chains, and troubleshoot indentation errors as they came up. I also used our conversation to work through the real-world context behind the tool — why patches can't roll out all at once, what PCI-scope means, and how FERPA would apply in a higher education environment. That context ended up in the README as well.

## Challenges
The biggest technical challenge was indentation errors. Python is very strict about consistent spacing, and several of my function definitions ended up with extra spaces that caused the script to crash. The fix was straightforward once I understood what was happening — clicking to the start of the affected line and deleting the extra spaces until it lined up with the other function definitions.

The bigger challenge early on was understanding the purpose of the tool. It wasn't immediately clear why a patch tracker needed multi-factor scoring instead of just sorting by patch age. Working through the real-world context — comparing a developer's laptop to a production web server handling credit card data — made the scoring logic click. Once I understood the why, the how made much more sense.

## Files
- `patch_tracker.py` — Main script
- `host_inventory.json` — Input data (20 host computers)
- `high_risk_report.json` — Output JSON report for automation pipelines
- `patch_summary.txt` — Output plain-language summary for managers
