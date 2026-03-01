# Config-Driven Backup Planner
## CVNP2646 — Week 7 Project
**Tamara Arnott**

---

## Overview

This program automates backup planning for critical security logs — firewall logs, IDS alerts, and authentication logs. Instead of hardcoding folder paths and settings directly into the Python script, all settings are stored in a separate JSON configuration file. Think of it like an RFP response template — the outline and structure stay the same for every submission, but each partner fills in their own section with their specific information. The template never changes, only the content does. This means the script never needs to change — only the config file does.

This is called config-driven programming. The same script can handle development backups, production backups, or disaster recovery backups by simply swapping the config file. No code changes needed.

This week's version is a dry-run only — it shows what WOULD be backed up without actually copying any files.

---

## Usage

**Run with a valid config:**
```
python3 backup_planner.py backup_config.json
```

**Run with an invalid config to test the validator:**
```
python3 backup_planner.py invalid_config.json
```

Notice that the config file name is placed after the script name. That is the point of this type of exercise — to be able to swap in different config files without touching the Python code directly.

---

## Schema Design

The config file has four sections:

**Metadata** — the plan name, version, who created it, and a description. These are informational fields that identify the backup plan.

**Sources** — a list of directories to back up. It must be a list because the program needs to loop through each source one at a time. Each source has a path, whether to search subfolders recursively, and file patterns to include or exclude. For example, `*.log` means grab any file ending in .log, and `*.tmp` means skip temporary files.

**Destination** — where the backed-up files go. This is not just a folder path — it is a full bundle of related settings including where to save, whether to create timestamped folders, and how long to keep the backups. Think of it like a student record — it is not just a name, it contains the student ID, program, enrollment status, GPA, and advisor all bundled together under one record. In the same way, destination bundles the path, the timestamp setting, and the retention period all together. This bundle of related information is what Python calls a dictionary.

**Options** — optional settings including whether to verify backups completed correctly and the maximum file size to include.

---

## Validation Levels

The validator checks the config file across four levels and collects ALL errors before reporting them. It never stops at the first error — just like reviewing a grant submission, you read the whole document and send back a complete list of everything that needs to be fixed.

**Level 1 — File Structure**
Handled by the load function. If the file does not exist, it reports a clear error. If the file exists but is corrupted or broken, it reports that instead.

**Level 2 — Required Fields**
Checks that the three required sections are present: plan_name, sources, and destination. If any are missing, they are added to the errors list.

**Level 3 — Data Types**
Checks that each field is the correct type. Sources must be a list — not a single line of text. Destination must be a full bundle of settings — not just a folder path. Plan name must be text.

**Level 4 — Values**
Checks that values make logical sense. The sources list cannot be empty. Each source must have a path field, and that path cannot be blank.

---

## Simulation Logic

The simulation generates fake file data to show what would be backed up — without reading any real directories or copying any files.

For each source in the config, the program:
- Randomly generates between 5 and 15 fake files
- Assigns each file a random size between 1 and 100 MB
- Creates a realistic filename based on the source name
- Calculates total file counts and total size across all sources

The random module is used for all file data. No actual file system operations are performed.

---

## Function Structure

The program uses five functions, each with one single responsibility:

**load_config()** — Opens the JSON config file and converts it into a Python dictionary. Handles file-not-found and broken JSON errors.

**validate_config()** — Checks the config across all four validation levels. Collects all errors before returning. Never stops at the first problem.

**simulate_backup()** — Generates fake file data for each source. Returns a report dictionary with summary statistics and file listings.

**generate_report()** — Prints a formatted, human-readable report to the screen showing the plan name, summary statistics, and sample files for each source.

**main()** — The orchestrator that coordinates all the other functions in the correct order: Load → Validate → Simulate → Report. It does not do the detailed work itself — it calls the right specialist function at the right time and passes results from one step to the next. Think of it like a student onboarding plan — it directs every step of the process in the right sequence without doing the work of any individual office. Reads the config file name from the command line.

Each function does one thing only. This makes the program easier to test, debug, and maintain.

---

## AI Tool Usage

I used Claude.ai throughout this project as a learning and development tool.

**What I used it for:**
- Building the JSON schema and config files
- Understanding Python concepts in plain language using real-world analogies from my work
- Writing and debugging each function step by step
- Generating the complete backup_planner.py file
- Reviewing requirements against the assignment rubric

**What I learned from the process:**
- Programming uses familiar words in unfamiliar ways. Every organization I have worked with uses its own acronyms and terminology — words that mean something completely specific in that context and something different everywhere else. Python is no different.
- Config-driven programming is something I already understand from my professional work — separating settings from processes so that the process never changes, only the settings do.

**What I verified myself:**
- Ran all tests on my own Mac to confirm the program works
- Checked that all four validation levels produce correct error messages
- Confirmed the simulation generates realistic fake data without reading real directories

---

## Testing

**Valid config test:**
Running the program with `backup_config.json` produces a full dry-run simulation report showing 3 sources, realistic file counts, and total size estimates.

**Invalid config test:**
Running the program with `invalid_config.json` produces:
```
Validation FAILED. 3 error(s) found:
  [1] Missing required field: 'plan_name'
  [2] Missing required field: 'destination'
  [3] 'sources' must be a list, got str
```

---

## Challenges

**Technical challenge:**
Python indentation was the most consistent technical difficulty. Python requires exact spacing to know which code belongs inside which block. A single extra space causes an error. This reminded me of entering data into a state reporting system — if a budget figure was off even by a penny, the entire report would not submit. Precision is not optional.

**Conceptual challenge:**
Programming uses familiar words in unfamiliar ways. Every organization I have worked with uses its own acronyms and terminology — words that mean something completely specific in that context and something different everywhere else. Python is no different. The word "dictionary" has nothing to do with word definitions — in Python it means a bundle of related information grouped together. Learning the local language of Python, just like learning the language of a new organization, was an important part of this assignment.

**What helped:**
Working through each concept with real-world analogies from my professional experience made the logic much clearer. The config-driven programming concept connected directly to work I already do — keeping settings separate from processes so that nothing breaks when settings change.
