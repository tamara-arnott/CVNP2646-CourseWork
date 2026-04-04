# Week 10: User Account & Permissions Auditor
**CVNP2646 – Cybersecurity with Python**
Tamara Arnott | Alexandria Technical & Community College

---

## What This Tool Does

This script audits two related datasets — a list of user accounts and a list
of role assignments — and flags security problems called violations. Think of
it like an enrollment audit at a college: you want to make sure that students
who withdrew aren't still showing up on active rosters, and that people only
have access to the systems they're supposed to. This tool does the same thing
for user accounts and permissions in an IT system.

The auditor loads both datasets, connects them by a shared ID number, runs
five detection rules, and produces two reports: one formatted for humans to
read, and one formatted for automated systems to process.

---

## The Two Datasets and How They Connect

**users.json** is the master list of user accounts. Each user appears once
and has a unique user_id (like a student ID number), a username, a status
(active or disabled), a department, and a last login date.

**roles.json** is the list of permissions assigned to users. Each entry
connects a user_id to a role (like "admin" or "hr_manager") and the date it
was assigned. One user can appear multiple times here if they have more than
one role.

The user_id is the foreign key that connects the two files — the same way a
student ID connects an enrollment record to a financial aid record in a
student information system.

To connect the two files quickly, the script organizes user records into a filing-cabinet-style lookup table where each user's ID is the label. This means the script can find any user's details instantly instead of scanning through every record one by one. 

---

## Detection Rules

### Rule 1: Disabled Users with Active Roles — CRITICAL
Flags any user whose account is disabled but still has role assignments in
the system. This is like a separated employee whose building access card was
never deactivated — they can't log in, but the permissions are still sitting
there waiting to be exploited.

### Rule 2: Unauthorized Admin Access — HIGH
Flags any user outside the IT or Security departments who has been assigned
an admin-level role. Admin roles carry elevated privileges. If someone in
Finance or Marketing has admin access, that's a policy violation that needs
immediate review — similar to a department chair having system-wide grade
change permissions when only the Registrar should.

### Rule 3: Stale Accounts — MEDIUM
Flags active accounts where the user hasn't logged in for 90 or more days.
Dormant accounts are a security risk because they can be compromised without
anyone noticing. This is like a student who stopped attending but was never
officially withdrawn — still on the books, but nobody's watching.

### Rule 4: Orphaned Roles — HIGH
Flags role assignments where the user_id doesn't match any user in the user
accounts file. This catches data integrity problems — permissions assigned to
accounts that no longer exist, or were never properly set up. Like finding
financial aid awards attached to student IDs that don't exist in the SIS.

### Rule 5: Excessive Permissions — LOW
Flags active users who have more roles assigned than the allowed threshold.
Over time, users accumulate permissions they no longer need — a pattern called
privilege creep. This rule catches accounts that have collected more access
than their job requires.

---

## AI-Assisted Development

### Tool Used
I used Claude (Anthropic) throughout this project for brainstorming additional
detection rules, talking through logic before writing code, and checking my
work as I built each piece. I chose Claude because it is the AI tool I have
been using throughout this course and I am familiar with how to work with it
effectively.

### Exact Prompt Used for Rule Brainstorming
"I'm building a user account auditor for cybersecurity per the instructions. 
I have been given two datasets:
user accounts (user_id, username, status, department, last_login) and role
memberships (user_id, role, assigned_date). I've already implemented rules
for disabled users with roles, unauthorized admins, and stale accounts. What
are additional security anomalies I should detect?"

### AI Suggestions — Implemented vs Rejected

| Suggestion | Decision | Reason |
|------------|----------|--------|
| Orphaned Roles | IMPLEMENTED | Practical, supported by our data, catches real data integrity problems |
| Excessive Permissions | IMPLEMENTED | Relevant to real-world privilege creep, threshold is configurable |
| Conflicting Roles | REJECTED | Claude said this would require a predefined list of conflicting role pairs not available in our test data |
| Service Account Detection | REJECTED | Our dataset doesn't include a field identifying automated system accounts vs. person accounts |
| Department Validation | REJECTED | Would require a separate list of valid departments to check against |

### Bugs or Issues Found in AI-Generated Code
No bugs were found in the AI-suggested code. One adjustment was made to the
excessive permissions rule: Claude initially suggested a threshold of 5 roles,
but I changed it to 1 because most users in our dataset have exactly one role,
making 1 the appropriate baseline for this environment.

### How AI Improved the Final Implementation
Working with Claude helped me think through the data relationships before
writing any code — similar to talking through a problem with a colleague
before jumping to a solution. Claude also helped me understand why certain
approaches are faster than others, such as why building a dictionary lookup
once at the start is more efficient than searching through a list repeatedly.

---

## Test Results

The auditor was run against 20 user accounts and 21 role assignments, with
intentional violations built into the test data to verify each rule.

| Rule | Violations Found |
|------|-----------------|
| Rule 1: Disabled with roles | 6 |
| Rule 2: Unauthorized admins | 2 |
| Rule 3: Stale accounts | 2 |
| Rule 4: Orphaned roles | 0 |
| Rule 5: Excessive permissions | 0 |
| **Total** | **10** |

**Severity breakdown:**
- CRITICAL: 6
- HIGH: 2
- MEDIUM: 2
- LOW: 0

Rules 4 and 5 correctly returned zero violations, confirming no false
positives in the test data for those rules.

---

## Output Files

- `audit_report.json` — machine-readable report for automated systems
- `audit_report.txt` — human-readable report for security staff review