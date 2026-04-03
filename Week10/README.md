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

To connect the two files quickly, the script organizes user records into a filling-cabinet-style lookup table where each user's ID is the label. This means that script can find any user's details instantly instead of scanning through every record on by one. 

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

I used Claude (Anthropic) to brainstorm additional detection rules beyond the
three required by the assignment.

**Prompt I used:**
"I'm building a user account auditor for cybersecurity. I have two datasets:
user accounts (user_id, username, status, department, last_login) and role
memberships (user_id, role, assigned_date). I've already implemented rules
for disabled users with roles, unauthorized admins, and stale accounts. What
are additional security anomalies I should detect?"

**What Claude suggested:**
1. Orphaned Roles — IMPLEMENTED. Practical and easy to implement with a set
   difference operation. Catches real data integrity problems.
2. Excessive Permissions — IMPLEMENTED. Relevant to real-world privilege
   creep. Threshold is configurable.
3. Conflicting Roles (e.g., auditor + admin) — NOT IMPLEMENTED. Good idea
   but would require a predefined list of conflicting role pairs that I don't
   have in my test data.
4. Service Account Detection — NOT IMPLEMENTED. Our data set doesn't include a field that identifies whether an account belongs to a person or an automated system, so this rule could not be built. 
5. Department Validation — NOT IMPLEMENTED. Would require a separate list of
   valid departments to check against.

I chose Rules 4 and 5 because both were supported by my existing test data,
made clear security sense, and were practical to implement and explain.

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