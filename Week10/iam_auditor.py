import json
from datetime import datetime, timedelta
from collections import defaultdict

# ── Load Data ──────────────────────────────────────────────────────────────────

def load_json(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

users_data = load_json('users.json')
roles_data = load_json('roles.json')

print(f"Loaded {len(users_data)} users")
print(f"Loaded {len(roles_data)} role assignments")
print(f"First user: {users_data[0]}")

# ── Build User Lookup Dictionary ───────────────────────────────────────────────

def build_user_lookup(users_data):
    # Create dictionary keyed by user_id for fast O(1) lookups
    return {user['user_id']: user for user in users_data}

users_dict = build_user_lookup(users_data)

# Test: look up a specific user
user = users_dict['U001']
print(f"\n{user['username']} is in the {user['department']} department")
print(f"Total users in lookup: {len(users_dict)}")

# ── Group Roles by User ────────────────────────────────────────────────────────

def group_roles_by_user(roles_data):
    # Group all roles for each user using defaultdict
    user_roles = defaultdict(list)
    
    for role_entry in roles_data:
        user_id = role_entry['user_id']
        user_roles[user_id].append(role_entry['role'])
    
    return dict(user_roles)

user_roles = group_roles_by_user(roles_data)

# Test: check U002 who has 2 roles
print(f"\nU002 has roles: {user_roles['U002']}")
print(f"U001 has roles: {user_roles['U001']}")

# ── Rule 1: Disabled Users with Active Roles ───────────────────────────────────

def check_disabled_with_roles(users_dict, roles_data):
    violations = []
    
    # Build set of user_ids that have roles
    users_with_roles = {r['user_id'] for r in roles_data}
    
    # Check each disabled user
    for user_id, user in users_dict.items():
        if user['status'] == 'disabled' and user_id in users_with_roles:
            # Find all roles for this user
            user_roles = [r['role'] for r in roles_data if r['user_id'] == user_id]
            
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'disabled_with_roles',
                'severity': 'CRITICAL',
                'details': f"Disabled account has {len(user_roles)} active role(s): {', '.join(user_roles)}"
            })
    
    return violations

# Test Rule 1
violations_rule1 = check_disabled_with_roles(users_dict, roles_data)
print(f"\nRule 1 found {len(violations_rule1)} violations:")
for v in violations_rule1:
    print(f"  {v['username']}: {v['details']}")

# ── Rule 2: Unauthorized Admin Access ─────────────────────────────────────────

def check_unauthorized_admins(users_dict, roles_data, authorized_depts={'IT', 'Security'}):
    violations = []
    
    for role_entry in roles_data:
        # Check if role contains "admin" (case-insensitive)
        if 'admin' in role_entry['role'].lower():
            user_id = role_entry['user_id']
            
            if user_id in users_dict:
                user = users_dict[user_id]
                
                # Flag if department is not authorized
                if user['department'] not in authorized_depts:
                    violations.append({
                        'user_id': user_id,
                        'username': user['username'],
                        'violation_type': 'unauthorized_admin',
                        'severity': 'HIGH',
                        'details': f"{user['department']} dept user has admin role: {role_entry['role']}",
                        'department': user['department'],
                        'role': role_entry['role']
                    })
    
    return violations

# Test Rule 2
violations_rule2 = check_unauthorized_admins(users_dict, roles_data)
print(f"\nRule 2 found {len(violations_rule2)} violations:")
for v in violations_rule2:
    print(f"  {v['username']} ({v['department']}): {v['details']}")

# ── Rule 3: Stale Accounts ─────────────────────────────────────────────────────

def check_stale_accounts(users_dict, stale_days=90):
    violations = []
    cutoff_date = datetime.now() - timedelta(days=stale_days)
    
    for user_id, user in users_dict.items():
        # Only check active accounts
        if user['status'] != 'active':
            continue
        
        last_login_str = user.get('last_login')
        
        if not last_login_str:
            # No login date recorded
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'stale_account',
                'severity': 'MEDIUM',
                'details': 'Active account with no recorded login date',
                'last_login': None
            })
        else:
            # Parse date and check threshold
            last_login = datetime.strptime(last_login_str, '%Y-%m-%d')
            
            if last_login < cutoff_date:
                days_since = (datetime.now() - last_login).days
                violations.append({
                    'user_id': user_id,
                    'username': user['username'],
                    'violation_type': 'stale_account',
                    'severity': 'MEDIUM',
                    'details': f"No login for {days_since} days (last: {last_login_str})",
                    'last_login': last_login_str,
                    'days_inactive': days_since
                })
    
    return violations

# Test Rule 3
violations_rule3 = check_stale_accounts(users_dict)
print(f"\nRule 3 found {len(violations_rule3)} violations:")
for v in violations_rule3:
    print(f"  {v['username']}: {v['details']}")

# ── Rule 4: Orphaned Roles ─────────────────────────────────────────────────────

def check_orphaned_roles(users_dict, roles_data):
    violations = []
    
    # Build set of all known user_ids from users.json
    known_user_ids = set(users_dict.keys())
    
    for role_entry in roles_data:
        user_id = role_entry['user_id']
        
        # Flag if user_id in roles has no matching user record
        if user_id not in known_user_ids:
            violations.append({
                'user_id': user_id,
                'username': 'UNKNOWN',
                'violation_type': 'orphaned_role',
                'severity': 'HIGH',
                'details': f"Role '{role_entry['role']}' assigned to user_id {user_id} which does not exist in user records",
                'role': role_entry['role']
            })
    
    return violations

# Test Rule 4
violations_rule4 = check_orphaned_roles(users_dict, roles_data)
print(f"\nRule 4 found {len(violations_rule4)} violations:")
for v in violations_rule4:
    print(f"  {v['user_id']}: {v['details']}")

# ── Rule 5: Excessive Permissions ─────────────────────────────────────────────

def check_excessive_permissions(users_dict, user_roles, max_roles=1):
    violations = []
    
    for user_id, roles in user_roles.items():
        # Only check active users
        if user_id in users_dict and users_dict[user_id]['status'] == 'active':
            if len(roles) > max_roles:
                violations.append({
                    'user_id': user_id,
                    'username': users_dict[user_id]['username'],
                    'violation_type': 'excessive_permissions',
                    'severity': 'LOW',
                    'details': f"Active user has {len(roles)} roles (max allowed: {max_roles}): {', '.join(roles)}",
                    'role_count': len(roles)
                })
    
    return violations

# Test Rule 5
violations_rule5 = check_excessive_permissions(users_dict, user_roles)
print(f"\nRule 5 found {len(violations_rule5)} violations:")
for v in violations_rule5:
    print(f"  {v['username']}: {v['details']}")

# ── Combine All Violations ─────────────────────────────────────────────────────

all_violations = []
all_violations.extend(violations_rule1)
all_violations.extend(violations_rule2)
all_violations.extend(violations_rule3)
all_violations.extend(violations_rule4)
all_violations.extend(violations_rule5)

print(f"\nTotal violations found: {len(all_violations)}")
print(f"Breakdown by severity:")
for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
    count = sum(1 for v in all_violations if v['severity'] == severity)
    print(f"  {severity}: {count}")

# ── Generate JSON Report ───────────────────────────────────────────────────────

def generate_json_report(all_violations, users_dict, roles_data):
    # Calculate summary statistics
    severity_counts = {}
    type_counts = {}
    
    for v in all_violations:
        sev = v['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        vtype = v['violation_type']
        type_counts[vtype] = type_counts.get(vtype, 0) + 1
    
    report = {
        'audit_metadata': {
            'timestamp': datetime.now().isoformat(),
            'total_users_audited': len(users_dict),
            'total_role_assignments': len(roles_data),
            'total_violations': len(all_violations),
            'auditor': 'IAM Audit System v1.0'
        },
        'violation_summary': {
            'by_severity': severity_counts,
            'by_type': type_counts
        },
        'all_violations': all_violations
    }
    
    with open('audit_report.json', "w") as f:
        json.dump(report, f, indent=2)

# Write JSON report to file
generate_json_report(all_violations, users_dict, roles_data)

print(f"\nJSON report saved to audit_report.json")

# ── Generate Text Report ───────────────────────────────────────────────────────

def generate_text_report(all_violations, users_dict, roles_data):
    lines = []
    lines.append("=" * 80)
    lines.append("USER ACCOUNT & PERMISSIONS AUDIT REPORT")
    lines.append("=" * 80)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    # Executive summary
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 80)
    lines.append(f"Total Users Audited:      {len(users_dict)}")
    lines.append(f"Total Role Assignments:   {len(roles_data)}")
    lines.append(f"Total Violations Found:   {len(all_violations)}")
    lines.append("")
    
    # Violations by severity
    severity_counts = {}
    for v in all_violations:
        sev = v['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.append("VIOLATIONS BY SEVERITY")
    lines.append("-" * 80)
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_counts.get(severity, 0)
        bar = "█" * count
        lines.append(f"{severity:12s} [{count:3d}] {bar}")
    lines.append("")

    # Violations by type
    type_counts = {}
    for v in all_violations:
        vtype = v['violation_type']
        type_counts[vtype] = type_counts.get(vtype, 0) + 1

    lines.append("VIOLATIONS BY TYPE")
    lines.append("-" * 80)
    for vtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"{vtype:30s} {count}")
    lines.append("")

    # Detailed violations by severity
    lines.append("DETAILED VIOLATIONS")
    lines.append("-" * 80)
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        severity_violations = [v for v in all_violations if v['severity'] == severity]
        if severity_violations:
            lines.append(f"\n[{severity}]")
            for v in severity_violations:
                lines.append(f"  User:    {v['username']} ({v['user_id']})")
                lines.append(f"  Type:    {v['violation_type']}")
                lines.append(f"  Details: {v['details']}")
                lines.append("")

    return "\n".join(lines)

# Write text report to file
text_report = generate_text_report(all_violations, users_dict, roles_data)
with open('audit_report.txt', 'w') as f:
    f.write(text_report)

print(f"Text report saved to audit_report.txt")