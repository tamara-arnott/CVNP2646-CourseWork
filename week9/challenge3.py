from datetime import datetime

def calculate_days_since_patch(host):
    patch_date = datetime.strptime(host['last_patch_date'], '%Y-%m-%d')
    delta = datetime.now() - patch_date
    return delta.days

def calculate_risk_score(host):
    score = 0

    # Factor 1: Criticality
    criticality_points = {"critical": 40, "high": 25, "medium": 10, "low": 5}
    score += criticality_points.get(host['criticality'], 0)

    # Factor 2: Patch age (check >90 FIRST — order matters)
    days = host.get('days_since_patch', 0)
    if days > 90:
        score += 30
    elif days > 60:
        score += 20
    elif days > 30:
        score += 10

    # Factor 3: Environment
    env_points = {"production": 15, "staging": 8, "development": 3}
    score += env_points.get(host['environment'], 0)

    # Factor 4-6: Tags
    tags = host.get('tags', [])
    if 'pci-scope' in tags:
        score += 10
    if 'hipaa' in tags:
        score += 10
    if 'internet-facing' in tags:
        score += 15

    return min(score, 100)

def get_risk_level(score):
    if score >= 70:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"
    
test_host = {
    "hostname": "FIN-WKS-001",
    "criticality": "high",
    "last_patch_date": "2024-08-15",
    "environment": "production",
    "tags": ["pci-scope", "internet-facing"]
}

test_host['days_since_patch'] = calculate_days_since_patch(test_host)

score = calculate_risk_score(test_host)
level = get_risk_level(score)
print(f"{test_host['hostname']}: score={score}, level={level}")

test_host['days_since_patch'] = calculate_days_since_patch(test_host)

score = calculate_risk_score(test_host)
level = get_risk_level(score)
print(f"{test_host['hostname']}: score={score}, level={level}")
