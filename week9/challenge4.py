import json

def load_inventory(filepath):
    with open(filepath, 'r') as f:
        hosts = json.load(f)
    return hosts

hosts = load_inventory('host_inventory.json')

def calculate_days_since_patch(host):
    from datetime import datetime
    patch_date = datetime.strptime(host['last_patch_date'], '%Y-%m-%d')
    delta = datetime.now() - patch_date
    return delta.days

def calculate_risk_score(host):
    score = 0

    criticality_points = {"critical": 40, "high": 25, "medium": 10, "low": 5}
    score += criticality_points.get(host['criticality'], 0)

    days = host.get('days_since_patch', 0)
    if days > 90:
        score += 30
    elif days > 60:
        score += 20
    elif days > 30:
        score += 10

    env_points = {"production": 15, "staging": 8, "development": 3}
    score += env_points.get(host['environment'], 0)

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
    
def get_top_n_risks(hosts, n=5):
    for host in hosts:
        host['days_since_patch'] = calculate_days_since_patch(host)
        host['risk_score'] = calculate_risk_score(host)
        host['risk_level'] = get_risk_level(host['risk_score'])
    
    return sorted(hosts, key=lambda h: h['risk_score'], reverse=True)[:n]

top_five = get_top_n_risks(hosts, 5)
print("Top 5 Highest Risk Hosts:")
for i, h in enumerate(top_five, 1):
    print(f"{i}. {h['hostname']} — Score: {h['risk_score']} ({h['risk_level']})")
    