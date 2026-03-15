import json
from datetime import datetime
from collections import Counter

def load_inventory(filepath):
    """Load host inventory from a JSON file."""
    with open(filepath, 'r') as f:
        hosts = json.load(f)
    return hosts

def calculate_days_since_patch(host):
    """Calculate the number of days since the host was last patched."""
    patch_date = datetime.strptime(host['last_patch_date'], '%Y-%m-%d')
    delta = datetime.now() - patch_date
    return delta.days

def filter_by_os(hosts, os_type):
    """Filter hosts by OS type (case-insensitive partial match)."""
    return [h for h in hosts if os_type.lower() in h['os'].lower()]

def filter_by_criticality(hosts, level):
    """Filter hosts by criticality level (exact match)."""
    return [h for h in hosts if h['criticality'] == level]

def filter_by_environment(hosts, env):
    """Filter hosts by environment (exact match)."""
    return [h for h in hosts if h['environment'] == env]

def filter_critical_production(hosts):
    """Return only critical-criticality production hosts."""
    return [h for h in hosts if h['criticality'] == 'critical' and h['environment'] == 'production']

def calculate_risk_score(host):
    """Calculate risk score (0-100) based on 6 factors."""
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
    """Convert numeric score to risk level string."""
    if score >= 70:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"
    
def analyze_inventory(hosts):
    """Add derived fields to each host: days_since_patch, risk_score, risk_level."""
    for host in hosts:
        host['days_since_patch'] = calculate_days_since_patch(host)
        host['risk_score'] = calculate_risk_score(host)
        host['risk_level'] = get_risk_level(host['risk_score'])
    return hosts

def get_high_risk_hosts(hosts, threshold=50):
    """Return hosts with risk_score >= threshold, sorted by score descending."""
    high_risk = [h for h in hosts if h['risk_score'] >= threshold]
    return sorted(high_risk, key=lambda h: h['risk_score'], reverse=True)

def generate_json_report(hosts, high_risk_hosts, filepath):
    """Generate a JSON report of high-risk hosts."""
    risk_dist = Counter(h['risk_level'] for h in hosts)
    
    report = {
        "report_date": datetime.now().isoformat(),
        "report_type": "High Risk Host Assessment",
        "total_hosts": len(hosts),
        "total_high_risk": len(high_risk_hosts),
        "risk_distribution": {
            "critical": risk_dist.get('critical', 0),
            "high": risk_dist.get('high', 0),
            "medium": risk_dist.get('medium', 0),
            "low": risk_dist.get('low', 0)
        },
        "high_risk_hosts": [
            {
                "hostname": h['hostname'],
                "risk_score": h['risk_score'],
                "risk_level": h['risk_level'],
                "days_since_patch": h['days_since_patch'],
                "criticality": h['criticality'],
                "environment": h['environment'],
                "tags": h.get('tags', [])
            }
            for h in high_risk_hosts
        ]
    }
    
    with open(filepath, 'w') as f:
        f.write(json.dumps(report, indent=2))
    print(f"JSON report saved to {filepath}")

def generate_text_summary(hosts, high_risk_hosts, filepath):
    
    """Generate a human-readable text summary report."""
    lines = []
    risk_dist = Counter(h['risk_level'] for h in hosts)
    critical_count = risk_dist.get('critical', 0)
    very_old = sum(1 for h in hosts if h['days_since_patch'] > 90)

    lines.append("=" * 60)
    lines.append("     WEEKLY PATCH COMPLIANCE SUMMARY REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 60)
    lines.append(f"Total Systems Analyzed:        {len(hosts)}")
    lines.append(f"High-Risk Systems Identified:  {len(high_risk_hosts)} ({len(high_risk_hosts)/len(hosts)*100:.1f}%)")
    lines.append(f"Critical Priority Systems:     {critical_count}")
    lines.append(f"Immediate Action Required:     {very_old} systems >90 days unpatched")
    lines.append("")

    lines.append("RISK DISTRIBUTION")
    lines.append("-" * 60)
    lines.append(f"Critical (>=70 points):        {risk_dist.get('critical', 0)} systems")
    lines.append(f"High (50-69 points):           {risk_dist.get('high', 0)} systems")
    lines.append(f"Medium (25-49 points):         {risk_dist.get('medium', 0)} systems")
    lines.append(f"Low (<25 points):              {risk_dist.get('low', 0)} systems")
    lines.append("")

    lines.append("TOP 5 HIGHEST RISK SYSTEMS")
    lines.append("-" * 60)
    for i, host in enumerate(high_risk_hosts[:5], 1):
        lines.append(f"{i}. {host['hostname']} (Score: {host['risk_score']}, {host['risk_level'].title()})")
        lines.append(f"   Last Patched: {host['days_since_patch']} days ago | {host['environment'].title()} | Tags: {', '.join(host.get('tags', []))}")
        lines.append("")

    lines.append("RECOMMENDED ACTIONS")
    lines.append("-" * 60)
    lines.append("IMMEDIATE (Next 48 hours):")
    lines.append(f"  Patch {critical_count} critical-risk systems")
    lines.append("")
    lines.append("THIS WEEK (Next 7 days):")
    lines.append(f"  Schedule maintenance windows for {len(high_risk_hosts)} high-risk production systems")
    lines.append("")

    lines.append("COMPLIANCE NOTES")
    lines.append("-" * 60)
    pci_count = sum(1 for h in hosts if 'pci-scope' in h.get('tags', []) and h['days_since_patch'] > 30)
    if pci_count > 0:
        lines.append(f"PCI-DSS: {pci_count} systems in PCI scope require immediate attention")
    lines.append("CIS Control 7: Patch critical vulnerabilities within 48 hours")
    lines.append("=" * 60)

    output = "\n".join(lines)
    with open(filepath, 'w') as f:
        f.write(output)
    print(output)
    print(f"\nText summary saved to {filepath}")

def main():
    """Main pipeline to run the patch compliance tracker."""
    hosts = load_inventory('host_inventory.json')
    print(f"Loaded {len(hosts)} hosts")

    hosts = analyze_inventory(hosts)

    high_risk = get_high_risk_hosts(hosts, threshold=50)
    print(f"High-risk hosts identified: {len(high_risk)}")

    generate_json_report(hosts, high_risk, 'high_risk_report.json')
    generate_text_summary(hosts, high_risk, 'patch_summary.txt')


if __name__ == "__main__":
    main()

