import json

def load_inventory(filepath):
    with open(filepath, 'r') as f:
        hosts = json.load(f)
    return hosts

hosts = load_inventory('host_inventory.json')
print(f"Loaded {len(hosts)} hosts")

def filter_critical_production(hosts):
    """Return only critical-criticality production hosts."""
    return [h for h in hosts if h['criticality'] == 'critical' and h['environment'] == 'production']

critical_prod = filter_critical_production(hosts)
print(f"\nCritical production hosts: {len(critical_prod)}")
for h in critical_prod:
    print(f"  {h['hostname']} ({h['criticality']} / {h['environment']})")
    