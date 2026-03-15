from datetime import datetime

host = {
    "hostname": "FIN-WKS-001",
    "last_patch_date": "2024-08-15"
}

def calculate_days_since_patch(host):
    patch_date = datetime.strptime(host['last_patch_date'], '%Y-%m-%d')
    delta = datetime.now() - patch_date
    return delta.days

days = calculate_days_since_patch(host)
print(f"{host['hostname']}: last patched {days} days ago")

