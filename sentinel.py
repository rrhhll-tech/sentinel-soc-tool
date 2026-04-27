import requests
import re

API_KEY = "c334492f110ff5c185f283f3742cca2c47c59c0c1226047dd6f82066dfd76e12b8998aa6b9c12a33"

# ─── PART 1: Alert Analyzer ───────────────────────────────
def analyze_alert(alert):
    alert_lower = alert.lower()

    if "multiple failed login" in alert_lower or ("failed login" in alert_lower and "multiple" in alert_lower):
        return "🔴 HIGH RISK: Possible brute force attack"
    elif "malware detected" in alert_lower:
        return "🔴 HIGH RISK: Malware activity"
    elif "ip flagged as malicious" in alert_lower:
        return "🔴 HIGH RISK: Known malicious IP"
    elif "ransomware" in alert_lower:
        return "🔴 CRITICAL: Ransomware detected — isolate host NOW"
    elif "powershell" in alert_lower and "encoded" in alert_lower:
        return "🔴 HIGH RISK: Suspicious PowerShell execution"
    elif "login from new location" in alert_lower:
        return "🟡 MEDIUM RISK: Suspicious login — verify with user"
    elif "large file transfer" in alert_lower:
        return "🟡 MEDIUM RISK: Possible data exfiltration"
    elif "login successful" in alert_lower:
        return "🟢 LOW RISK: Normal activity"
    else:
        return "⚪ UNKNOWN: Manual review needed"


# ─── PART 2: IP Extractor ─────────────────────────────────
def extract_ip(alert):
    # This finds any IP address pattern inside the alert text
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(pattern, alert)
    if match:
        return match.group()
    return None


# ─── PART 3: IP Reputation Checker ───────────────────────
def check_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json()["data"]

    score = data["abuseConfidenceScore"]

    print(f"   🔍 IP Address  : {data['ipAddress']}")
    print(f"   🌍 Country     : {data['countryCode']}")
    print(f"   🏢 ISP         : {data['isp']}")
    print(f"   📊 Abuse Score : {score}%")
    print(f"   📋 Reports     : {data['totalReports']}")

    if score >= 80:
        print(f"   🔴 IP VERDICT  : HIGHLY MALICIOUS — Block immediately")
    elif score >= 40:
        print(f"   🟡 IP VERDICT  : SUSPICIOUS — Monitor closely")
    elif score >= 10:
        print(f"   🟠 IP VERDICT  : LOW RISK — Keep an eye on it")
    else:
        print(f"   🟢 IP VERDICT  : CLEAN — No threat detected")


# ─── PART 4: Combined SENTINEL Engine ────────────────────
def sentinel(alert):
    print("\n" + "=" * 60)
    print("        🛡️  SENTINEL — SOC L1 DASHBOARD")
    print("=" * 60)
    print(f"\n📨 ALERT : {alert}")
    print("\n📋 ALERT ANALYSIS:")
    print(f"   {analyze_alert(alert)}")

    ip = extract_ip(alert)
    if ip:
        print(f"\n🌐 IP FOUND IN ALERT: {ip}")
        print("   Checking live threat intelligence...\n")
        check_ip(ip)
    else:
        print("\n⚪ NO IP ADDRESS found in this alert")

    print("\n" + "=" * 60)


# ─── TEST ALERTS ──────────────────────────────────────────
alerts = [
    "Multiple failed login attempts from IP 185.220.101.45",
    "Malware detected in file upload from IP 8.8.8.8",
    "User login from new location - no IP available",
    "Ransomware activity detected from IP 45.33.32.156",
]

for alert in alerts:
    sentinel(alert)