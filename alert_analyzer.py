def analyze_alert(alert):
    alert = alert.lower()

    if "multiple failed login" in alert or ("failed login" in alert and "multiple" in alert):
        return "🔴 HIGH RISK: Possible brute force attack"

    elif "malware detected" in alert:
        return "🔴 HIGH RISK: Malware activity"

    elif "ip flagged as malicious" in alert:
        return "🔴 HIGH RISK: Known malicious IP — block immediately"

    elif "ransomware" in alert:
        return "🔴 CRITICAL: Ransomware detected — isolate host NOW"

    elif "powershell" in alert and "encoded" in alert:
        return "🔴 HIGH RISK: Suspicious PowerShell execution"

    elif "login from new location" in alert:
        return "🟡 MEDIUM RISK: Suspicious login — verify with user"

    elif "large file transfer" in alert:
        return "🟡 MEDIUM RISK: Possible data exfiltration"

    elif "login successful" in alert or "logged in successfully" in alert:
        return "🟢 LOW RISK: Normal activity"

    else:
        return "⚪ UNKNOWN: Manual review needed"


alerts = [
    "Multiple failed login attempts detected",
    "User login from new location",
    "Malware detected in file upload",
    "User logged in successfully",
    "IP flagged as malicious - 185.220.101.45",
    "Ransomware activity detected on DESKTOP-042",
    "PowerShell encoded command executed by jsmith",
    "Large file transfer to external IP detected",
    "Unknown event type from server",
]

print("=" * 60)
print("        SENTINEL — SOC L1 Alert Analyzer v1")
print("=" * 60)

for alert in alerts:
    print(f"\n📨 Alert : {alert}")
    print(f"   Result: {analyze_alert(alert)}")
    print("-" * 60)