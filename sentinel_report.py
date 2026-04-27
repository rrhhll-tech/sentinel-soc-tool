import requests
import re
from datetime import datetime

API_KEY = "c334492f110ff5c185f283f3742cca2c47c59c0c1226047dd6f82066dfd76e12b8998aa6b9c12a33"

# ─── Alert Analyzer ───────────────────────────────────────
def analyze_alert(alert):
    alert_lower = alert.lower()

    if "multiple failed login" in alert_lower or ("failed login" in alert_lower and "multiple" in alert_lower):
        return "HIGH RISK", "Possible brute force attack"
    elif "malware detected" in alert_lower:
        return "HIGH RISK", "Malware activity detected"
    elif "ip flagged as malicious" in alert_lower:
        return "HIGH RISK", "Known malicious IP"
    elif "ransomware" in alert_lower:
        return "CRITICAL", "Ransomware detected — isolate host NOW"
    elif "powershell" in alert_lower and "encoded" in alert_lower:
        return "HIGH RISK", "Suspicious PowerShell execution"
    elif "login from new location" in alert_lower:
        return "MEDIUM RISK", "Suspicious login — verify with user"
    elif "large file transfer" in alert_lower:
        return "MEDIUM RISK", "Possible data exfiltration"
    elif "login successful" in alert_lower:
        return "LOW RISK", "Normal activity"
    else:
        return "UNKNOWN", "Manual review needed"


# ─── IP Extractor ─────────────────────────────────────────
def extract_ip(alert):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(pattern, alert)
    if match:
        return match.group()
    return None


# ─── IP Checker ───────────────────────────────────────────
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

    if score >= 80:
        verdict = "HIGHLY MALICIOUS — Block immediately"
    elif score >= 40:
        verdict = "SUSPICIOUS — Monitor closely"
    elif score >= 10:
        verdict = "LOW RISK — Keep an eye on it"
    else:
        verdict = "CLEAN — No threat detected"

    return {
        "ip": data["ipAddress"],
        "country": data["countryCode"],
        "isp": data["isp"],
        "score": score,
        "reports": data["totalReports"],
        "verdict": verdict
    }


# ─── Report Generator ─────────────────────────────────────
def generate_report(alert, severity, analysis, ip_data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    report = f"""
============================================================
           SENTINEL SOC L1 INCIDENT REPORT
============================================================

REPORT GENERATED : {timestamp}
ANALYST LEVEL    : L1
STATUS           : Open — Pending L2 Review

------------------------------------------------------------
ALERT DETAILS
------------------------------------------------------------
ALERT            : {alert}
SEVERITY         : {severity}
ANALYSIS         : {analysis}

------------------------------------------------------------
IP INTELLIGENCE
------------------------------------------------------------
"""

    if ip_data:
        report += f"""IP ADDRESS       : {ip_data['ip']}
COUNTRY          : {ip_data['country']}
ISP              : {ip_data['isp']}
ABUSE SCORE      : {ip_data['score']}%
TOTAL REPORTS    : {ip_data['reports']}
IP VERDICT       : {ip_data['verdict']}
"""
    else:
        report += "No IP address found in this alert.\n"

    report += """
------------------------------------------------------------
RECOMMENDED ACTIONS
------------------------------------------------------------
"""

    if severity == "CRITICAL":
        report += """1. ISOLATE affected host immediately
2. Block IP at firewall
3. Escalate to L2 and L3 NOW
4. Notify security manager
5. Preserve logs and memory dump
"""
    elif severity == "HIGH RISK":
        report += """1. Block suspicious IP at firewall
2. Investigate affected user account
3. Escalate to L2 analyst
4. Check for lateral movement
5. Document all findings
"""
    elif severity == "MEDIUM RISK":
        report += """1. Verify with affected user
2. Monitor account for 24 hours
3. Check login history
4. Document findings
"""
    else:
        report += """1. Monitor and log
2. No immediate action required
3. Review if pattern continues
"""

    report += """
------------------------------------------------------------
ESCALATION NOTES
------------------------------------------------------------
[ ] Escalated to L2 Analyst
[ ] Ticket created in SIEM
[ ] User notified
[ ] Manager informed

============================================================
                    END OF REPORT
============================================================
"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)

    return filename, report


# ─── SENTINEL Live Engine ─────────────────────────────────
def sentinel(alert):
    print("\n" + "=" * 60)
    print("        SENTINEL — SOC L1 REPORT DASHBOARD")
    print("=" * 60)
    print(f"\nALERT : {alert}")

    severity, analysis = analyze_alert(alert)
    print(f"\nSEVERITY : {severity}")
    print(f"ANALYSIS : {analysis}")

    ip_data = None
    ip = extract_ip(alert)
    if ip:
        print(f"\nIP FOUND: {ip}")
        print("Checking live threat intelligence...\n")
        ip_data = check_ip(ip)
        print(f"IP       : {ip_data['ip']}")
        print(f"Country  : {ip_data['country']}")
        print(f"ISP      : {ip_data['isp']}")
        print(f"Score    : {ip_data['score']}%")
        print(f"Verdict  : {ip_data['verdict']}")
    else:
        print("\nNO IP ADDRESS found in this alert")

    print("\nGenerating incident report...")
    filename, report = generate_report(alert, severity, analysis, ip_data)
    print(f"Report saved as: {filename}")
    print("\n" + "=" * 60)


# ─── LIVE INTERACTIVE LOOP ────────────────────────────────
print("\n" + "=" * 60)
print("        SENTINEL REPORT — SOC L1 ANALYST TOOL")
print("        Type any alert — report auto generated")
print("        Type exit to quit")
print("=" * 60)

while True:
    print()
    alert = input("Paste Alert Here: ")

    if alert.lower() == "exit":
        print("\nSENTINEL shutting down. Stay secure!\n")
        break

    if alert.strip() == "":
        print("Please type an alert first!")
        continue

    sentinel(alert)