import requests

API_KEY = "c334492f110ff5c185f283f3742cca2c47c59c0c1226047dd6f82066dfd76e12b8998aa6b9c12a33"

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

    print("=" * 60)
    print(f"🔍 IP Address     : {data['ipAddress']}")
    print(f"🌍 Country        : {data['countryCode']}")
    print(f"📊 Abuse Score    : {data['abuseConfidenceScore']}%")
    print(f"📋 Total Reports  : {data['totalReports']}")
    print(f"🏢 ISP            : {data['isp']}")
    print("=" * 60)

    score = data["abuseConfidenceScore"]

    if score >= 80:
        print("🔴 VERDICT: HIGHLY MALICIOUS — Block immediately")
    elif score >= 40:
        print("🟡 VERDICT: SUSPICIOUS — Monitor closely")
    elif score >= 10:
        print("🟠 VERDICT: LOW RISK — Keep an eye on it")
    else:
        print("🟢 VERDICT: CLEAN — No threat detected")
    
    print("=" * 60)


# Test IPs
ips_to_check = [
    "185.220.101.45",   # Known malicious TOR exit node
    "8.8.8.8",          # Google DNS - should be clean
]

for ip in ips_to_check:
    check_ip(ip)
    print()