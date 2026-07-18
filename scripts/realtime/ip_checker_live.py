import requests
import os

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip_live(ip):
    if not API_KEY:
        return {"error": "ABUSEIPDB_API_KEY is not configured"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code != 200:
            return {"error": f"API Error {response.status_code}"}
        data = response.json()["data"]
        return {
            "ip": ip,
            "abuse_score": data["abuseConfidenceScore"],
            "country": data["countryCode"],
            "isp": data["isp"]
        }
    except Exception as e:
        return {"error": str(e)}
