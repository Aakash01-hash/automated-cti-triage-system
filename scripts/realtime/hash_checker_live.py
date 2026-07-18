import requests
import os

VT_API_KEY = os.getenv("VT_API_KEY")

def check_hash_live(file_hash):
    """Queries VirusTotal API v3 for file hash reputation and malware family."""
    if not VT_API_KEY:
        return {"hash": file_hash, "found": False, "error": "VT_API_KEY is not configured"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            total_scans = malicious + stats.get("undetected", 0)
            
            # Extract suggested malware family (e.g., "trojan.emotet")
            threat_label = data.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown Malware")
            
            return {
                "hash": file_hash,
                "malicious": malicious,
                "total": total_scans,
                "family": threat_label,
                "found": True
            }
            
        elif response.status_code == 404:
            return {"hash": file_hash, "found": False, "error": "Clean / Not found in VT"}
        else:
            return {"hash": file_hash, "found": False, "error": f"API Error {response.status_code}"}
            
    except Exception as e:
        return {"hash": file_hash, "found": False, "error": str(e)}

if __name__ == "__main__":
    print(check_hash_live("<sha256-file-hash>"))
