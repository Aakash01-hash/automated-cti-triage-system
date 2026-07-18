import re

# Adjusted regex to catch defanged IPs
IP_REGEX = r"\b(?:[0-9]{1,3}(?:\.|\[\.\])){3}[0-9]{1,3}\b"
IPSUM_PATH = "D:/CTI/data/raw/ips/ipsum.txt"

def load_malicious_ips():
    malicious_ips = set()
    try:
        with open(IPSUM_PATH, "r") as f:
            for line in f:
                if not line.startswith("#"):
                    ip = line.strip().split()[0]
                    malicious_ips.add(ip)
    except:
        pass
    return malicious_ips

def extract_ips(text):
    # Find all IPs, clean defanged brackets, and deduplicate using set()
    raw_ips = re.findall(IP_REGEX, text)
    clean_ips = [ip.replace("[.]", ".") for ip in raw_ips]
    return list(set(clean_ips))

def check_ips(text):
    ips = extract_ips(text)
    malicious_db = load_malicious_ips()
    results = []

    for ip in ips:
        if ip in malicious_db:
            results.append((ip, "Malicious"))
        else:
            results.append((ip, "Unknown"))

    return results