import re

def extract_features(text):
    text_lower = text.lower()

    # 1. KEYWORDS
    keywords = ["phishing", "exploit", "malware", "ransomware", "backdoor", "attack", "payload", "trojan"]
    keyword_score = sum(1 for k in keywords if k in text_lower)

    # 2. TEXT LENGTH
    text_length = len(text.split())

    # 3. ATTACK RELATED
    attack_terms = ["exploit", "attack", "payload", "execution", "powershell", "command", "lateral movement", "persistence", "credential dumping"]
    attack_related = int(any(term in text_lower for term in attack_terms))

    # 4. IOC COUNT (Upgraded for defanged domains/IPs like [.])
    ip_pattern = r"\b(?:[0-9]{1,3}(?:\.|\[\.\])){3}[0-9]{1,3}\b"
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+(?:\.|\[\.\]))+[a-zA-Z]{2,}\b"
    hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"
    file_pattern = r"\b[\w-]+\.(?:exe|dll|bat|sh|ps1)\b" # Added file extraction

    ips = re.findall(ip_pattern, text)
    domains = re.findall(domain_pattern, text)
    hashes = re.findall(hash_pattern, text)
    files = re.findall(file_pattern, text, re.IGNORECASE)

    ioc_count = len(ips) + len(domains) + len(hashes) + len(files)

    # 5 & 6. CVE COUNT & BOOLEAN
    cve_pattern = r"CVE-\d{4}-\d+"
    cves = re.findall(cve_pattern, text, re.IGNORECASE)
    cve_count = len(cves)
    has_cve = 1 if cve_count > 0 else 0

    # 7. ENTITY COUNT
    entity_count = len(re.findall(r"\b[A-Z][a-zA-Z]+\b", text))

    # 8. THREAT SCORE
    threat_score = (keyword_score * 2) + (attack_related * 2) + (ioc_count * 3) + (cve_count * 2)

    # LOW FILTER
    if "general" in text_lower or "awareness" in text_lower or "educational" in text_lower:
        keyword_score = 0
        attack_related = 0
        threat_score = 0

    return [keyword_score, text_length, attack_related, ioc_count, cve_count, has_cve, entity_count, threat_score]

def extract_indicators(text):
    """Helper function to return raw lists for the GUI"""
    ip_pattern = r"\b(?:[0-9]{1,3}(?:\.|\[\.\])){3}[0-9]{1,3}\b"
    file_pattern = r"\b[\w-]+\.(?:exe|dll|bat|sh|ps1)\b"
    cve_pattern = r"CVE-\d{4}-\d+"
    
    ips = list(set(re.findall(ip_pattern, text))) # Deduplicated
    files = list(set(re.findall(file_pattern, text, re.IGNORECASE)))
    cves = list(set(re.findall(cve_pattern, text, re.IGNORECASE)))
    
    return {"ips": ips, "files": files, "cves": cves}

# ... [Keep your existing extract_features function exactly the same] ...

def extract_indicators(text):
    """Helper function to return raw lists for the GUI and WebApp"""
    ip_pattern = r"\b(?:[0-9]{1,3}(?:\.|\[\.\])){3}[0-9]{1,3}\b"
    file_pattern = r"\b[\w-]+\.(?:exe|dll|bat|sh|ps1)\b"
    cve_pattern = r"CVE-\d{4}-\d+"
    hash_pattern = r"\b[a-fA-F0-9]{32,64}\b" # Catches MD5, SHA1, and SHA256
    
    ips = list(set(re.findall(ip_pattern, text)))
    files = list(set(re.findall(file_pattern, text, re.IGNORECASE)))
    cves = list(set(re.findall(cve_pattern, text, re.IGNORECASE)))
    hashes = list(set(re.findall(hash_pattern, text, re.IGNORECASE)))
    
    # Clean defanged IPs for the API
    clean_ips = [ip.replace("[.]", ".") for ip in ips]
    
    return {"ips": clean_ips, "files": files, "cves": cves, "hashes": hashes}