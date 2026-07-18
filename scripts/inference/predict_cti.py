import os
import re
import sys
import ipaddress

import joblib


CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "cti_pipeline.pkl")

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


HIGH_THREAT_TERMS = [
    "ransomware",
    "double extortion",
    "wiper",
    "cobalt strike",
    "beacon",
    "mimikatz",
    "rootkit",
    "lateral movement",
    "exfiltration",
    "exfiltrating",
    "command and control",
    "c2",
    "credential dumping",
    "dump credentials",
    "dumped credentials",
    "reverse shell",
    "webshell",
    "zero-day",
    "rce",
    "remote code execution",
    "privilege escalation",
    "system-level privilege escalation",
    "active exploitation",
    "actively monitoring",
    "threat actor",
    "apt",
    "breach",
    "malware",
    "payload",
    "memory dump",
    "perimeter firewall",
]

MEDIUM_THREAT_TERMS = [
    "phishing",
    "phishing payload",
    "malspam",
    "macro",
    "obfuscated",
    "credential stuffing",
    "brute force",
    "password spraying",
    "failed vpn",
    "auth_failed",
    "invalid_credentials",
    "failed logon",
    "failed login",
    "port scan",
    "tor exit node",
    "beaconing",
    "anomalous",
    "unauthorized access",
    "suspicious",
    "scan",
    "recon",
    "acunetix",
]

BENIGN_CONTEXT_TERMS = [
    "scanner",
    "qualys",
    "nessus",
    "false positive",
    "remediated",
    "quarantined",
    "blocked",
    "mitigated",
    "clean",
    "authorized",
    "maintenance",
    "informational",
    "baseline",
    "patch",
    "routine",
    "approved",
    "expected behavior",
    "no active exploitation",
    "crl.microsoft.com",
    "microsoft-cryptoapi",
    "application/pkix-crl",
    "certificate revocation",
    "windowsupdate",
    "educational purposes",
    "simulated exercise",
    "theoretical",
    "training module",
    "curriculum",
    "no active threats",
]

TTP_PATTERNS = [
    {
        "name": "Phishing",
        "patterns": ["phishing", "phishing payload", "malspam"],
        "tactic": "Initial Access",
        "technique": "T1566 - Phishing",
    },
    {
        "name": "Exploit public-facing application",
        "patterns": ["cve-", "exploit", "exploiting", "authentication bypass", "public-facing", "perimeter firewall", "shellshock", "coldfusion"],
        "tactic": "Initial Access",
        "technique": "T1190 - Exploit Public-Facing Application",
    },
    {
        "name": "Privilege escalation",
        "patterns": ["privilege escalation", "system-level", "system level", "administrator privilege gain"],
        "tactic": "Privilege Escalation",
        "technique": "T1068 - Exploitation for Privilege Escalation",
    },
    {
        "name": "Command and control",
        "patterns": ["command and control", " c2 ", "cobalt strike", "beacon", "beacon64.exe"],
        "tactic": "Command and Control",
        "technique": "T1071 - Application Layer Protocol",
    },
    {
        "name": "Credential dumping",
        "patterns": ["credential dumping", "dump credentials", "lsass", "lsass_hook", "memory dump"],
        "tactic": "Credential Access",
        "technique": "T1003 - OS Credential Dumping",
    },
    {
        "name": "Lateral movement",
        "patterns": ["lateral movement"],
        "tactic": "Lateral Movement",
        "technique": "TA0008 - Lateral Movement",
    },
    {
        "name": "Exfiltration",
        "patterns": ["exfiltration", "exfiltrating", "active directory databases", "data theft"],
        "tactic": "Exfiltration",
        "technique": "TA0010 - Exfiltration",
    },
    {
        "name": "Ransomware impact",
        "patterns": ["ransomware", "encrypting", "encrypted files", "shadow copy deletion"],
        "tactic": "Impact",
        "technique": "T1486 - Data Encrypted for Impact",
    },
    {
        "name": "Active scanning",
        "patterns": [" scan ", "acunetix", "nikto", "dirbuster", "recon"],
        "tactic": "Reconnaissance",
        "technique": "T1595 - Active Scanning",
    },
    {
        "name": "Suspicious script execution",
        "patterns": ["powershell", "rundll32", "encoded", "obfuscated", "scriptlet"],
        "tactic": "Execution",
        "technique": "T1059 - Command and Scripting Interpreter",
    },
]

_MODEL = None


def _load_model():
    global _MODEL
    if _MODEL is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Production ML model not found at {MODEL_PATH}. "
                "Run scripts/models/train_pipeline.py first."
            )
        _MODEL = joblib.load(MODEL_PATH)
    return _MODEL


def _unique(values):
    return sorted(set(values))


def _count_terms(text_lower, terms):
    count = 0
    for term in terms:
        pattern = r"\b" + re.escape(term) + r"(?:s|es|ed|ing)?\b"
        if re.search(pattern, text_lower):
            count += 1
    return count


def extract_ttp_matches(text):
    text_lower = f" {text.lower()} "
    matches = []
    seen = set()
    for ttp in TTP_PATTERNS:
        if any(pattern in text_lower for pattern in ttp["patterns"]):
            key = ttp["technique"]
            if key not in seen:
                matches.append(
                    {
                        "name": ttp["name"],
                        "tactic": ttp["tactic"],
                        "technique": ttp["technique"],
                    }
                )
                seen.add(key)
    return matches


def extract_indicators(text):
    indicators = {"ips": [], "hashes": [], "cves": [], "files": [], "domains": []}

    clean_text_for_ips = text.replace("[.]", ".").replace("(.)", ".")
    raw_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", clean_text_for_ips)
    valid_ips = []
    for ip in raw_ips:
        try:
            ipaddress.IPv4Address(ip)
            valid_ips.append(ip)
        except ipaddress.AddressValueError:
            continue

    indicators["ips"] = _unique(valid_ips)
    indicators["hashes"] = _unique(
        re.findall(
            r"\b[A-Fa-f0-9]{64}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{32}\b",
            text,
        )
    )
    indicators["cves"] = _unique(
        cve.upper()
        for cve in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)
    )
    indicators["files"] = _unique(
        re.findall(r"\b[\w-]+\.(?:exe|dll|sh|py|js|aspx|bat|ps1)\b", text, re.IGNORECASE)
    )
    domain_candidates = re.findall(
        r"\b(?:[a-zA-Z0-9-]+(?:\.|\[\.\]))+[a-zA-Z]{2,}\b",
        text,
        re.IGNORECASE,
    )
    indicators["domains"] = _unique(
        domain.replace("[.]", ".")
        for domain in domain_candidates
        if not re.search(r"\.(exe|dll|sh|py|js|aspx|bat|ps1)$", domain, re.IGNORECASE)
        and ("\\" + domain.replace("[.]", ".")) not in text
    )
    return indicators


def extract_features(text):
    text_lower = text.lower()
    indicators = extract_indicators(text)
    ttp_matches = extract_ttp_matches(text)
    ioc_count = (
        len(indicators["ips"])
        + len(indicators["hashes"])
        + len(indicators["cves"])
        + len(indicators["domains"])
    )
    high_keywords = _count_terms(text_lower, HIGH_THREAT_TERMS)
    med_keywords = _count_terms(text_lower, MEDIUM_THREAT_TERMS)
    benign_keywords = _count_terms(text_lower, BENIGN_CONTEXT_TERMS)

    return {
        "high_keywords": high_keywords,
        "med_keywords": med_keywords,
        "benign_keywords": benign_keywords,
        "ioc_count": ioc_count,
        "cve_count": len(indicators["cves"]),
        "hash_count": len(indicators["hashes"]),
        "ip_count": len(indicators["ips"]),
        "file_count": len(indicators["files"]),
        "domain_count": len(indicators["domains"]),
        "keyword_score": high_keywords + med_keywords,
        "attack_related": len(ttp_matches),
        "ttp_count": len(ttp_matches),
        "ttp_matches": ttp_matches,
        "indicators": indicators,
    }


def _prediction_confidence(model, text):
    prediction = model.predict([text])[0]
    probabilities = {}
    confidence = None

    if hasattr(model, "predict_proba"):
        scores = model.predict_proba([text])[0]
        classes = list(model.classes_)
        probabilities = {label: round(float(score), 4) for label, score in zip(classes, scores)}
        confidence = round(float(max(scores)), 4)

    return prediction, confidence, probabilities


def _build_explanation(prediction, confidence, features):
    explanation = []
    confidence_text = f"{confidence:.1%}" if confidence is not None else "unavailable"
    explanation.append(f"ML pipeline classified this sample as {prediction} with confidence {confidence_text}.")

    if features["cve_count"]:
        explanation.append(f"Detected {features['cve_count']} CVE reference(s).")
    if features["ioc_count"]:
        explanation.append(f"Extracted {features['ioc_count']} actionable IoC(s) for enrichment.")
    if features["high_keywords"]:
        explanation.append(f"Matched {features['high_keywords']} high-severity threat term(s).")
    if features["med_keywords"]:
        explanation.append(f"Matched {features['med_keywords']} suspicious activity term(s).")
    if features["benign_keywords"]:
        explanation.append(f"Detected {features['benign_keywords']} benign or mitigated-context term(s).")
    if features.get("ttp_count"):
        explanation.append(f"Mapped {features['ttp_count']} behavior/TTP pattern(s) to MITRE-style context.")
    if len(explanation) == 1:
        explanation.append("No explicit IoCs were extracted; classification is based on learned text patterns.")

    return explanation


def _contains_any(text_lower, terms):
    return any(term in text_lower for term in terms)


def _has_json_event_type(text_lower, event_type):
    return f'"event_type":"{event_type}"' in text_lower or f'"event_type": "{event_type}"' in text_lower


def _is_benign_certificate_or_update(text_lower):
    return _contains_any(
        text_lower,
        [
            "crl.microsoft.com",
            "ocsp.",
            "/pki/crl/",
            ".crl",
            "microsoft-cryptoapi",
            "application/pkix-crl",
            "codesignpca.crl",
            "certificate revocation",
            "windowsupdate",
            "update.microsoft.com",
            "download.windowsupdate.com",
            "ctldl.windowsupdate.com",
            "msftncsi.com",
        ],
    )


def _is_educational_or_simulated(text_lower):
    educational_terms = [
        "educational purposes",
        "training module",
        "curriculum",
        "simulated exercise",
        "theoretical",
        "students will learn",
        "teach junior analysts",
        "no active threats",
        "example only",
        "awareness module",
    ]
    return _contains_any(text_lower, educational_terms) and _contains_any(
        text_lower,
        ["no active threats", "simulated", "theoretical", "educational purposes", "curriculum"],
    )


def _is_cti_report_context(text_lower):
    report_terms = [
        "security operations center",
        "soc",
        "threat actor",
        "apt",
        "campaign",
        "cisa",
        "fbi",
        "organizations are strongly advised",
        "forensic triage",
        "indicators of compromise",
        "telemetry indicates",
        "initial access",
    ]
    return _contains_any(text_lower, report_terms) and not _looks_like_single_raw_log(text_lower)


def _looks_like_single_raw_log(text_lower):
    raw_markers = [
        '"event_type":',
        "cef:",
        "leef:",
        "sourcetype=",
        "eventcode=",
        "eventid=",
        "src_ip",
        "dest_ip",
    ]
    return _contains_any(text_lower, raw_markers)


def _has_active_cti_compromise(text_lower, features):
    active_terms = [
        "threat actor",
        "apt",
        "active campaign",
        "actively monitoring",
        "gained initial access",
        "initial access is achieved",
        "established a command and control",
        "command and control",
        " c2 ",
        "cobalt strike",
        "beacon",
        "exfiltrating",
        "exfiltration",
        "ransomware",
        "credential",
        "lateral movement",
        "privilege escalation",
        "authentication bypass",
        "malware",
        "payload",
        "compromise enterprise networks",
    ]
    return features["cve_count"] > 0 or features["hash_count"] > 0 or _contains_any(f" {text_lower} ", active_terms)


def _is_plain_network_telemetry(text_lower):
    routine_event = any(
        _has_json_event_type(text_lower, event_type)
        for event_type in ["dns", "flow", "tls", "stats"]
    )
    return routine_event and '"event_type":"alert"' not in text_lower


def _is_http_or_fileinfo_telemetry(text_lower):
    return (
        _has_json_event_type(text_lower, "http")
        or _has_json_event_type(text_lower, "fileinfo")
    ) and '"event_type":"alert"' not in text_lower


def _is_routine_benign_telemetry(text_lower):
    if '"event_type":"alert"' in text_lower:
        return False
    routine_terms = [
        "routine",
        "allowed",
        "authorized",
        "informational",
        "baseline",
        "expected behavior",
        "clean state",
        "within expected",
        "maintenance",
    ]
    telemetry_markers = [
        "cef:",
        "leef:",
        "event_type",
        "sourcetype=",
        "src=",
        "dst=",
        "src_ip",
        "dest_ip",
        "http_method",
        "dns",
    ]
    return _contains_any(text_lower, routine_terms) and _contains_any(text_lower, telemetry_markers)


def _is_generic_scan_alert(text_lower):
    if '"event_type":"alert"' not in text_lower:
        return False
    scan_terms = [
        " scan ",
        "acunetix",
        "nikto",
        "dirbuster",
        "attempted information leak",
        "web application attack",
        "recon",
        "policy",
    ]
    return _contains_any(f" {text_lower} ", scan_terms)


def _alert_severity(text_lower):
    if '"event_type":"alert"' not in text_lower:
        return None
    match = re.search(r'"severity"\s*:\s*"?(\d+)"?', text_lower)
    if not match:
        return None
    return int(match.group(1))


def _is_high_risk_alert(text_lower):
    if '"event_type":"alert"' not in text_lower:
        return False
    high_risk_terms = [
        "trojan",
        "malware",
        "exploit",
        "shellcode",
        "webshell",
        "sql injection",
        "command execution",
        "cve-",
        "meterpreter",
        "cobalt",
        "ransomware",
        "mimikatz",
        "credential",
        "exfil",
        "backdoor",
        "cnc",
        " c2 ",
        "botnet",
    ]
    return _contains_any(f" {text_lower} ", high_risk_terms)


def _is_ids_alert(text_lower):
    return '"event_type":"alert"' in text_lower


def _has_high_risk_wording(text_lower):
    high_risk_terms = [
        "trojan",
        "malware",
        "exploit",
        "shellcode",
        "webshell",
        "sql injection",
        "command execution",
        "cve-",
        "meterpreter",
        "cobalt",
        "ransomware",
        "mimikatz",
        "credential",
        "exfil",
        "backdoor",
        "cnc",
        " c2 ",
        "botnet",
    ]
    return _contains_any(f" {text_lower} ", high_risk_terms)


def _has_scan_or_recon_wording(text_lower):
    scan_terms = [
        " scan ",
        "acunetix",
        "nikto",
        "dirbuster",
        "attempted information leak",
        "web application attack",
        "recon",
        "policy",
        "wp-",
        "phpmyadmin",
        "../",
        "%2e%2e",
    ]
    return _contains_any(f" {text_lower} ", scan_terms)


def _calibrate_prediction(ml_prediction, confidence, features, text):
    text_lower = text.lower()
    calibrated = ml_prediction
    notes = []
    confidence_value = confidence if confidence is not None else 1.0

    critical_terms = [
        "ransomware",
        "credential dumping",
        "lsass",
        "webshell",
        "remote code execution",
        " rce ",
        "active exploitation of cve",
        "actively exploited",
        "data exfiltration",
        "shadow copy deletion",
    ]
    has_critical_context = any(term in f" {text_lower} " for term in critical_terms)
    auth_attack_terms = [
        "password spraying",
        "credential stuffing",
        "brute force",
        "failed password",
        "failed logon",
        "failed login",
        "failed vpn",
        "auth_failed",
        "invalid_credentials",
    ]
    has_auth_attack = any(term in f" {text_lower} " for term in auth_attack_terms)

    if _is_educational_or_simulated(text_lower):
        calibrated = "LOW"
        if calibrated != ml_prediction:
            notes.append("Calibrated to LOW because the content is educational, simulated, or explicitly states there are no active threats.")
        return calibrated, notes

    if _is_cti_report_context(text_lower) and _has_active_cti_compromise(text_lower, features):
        calibrated = "HIGH"
        if calibrated != ml_prediction:
            notes.append("Calibrated to HIGH because the CTI report describes active compromise, exploitation, C2, ransomware, credential access, or exfiltration.")
        return calibrated, notes

    if _is_high_risk_alert(text_lower) or (_is_http_or_fileinfo_telemetry(text_lower) and _has_high_risk_wording(text_lower)):
        calibrated = "HIGH"
        if calibrated != ml_prediction:
            notes.append("Calibrated to HIGH because the event contains exploit, malware, credential, C2, or exfiltration wording.")
        return calibrated, notes

    alert_severity = _alert_severity(text_lower)
    if alert_severity == 1:
        calibrated = "HIGH"
        if calibrated != ml_prediction:
            notes.append("Calibrated to HIGH because the IDS alert is severity 1.")
        return calibrated, notes

    if _is_generic_scan_alert(text_lower):
        calibrated = "MEDIUM"
        if calibrated != ml_prediction:
            notes.append("Calibrated to MEDIUM because the IDS alert indicates scan/recon activity without confirmed compromise.")
        return calibrated, notes

    if has_auth_attack and not has_critical_context:
        calibrated = "MEDIUM"
        if calibrated != ml_prediction:
            notes.append("Calibrated to MEDIUM because the event indicates brute-force, credential stuffing, or password spraying without confirmed compromise.")
        return calibrated, notes

    if _is_ids_alert(text_lower):
        calibrated = "MEDIUM"
        if calibrated != ml_prediction:
            notes.append("Calibrated to MEDIUM because this is a generic IDS alert without confirmed high-risk compromise wording.")
        return calibrated, notes

    if _is_benign_certificate_or_update(text_lower) and not has_critical_context:
        calibrated = "LOW"
        if calibrated != ml_prediction:
            notes.append("Calibrated to LOW because the event matches benign certificate revocation or update infrastructure traffic.")
        return calibrated, notes

    if _is_routine_benign_telemetry(text_lower) and not has_critical_context and features["med_keywords"] == 0:
        calibrated = "LOW"
        if calibrated != ml_prediction:
            notes.append("Calibrated to LOW because the event contains routine/allowed/baseline telemetry context without attack indicators.")
        return calibrated, notes

    if _is_http_or_fileinfo_telemetry(text_lower) and _has_scan_or_recon_wording(text_lower) and not has_critical_context:
        calibrated = "MEDIUM"
        if calibrated != ml_prediction:
            notes.append("Calibrated to MEDIUM because the HTTP/fileinfo event contains scan, recon, or suspicious path wording.")
        return calibrated, notes

    if _is_plain_network_telemetry(text_lower) and not has_critical_context and features["med_keywords"] == 0:
        calibrated = "LOW"
        if calibrated != ml_prediction:
            notes.append("Calibrated to LOW because the event is routine DNS/flow/TLS/stat telemetry without alert or compromise context.")
        return calibrated, notes

    if _is_http_or_fileinfo_telemetry(text_lower) and not has_critical_context and features["med_keywords"] == 0:
        calibrated = "LOW"
        if calibrated != ml_prediction:
            notes.append("Calibrated to LOW because the HTTP/fileinfo event lacks alert, exploit, malware, credential, or C2 context.")
        return calibrated, notes

    if text_lower.strip().startswith("{") and not has_critical_context and features["med_keywords"] == 0:
        calibrated = "LOW"
        if calibrated != ml_prediction:
            notes.append("Calibrated to LOW because the JSON event has no alert, exploit, malware, credential, C2, or suspicious context.")
        return calibrated, notes

    benign_dominates = (
        features["benign_keywords"] >= 3
        and features["benign_keywords"] >= features["high_keywords"] + features["med_keywords"]
    )
    no_confirmed_exploitation = any(
        phrase in text_lower
        for phrase in [
            "no active exploitation",
            "false positive",
            "authorized",
            "expected baseline",
            "informational",
            "routine",
            "clean state",
        ]
    )

    if benign_dominates and no_confirmed_exploitation and not has_critical_context:
        calibrated = "LOW"
        if calibrated != ml_prediction:
            notes.append("Calibrated to LOW because benign/authorized context dominates a low-confidence alert.")

    suspicious_only = (
        features["med_keywords"] >= 2
        and features["cve_count"] == 0
        and features["hash_count"] == 0
        and not has_critical_context
    )
    if ml_prediction == "HIGH" and suspicious_only and confidence_value < 0.75:
        calibrated = "MEDIUM"
        notes.append("Calibrated to MEDIUM because suspicious activity is present without confirmed compromise.")

    return calibrated, notes


def _first_match(patterns, text, flags=re.IGNORECASE):
    for pattern in patterns:
        match = re.search(pattern, text, flags)
        if match:
            return match.group(1)
    return None


def _extract_entities(text, indicators):
    hosts = []
    for pattern in [
        r'"hostname":"([^"]+)"',
        r'"host(?:\.name)?":"([^"]+)"',
        r'"Computer":"([^"]+)"',
        r"\bhost=([A-Za-z0-9_.-]+)",
        r"\btarget=([A-Za-z0-9_.-]+)",
        r"\bsrc=([A-Za-z][A-Za-z0-9_.-]+)",
    ]:
        hosts.extend(re.findall(pattern, text, re.IGNORECASE))
    hosts = [host for host in hosts if not re.search(r"\.(exe|dll|ps1|bat|sh|py|js)$", host, re.IGNORECASE)]

    users = []
    for pattern in [
        r"\buser=([A-Za-z0-9_.@\\-]+)",
        r"\bsuser=([A-Za-z0-9_.@\\-]+)",
        r'"alternateId":"([^"]+)"',
        r'"actor":\{"alternateId":"([^"]+)"',
    ]:
        users.extend(re.findall(pattern, text, re.IGNORECASE))
    process_names = re.findall(
        r"(?:process(?:\.name)?|Process_Name|Image|ParentImage|target)=['\"]?([^'\"\s,}]+)",
        text,
        re.IGNORECASE,
    )
    event_ids = re.findall(r"(?:EventID|EventCode|event\.code)[=:]\"?(\d+)\"?", text, re.IGNORECASE)

    process_names.extend(indicators.get("files", []))
    return {
        "hosts": _unique(hosts),
        "users": _unique(users),
        "processes": _unique(os.path.basename(p.replace("\\\\", "\\")).strip("\\") for p in process_names),
        "event_ids": _unique(event_ids),
        "source_ip": _first_match([r"\bsrc(?:_ip)?=([0-9.]+)", r'"clientIP":"([0-9.]+)"'], text),
        "destination_ip": _first_match([r"\bdst(?:_ip)?=([0-9.]+)", r'"DestinationIp":"([0-9.]+)"'], text),
    }


def _forensic_profile(text, prediction, confidence, indicators, ttp_matches=None):
    text_lower = text.lower()
    ttp_matches = ttp_matches or extract_ttp_matches(text)

    if _is_educational_or_simulated(text_lower):
        return {
            "incident_type": "Educational or simulated security content",
            "mitre_tactic": "Benign / training context",
            "mitre_technique": "No ATT&CK technique assigned",
            "evidence_value": "Low",
            "recommended_actions": [
                "Treat as training or awareness material unless corroborated by live telemetry.",
                "Do not escalate based only on threat terminology inside educational content.",
                "Retain as reference material if it supports analyst training.",
            ],
            "triage_priority": "P4",
            "confidence_band": "High" if confidence and confidence >= 0.75 else "Medium" if confidence and confidence >= 0.45 else "Low",
            "mapped_ttps": [],
        }

    if len(ttp_matches) >= 2 and prediction == "HIGH":
        return {
            "incident_type": "Multi-stage intrusion / CTI campaign",
            "mitre_tactic": ", ".join(_unique(match["tactic"] for match in ttp_matches[:4])),
            "mitre_technique": "; ".join(match["technique"] for match in ttp_matches[:4]),
            "evidence_value": "High",
            "recommended_actions": [
                "Prioritize containment and preserve raw logs, memory artifacts, binaries, and network telemetry.",
                "Hunt across the environment for the mapped techniques and extracted indicators.",
                "Patch exploited vulnerabilities and review identity, endpoint, proxy, and firewall evidence.",
            ],
            "triage_priority": "P1",
            "confidence_band": "High" if confidence and confidence >= 0.75 else "Medium" if confidence and confidence >= 0.45 else "Low",
            "mapped_ttps": ttp_matches,
        }

    profiles = [
        {
            "match": ["cve-", "shellshock", "cve-2014-6271", "authentication bypass", "administrator privilege gain", "coldfusion administrator access"],
            "incident_type": "Public-facing application exploitation",
            "tactic": "Initial Access",
            "technique": "T1190 - Exploit Public-Facing Application",
            "evidence_value": "High",
            "actions": [
                "Validate vulnerable service exposure and preserve web/proxy/IDS logs.",
                "Patch the affected application or appliance and hunt for created accounts or dropped payloads.",
                "Correlate with post-exploitation activity such as C2, privilege escalation, and exfiltration.",
            ],
        },
        {
            "match": ["acunetix", " scan ", "nikto", "dirbuster", "attempted information leak"],
            "incident_type": "Web scanning / reconnaissance",
            "tactic": "Reconnaissance",
            "technique": "T1595 - Active Scanning",
            "evidence_value": "Medium",
            "actions": [
                "Review web logs for the scanner source and requested paths.",
                "Confirm whether scanning was authorized or external reconnaissance.",
                "Escalate if scan traffic is followed by exploitation or authentication success.",
            ],
        },
        {
            "match": ["cobalt strike", "beacon64.exe", "beacon"],
            "incident_type": "Cobalt Strike / C2 beaconing",
            "tactic": "Command and Control",
            "technique": "T1071 - Application Layer Protocol",
            "evidence_value": "High",
            "actions": [
                "Block C2 infrastructure and preserve proxy/firewall/EDR telemetry.",
                "Identify the host process and collect memory/process artifacts.",
                "Hunt for periodic beaconing and related payloads across endpoints.",
            ],
        },
        {
            "match": ["crl.microsoft.com", "microsoft-cryptoapi", "application/pkix-crl", "codesignpca.crl", "windowsupdate"],
            "incident_type": "Benign certificate or update validation",
            "tactic": "Benign / administrative",
            "technique": "No ATT&CK technique assigned",
            "evidence_value": "Low",
            "actions": [
                "Document as certificate revocation, update, or baseline validation traffic.",
                "Confirm the destination domain belongs to trusted vendor infrastructure.",
                "Suppress similar events only when host, domain, and URL context remain consistent.",
            ],
        },
        {
            "match": ['"event_type":"dns"', '"event_type":"flow"', '"event_type":"tls"', '"event_type":"stats"'],
            "incident_type": "Routine network telemetry",
            "tactic": "Benign / baseline telemetry",
            "technique": "No ATT&CK technique assigned without alert context",
            "evidence_value": "Low",
            "actions": [
                "Use as supporting network context rather than a standalone incident.",
                "Correlate with IDS, endpoint, proxy, or authentication alerts before escalation.",
                "Retain timestamps and endpoints for timeline reconstruction if another alert exists.",
            ],
        },
        {
            "match": ["ransomware", ".locked", "delete shadows", "shadow copy deletion", "encrypting user directories"],
            "incident_type": "Ransomware / destructive encryption",
            "tactic": "Impact",
            "technique": "T1486 - Data Encrypted for Impact",
            "evidence_value": "High",
            "actions": [
                "Isolate affected host or file share immediately.",
                "Preserve ransom note, payload hash, process tree, and file modification timeline.",
                "Collect EDR triage package, volatile data if possible, and recent backup status.",
            ],
        },
        {
            "match": ["lsass", "credential dumping", "procdump", "nanodump", "memory scraping"],
            "incident_type": "Credential dumping",
            "tactic": "Credential Access",
            "technique": "T1003.001 - LSASS Memory",
            "evidence_value": "High",
            "actions": [
                "Isolate endpoint and preserve memory/process artifacts.",
                "Collect Security 4656/4688, Sysmon process access, command line, and parent process data.",
                "Reset exposed credentials and review lateral movement from the affected account.",
            ],
        },
        {
            "match": ["remote code execution", " rce ", "webshell", "active exploitation", "actively exploited", "bypassed authentication"],
            "incident_type": "Active exploitation / web compromise",
            "tactic": "Initial Access",
            "technique": "T1190 - Exploit Public-Facing Application",
            "evidence_value": "High",
            "actions": [
                "Contain the exposed service and preserve web logs before rotation.",
                "Collect dropped files, webroot changes, process execution, and network egress.",
                "Patch the vulnerable service and hunt for webshell persistence.",
            ],
        },
        {
            "match": ["powershell", "rundll32", "encoded", "obfuscated", "scriptlet", "living off the land", "lotl"],
            "incident_type": "Suspicious script or fileless execution",
            "tactic": "Execution",
            "technique": "T1059 - Command and Scripting Interpreter",
            "evidence_value": "Medium",
            "actions": [
                "Collect full command line, parent/child process chain, and downloaded content.",
                "Resolve contacted domains and preserve DNS/proxy history.",
                "Hunt for the same command pattern across endpoints.",
            ],
        },
        {
            "match": ["brute force", "credential stuffing", "password spraying", "failed password", "failed logon", "failed login", "failed vpn", "auth_failed", "invalid_credentials"],
            "incident_type": "Brute force / credential attack",
            "tactic": "Credential Access",
            "technique": "T1110 - Brute Force",
            "evidence_value": "Medium",
            "actions": [
                "Block or rate-limit the source where appropriate.",
                "Review successful logins after the failed attempts.",
                "Verify MFA status and reset credentials for targeted accounts if needed.",
            ],
        },
        {
            "match": ["tor exit", "beacon", "command and control", "c2", "exfiltration staging"],
            "incident_type": "Suspicious C2 or exfiltration staging",
            "tactic": "Command and Control",
            "technique": "T1071 - Application Layer Protocol",
            "evidence_value": "Medium",
            "actions": [
                "Preserve Zeek/proxy/firewall flow records around the session window.",
                "Check host process responsible for the connection.",
                "Block destination and hunt for periodic beacon intervals.",
            ],
        },
        {
            "match": ["false positive", "qualys", "nessus", "authorized", "routine", "baseline", "expected", "no active exploitation"],
            "incident_type": "Authorized or benign security activity",
            "tactic": "Benign / administrative",
            "technique": "No ATT&CK technique assigned",
            "evidence_value": "Low",
            "actions": [
                "Document authorized source, maintenance window, and approval ticket.",
                "Close or suppress the alert if the context is verified.",
                "Retain evidence for audit trail and tuning.",
            ],
        },
    ]

    selected = None
    for profile in profiles:
        if any(term in f" {text_lower} " for term in profile["match"]):
            selected = profile
            break

    if selected is None:
        selected = {
            "incident_type": "General threat intelligence event",
            "tactic": "Triage required",
            "technique": "Unmapped",
            "evidence_value": "Medium" if prediction == "MEDIUM" else prediction.title(),
            "actions": [
                "Validate the alert context and confirm whether activity is authorized.",
                "Preserve raw logs, timestamps, and extracted indicators.",
                "Correlate with endpoint, network, identity, and vulnerability telemetry.",
            ],
        }

    return {
        "incident_type": selected["incident_type"],
        "mitre_tactic": selected["tactic"],
        "mitre_technique": selected["technique"],
        "evidence_value": selected["evidence_value"],
        "recommended_actions": selected["actions"],
        "triage_priority": "P1" if prediction == "HIGH" else "P2" if prediction == "MEDIUM" else "P4",
        "confidence_band": "High" if confidence and confidence >= 0.75 else "Medium" if confidence and confidence >= 0.45 else "Low",
        "mapped_ttps": ttp_matches,
    }


def predict_cti(text):
    model = _load_model()
    ml_prediction, confidence, probabilities = _prediction_confidence(model, text)
    features = extract_features(text)
    indicators = features.pop("indicators")
    prediction, calibration_notes = _calibrate_prediction(ml_prediction, confidence, features, text)
    explanation = _build_explanation(ml_prediction, confidence, features)
    explanation.extend(calibration_notes)
    entities = _extract_entities(text, indicators)
    forensic = _forensic_profile(text, prediction, confidence, indicators, features.get("ttp_matches"))

    return {
        "prediction": prediction,
        "ml_prediction": ml_prediction,
        "confidence": confidence,
        "probabilities": probabilities,
        "explanation": explanation,
        "features": features,
        "indicators": indicators,
        "entities": entities,
        "forensic": forensic,
        "text": text,
    }


def _looks_like_log_start(line):
    stripped = line.strip()
    if not stripped:
        return False
    patterns = [
        r"^\{.*\}\s*$",
        r"^CEF:\d+\|",
        r"^LEEF:\d+\|",
        r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+",
        r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}",
        r"^\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}",
        r"^(?:index|sourcetype|source|host)=",
        r"^(?:EventCode|EventID|WinEventLog|XmlWinEventLog)[:=]",
        r"^\[[A-Z0-9_.:-]+\]\s+",
    ]
    return any(re.search(pattern, stripped, re.IGNORECASE) for pattern in patterns)


def _is_complete_json_line(line):
    stripped = line.strip()
    return stripped.startswith("{") and stripped.endswith("}")


def _split_bulk_samples(bulk_text):
    if "[INCIDENT" in bulk_text:
        return re.split(r"(?=\[INCIDENT)", bulk_text)

    paragraph_samples = [
        sample.strip()
        for sample in re.split(r"\n\s*\n", bulk_text)
        if sample.strip()
    ]
    if len(paragraph_samples) > 1:
        split_samples = []
        for sample in paragraph_samples:
            lines = [line.strip() for line in sample.splitlines() if line.strip()]
            if len(lines) > 1 and all(_is_complete_json_line(line) for line in lines):
                split_samples.extend(lines)
            elif len(lines) > 1 and all(_looks_like_log_start(line) for line in lines):
                split_samples.extend(lines)
            else:
                split_samples.append(sample)
        return split_samples

    lines = [line.rstrip() for line in bulk_text.splitlines() if line.strip()]
    if not lines:
        return []
    if len(lines) > 1 and all(_is_complete_json_line(line) for line in lines):
        return lines
    if len(lines) > 1 and all(_looks_like_log_start(line) for line in lines):
        return lines

    samples = []
    current = []
    for line in lines:
        if _looks_like_log_start(line) and current:
            samples.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)
    if current:
        samples.append("\n".join(current).strip())
    return samples


def predict_multiple_cti(bulk_text):
    samples = _split_bulk_samples(bulk_text)

    results = []
    for sample in samples:
        sample = sample.strip()
        sample_indicators = extract_indicators(sample)
        has_indicator = bool(
            sample_indicators["ips"]
            or sample_indicators["hashes"]
            or sample_indicators["cves"]
            or sample_indicators["domains"]
        )
        is_incident = sample.upper().startswith("[INCIDENT")
        if sample and not sample.startswith("=====") and (len(sample) > 20 or has_indicator or is_incident):
            results.append(predict_cti(sample))

    return results


if __name__ == "__main__":
    sample = "CVE-2024-1234 exploited for remote code execution with Cobalt Strike beaconing."
    print(predict_cti(sample))
