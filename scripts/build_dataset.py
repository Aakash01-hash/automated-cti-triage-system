import json
import pandas as pd
import os
import random
from itertools import product

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BASE_DIR = os.path.join(PROJECT_ROOT, "data", "raw")

MITRE_PATH = os.path.join(BASE_DIR, "mitre", "enterprise-attack.json")
CVE_PATHS = [
    os.path.join(BASE_DIR, "cve", "nvdcve-2.0-2022.json"),
    os.path.join(BASE_DIR, "cve", "nvdcve-2.0-2023.json"),
    os.path.join(BASE_DIR, "cve", "nvdcve-2.0-2024.json")
]
APT_PATH = os.path.join(BASE_DIR, "apt_reports", "APTnotes.csv")

OUTPUT_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "final_cti_dataset.csv")


# ---------------- MITRE ----------------
def parse_mitre():
    data = json.load(open(MITRE_PATH, encoding="utf-8"))
    return [
        {"text": obj.get("description", ""), "label": "HIGH"}
        for obj in data.get("objects", [])
        if obj.get("type") == "attack-pattern" and obj.get("description")
    ]


# ---------------- CVE ----------------
def extract_cvss_severity(cve_item):
    metrics = cve_item.get("cve", {}).get("metrics", {})
    for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric = metrics.get(metric_name)
        if not metric:
            continue
        try:
            if metric_name == "cvssMetricV2":
                score = float(metric[0]["cvssData"]["baseScore"])
                if score >= 7.0:
                    return "HIGH"
                if score >= 4.0:
                    return "MEDIUM"
                return "LOW"
            return metric[0]["cvssData"]["baseSeverity"].upper()
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return None


def severity_to_label(severity, description):
    if severity in {"CRITICAL", "HIGH"}:
        return "HIGH"
    if severity == "MEDIUM":
        return "MEDIUM"
    if severity == "LOW":
        return "LOW"

    text_lower = description.lower()
    if any(w in text_lower for w in ["actively exploited", "active exploitation", "ransomware", "malware"]):
        return "HIGH"
    if any(w in text_lower for w in ["denial of service", "cross-site scripting", "information disclosure"]):
        return "MEDIUM"
    return "MEDIUM"


def parse_cve():
    records = []

    for path in CVE_PATHS:
        data = json.load(open(path, encoding="utf-8"))

        for item in data.get("vulnerabilities", []):
            try:
                desc = item["cve"]["descriptions"][0]["value"]
                severity = extract_cvss_severity(item)
                label = severity_to_label(severity, desc)
                records.append({"text": desc, "label": label})
            except:
                continue

    return records


# ---------------- APT ----------------
def parse_apt():
    df = pd.read_csv(APT_PATH)
    return [{"text": t, "label": "HIGH"} for t in df.iloc[:, 0] if isinstance(t, str)]


# ---------------- LOW (REALISTIC) ----------------
def generate_low_samples(n=20000):
    tools = ["Nessus", "Qualys", "Defender", "EDR", "SIEM", "Nmap", "asset scanner", "patch manager"]
    assets = ["workstation", "web server", "mail gateway", "domain controller", "VPN appliance", "database node", "developer laptop"]
    statuses = ["blocked", "remediated", "quarantined", "patched", "approved", "expected", "scheduled", "suppressed"]
    activities = [
        "routine vulnerability scan",
        "authorized maintenance window",
        "baseline telemetry review",
        "software inventory check",
        "patch compliance validation",
        "backup verification",
        "policy audit",
        "clean health check",
        "security awareness reminder",
        "regular system update reminder",
        "password hygiene campaign",
        "phishing simulation training",
    ]
    contexts = [
        "no active exploitation observed",
        "no malicious indicators found",
        "change ticket approved",
        "false positive confirmed by analyst",
        "activity matches expected behavior",
        "no lateral movement detected",
        "no external beaconing observed",
        "asset owner verified the action",
    ]

    templates = [
        "{tool} reported a {activity} on the {asset}; status is {status} and {context}.",
        "{asset} generated an informational alert during {activity}; {context} and the event was {status}.",
        "Analyst review marked the {tool} finding on {asset} as {status}; {context}.",
        "Routine security operation: {activity} completed for {asset} using {tool}; {context}.",
        "Users should update systems regularly as part of {activity}; {context}.",
        "Security awareness notice for {asset}: {activity} completed and {context}.",
    ]

    combinations = list(product(templates, tools, assets, statuses, activities, contexts))
    random.shuffle(combinations)

    records = []
    for template, tool, asset, status, activity, context in combinations[:n]:
        records.append(
            {
                "text": template.format(
                    tool=tool,
                    asset=asset,
                    status=status,
                    activity=activity,
                    context=context,
                ),
                "label": "LOW",
            }
        )

    return records


# ---------------- MEDIUM (SUSPICIOUS TELEMETRY) ----------------
def generate_medium_samples(n=15000):
    actors = ["unknown source", "external IP", "untrusted host", "guest network", "newly observed endpoint"]
    targets = ["VPN portal", "mail gateway", "web application", "domain account", "SSH service", "RDP service"]
    activities = [
        "multiple failed logon attempts",
        "port scan",
        "brute force pattern",
        "suspicious PowerShell invocation",
        "unusual outbound connection",
        "possible phishing submission",
        "macro-enabled document delivery",
        "credential stuffing attempt",
    ]
    contexts = [
        "no confirmed compromise yet",
        "requires analyst review",
        "blocked by perimeter controls",
        "limited scope observed",
        "no malware payload confirmed",
        "no lateral movement observed",
    ]
    templates = [
        "{activity} detected from {actor} against {target}; {context}.",
        "SIEM alert shows {activity} involving {target}; {context}.",
        "Suspicious activity: {actor} triggered {activity} on {target}; {context}.",
    ]

    combinations = list(product(templates, actors, targets, activities, contexts))
    random.shuffle(combinations)

    records = []
    for template, actor, target, activity, context in combinations[:n]:
        records.append(
            {
                "text": template.format(
                    actor=actor,
                    target=target,
                    activity=activity,
                    context=context,
                ),
                "label": "MEDIUM",
            }
        )

    return records


# ---------------- SIEM RAW LOG SAMPLES ----------------
def generate_siem_samples():
    records = []

    def render(template, **values):
        text = template
        for key, value in values.items():
            text = text.replace("{" + key + "}", value)
        return text

    high_templates = [
        '{"@timestamp":"2026-05-01T07:11:22.000Z","agent":{"hostname":"{host}","type":"winlogbeat"},"process":{"name":"{proc}"},"message":"High-confidence ransomware behavior detected. Process executed rapidly encrypting user directories. Shadow copy deletion and payload hash observed: {hash}."}',
        '{"@timestamp":"2026-05-01T13:20:05Z","host":"{host}","source":"IIS_Logs","Severity":"CRITICAL","msg":"Active exploitation of {cve} detected. Threat actor bypassed authentication and achieved RCE. Webshell dropped into public HTML directory. Originating threat IP: {ip}."}',
        'index=windows_security sourcetype=WinEventLog:Security EventCode=4656 Object_Name="\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\lsass.exe" Process_Name="C:\\\\Sysinternals\\\\procdump.exe" msg="Critical memory access violation. Procdump execution against lsass.exe. High confidence credential dumping and memory scraping. Data staged for exfiltration."',
        'CEF:0|EDR|Endpoint|1.0|RansomwareBehavior|File Encryption|10|src={host} suser=CORP\\\\{user} msg=Ransomware note created, files encrypted, vssadmin delete shadows executed, outbound transfer to {ip}.',
    ]
    medium_templates = [
        'May  1 08:05:14 {host} sshd[19022]: Failed password for root from {ip} port 39412 ssh2. Sustained anomaly. Brute force credential stuffing campaign suspected against external perimeter.',
        '{"time":"2026-05-01T09:44:10Z","index":"sysmon","Computer":"{host}","EventID":3,"DestinationIp":"{ip}","msg":"Suspicious outbound network connection established. Process communicating with Tor exit node infrastructure. Potential command and control beaconing requires analyst review."}',
        'CEF:0|CrowdStrike|FalconHost|1.0|ProcessCreation|Suspicious Process Creation|5|rt=1714561200000 src={ip} suser=CORP\\\\{user} msg=Suspicious execution of powershell.exe with obfuscated command line arguments. Living off the land tactics suspected. No confirmed payload execution.',
        '{"creationTime":"2026-05-01T16:45:12Z","operation":"UserLoggedIn","resultStatus":"Failure","clientIP":"{ip}","msg":"Anomalous login detected. High volume of failed logon attempts indicative of distributed brute force. Anonymous proxy infrastructure observed."}',
    ]
    low_templates = [
        'CEF:0|PaloAltoNetworks|PAN-OS|11.0|Traffic|Allowed|1|rt=1714555000000 src={src_ip} dst={dst_ip} msg=Routine outbound DNS telemetry. Connections to authorized external resolvers are within expected baseline behavior. Informational event.',
        'May  1 10:15:33 fw-core-01 suricata[882]: {{"timestamp":"2026-05-01T10:15:33.123456+0000","event_type":"alert","src_ip":"{src_ip}","dest_ip":"{dst_ip}","alert":{{"signature":"ET SCAN Qualys Vulnerability Scanner Activity","severity":3}},"msg":"Confirmed false positive. Traffic originates from authorized Qualys scanner IP block during scheduled maintenance window. Event suppressed."}}',
        '{"creationTime":"2026-05-01T14:10:00Z","system":"UpdateServices","msg":"Informational baseline sync. Routine Windows servicing stack update applied successfully. Clean state verified via catalog signature hash {hash}. No active exploitation."}',
        'index=proxy sourcetype=bluecoat src={src_ip} dst={dst_ip} action=allowed category=Business msg="Approved baseline traffic to authorized resolver. No malicious indicators found. Routine telemetry."',
    ]

    hosts = ["WKSTN-HR-04", "SRV-BACKUP-01", "SRV-WEB-DMZ", "FIN-WS-022", "ext-gateway"]
    users = ["a.admin", "svc_backup", "temp-884", "j.singh", "buildsvc"]
    procs = ["tasksche.exe", "svhost.exe", "payload.exe", "encryptor.exe", "backupsvc.exe"]
    ips = ["45.133.1.53", "185.220.101.46", "194.169.175.122", "103.236.201.88", "167.88.44.21"]
    internal_ips = ["10.0.5.22", "192.168.1.50", "10.10.5.55", "172.16.3.20"]
    benign_ips = ["8.8.8.8", "1.1.1.1", "64.39.96.10", "10.0.0.53"]
    hashes = [
        "24d004a104d4d54f1464c92253896dfa4b162de813c93ee09bbf4af5449fbab3",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "44d88612fea8a8f36de82e1278abb02f",
    ]
    cves = ["CVE-2023-46805", "CVE-2024-3400", "CVE-2024-21762", "CVE-2023-34362"]

    for template in high_templates:
        for host, user, proc, ip, cve, hash_value in product(hosts, users, procs, ips, cves, hashes):
            records.append({"text": render(template, host=host, user=user, proc=proc, ip=ip, cve=cve, hash=hash_value), "label": "HIGH"})

    for template in medium_templates:
        for host, user, ip in product(hosts, users, ips):
            records.append({"text": render(template, host=host, user=user, ip=ip), "label": "MEDIUM"})

    for template in low_templates:
        for src_ip, dst_ip, hash_value in product(internal_ips, benign_ips, hashes):
            records.append({"text": render(template, src_ip=src_ip, dst_ip=dst_ip, hash=hash_value), "label": "LOW"})

    return records


# ---------------- MAIN ----------------
def main():
    mitre = parse_mitre()
    cve = parse_cve()
    apt = parse_apt()
    medium = generate_medium_samples()
    low = generate_low_samples()
    siem = generate_siem_samples()

    df = pd.DataFrame(mitre + cve + apt + medium + low + siem)

    print("\nBefore Balancing:")
    print(df["label"].value_counts())

    df_high = df[df["label"] == "HIGH"]
    df_medium = df[df["label"] == "MEDIUM"]
    df_low = df[df["label"] == "LOW"]

    target_size = min(len(df_high), len(df_medium), 20000)

    df_high = df_high.sample(n=target_size, random_state=42)
    df_medium = df_medium.sample(n=target_size, random_state=42)

    # Oversample LOW
    low_records = df_low.to_dict("records")
    if len(low_records) < target_size:
        low_records += random.choices(low_records, k=target_size - len(low_records))

    df_low = pd.DataFrame(low_records[:target_size])

    df_balanced = pd.concat([df_high, df_medium, df_low])
    df_balanced = df_balanced.sample(frac=1, random_state=42)

    print("\nAfter Balancing:")
    print(df_balanced["label"].value_counts())

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df_balanced.to_csv(OUTPUT_PATH, index=False)
    print("Dataset saved")


if __name__ == "__main__":
    main()
