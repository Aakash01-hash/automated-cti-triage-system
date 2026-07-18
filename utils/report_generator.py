import html
import ipaddress
import os
import re
from datetime import datetime, UTC

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

try:
    from scripts.realtime.ip_checker_live import check_ip_live
except ImportError:
    check_ip_live = None

try:
    from scripts.realtime.hash_checker_live import check_hash_live
except ImportError:
    check_hash_live = None


def _safe(value):
    return html.escape(str(value if value is not None else ""))


def _para(text, style):
    return Paragraph(_safe(text), style)


def _join(values, fallback="None"):
    values = [str(v) for v in values if v]
    return ", ".join(values) if values else fallback


def _confidence_pct(value):
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "N/A"


def _calibration_notes(result):
    return [note for note in result.get("explanation", []) if str(note).startswith("Calibrated")]


def _mapped_ttp_text(forensic):
    mapped = forensic.get("mapped_ttps", []) or []
    techniques = []
    for item in mapped:
        if isinstance(item, dict) and item.get("technique"):
            techniques.append(item["technique"])
    return _join(techniques, "None mapped")


def _contains_any(text, terms):
    return any(term in text for term in terms)


def _report_forensic(result):
    """Return a report-facing forensic profile that cannot contradict final severity."""
    severity = str(result.get("prediction", "LOW")).upper()
    forensic = dict(result.get("forensic", {}) or {})
    text_lower = str(result.get("text", "")).lower()
    notes_lower = " ".join(str(note).lower() for note in result.get("explanation", []))
    combined = f"{text_lower} {notes_lower}"

    if _contains_any(combined, ["password spraying", "credential stuffing", "brute force", "failed password", "failed logon", "failed vpn", "auth_failed", "invalid_credentials"]):
        forensic.update(
            {
                "incident_type": "Brute force / credential attack",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110 - Brute Force",
                "evidence_value": "Medium" if severity != "LOW" else "Low",
                "triage_priority": "P2" if severity != "LOW" else "P4",
                "recommended_actions": [
                    "Block or rate-limit the source where appropriate.",
                    "Review successful logins after the failed attempts.",
                    "Verify MFA status and reset credentials for targeted accounts if needed.",
                ],
            }
        )

    if severity == "LOW":
        if _contains_any(combined, ["crl.microsoft.com", "microsoft-cryptoapi", "application/pkix-crl", "codesignpca.crl", "windowsupdate"]):
            forensic.update(
                {
                    "incident_type": "Benign certificate or update validation",
                    "mitre_tactic": "Benign / administrative",
                    "mitre_technique": "No ATT&CK technique assigned",
                    "evidence_value": "Low",
                    "triage_priority": "P4",
                    "recommended_actions": [
                        "Document as certificate revocation, update, or baseline validation traffic.",
                        "Confirm the destination domain belongs to trusted vendor infrastructure.",
                        "Suppress similar events only when host, domain, and URL context remain consistent.",
                    ],
                    "mapped_ttps": [],
                }
            )
        elif _contains_any(combined, ['"event_type":"dns"', '"event_type":"flow"', '"event_type":"tls"', '"event_type":"stats"', "routine dns/flow/tls/stat telemetry"]):
            forensic.update(
                {
                    "incident_type": "Routine network telemetry",
                    "mitre_tactic": "Benign / baseline telemetry",
                    "mitre_technique": "No ATT&CK technique assigned without alert context",
                    "evidence_value": "Low",
                    "triage_priority": "P4",
                    "recommended_actions": [
                        "Use as supporting network context rather than a standalone incident.",
                        "Correlate with IDS, endpoint, proxy, or authentication alerts before escalation.",
                        "Retain timestamps and endpoints for timeline reconstruction if another alert exists.",
                    ],
                    "mapped_ttps": [],
                }
            )
        elif _contains_any(combined, ["authorized", "approved", "maintenance", "false positive", "no active exploitation", "informational", "routine", "baseline", "expected behavior", "clean state"]):
            forensic.update(
                {
                    "incident_type": "Authorized or benign security activity",
                    "mitre_tactic": "Benign / administrative",
                    "mitre_technique": "No ATT&CK technique assigned",
                    "evidence_value": "Low",
                    "triage_priority": "P4",
                    "recommended_actions": [
                        "Document authorized source, maintenance window, and approval ticket if applicable.",
                        "Close or suppress the alert after the benign context is verified.",
                        "Retain evidence for audit trail and future alert tuning.",
                    ],
                    "mapped_ttps": [],
                }
            )
        else:
            if forensic.get("evidence_value", "").lower() in {"high", "medium"}:
                forensic["evidence_value"] = "Low"
            forensic["triage_priority"] = "P4"

    forensic.setdefault("incident_type", "General threat intelligence event")
    forensic.setdefault("mitre_tactic", "Triage required")
    forensic.setdefault("mitre_technique", "Unmapped")
    forensic.setdefault("evidence_value", severity.title() if severity in {"HIGH", "LOW"} else "Medium")
    forensic.setdefault("triage_priority", "P1" if severity == "HIGH" else "P2" if severity == "MEDIUM" else "P4")
    forensic.setdefault("recommended_actions", [])
    forensic.setdefault("mapped_ttps", result.get("features", {}).get("ttp_matches", []))
    if severity == "MEDIUM" and str(forensic.get("evidence_value", "")).lower() == "high":
        forensic["evidence_value"] = "Medium"
    if severity == "HIGH" and str(forensic.get("evidence_value", "")).lower() in {"low", "medium"}:
        forensic["evidence_value"] = "High"
    return forensic


def _is_private_ip(ip):
    try:
        parsed = ipaddress.ip_address(ip)
        return parsed.is_private or parsed.is_loopback or parsed.is_link_local
    except ValueError:
        return False


def _severity_color(severity):
    return {
        "HIGH": colors.HexColor("#c0302a"),
        "MEDIUM": colors.HexColor("#d4811a"),
        "LOW": colors.HexColor("#1f8f4d"),
    }.get(str(severity).upper(), colors.HexColor("#444444"))


def _page_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#667085"))
    canvas.drawString(30, 16, "Generated by CTI.Engine forensic triage")
    canvas.drawRightString(A4[0] - 30, 16, f"Page {doc.page}")
    canvas.restoreState()


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            alignment=1,
            fontSize=16,
            leading=20,
            spaceAfter=14,
            textColor=colors.HexColor("#0a2d4d"),
        )
    )
    styles.add(
        ParagraphStyle(
            "SectionTitle",
            parent=styles["Heading2"],
            fontSize=12,
            leading=15,
            spaceBefore=10,
            spaceAfter=8,
            textColor=colors.HexColor("#1163a8"),
        )
    )
    styles.add(
        ParagraphStyle(
            "Small",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
        )
    )
    styles.add(
        ParagraphStyle(
            "Mono",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7,
            leading=9,
        )
    )
    styles.add(
        ParagraphStyle(
            "BulletText",
            parent=styles["Normal"],
            leftIndent=10,
            firstLineIndent=-6,
            fontSize=9,
            leading=12,
        )
    )
    return styles


def _summary_counts(results):
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for result in results:
        severity = str(result.get("prediction", "LOW")).upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def _collect_key_values(results):
    hosts = []
    users = []
    cves = []
    ips = []
    hashes = []
    domains = []
    incident_types = []
    for result in results:
        entities = result.get("entities", {})
        indicators = result.get("indicators", {})
        forensic = _report_forensic(result)
        hosts.extend(entities.get("hosts", []))
        users.extend(entities.get("users", []))
        cves.extend(indicators.get("cves", []))
        ips.extend(indicators.get("ips", []))
        hashes.extend(indicators.get("hashes", []))
        domains.extend(indicators.get("domains", []))
        if forensic.get("incident_type"):
            incident_types.append(forensic["incident_type"])
    return {
        "hosts": sorted(set(hosts)),
        "users": sorted(set(users)),
        "cves": sorted(set(cves)),
        "ips": sorted(set(ips)),
        "hashes": sorted(set(hashes)),
        "domains": sorted(set(domains)),
        "incident_types": sorted(set(incident_types)),
    }


def _add_document_control(story, styles, analyst_name, purpose, tlp_marking):
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = "CTI-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    tlp = str(tlp_marking or "AMBER").upper()
    tlp_color = {
        "CLEAR": "green",
        "GREEN": "#188038",
        "AMBER": "#d4811a",
        "RED": "#c0302a",
    }.get(tlp, "#d4811a")

    story.append(Paragraph("Automated Cyber Threat Intelligence Triage Report", styles["ReportTitle"]))
    rows = [
        ["Report ID", report_id, "Date Generated", generated_at],
        ["Reporting Analyst", analyst_name, "Report Purpose", purpose],
        ["TLP Designation", f"TLP:{tlp}", "Model Output", "ML severity + forensic enrichment"],
    ]
    table_data = [[_para(cell, styles["Small"]) for cell in row] for row in rows]
    table = Table(table_data, colWidths=[90, 180, 90, 170])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f6f8")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (1, 2), (1, 2), colors.HexColor(tlp_color)),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 12))


def _add_executive_summary(story, styles, results):
    counts = _summary_counts(results)
    key = _collect_key_values(results)
    top_types = key["incident_types"][:5]
    priority = "Immediate containment required" if counts["HIGH"] else "Review and monitor"

    story.append(Paragraph("Executive Summary", styles["SectionTitle"]))
    rows = [
        ["Total Events", str(len(results)), "Severity Mix", f"H:{counts['HIGH']} M:{counts['MEDIUM']} L:{counts['LOW']}"],
        ["Top Finding Types", _join(top_types), "Primary Hosts", _join(key["hosts"][:6])],
        ["Key CVEs", _join(key["cves"][:6]), "Key Domains", _join(key["domains"][:6])],
        ["Recommended Priority", priority, "Unique IPs", str(len(key["ips"]))],
    ]
    table_data = [[_para(cell, styles["Small"]) for cell in row] for row in rows]
    table = Table(table_data, colWidths=[90, 180, 90, 170])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf3fb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 12))


def _add_incident_index(story, styles, results):
    story.append(Paragraph("Incident Index", styles["SectionTitle"]))
    rows = [["#", "Severity", "Type", "MITRE Technique", "Host/User", "IoCs", "Priority"]]
    for idx, result in enumerate(results, 1):
        forensic = _report_forensic(result)
        entities = result.get("entities", {})
        indicators = result.get("indicators", {})
        ioc_count = sum(len(indicators.get(k, [])) for k in ("ips", "hashes", "cves", "domains"))
        rows.append(
            [
                str(idx),
                result.get("prediction", "UNKNOWN"),
                forensic.get("incident_type", "General"),
                forensic.get("mitre_technique", "Unmapped"),
                _join((entities.get("hosts", []) + entities.get("users", []))[:3], "Not extracted"),
                str(ioc_count),
                forensic.get("triage_priority", ""),
            ]
        )

    table_data = [[_para(cell, styles["Small"]) for cell in row] for row in rows]
    table = Table(table_data, colWidths=[22, 48, 110, 130, 100, 35, 45], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1163a8")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 12))


def _add_timeline(story, styles, results):
    story.append(Paragraph("Evidence Timeline", styles["SectionTitle"]))
    rows = [["Time", "Severity", "Host", "Event Type"]]
    for result in results:
        text = result.get("text", "")
        time_value = "Unknown"
        for pattern in [r'"@timestamp":"([^"]+)"', r'"time":"([^"]+)"', r"^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)", r"rt=(\d+)"]:
            match = re.search(pattern, text)
            if match:
                time_value = match.group(1)
                break
        forensic = _report_forensic(result)
        entities = result.get("entities", {})
        rows.append(
            [
                time_value,
                result.get("prediction", "UNKNOWN"),
                _join(entities.get("hosts", [])[:2], "Not extracted"),
                forensic.get("incident_type", "General"),
            ]
        )

    table_data = [[_para(cell, styles["Small"]) for cell in row] for row in rows]
    table = Table(table_data, colWidths=[120, 55, 120, 235], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1163a8")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 12))


def _add_detail(story, styles, result, idx):
    severity = str(result.get("prediction", "UNKNOWN")).upper()
    forensic = _report_forensic(result)
    entities = result.get("entities", {})
    indicators = result.get("indicators", {})
    features = result.get("features", {})

    heading = f"Finding {idx}: {severity} - {forensic.get('incident_type', 'General event')}"
    story.append(Paragraph(f"<font color='{_severity_color(severity).hexval()}'> <b>{_safe(heading)}</b></font>", styles["SectionTitle"]))

    ttp_matches = forensic.get("mapped_ttps", []) or []
    rows = [
        ["Final Severity", severity, "ML Prediction", result.get("ml_prediction", severity)],
        ["ML Confidence", _confidence_pct(result.get("confidence")), "Calibration Notes", _join(_calibration_notes(result), "None")],
        ["Triage Priority", forensic.get("triage_priority", ""), "Evidence Value", forensic.get("evidence_value", "")],
        ["MITRE Tactic", forensic.get("mitre_tactic", ""), "MITRE Technique", forensic.get("mitre_technique", "")],
        ["Mapped TTPs", _mapped_ttp_text(forensic), "TTP Count", str(len(ttp_matches))],
        ["Hosts", _join(entities.get("hosts", []), "Not extracted"), "Users", _join(entities.get("users", []), "Not extracted")],
        ["Processes", _join(entities.get("processes", []), "Not extracted"), "Event IDs", _join(entities.get("event_ids", []), "Not extracted")],
        ["CVEs", _join(indicators.get("cves", []), "None detected"), "Domains", _join(indicators.get("domains", []), "None detected")],
        ["IPs", _join(indicators.get("ips", []), "None detected"), "Files", _join(indicators.get("files", []), "None detected")],
    ]
    table_data = [[_para(cell, styles["Small"]) for cell in row] for row in rows]
    table = Table(table_data, colWidths=[80, 185, 90, 175])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4f6f8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Model and Forensic Rationale", styles["SectionTitle"]))
    story.append(Paragraph(f"- Final severity: {_safe(severity)}; ML prediction: {_safe(result.get('ml_prediction', severity))}; ML confidence: {_safe(_confidence_pct(result.get('confidence')))}", styles["BulletText"]))
    story.append(Paragraph(f"- Mapped TTP count: {_safe(len(ttp_matches))}", styles["BulletText"]))
    for exp in result.get("explanation", []):
        story.append(Paragraph(f"- {_safe(exp)}", styles["BulletText"]))
    story.append(Paragraph(f"- Keyword score: {_safe(features.get('keyword_score', 0))}; IoC count: {_safe(features.get('ioc_count', 0))}", styles["BulletText"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Recommended Response", styles["SectionTitle"]))
    for action in forensic.get("recommended_actions", []):
        story.append(Paragraph(f"- {_safe(action)}", styles["BulletText"]))
    story.append(Spacer(1, 6))

    raw_text = result.get("text", "")
    raw_preview = raw_text[:1200] + ("..." if len(raw_text) > 1200 else "")
    story.append(Paragraph("Raw Evidence", styles["SectionTitle"]))
    story.append(Paragraph(_safe(raw_preview), styles["Mono"]))
    story.append(Spacer(1, 8))


def _add_hash_enrichment(story, styles, indicators):
    hashes = indicators.get("hashes", [])
    if not hashes or not check_hash_live:
        return
    story.append(Paragraph("VirusTotal Hash Enrichment", styles["SectionTitle"]))
    rows = [["Hash", "Detection", "Family", "Status"]]
    for hash_value in hashes:
        try:
            vt = check_hash_live(hash_value)
            if vt and vt.get("found"):
                malicious = vt.get("malicious", 0)
                total = vt.get("total", 0)
                rows.append([hash_value, f"{malicious}/{total}", vt.get("family", "Unknown"), "MALICIOUS" if malicious else "CLEAN"])
            else:
                rows.append([hash_value, "N/A", "N/A", vt.get("error", "Not found") if vt else "Not found"])
        except Exception:
            rows.append([hash_value, "Error", "Error", "API failure"])
    table_data = [[_para(cell, styles["Small"]) for cell in row] for row in rows]
    table = Table(table_data, colWidths=[210, 65, 165, 80], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1163a8")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 8))


def _add_ip_enrichment(story, styles, indicators):
    ips = indicators.get("ips", [])
    if not ips:
        return
    story.append(Paragraph("Network Enrichment", styles["SectionTitle"]))
    rows = [["IP Address", "Scope", "Abuse Score", "Country", "ISP"]]
    for ip in ips:
        if _is_private_ip(ip):
            rows.append([ip, "Private/Internal", "N/A", "N/A", "Internal address; not queried"])
            continue
        if not check_ip_live:
            rows.append([ip, "Public", "N/A", "N/A", "Checker unavailable"])
            continue
        try:
            abuse = check_ip_live(ip)
            if abuse and "error" not in abuse:
                rows.append([ip, "Public", f"{abuse.get('abuse_score', 0)}%", abuse.get("country", "Unknown"), abuse.get("isp", "Unknown")])
            else:
                rows.append([ip, "Public", "Error", "N/A", abuse.get("error", "Lookup failed") if abuse else "Lookup failed"])
        except Exception:
            rows.append([ip, "Public", "Error", "N/A", "API failure"])
    table_data = [[_para(cell, styles["Small"]) for cell in row] for row in rows]
    table = Table(table_data, colWidths=[105, 85, 75, 60, 205], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1163a8")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 8))


def generate_forensic_pdf(results, output_path, analyst_name="SOC Analyst", purpose="Automated Threat Triage", tlp_marking="AMBER"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=26)
    styles = _build_styles()
    story = []

    _add_document_control(story, styles, analyst_name, purpose, tlp_marking)
    _add_executive_summary(story, styles, results)
    _add_incident_index(story, styles, results)
    _add_timeline(story, styles, results)
    story.append(PageBreak())

    for idx, result in enumerate(results, 1):
        _add_detail(story, styles, result, idx)
        indicators = result.get("indicators", {})
        _add_hash_enrichment(story, styles, indicators)
        _add_ip_enrichment(story, styles, indicators)
        if idx != len(results):
            story.append(PageBreak())

    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    return output_path
