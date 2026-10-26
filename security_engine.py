import io
import re
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


KILL_CHAIN_PHASES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]

TECHNIQUE_MAP = {
    "T1046": ("Network Service Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Exploitation"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1498": ("Network Denial of Service", "Actions on Objectives"),
    "T1555": ("Credentials from Password Stores", "Credential Access"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1204": ("User Execution", "Execution"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T0886": ("Remote Services", "Initial Access"),
}

ATTACK_TO_PHASE = {
    "Network Intrusion": "Exploitation",
    "Remote Exploitation": "Exploitation",
    "Web Attack": "Exploitation",
    "Command Injection": "Execution",
    "Credential Theft": "Credential Access",
    "Unauthorized Access": "Initial Access",
    "Lateral Movement": "Lateral Movement",
    "Data Exfiltration": "Exfiltration",
    "Data Theft": "Exfiltration",
    "DDoS": "Actions on Objectives",
    "DoS": "Actions on Objectives",
    "Ransomware": "Actions on Objectives",
    "Malware": "Installation",
}


def map_incident(incident_text, dataset=None):
    text = incident_text.strip()
    lowered = text.lower()
    matched_techniques = []
    for technique_id, (name, tactic) in TECHNIQUE_MAP.items():
        if technique_id.lower() in lowered or name.lower() in lowered:
            matched_techniques.append({"id": technique_id, "name": name, "tactic": tactic})

    matched_attack_types = [attack for attack, phase in ATTACK_TO_PHASE.items() if attack.lower() in lowered]
    cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    sector = next((value for value in ("Power", "Transportation", "Healthcare", "Banking", "Water", "Telecommunication") if value.lower() in lowered), "Critical Infrastructure")
    phase = ATTACK_TO_PHASE.get(matched_attack_types[0], "Exploitation" if cve_matches else "Reconnaissance") if matched_attack_types else ("Exploitation" if cve_matches else "Reconnaissance")

    if not matched_techniques and dataset is not None and not dataset.empty:
        attack_type = next((value for value in dataset["attack_type"].dropna().unique() if value.lower() in lowered), None)
        technique_id = next((value for value in dataset["mitre_technique"].dropna().unique() if str(value).lower() in lowered), None)
        if technique_id:
            name, tactic = TECHNIQUE_MAP.get(str(technique_id), ("Observed ATT&CK technique", "Unknown tactic"))
            matched_techniques.append({"id": str(technique_id), "name": name, "tactic": tactic})
        if attack_type:
            matched_attack_types.append(attack_type)
            phase = ATTACK_TO_PHASE.get(attack_type, phase)

    risk = "CRITICAL" if any(word in lowered for word in ("ransomware", "data exfiltration", "active", "critical")) else "HIGH" if cve_matches or matched_techniques else "MEDIUM"
    return {
        "incident": text,
        "sector": sector,
        "risk_level": risk,
        "kill_chain_phase": phase,
        "mitre_techniques": matched_techniques or [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
        "attack_types": matched_attack_types,
        "cves": sorted(set(cve_matches)),
        "kill_chain": [{"phase": item, "active": item == phase} for item in KILL_CHAIN_PHASES],
    }


def create_executive_briefing(stats, analysis):
    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=A4, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("Title", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, textColor=colors.HexColor("#0f766e"), spaceAfter=8)
    subtitle = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#64748b"), spaceAfter=18)
    heading = ParagraphStyle("Heading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, textColor=colors.HexColor("#0f766e"), spaceBefore=14, spaceAfter=7)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9, leading=13, textColor=colors.HexColor("#1e293b"))

    story = [Paragraph("NCIRIP Executive Security Briefing", title), Paragraph(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | National Cyber Intelligence Operations", subtitle)]
    summary_data = [["Metric", "Current posture"], ["Monitored records", str(stats.get("total_records", 0))], ["Critical incidents", str(stats.get("critical_count", 0))], ["Average risk score", str(stats.get("avg_risk", "N/A"))], ["Assessment risk", analysis.get("risk_level", "MEDIUM")]]
    table = Table(summary_data, colWidths=[2.3 * inch, 3.9 * inch])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 9), ("PADDING", (0, 0), (-1, -1), 7)]))
    story += [table, Paragraph("Incident Assessment", heading), Paragraph(analysis.get("incident", "No incident description supplied."), body), Paragraph("MITRE ATT&CK Mapping", heading)]
    mitre_rows = [["ID", "Technique", "Tactic"]] + [[item["id"], item["name"], item["tactic"]] for item in analysis.get("mitre_techniques", [])]
    mitre_table = Table(mitre_rows, colWidths=[.8 * inch, 3.3 * inch, 2.1 * inch])
    mitre_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#cbd5e1")), ("FONTSIZE", (0, 0), (-1, -1), 8), ("PADDING", (0, 0), (-1, -1), 6)]))
    story += [mitre_table, Paragraph("Cyber Kill Chain Position", heading), Paragraph(f"Current phase: <b>{analysis.get('kill_chain_phase', 'Reconnaissance')}</b>. Continue monitoring for progression across adjacent phases and validate containment before recovery.", body), Spacer(1, 18), Paragraph("Prepared by NCIRIP Threat Intelligence Platform", subtitle)]
    document.build(story)
    output.seek(0)
    return output
