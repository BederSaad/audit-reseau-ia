import io
import os
import re
import ipaddress
from typing import Optional
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ── Colors ────────────────────────────────────────────────────────────────────
PDF_COLORS = {
    "primary": colors.HexColor("#4F46E5"),      # indigo
    "critical": colors.HexColor("#DC2626"),     # red
    "high": colors.HexColor("#EA580C"),         # orange
    "medium": colors.HexColor("#CA8A04"),       # amber
    "low": colors.HexColor("#2563EB"),          # blue
    "info": colors.HexColor("#64748B"),         # gray
    "safe": colors.HexColor("#16A34A"),         # green
    "text_dark": colors.HexColor("#1E293B"),
    "text_muted": colors.HexColor("#64748B"),
    "bg_light": colors.HexColor("#F8FAFC"),
    "bg_critical_tint": colors.HexColor("#FEF2F2"),
    "bg_high_tint": colors.HexColor("#FFF7ED"),
    "bg_medium_tint": colors.HexColor("#FEFCE8"),
    "bg_low_tint": colors.HexColor("#EFF6FF"),
    "bg_safe_tint": colors.HexColor("#F0FDF4"),
}

def get_severity_color(sev):
    sev = str(sev).lower()
    if sev in ["critical", "critique"]: return PDF_COLORS["critical"]
    if sev in ["high", "élevé"]: return PDF_COLORS["high"]
    if sev in ["medium", "moyen"]: return PDF_COLORS["medium"]
    if sev in ["low", "faible"]: return PDF_COLORS["low"]
    if sev in ["info"]: return PDF_COLORS["info"]
    return PDF_COLORS["safe"]

def get_severity_bg_tint(sev):
    sev = str(sev).lower()
    if sev in ["critical", "critique"]: return PDF_COLORS["bg_critical_tint"]
    if sev in ["high", "élevé"]: return PDF_COLORS["bg_high_tint"]
    if sev in ["medium", "moyen"]: return PDF_COLORS["bg_medium_tint"]
    if sev in ["low", "faible"]: return PDF_COLORS["bg_low_tint"]
    return PDF_COLORS["bg_safe_tint"]

def get_timeframe_color(tf):
    tf = str(tf).lower()
    if "immédiat" in tf: return PDF_COLORS["critical"]
    if "semaine" in tf: return PDF_COLORS["high"]
    if "mois" in tf: return PDF_COLORS["medium"]
    return PDF_COLORS["low"]

def parse_target_range(target: str) -> list[str]:
    """Parse nmap target string (CIDR, range, IP list) and return list of individual IPs."""
    import ipaddress
    import re
    target = target.strip()
    parts = []
    for p in re.split(r'[\s,]+', target):
        p = p.strip()
        if p:
            parts.append(p)
    ips = []
    for part in parts:
        if '/' in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                if net.num_addresses <= 256:
                    if net.prefixlen in (31, 32):
                        ips.extend(str(ip) for ip in net)
                    else:
                        ips.extend(str(ip) for ip in net.hosts())
            except Exception:
                pass
        elif '-' in part:
            try:
                start_str, end_str = part.split('-')
                start_str = start_str.strip()
                end_str = end_str.strip()
                start_ip = ipaddress.IPv4Address(start_str)
                if '.' in end_str:
                    end_ip = ipaddress.IPv4Address(end_str)
                else:
                    octets = start_str.split('.')
                    octets[-1] = end_str
                    end_ip = ipaddress.IPv4Address('.'.join(octets))
                start_int = int(start_ip)
                end_int = int(end_ip)
                if start_int <= end_int and (end_int - start_int) <= 256:
                    for ip_int in range(start_int, end_int + 1):
                        ips.append(str(ipaddress.IPv4Address(ip_int)))
            except Exception:
                pass
        else:
            try:
                ipaddress.IPv4Address(part)
                ips.append(part)
            except Exception:
                pass
    return ips

# ── Per-host methodology / attack-path helpers ────────────────────────────────
def build_host_methodology_line(host: dict) -> str:
    parts = ["découverte réseau (ARP/ICMP)"]
    if host.get("services"):
        parts.append("scan de ports Nmap (Pn, top-1000/-p-)")
    web_ports = [s["port"] for s in host.get("services", []) if s.get("port") in
                 {80, 443, 8080, 8443, 3000, 8000, 8888, 9090, 9443, 4443}]
    if web_ports:
        parts.append(f"tests de vulnérabilités Nuclei sur {len(web_ports)} port(s) web détecté(s)")
    cred_tested = any(e.get("type") in ("auth_screenshot", "text") for e in host.get("evidence", []))
    if cred_tested:
        parts.append("tests d'identifiants par défaut sur les services exposés")
    return f"Cet hôte a été analysé via {', '.join(parts)}."

def build_port_status_table(host: dict, mono_style, meta_label_style, body_style, body_bold, colwidths=None):
    rows = [[
        Paragraph("<b>État</b>", meta_label_style),
        Paragraph("<b>Port</b>", meta_label_style),
        Paragraph("<b>Protocole</b>", meta_label_style),
        Paragraph("<b>Service</b>", meta_label_style),
        Paragraph("<b>Version</b>", meta_label_style),
    ]]
    for s in host.get("services", []):
        is_open = (s.get("state", "open") == "open")
        icon = "✅ Ouvert" if is_open else "⛔ Fermé"
        icon_color = PDF_COLORS["safe"] if is_open else PDF_COLORS["text_muted"]
        rows.append([
            Paragraph(f"<font color='{icon_color.hexval()}'><b>{icon}</b></font>", body_style),
            Paragraph(str(s["port"]), mono_style),
            Paragraph(s.get("protocol", "tcp"), body_style),
            Paragraph(s.get("name") or "Unknown", body_style),
            Paragraph(s.get("version") or "Unknown", body_style),
        ])
    widths = colwidths or [1*inch, 0.8*inch, 1*inch, 2*inch, 2.7*inch]
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PDF_COLORS["bg_light"]),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, 0), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, PDF_COLORS["bg_light"]]),
    ]))
    return t

def build_host_attack_path(host: dict) -> Optional[str]:
    vulns = host.get("vulnerabilities", [])
    if not vulns:
        return None
    crit_high = [v for v in vulns if v.get("severity", "").lower() in ("critical", "high")]
    cred_vulns = [v for v in vulns if v.get("source") == "credential_test"]
    has_smb = any("smb" in (v.get("name", "") + str(host.get("services", []))).lower() for v in vulns) or \
              any(s.get("port") in (139, 445) for s in host.get("services", []))
    has_web = any(s.get("port") in {80, 443, 8080, 8443} for s in host.get("services", []))
    if not crit_high and not cred_vulns:
        return None
    steps = []
    if cred_vulns:
        cred_names = ", ".join(sorted({c.get("name", "un service") for c in cred_vulns}))
        steps.append(
            f"Un attaquant disposant d'un accès réseau pourrait utiliser les identifiants par défaut "
            f"validés sur {host['ip']} ({cred_names}) pour obtenir un accès direct au système."
        )
    elif crit_high:
        worst = crit_high[0]
        steps.append(
            f"La vulnérabilité « {worst.get('name', 'identifiée')} » sur {host['ip']} pourrait être "
            f"exploitée par un attaquant pour obtenir un accès non autorisé au système."
        )
    if has_smb:
        steps.append("Cet accès pourrait ensuite servir à consulter ou exfiltrer les fichiers partagés via SMB.")
    if has_web and len(steps) < 3:
        steps.append("Un service web exposé sur cet hôte offre également une surface d'attaque supplémentaire pour la reconnaissance ou l'exploitation.")
    if len(steps) < 2:
        steps.append("Depuis cet hôte compromis, un attaquant pourrait pivoter vers d'autres machines du même réseau.")
    return " ".join(steps[:3])

# ── Matplotlib Chart Generators ────────────────────────────────────────────────
def make_health_gauge(score):
    fig, ax = plt.subplots(figsize=(3, 2), subplot_kw={'projection': 'polar'})
    color = "#16A34A" if score >= 80 else ("#CA8A04" if score >= 50 else "#DC2626")
    ax.barh(0.5, 3.14 * (score / 100.0), left=0, height=0.3, color=color, align='center')
    ax.barh(0.5, 3.14, left=0, height=0.3, color='#E2E8F0', align='center', zorder=0)
    ax.set_ylim(-1, 1)
    ax.set_theta_zero_location('W')
    ax.set_theta_direction(-1)
    ax.set_thetagrids([])
    ax.set_rgrids([])
    ax.spines['polar'].set_visible(False)
    ax.text(0, -0.2, f"{int(score)}/100", ha='center', va='center', fontsize=20, weight='bold', color='#1E293B')
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', transparent=True, dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf

def make_severity_donut(vulns):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        s = v.get("severity", "info").lower()
        if s in counts:
            counts[s] += 1
    labels = [k.capitalize() for k, val in counts.items() if val > 0]
    sizes = [val for val in counts.values() if val > 0]
    map_sev_hex = {
        "critical": "#DC2626", "high": "#EA580C", "medium": "#CA8A04",
        "low": "#2563EB", "info": "#64748B",
    }
    colors_list = [map_sev_hex[k.lower()] for k, val in counts.items() if val > 0]
    if not sizes:
        labels, sizes, colors_list = ["Aucune"], [1], ["#16A34A"]
    fig, ax = plt.subplots(figsize=(4, 3))
    ax.pie(sizes, labels=labels, colors=colors_list, autopct='%1.0f%%', startangle=90, 
           wedgeprops=dict(width=0.4, edgecolor='w'))
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', transparent=True, dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf

def make_top_hosts_bar(hosts):
    host_scores = []
    for h in hosts:
        weight = 0
        for v in h.get("vulnerabilities", []):
            sev = v.get("severity", "info").lower()
            if sev == "critical": weight += 10
            elif sev == "high": weight += 6
            elif sev == "medium": weight += 3
            elif sev == "low": weight += 1
        host_scores.append((h["ip"], weight))
    host_scores = sorted(host_scores, key=lambda x: x[1], reverse=True)[:5]
    host_scores = [h for h in host_scores if h[1] > 0]
    if not host_scores:
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.text(0.5, 0.5, "Aucun risque détecté", ha='center', va='center', color='#64748B')
        ax.set_axis_off()
    else:
        ips = [x[0] for x in reversed(host_scores)]
        scores = [x[1] for x in reversed(host_scores)]
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.barh(ips, scores, color='#4F46E5')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.set_xlabel("Poids du Risque Global")
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', transparent=True, dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf

# ── PDF Generation ────────────────────────────────────────────────────────────
async def generate_pdf_report(scan_id: str) -> bytes:
    from main import AsyncSessionLocal, Scan, Host, select, selectinload, compute_health_score
    from services.audit_analysis import fetch_audit_analysis, generate_audit_analysis, persist_audit_analysis
    import logging
    logger = logging.getLogger("PDFReport")

    async with AsyncSessionLocal() as session:
        s_res = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = s_res.scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        h_res = await session.execute(
            select(Host)
            .where(Host.scan_id == scan_id)
            .options(selectinload(Host.services), selectinload(Host.vulnerabilities))
        )
        hosts_orm = h_res.scalars().unique().all()

    hosts = []
    for h in hosts_orm:
        hosts.append({
            "ip": h.ip,
            "hostname": h.hostname or "Unknown",
            "os": h.os or "Unknown",
            "mac_address": h.mac_address or "Unknown",
            "scanned": len(h.services) > 0,
            "screenshot_path": h.screenshot_path,
            "evidence": h.evidence or [],
            "services": [
                {"port": s.port, "protocol": s.protocol, "name": s.name, "version": s.version, "state": s.state}
                for s in h.services
            ],
            "vulnerabilities": [
                {
                    "template_id": v.template_id,
                    "name": v.name,
                    "severity": v.severity,
                    "cve_id": v.cve_id,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "source": v.source,
                    "matcher_name": v.matcher_name,
                    "host_ip": h.ip
                }
                for v in h.vulnerabilities
            ]
        })

    analysis = await fetch_audit_analysis(scan_id)
    if not analysis:
        try:
            analysis = await generate_audit_analysis(scan_id)
            if analysis:
                try:
                    await persist_audit_analysis(scan_id, analysis)
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"[PDF] LLM analysis failed for {scan_id}, using fallback: {e}")
            try:
                from services.audit_analysis import build_scan_context, build_fallback_analysis
                context = await build_scan_context(scan_id)
                analysis = build_fallback_analysis(context)
            except Exception as fallback_error:
                logger.error(f"[PDF] Fallback analysis also failed for {scan_id}: {fallback_error}")
                analysis = {
                    "security_score": 50, "maturity_level": "Unknown",
                    "executive_summary": "Analyse non disponible due to technical errors.",
                    "attack_vectors": [], "most_dangerous_vulnerabilities": [],
                    "business_impact": {}, "likelihood_of_compromise": "Unknown",
                    "attacker_scenario": "Non disponible", "security_strengths": [],
                    "security_weaknesses": [], "global_risk_conclusion": "Analyse non disponible",
                    "key_findings": [], "strategic_recommendations": [],
                    "overall_verdict": "Analyse non disponible", "ai_generated": False
                }

    if not analysis:
        logger.warning(f"[PDF] Analysis is None for {scan_id}, creating minimal analysis")
        analysis = {
            "security_score": 50, "maturity_level": "Unknown",
            "executive_summary": "Analyse non disponible.",
            "attack_vectors": [], "most_dangerous_vulnerabilities": [],
            "business_impact": {}, "likelihood_of_compromise": "Unknown",
            "attacker_scenario": "Non disponible", "security_strengths": [],
            "security_weaknesses": [], "global_risk_conclusion": "Analyse non disponible",
            "key_findings": [], "strategic_recommendations": [],
            "overall_verdict": "Analyse non disponible", "ai_generated": False
        }

    all_vulns = [v for h in hosts for v in h["vulnerabilities"]]
    seen_vulns = {}
    deduplicated_vulns = []
    for v in all_vulns:
        key = (v.get("name", ""), v.get("severity", "info"))
        if key not in seen_vulns:
            seen_vulns[key] = v
            deduplicated_vulns.append(v)
            seen_vulns[key]["affected_hosts"] = [v.get("host_ip")]
        else:
            if v.get("host_ip") not in seen_vulns[key]["affected_hosts"]:
                seen_vulns[key]["affected_hosts"].append(v.get("host_ip"))
    all_vulns = deduplicated_vulns
    health_score = compute_health_score([{"severity": v["severity"]} for v in all_vulns])

    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in all_vulns:
        sev = v.get("severity", "info").lower()
        if sev in vuln_counts:
            vuln_counts[sev] += 1
    total_services = sum(len(h["services"]) for h in hosts)
    credential_vulns = [v for v in all_vulns if v.get("source") == "credential_test"]

    def calculate_host_score(host):
        base_score = 100
        vulns = host["vulnerabilities"]
        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev == "critical": base_score -= 25
            elif sev == "high": base_score -= 15
            elif sev == "medium": base_score -= 8
            elif sev == "low": base_score -= 3
        cred_vulns = [v for v in vulns if v.get("source") == "credential_test"]
        base_score -= len(cred_vulns) * 20
        service_count = len(host["services"])
        base_score -= min(service_count * 2, 20)
        return max(0, min(100, base_score))

    for h in hosts:
        h["security_score"] = calculate_host_score(h)
    hosts_sorted = sorted(hosts, key=lambda x: x["security_score"])

    def get_remediation_commands(vuln_name, service_name=None):
        commands = []
        vuln_lower = vuln_name.lower()
        if "ftp" in vuln_lower or service_name == "ftp":
            commands.extend(["Disable anonymous FTP access: Edit /etc/vsftpd.conf, set anonymous_enable=NO", "Restrict FTP to specific users: Add userlist_enable=YES and userlist_file=/etc/vsftpd.userlist", "Use SFTP instead of FTP for encrypted file transfers", "Block FTP port 21 in firewall if not required"])
        elif "ssh" in vuln_lower or service_name == "ssh":
            commands.extend(["Disable weak ciphers: Edit /etc/ssh/sshd_config, set Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com", "Enable key-based auth: Set PasswordAuthentication no in sshd_config", "Disable root login: Set PermitRootLogin no in sshd_config", "Restart SSH: systemctl restart sshd"])
        elif "postgresql" in vuln_lower or service_name == "postgresql":
            commands.extend(["Remove empty passwords: ALTER USER postgres WITH PASSWORD 'strong_password'", "Restrict remote access: Edit pg_hba.conf, allow only specific IPs", "Enable SSL: Set ssl=on in postgresql.conf", "Update PostgreSQL to latest version"])
        elif "mysql" in vuln_lower or service_name == "mysql":
            commands.extend(["Remove empty passwords: ALTER USER 'root'@'localhost' IDENTIFIED BY 'strong_password'", "Restrict remote access: Bind to 127.0.0.1 in my.cnf", "Enable SSL: Add require_ssl in my.cnf", "Update MySQL to latest version"])
        elif "http" in vuln_lower or service_name in ["http", "https", "apache", "nginx"]:
            commands.extend(["Disable HTTP methods: Configure server to allow only GET, POST, HEAD", "Enable HTTPS/TLS: Install SSL certificate and redirect HTTP to HTTPS", "Install security headers: X-Frame-Options, X-Content-Type-Options, CSP", "Update web server to latest version"])
        elif "smb" in vuln_lower or service_name == "smb":
            commands.extend(["Disable SMBv1: Set SMB1=0 in Windows registry or /etc/samba/smb.conf", "Require SMB signing: Set server signing = required", "Restrict SMB to specific networks: Use firewall rules", "Update Samba to latest version"])
        elif "rdp" in vuln_lower or service_name == "rdp":
            commands.extend(["Enable Network Level Authentication (NLA)", "Restrict RDP to specific users via Group Policy", "Block RDP port 3389 in firewall if not required", "Use VPN for remote access instead of direct RDP"])
        else:
            commands.extend(["Update the affected service to the latest version", "Check vendor advisories for security patches", "Restrict network access using firewall rules", "Monitor for suspicious activity"])
        return commands

    def get_mitre_mapping(vuln_name, service_name=None):
        vuln_lower = vuln_name.lower()
        mitre_techniques = []
        if "credential" in vuln_lower or "password" in vuln_lower:
            mitre_techniques.extend(["T1078 - Valid Accounts", "T1110 - Brute Force", "T1078.004 - Cloud Account"])
        if "ssh" in vuln_lower or service_name == "ssh":
            mitre_techniques.extend(["T1021.004 - Remote Services: SSH", "T1562.001 - Impair Defenses: Disable or Modify Tools"])
        if "ftp" in vuln_lower or service_name == "ftp":
            mitre_techniques.extend(["T1078.003 - Local Accounts", "T1110.003 - Password Spraying"])
        if "http" in vuln_lower or service_name in ["http", "https", "apache", "nginx"]:
            mitre_techniques.extend(["T1190 - Exploit Public-Facing Application", "T1071.001 - Application Layer Protocol: Web Protocols"])
        if "smb" in vuln_lower or service_name == "smb":
            mitre_techniques.extend(["T1021.002 - Remote Services: SMB/Windows Admin Shares", "T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools"])
        if "rdp" in vuln_lower or service_name == "rdp":
            mitre_techniques.extend(["T1021.001 - Remote Services: Remote Desktop Protocol", "T1566.002 - Phishing: Spearphishing Link"])
        if "sql" in vuln_lower or service_name in ["mysql", "postgresql", "mssql"]:
            mitre_techniques.extend(["T1190 - Exploit Public-Facing Application", "T1055 - Process Injection"])
        if not mitre_techniques:
            mitre_techniques.append("T1059 - Command and Scripting Interpreter")
        cwe_ids = []
        if "credential" in vuln_lower or "password" in vuln_lower:
            cwe_ids.extend(["CWE-798 - Use of Hard-coded Credentials", "CWE-521 - Weak Authentication"])
        if "injection" in vuln_lower or "sql" in vuln_lower:
            cwe_ids.extend(["CWE-89 - SQL Injection", "CWE-94 - Code Injection"])
        if "xss" in vuln_lower:
            cwe_ids.append("CWE-79 - Cross-site Scripting")
        if "buffer" in vuln_lower or "overflow" in vuln_lower:
            cwe_ids.extend(["CWE-119 - Buffer Errors", "CWE-120 - Buffer Copy without Checking Size"])
        if "ssh" in vuln_lower:
            cwe_ids.extend(["CWE-798 - Use of Hard-coded Credentials", "CWE-255 - Credentials Management"])
        if "ftp" in vuln_lower:
            cwe_ids.extend(["CWE-798 - Use of Hard-coded Credentials", "CWE-521 - Weak Authentication"])
        if "http" in vuln_lower or "ssl" in vuln_lower or "tls" in vuln_lower:
            cwe_ids.extend(["CWE-319 - Cleartext Transmission", "CWE-295 - Improper Certificate Validation"])
        if "smb" in vuln_lower:
            cwe_ids.append("CWE-306 - Missing Critical Authentication")
        if "rdp" in vuln_lower:
            cwe_ids.extend(["CWE-306 - Missing Critical Authentication", "CWE-287 - Improper Authentication"])
        if not cwe_ids:
            cwe_ids.append("CWE-200 - Exposure of Sensitive Information")
        return {"mitre_techniques": mitre_techniques[:3], "cwe_ids": cwe_ids[:2]}

    def get_compliance_mapping(vuln_name, service_name=None):
        vuln_lower = vuln_name.lower()
        compliance_map = {"ISO 27001": [], "NIST CSF": [], "CIS Controls": [], "OWASP Top 10": [], "MITRE D3FEND": []}
        if "credential" in vuln_lower or "password" in vuln_lower:
            compliance_map["ISO 27001"].extend(["A.9.4.1 - User authentication", "A.9.4.3 - Password management"])
        if "ssh" in vuln_lower or service_name == "ssh":
            compliance_map["ISO 27001"].extend(["A.13.1.1 - Network controls", "A.14.2.1 - Secure development"])
        if "ftp" in vuln_lower or service_name == "ftp":
            compliance_map["ISO 27001"].append("A.13.1.1 - Network controls")
        if "http" in vuln_lower or "ssl" in vuln_lower or "tls" in vuln_lower:
            compliance_map["ISO 27001"].extend(["A.14.1.2 - Secure transfer", "A.14.2.1 - Secure development"])
        if "smb" in vuln_lower or service_name == "smb":
            compliance_map["ISO 27001"].append("A.13.1.1 - Network controls")
        if not compliance_map["ISO 27001"]:
            compliance_map["ISO 27001"].append("A.12.2.1 - Vulnerability management")
        if "credential" in vuln_lower or "password" in vuln_lower:
            compliance_map["NIST CSF"].extend(["PR.AC - Access Control", "PR.AT - Awareness and Training"])
        if "ssh" in vuln_lower or service_name == "ssh":
            compliance_map["NIST CSF"].extend(["PR.AC - Access Control", "PR.DS - Data Security"])
        if "ftp" in vuln_lower or service_name == "ftp":
            compliance_map["NIST CSF"].append("PR.AC - Access Control")
        if "http" in vuln_lower or "ssl" in vuln_lower or "tls" in vuln_lower:
            compliance_map["NIST CSF"].extend(["PR.DS - Data Security", "PR.PS - Protective Technology"])
        if "smb" in vuln_lower or service_name == "smb":
            compliance_map["NIST CSF"].append("PR.AC - Access Control")
        if not compliance_map["NIST CSF"]:
            compliance_map["NIST CSF"].append("ID.RA - Risk Assessment")
        if "credential" in vuln_lower or "password" in vuln_lower:
            compliance_map["CIS Controls"].extend(["CIS 4.3 - Use Unique Passwords", "CIS 16.1 - Establish Password Policy"])
        if "ssh" in vuln_lower or service_name == "ssh":
            compliance_map["CIS Controls"].extend(["CIS 4.4 - Use SSH Key Authentication", "CIS 18.1 - Secure SSH Configuration"])
        if "ftp" in vuln_lower or service_name == "ftp":
            compliance_map["CIS Controls"].append("CIS 9.2 - Ensure Only Authorized FTP Access")
        if "http" in vuln_lower or "ssl" in vuln_lower or "tls" in vuln_lower:
            compliance_map["CIS Controls"].extend(["CIS 9.1 - Ensure SSL/TLS Enabled", "CIS 18.2 - Secure Web Server Configuration"])
        if "smb" in vuln_lower or service_name == "smb":
            compliance_map["CIS Controls"].append("CIS 9.3 - Disable SMBv1")
        if not compliance_map["CIS Controls"]:
            compliance_map["CIS Controls"].append("CIS 3.1 - Inventory Authorized Software")
        if "credential" in vuln_lower or "password" in vuln_lower:
            compliance_map["OWASP Top 10"].append("A07: Identification and Authentication Failures")
        if "injection" in vuln_lower or "sql" in vuln_lower:
            compliance_map["OWASP Top 10"].append("A03: Injection")
        if "xss" in vuln_lower:
            compliance_map["OWASP Top 10"].append("A03: Cross-Site Scripting (XSS)")
        if "http" in vuln_lower or "ssl" in vuln_lower or "tls" in vuln_lower:
            compliance_map["OWASP Top 10"].append("A02: Cryptographic Failures")
        if "ssh" in vuln_lower or service_name == "ssh":
            compliance_map["OWASP Top 10"].append("A01: Broken Access Control")
        if not compliance_map["OWASP Top 10"]:
            compliance_map["OWASP Top 10"].append("A05: Security Misconfiguration")
        if "credential" in vuln_lower or "password" in vuln_lower:
            compliance_map["MITRE D3FEND"].extend(["D3-ADT: Authentication Data Validation", "D3-AUTH: Authentication"])
        if "ssh" in vuln_lower or service_name == "ssh":
            compliance_map["MITRE D3FEND"].extend(["D3-AUTH: Authentication", "D3-ENCR: Encrypted Tunnel"])
        if "ftp" in vuln_lower or service_name == "ftp":
            compliance_map["MITRE D3FEND"].append("D3-AUTH: Authentication")
        if "http" in vuln_lower or "ssl" in vuln_lower or "tls" in vuln_lower:
            compliance_map["MITRE D3FEND"].extend(["D3-ENCR: Encrypted Tunnel", "D3-ADT: Authentication Data Validation"])
        if "smb" in vuln_lower or service_name == "smb":
            compliance_map["MITRE D3FEND"].append("D3-AUTH: Authentication")
        if not compliance_map["MITRE D3FEND"]:
            compliance_map["MITRE D3FEND"].append("D3-ADT: Authentication Data Validation")
        return compliance_map

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter, leftMargin=0.5*inch, rightMargin=0.5*inch,
        topMargin=0.5*inch, bottomMargin=0.5*inch
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('CoverTitle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=32, leading=38, textColor=colors.white, spaceAfter=15)
    subtitle_style = ParagraphStyle('CoverSubtitle', parent=styles['Normal'], fontName='Helvetica', fontSize=14, leading=18, textColor=colors.HexColor("#E2E8F0"), spaceAfter=20)
    h1_style = ParagraphStyle('SectionH1', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=20, leading=24, textColor=PDF_COLORS["primary"], spaceBefore=20, spaceAfter=12, keepWithNext=True)
    h2_style = ParagraphStyle('SectionH2', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=16, leading=20, textColor=PDF_COLORS["text_dark"], spaceBefore=15, spaceAfter=10, keepWithNext=True)
    h3_style = ParagraphStyle('SectionH3', parent=styles['Heading3'], fontName='Helvetica-Bold', fontSize=12, leading=16, textColor=PDF_COLORS["text_dark"], spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle('ReportBody', parent=styles['Normal'], fontName='Helvetica', fontSize=10, leading=14, textColor=PDF_COLORS["text_dark"], spaceAfter=8)
    body_bold = ParagraphStyle('ReportBodyBold', parent=body_style, fontName='Helvetica-Bold')
    mono_style = ParagraphStyle('ReportMono', parent=styles['Normal'], fontName='Courier', fontSize=9, leading=12, textColor=PDF_COLORS["text_dark"])
    meta_label_style = ParagraphStyle('MetaLabel', parent=body_style, fontName='Helvetica-Bold', textColor=PDF_COLORS["text_muted"], fontSize=9)
    bullet_style = ParagraphStyle('BulletStyle', parent=body_style, leftIndent=20, spaceAfter=4)
    methodology_style = ParagraphStyle('MethodologyStyle', parent=body_style, fontName='Helvetica-Oblique', fontSize=9, textColor=PDF_COLORS["text_muted"], spaceAfter=10)
    caption_style = ParagraphStyle('EvidenceCaption', parent=body_style, fontName='Helvetica-Oblique', fontSize=8.5, textColor=PDF_COLORS["text_muted"], spaceAfter=6)

    crit_count = len([v for v in all_vulns if v.get("severity", "").lower() == "critical"])
    high_count = len([v for v in all_vulns if v.get("severity", "").lower() == "high"])
    cred_count = len([v for v in all_vulns if v.get("source") == "credential_test"])

    domain_scores = {
        "Patch Management": 100, "Network Security": 100, "Authentication": 100,
        "Access Control": 100, "Encryption": 100, "Monitoring": 100,
        "Hardening": 100, "Vulnerability Management": 100
    }
    for v in all_vulns:
        vuln_lower = v.get("name", "").lower()
        sev = v.get("severity", "info").lower()
        deduction = 0
        if sev == "critical": deduction = 15
        elif sev == "high": deduction = 10
        elif sev == "medium": deduction = 5
        elif sev == "low": deduction = 2
        if "ssh" in vuln_lower or "ftp" in vuln_lower or "smb" in vuln_lower or "rdp" in vuln_lower:
            domain_scores["Network Security"] -= deduction
        if "credential" in vuln_lower or "password" in vuln_lower:
            domain_scores["Authentication"] -= deduction
            domain_scores["Access Control"] -= deduction
        if "ssl" in vuln_lower or "tls" in vuln_lower or "http" in vuln_lower:
            domain_scores["Encryption"] -= deduction
        if "ssh" in vuln_lower or "ftp" in vuln_lower:
            domain_scores["Hardening"] -= deduction
        domain_scores["Vulnerability Management"] -= deduction
        domain_scores["Patch Management"] -= deduction
    for domain in domain_scores:
        domain_scores[domain] = max(0, min(100, domain_scores[domain]))

    story = []
    
    # Cover Page
    cover_header = [
        [Paragraph("RAPPORT D'AUDIT DE SÉCURITÉ RÉSEAU", title_style)],
        [Paragraph("Analyse complète des vulnérabilités et recommandations de remédiation", subtitle_style)]
    ]
    cover_header_table = Table(cover_header, colWidths=[7.5*inch])
    cover_header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["primary"]),
        ('PADDING', (0,0), (-1,-1), 36), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(cover_header_table)
    story.append(Spacer(1, 20))

    metadata_data = [
        [Paragraph("<b>Informations du Scan</b>", h2_style)],
        [Paragraph("<b>Cible :</b>", meta_label_style), Paragraph(scan.target, body_style),
         Paragraph("<b>ID Scan :</b>", meta_label_style), Paragraph(scan.id[:8] + "...", mono_style)],
        [Paragraph("<b>Date de début :</b>", meta_label_style), Paragraph(scan.started_at.strftime('%d/%m/%Y %H:%M') if scan.started_at else "N/A", body_style),
         Paragraph("<b>Date de fin :</b>", meta_label_style), Paragraph(scan.finished_at.strftime('%d/%m/%Y %H:%M') if scan.finished_at else "N/A", body_style)],
        [Paragraph("<b>Statut :</b>", meta_label_style), Paragraph(scan.status.upper(), body_bold),
         Paragraph("<b>Durée :</b>", meta_label_style), Paragraph(f"{(scan.finished_at - scan.started_at).total_seconds():.0f}s" if scan.finished_at and scan.started_at else "N/A", body_style)]
    ]
    metadata_table = Table(metadata_data, colWidths=[1.5*inch, 2.25*inch, 1.5*inch, 2.25*inch])
    metadata_table.setStyle(TableStyle([
        ('SPAN', (0,0), (-1,0)), ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 8), ('LINEBELOW', (0,1), (-1,1), 1, colors.HexColor("#E2E8F0")),
        ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("SCORE GLOBAL DE SANTÉ DU RÉSEAU", h2_style))
    health_data = [
        [Paragraph("<b>Score de Santé</b>", meta_label_style), Paragraph("<b>Appareils</b>", meta_label_style),
         Paragraph("<b>Services</b>", meta_label_style), Paragraph("<b>Vulnérabilités</b>", meta_label_style)],
        [Paragraph(f"<font size=24 color='{PDF_COLORS['primary'].hexval()}'><b>{int(health_score)}/100</b></font>", body_bold),
         Paragraph(f"<font size=18><b>{len(hosts)}</b></font>", body_bold),
         Paragraph(f"<font size=18><b>{total_services}</b></font>", body_bold),
         Paragraph(f"<font size=18 color='{PDF_COLORS['critical'].hexval()}'><b>{len(all_vulns)}</b></font>", body_bold)]
    ]
    health_table = Table(health_data, colWidths=[1.875*inch]*4)
    health_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 16), ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(health_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("RÉPARTITION PAR SÉVÉRITÉ", h3_style))
    sev_data = [
        [Paragraph("<b>Critique</b>", meta_label_style), Paragraph("<b>Élevé</b>", meta_label_style),
         Paragraph("<b>Moyen</b>", meta_label_style), Paragraph("<b>Faible</b>", meta_label_style), Paragraph("<b>Info</b>", meta_label_style)],
        [Paragraph(f"<font size=16 color='{PDF_COLORS['critical'].hexval()}'><b>{vuln_counts['critical']}</b></font>", body_bold),
         Paragraph(f"<font size=16 color='{PDF_COLORS['high'].hexval()}'><b>{vuln_counts['high']}</b></font>", body_bold),
         Paragraph(f"<font size=16 color='{PDF_COLORS['medium'].hexval()}'><b>{vuln_counts['medium']}</b></font>", body_bold),
         Paragraph(f"<font size=16 color='{PDF_COLORS['low'].hexval()}'><b>{vuln_counts['low']}</b></font>", body_bold),
         Paragraph(f"<font size=16 color='{PDF_COLORS['info'].hexval()}'><b>{vuln_counts['info']}</b></font>", body_bold)]
    ]
    sev_table = Table(sev_data, colWidths=[1.5*inch]*5)
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 12), ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 30))

    footer_data = [
        [Paragraph("CONFIDENTIEL — Usage interne uniquement | Rapport généré automatiquement par Audit Réseau IA", ParagraphStyle('FooterText', parent=body_style, textColor=PDF_COLORS["text_muted"], alignment=1, fontSize=8))]
    ]
    footer_table = Table(footer_data, colWidths=[7.5*inch])
    story.append(footer_table)
    story.append(PageBreak())

    # Executive Summary Page
    story.append(Paragraph("RÉSUMÉ EXÉCUTIF", h1_style))
    exec_summary = analysis.get("executive_summary", "No summary available.")
    exec_box = Table([[Paragraph(exec_summary, body_style)]], colWidths=[7.5*inch])
    exec_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 20),
        ('LINELEFT', (0,0), (-1,-1), 8, PDF_COLORS["primary"]), ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(exec_box)
    story.append(Spacer(1, 25))

    story.append(Paragraph("MÉTRIQUES CLÉS POUR LA DIRECTION", h2_style))
    avg_score = sum(domain_scores.values()) / len(domain_scores)
    if avg_score >= 90: exec_grade, exec_grade_color = "A", PDF_COLORS["safe"]
    elif avg_score >= 80: exec_grade, exec_grade_color = "B", PDF_COLORS["medium"]
    elif avg_score >= 70: exec_grade, exec_grade_color = "C", PDF_COLORS["high"]
    elif avg_score >= 60: exec_grade, exec_grade_color = "D", PDF_COLORS["high"]
    else: exec_grade, exec_grade_color = "F", PDF_COLORS["critical"]

    if crit_count > 0 or cred_count > 0: risk_level, risk_color = "CRITIQUE", PDF_COLORS["critical"]
    elif high_count > 3: risk_level, risk_color = "ÉLEVÉ", PDF_COLORS["high"]
    elif high_count > 0: risk_level, risk_color = "MODÉRÉ", PDF_COLORS["medium"]
    else: risk_level, risk_color = "FAIBLE", PDF_COLORS["safe"]

    exec_metrics_data = [
        [Paragraph("<b>Métrique</b>", meta_label_style), Paragraph("<b>Valeur</b>", meta_label_style),
         Paragraph("<b>Métrique</b>", meta_label_style), Paragraph("<b>Valeur</b>", meta_label_style)],
        [Paragraph("Score de Sécurité", body_style), Paragraph(f"<b>{int(avg_score)}/100</b>", body_bold),
         Paragraph("Note Globale", body_style), Paragraph(f"<b color='{exec_grade_color.hexval()}'>{exec_grade}</b>", body_bold)],
        [Paragraph("Niveau de Risque", body_style), Paragraph(f"<b color='{risk_color.hexval()}'>{risk_level}</b>", body_bold),
         Paragraph("Appareils Détectés", body_style), Paragraph(f"<b>{len(hosts)}</b>", body_bold)],
        [Paragraph("Services Ouverts", body_style), Paragraph(f"<b>{total_services}</b>", body_bold),
         Paragraph("Vulnérabilités", body_style), Paragraph(f"<b>{len(all_vulns)}</b>", body_bold)],
        [Paragraph("Vulnérabilités Critiques", body_style), Paragraph(f"<b color='{PDF_COLORS['critical'].hexval()}'>{crit_count}</b>", body_bold),
         Paragraph("Identifiants Validés", body_style), Paragraph(f"<b color='{PDF_COLORS['critical'].hexval()}'>{cred_count}</b>", body_bold)]
    ]
    exec_metrics_table = Table(exec_metrics_data, colWidths=[2*inch, 1.75*inch, 2*inch, 1.75*inch])
    exec_metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 12),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(exec_metrics_table)
    story.append(Spacer(1, 25))

    story.append(Paragraph("CE QUI A ÉTÉ DÉCOUVERT", h2_style))
    discovered_text = f"""
    L'audit a identifié <b>{len(all_vulns)}</b> vulnérabilités sur <b>{len(hosts)}</b> appareils.
    Parmi celles-ci, <b color='{PDF_COLORS['critical'].hexval()}'>{crit_count}</b> sont critiques et <b color='{PDF_COLORS['high'].hexval()}'>{high_count}</b> sont élevées.
    <b>{cred_count}</b> identifiants par défaut ont été validés, permettant un accès direct aux systèmes.
    <b>{total_services}</b> services sont exposés sur le réseau, représentant une surface d'attaque significative.
    """
    story.append(Paragraph(discovered_text, body_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph("POURQUOI C'EST IMPORTANT", h2_style))
    why_matters_text = f"""
    Les vulnérabilités critiques peuvent permettre à des attaquants de prendre le contrôle complet des systèmes,
    d'exfiltrer des données sensibles, ou de perturber les opérations business.
    Les identifiants par défaut validés représentent un risque immédiat de compromission.
    Sans action corrective, le risque d'incident de sécurité est <b color='{risk_color.hexval()}'>{risk_level.lower()}</b>.
    """
    story.append(Paragraph(why_matters_text, body_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph("CE QUI DOIT ÊTRE CORRIGÉ EN PRIORITÉ", h2_style))
    priority_fixes = []
    if crit_count > 0: priority_fixes.append(f"1. Corriger les {crit_count} vulnérabilités critiques (risque immédiat)")
    if cred_count > 0: priority_fixes.append(f"2. Changer les {cred_count} identifiants par défaut validés")
    if high_count > 0: priority_fixes.append(f"3. Traiter les {high_count} vulnérabilités élevées")
    priority_fixes.append("4. Restreindre l'accès aux services non essentiels")
    priority_fixes.append("5. Mettre en place le monitoring de sécurité")
    for fix in priority_fixes:
        fix_box = Table([[Paragraph(fix, body_style)]], colWidths=[7.5*inch])
        fix_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 10),
            ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["primary"]),
        ]))
        story.append(fix_box)
        story.append(Spacer(1, 8))
    story.append(Spacer(1, 20))

    overall_verdict = analysis.get("overall_verdict", "")
    if overall_verdict:
        verdict_box = Table([[Paragraph(f"<b>CONCLUSION GLOBALE:</b> {overall_verdict}", body_bold)]], colWidths=[7.5*inch])
        verdict_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_high_tint"]), ('PADDING', (0,0), (-1,-1), 16),
            ('LINELEFT', (0,0), (-1,-1), 6, PDF_COLORS["high"]),
        ]))
        story.append(verdict_box)
    story.append(Spacer(1, 30))

    separator = Table([[Paragraph("— FIN DU RÉSUMÉ EXÉCUTIF — DÉTAILS TECHNIQUES SUIVANT —", ParagraphStyle('SeparatorStyle', parent=body_style, alignment=1, textColor=PDF_COLORS["text_muted"]))]], colWidths=[7.5*inch])
    story.append(separator)
    story.append(PageBreak())

    # Technical Details
    story.append(Paragraph("EXECUTIVE SUMMARY", h1_style))
    security_score = analysis.get("security_score", health_score)
    maturity_level = analysis.get("maturity_level", "Unknown")
    score_maturity_data = [
        [Paragraph("<b>Security Score</b>", meta_label_style), Paragraph("<b>Maturity Level</b>", meta_label_style)],
        [Paragraph(f"<font size=20 color='{PDF_COLORS['primary'].hexval()}'><b>{security_score}/100</b></font>", body_bold),
         Paragraph(f"<b>{maturity_level}</b>", body_bold)]
    ]
    score_maturity_table = Table(score_maturity_data, colWidths=[3.75*inch]*2)
    score_maturity_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 16), ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(score_maturity_table)
    story.append(Spacer(1, 20))

    exec_box = Table([[Paragraph(exec_summary, body_style)]], colWidths=[7.5*inch])
    exec_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 16),
        ('LINELEFT', (0,0), (-1,-1), 6, PDF_COLORS["primary"]), ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(exec_box)
    story.append(Spacer(1, 20))

    attack_vectors = analysis.get("attack_vectors", [])
    if attack_vectors:
        story.append(Paragraph("ATTACK VECTORS", h2_style))
        for av in attack_vectors:
            story.append(Paragraph(f"- {av}", bullet_style))
        story.append(Spacer(1, 15))

    business_impact = analysis.get("business_impact", {})
    if business_impact:
        story.append(Paragraph("BUSINESS IMPACT ASSESSMENT", h2_style))
        impact_data = [[Paragraph("<b>Impact Area</b>", meta_label_style), Paragraph("<b>Level</b>", meta_label_style)]]
        for area, level in business_impact.items():
            impact_color = PDF_COLORS["critical"] if level == "High" else (PDF_COLORS["high"] if level == "Medium" else PDF_COLORS["safe"])
            impact_data.append([
                Paragraph(area.replace("_", " ").title(), body_style),
                Paragraph(f"<b color='{impact_color.hexval()}'>{level}</b>", body_bold)
            ])
        impact_table = Table(impact_data, colWidths=[4*inch, 3.5*inch])
        impact_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 10),
            ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(impact_table)
        story.append(Spacer(1, 15))

    likelihood = analysis.get("likelihood_of_compromise", "Unknown")
    story.append(Paragraph("LIKELIHOOD OF COMPROMISE", h2_style))
    likelihood_color = PDF_COLORS["critical"] if likelihood == "Critical" else (PDF_COLORS["high"] if likelihood == "High" else PDF_COLORS["medium"])
    likelihood_style = ParagraphStyle('LikelihoodStyle', parent=body_bold, textColor=likelihood_color, fontSize=14)
    likelihood_box = Table([[Paragraph(f"<b>{likelihood}</b>", likelihood_style)]], colWidths=[7.5*inch])
    likelihood_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 12), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(likelihood_box)
    story.append(Spacer(1, 20))

    attacker_scenario = analysis.get("attacker_scenario", "")
    if attacker_scenario:
        story.append(Paragraph("ATTACKER SCENARIO", h2_style))
        scenario_box = Table([[Paragraph(attacker_scenario, body_style)]], colWidths=[7.5*inch])
        scenario_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_critical_tint"]), ('PADDING', (0,0), (-1,-1), 16),
            ('LINELEFT', (0,0), (-1,-1), 6, PDF_COLORS["critical"]), ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(scenario_box)
        story.append(Spacer(1, 20))

    strengths = analysis.get("security_strengths", [])
    weaknesses = analysis.get("security_weaknesses", [])
    if strengths or weaknesses:
        story.append(Paragraph("SECURITY POSTURE ANALYSIS", h2_style))
        swot_data = [[Paragraph("<b>Strengths</b>", meta_label_style), Paragraph("<b>Weaknesses</b>", meta_label_style)]]
        max_len = max(len(strengths), len(weaknesses))
        for i in range(max_len):
            strength = strengths[i] if i < len(strengths) else ""
            weakness = weaknesses[i] if i < len(weaknesses) else ""
            swot_data.append([
                Paragraph(f"+ {strength}", ParagraphStyle('StrengthStyle', parent=body_style, textColor=PDF_COLORS["safe"])) if strength else Paragraph(""),
                Paragraph(f"- {weakness}", ParagraphStyle('WeaknessStyle', parent=body_style, textColor=PDF_COLORS["critical"])) if weakness else Paragraph("")
            ])
        swot_table = Table(swot_data, colWidths=[3.75*inch]*2)
        swot_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 8),
            ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")), ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(swot_table)
        story.append(Spacer(1, 20))

    global_risk = analysis.get("global_risk_conclusion", "")
    if global_risk:
        story.append(Paragraph("GLOBAL RISK CONCLUSION", h2_style))
        risk_box = Table([[Paragraph(global_risk, body_style)]], colWidths=[7.5*inch])
        risk_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_high_tint"]), ('PADDING', (0,0), (-1,-1), 16),
            ('LINELEFT', (0,0), (-1,-1), 6, PDF_COLORS["high"]), ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(risk_box)
        story.append(Spacer(1, 20))

    is_ai = analysis.get("ai_generated", False)
    ai_label = "[IA] Analysee generee par Intelligence Artificielle (Ollama / llama3.2)" if is_ai else "[AUTO] Analysee generee par Regles Automatiques de Secours"
    ai_style = ParagraphStyle('AiLabel', parent=body_style, fontName='Helvetica-Oblique', textColor=PDF_COLORS["text_muted"], fontSize=9)
    ai_box = Table([[Paragraph(ai_label, ai_style)]], colWidths=[7.5*inch])
    ai_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#FFF7ED")), ('PADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(ai_box)
    story.append(Spacer(1, 20))

    story.append(Paragraph("STATISTIQUES CLÉS", h2_style))
    stats_data = [
        [Paragraph("<b>Métrique</b>", meta_label_style), Paragraph("<b>Valeur</b>", meta_label_style),
         Paragraph("<b>Métrique</b>", meta_label_style), Paragraph("<b>Valeur</b>", meta_label_style)],
        [Paragraph("Appareils détectés", body_style), Paragraph(f"<b>{len(hosts)}</b>", body_bold),
         Paragraph("Services ouverts", body_style), Paragraph(f"<b>{total_services}</b>", body_bold)],
        [Paragraph("Vulnérabilités totales", body_style), Paragraph(f"<b>{len(all_vulns)}</b>", body_bold),
         Paragraph("Identifiants compromis", body_style), Paragraph(f"<b>{len(credential_vulns)}</b>", body_bold)],
        [Paragraph("Vulnérabilités critiques", body_style), Paragraph(f"<b color='{PDF_COLORS['critical'].hexval()}'>{vuln_counts['critical']}</b>", body_bold),
         Paragraph("Vulnérabilités élevées", body_style), Paragraph(f"<b color='{PDF_COLORS['high'].hexval()}'>{vuln_counts['high']}</b>", body_bold)]
    ]
    stats_table = Table(stats_data, colWidths=[2*inch, 1.75*inch, 2*inch, 1.75*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 10),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(stats_table)
    story.append(PageBreak())

    # IP Mapping
    story.append(Paragraph("CARTOGRAPHIE D'ADRESSAGE DU RÉSEAU", h1_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Ce tableau présente l'état de toutes les adresses IP de la plage réseau ciblée par l'audit. "
        "Les hôtes <b>découverts/actifs</b> sont mis en évidence en <font color='#16A34A'><b>vert</b></font>, "
        "tandis que les adresses <b>inactives</b> ou non répondantes sont affichées en <font color='#64748B'><b>gris</b></font>.",
        body_style
    ))
    story.append(Spacer(1, 15))

    all_range_ips = parse_target_range(scan.target)
    if len(all_range_ips) == 1 and len(hosts) > 1:
        try:
            t_ip = all_range_ips[0]
            octets = t_ip.split('.')
            subnet_cidr = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            all_range_ips = parse_target_range(subnet_cidr)
        except Exception:
            pass
    discovered_ips = {h["ip"]: h for h in hosts}
    for dip in discovered_ips:
        if dip not in all_range_ips:
            all_range_ips.append(dip)
    def ip_sort_key(ip_str):
        try: return int(ipaddress.IPv4Address(ip_str))
        except Exception: return 0
    all_range_ips = sorted(list(set(all_range_ips)), key=ip_sort_key)

    if len(all_range_ips) <= 16:
        mapping_rows = [[
            Paragraph("<b>Adresse IP</b>", meta_label_style), Paragraph("<b>Statut</b>", meta_label_style),
            Paragraph("<b>Nom d'hôte</b>", meta_label_style), Paragraph("<b>Système / Classification</b>", meta_label_style),
            Paragraph("<b>Ports ouverts</b>", meta_label_style),
        ]]
        for ip in all_range_ips:
            if ip in discovered_ips:
                h = discovered_ips[ip]
                status_html = f"<font color='{PDF_COLORS['safe'].hexval()}'><b>● Actif</b></font>"
                hostname = h.get("hostname") or "Unknown"
                os_class = h.get("os") or h.get("device_classification") or "Unknown"
                ports_count = str(len(h.get("services", [])))
            else:
                status_html = f"<font color='{PDF_COLORS['text_muted'].hexval()}'>○ Inactif</font>"
                hostname = "—"
                os_class = "—"
                ports_count = "—"
            mapping_rows.append([
                Paragraph(ip, mono_style), Paragraph(status_html, body_style),
                Paragraph(hostname, body_style), Paragraph(os_class, body_style),
                Paragraph(ports_count, body_style),
            ])
        mapping_table = Table(mapping_rows, colWidths=[1.5*inch, 1*inch, 1.8*inch, 2.2*inch, 1*inch])
        mapping_table_style = [
            ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 8),
            ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]
        for idx, ip in enumerate(all_range_ips, 1):
            if ip in discovered_ips:
                mapping_table_style.append(('BACKGROUND', (0, idx), (-1, idx), PDF_COLORS["bg_safe_tint"]))
            else:
                mapping_table_style.append(('BACKGROUND', (0, idx), (-1, idx), colors.white))
        mapping_table.setStyle(TableStyle(mapping_table_style))
        story.append(mapping_table)
    else:
        grid_rows = []
        header_row = []
        for _ in range(4):
            header_row.extend([Paragraph("<b>IP</b>", meta_label_style), Paragraph("<b>Statut</b>", meta_label_style)])
        grid_rows.append(header_row)
        import math
        num_cols = 4
        num_rows = math.ceil(len(all_range_ips) / num_cols)
        for r in range(num_rows):
            row_data = []
            for c in range(num_cols):
                idx = r + c * num_rows
                if idx < len(all_range_ips):
                    ip = all_range_ips[idx]
                    if ip in discovered_ips:
                        status_html = f"<font color='{PDF_COLORS['safe'].hexval()}'><b>● Actif</b></font>"
                        ip_html = f"<b>{ip}</b>"
                    else:
                        status_html = f"<font color='{PDF_COLORS['text_muted'].hexval()}'>○ Inactif</font>"
                        ip_html = f"<font color='{PDF_COLORS['text_muted'].hexval()}'>{ip}</font>"
                    row_data.extend([Paragraph(ip_html, mono_style), Paragraph(status_html, body_style)])
                else:
                    row_data.extend([Paragraph(""), Paragraph("")])
            grid_rows.append(row_data)
        col_widths = [0.95*inch, 0.925*inch] * 4
        grid_table = Table(grid_rows, colWidths=col_widths)
        grid_table_style = [
            ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 4),
            ('LINEBELOW', (0,0), (-1,0), 1.5, PDF_COLORS["primary"]), ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]
        for r in range(num_rows):
            for c in range(num_cols):
                idx = r + c * num_rows
                if idx < len(all_range_ips):
                    ip = all_range_ips[idx]
                    if ip in discovered_ips:
                        grid_table_style.append(('BACKGROUND', (c*2, r+1), (c*2+1, r+1), PDF_COLORS["bg_safe_tint"]))
        grid_table.setStyle(TableStyle(grid_table_style))
        story.append(grid_table)

    story.append(Spacer(1, 15))
    story.append(Paragraph(
        f"<b>Synthèse de la découverte :</b> Sur un total de {len(all_range_ips)} adresses testées, "
        f"<b>{len(hosts)}</b> ont été identifiées comme actives et ont fait l'objet d'un audit de sécurité approfondi.",
        body_bold
    ))
    story.append(PageBreak())

    # Visual Risk
    story.append(Paragraph("ANALYSE VISUELLE DES RISQUES", h1_style))
    donut_img = make_severity_donut(all_vulns)
    bar_img = make_top_hosts_bar(hosts)
    charts_data = [[Image(donut_img, width=3.5*inch, height=2.8*inch), Image(bar_img, width=3.5*inch, height=2.8*inch)]]
    charts_table = Table(charts_data, colWidths=[3.75*inch]*2)
    charts_table.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'MIDDLE')]))
    story.append(charts_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("ANALYSE DES RISQUES PAR HÔTE", h2_style))
    host_risk_data = [[Paragraph("<b>Adresse IP</b>", meta_label_style), Paragraph("<b>OS Détecté</b>", meta_label_style),
                       Paragraph("<b>Services</b>", meta_label_style), Paragraph("<b>Vulnérabilités</b>", meta_label_style),
                       Paragraph("<b>Risque Global</b>", meta_label_style)]]
    for h in hosts:
        vuln_count = len(h["vulnerabilities"])
        host_crit_count = sum(1 for v in h["vulnerabilities"] if v.get("severity", "").lower() == "critical")
        host_high_count = sum(1 for v in h["vulnerabilities"] if v.get("severity", "").lower() == "high")
        if host_crit_count > 0: risk, risk_color = "CRITIQUE", PDF_COLORS["critical"]
        elif host_high_count > 0: risk, risk_color = "ÉLEVÉ", PDF_COLORS["high"]
        elif vuln_count > 0: risk, risk_color = "MODÉRÉ", PDF_COLORS["medium"]
        else: risk, risk_color = "FAIBLE", PDF_COLORS["safe"]
        host_risk_data.append([
            Paragraph(h["ip"], mono_style), Paragraph(h["os"][:30] if h["os"] else "Unknown", body_style),
            Paragraph(str(len(h["services"])), body_bold), Paragraph(str(vuln_count), body_bold),
            Paragraph(f"<b color='{risk_color.hexval()}'>{risk}</b>", body_bold)
        ])
    host_risk_table = Table(host_risk_data, colWidths=[1.5*inch, 2*inch, 1*inch, 1*inch, 2*inch])
    host_risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(host_risk_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("CLASSEMENT DES HÔTES PAR SCORE DE SÉCURITÉ", h2_style))
    host_score_data = [[Paragraph("<b>Rang</b>", meta_label_style), Paragraph("<b>Adresse IP</b>", meta_label_style),
                        Paragraph("<b>Score Sécurité</b>", meta_label_style), Paragraph("<b>Services</b>", meta_label_style),
                        Paragraph("<b>Vulnérabilités</b>", meta_label_style), Paragraph("<b>Évaluation</b>", meta_label_style)]]
    for rank, h in enumerate(hosts_sorted, 1):
        score = h["security_score"]
        vuln_count = len(h["vulnerabilities"])
        if score >= 80: evaluation, eval_color = "Excellent", PDF_COLORS["safe"]
        elif score >= 60: evaluation, eval_color = "Bon", PDF_COLORS["medium"]
        elif score >= 40: evaluation, eval_color = "Faible", PDF_COLORS["high"]
        else: evaluation, eval_color = "Critique", PDF_COLORS["critical"]
        score_color = PDF_COLORS["safe"] if score >= 80 else (PDF_COLORS["medium"] if score >= 60 else PDF_COLORS["high"] if score >= 40 else PDF_COLORS["critical"])
        host_score_data.append([
            Paragraph(f"#{rank}", body_bold), Paragraph(h["ip"], mono_style),
            Paragraph(f"<b color='{score_color.hexval()}'>{score}/100</b>", body_bold),
            Paragraph(str(len(h["services"])), body_style), Paragraph(str(vuln_count), body_style),
            Paragraph(f"<b color='{eval_color.hexval()}'>{evaluation}</b>", body_bold)
        ])
    host_score_table = Table(host_score_data, colWidths=[0.8*inch, 1.5*inch, 1.2*inch, 1*inch, 1*inch, 2*inch])
    host_score_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(host_score_table)
    story.append(Spacer(1, 15))

    explanation_text = (
        "Le score de sécurité est calculé sur 100 points. Les déductions sont appliquées pour: "
        "vulnérabilités critiques (-25), élevées (-15), moyennes (-8), faibles (-3), "
        "identifiants validés (-20 chacun), et surface d'attaque exposée (-2 par service, max -20)."
    )
    story.append(Paragraph(explanation_text, ParagraphStyle('ExplanationStyle', parent=body_style, fontSize=8, textColor=PDF_COLORS["text_muted"])))
    story.append(PageBreak())

    # Key Findings
    story.append(Paragraph("CONSTATS CLÉS ET PLAN DE REMÉDIATION", h1_style))
    findings = analysis.get("key_findings", [])
    if not findings:
        story.append(Paragraph("Aucun constat clé identifié.", body_style))
    else:
        for idx, f in enumerate(findings[:10], 1):
            sev = f.get("severity", "info")
            sev_color = get_severity_color(sev)
            bg_tint = get_severity_bg_tint(sev)
            story.append(Paragraph(f"CONSTAT #{idx} : {f.get('finding_name', 'Inconnu')}", h2_style))
            metrics_data = [
                [Paragraph("<b>Sévérité</b>", meta_label_style), Paragraph("<b>Probabilité</b>", meta_label_style),
                 Paragraph("<b>Impact</b>", meta_label_style), Paragraph("<b>Hôtes Affectés</b>", meta_label_style)],
                [Paragraph(f"<b color='{sev_color.hexval()}'>{sev.upper()}</b>", body_bold),
                 Paragraph(f"<b>{f.get('likelihood', 'N/A')}</b>", body_bold),
                 Paragraph(f"<b>{f.get('impact', 'N/A')}</b>", body_bold),
                 Paragraph(", ".join(f.get('affected_hosts', [])), mono_style)]
            ]
            metrics_table = Table(metrics_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 3*inch])
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), bg_tint), ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'), ('PADDING', (0,0), (-1,-1), 10),
                ('LINEBELOW', (0,0), (-1,0), 2, sev_color), ('LINELEFT', (0,0), (-1,-1), 4, sev_color),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(metrics_table)
            story.append(Spacer(1, 12))
            story.append(Paragraph("<b>Description détaillée :</b>", h3_style))
            story.append(Paragraph(f.get('description', 'Non disponible.'), body_style))
            story.append(Spacer(1, 12))

            mitre_mapping = get_mitre_mapping(f.get('finding_name', ''), f.get('service'))
            story.append(Paragraph("<b>Mappings MITRE ATT&CK & CWE :</b>", h3_style))
            mapping_data = [[Paragraph("<b>Type</b>", meta_label_style), Paragraph("<b>Identifiant</b>", meta_label_style)]]
            for technique in mitre_mapping["mitre_techniques"]:
                mapping_data.append([Paragraph("MITRE ATT&CK", body_style), Paragraph(technique, mono_style)])
            for cwe in mitre_mapping["cwe_ids"]:
                mapping_data.append([Paragraph("CWE", body_style), Paragraph(cwe, mono_style)])
            mapping_table = Table(mapping_data, colWidths=[2*inch, 5.5*inch])
            mapping_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(mapping_table)
            story.append(Spacer(1, 12))

            compliance_map = get_compliance_mapping(f.get('finding_name', ''), f.get('service'))
            story.append(Paragraph("<b>Conformité aux Standards :</b>", h3_style))
            compliance_data = [[Paragraph("<b>Framework</b>", meta_label_style), Paragraph("<b>Contrôle</b>", meta_label_style)]]
            for framework, controls in compliance_map.items():
                for control in controls[:2]:
                    compliance_data.append([Paragraph(framework, body_bold), Paragraph(control, body_style)])
            compliance_table = Table(compliance_data, colWidths=[2*inch, 5.5*inch])
            compliance_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(compliance_table)
            story.append(Spacer(1, 12))

            story.append(Paragraph("<b>Plan de remédiation détaillé :</b>", h3_style))
            remediation_steps = f.get('remediation_steps', [])
            if remediation_steps:
                for step_idx, step in enumerate(remediation_steps, 1):
                    story.append(Paragraph(f"{step_idx}. {step}", bullet_style))
            else:
                story.append(Paragraph("Aucune étape de remédiation disponible.", body_style))
            story.append(Spacer(1, 20))
    story.append(PageBreak())

    # Remediation Timeline
    story.append(Paragraph("CALENDRIER DE REMÉDIATION", h1_style))
    story.append(Paragraph("PHASE 1: ACTIONS IMMÉDIATES (24 HEURES)", h2_style))
    phase1_actions = []
    crit_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "critical"]
    for v in crit_vulns[:5]:
        commands = get_remediation_commands(v.get("name", ""))
        phase1_actions.append({"vuln": v.get("name", "Unknown"), "host": v.get("host_ip", "Unknown"), "commands": commands[:2] if commands else ["Apply vendor patch immediately"]})
    cred_vulns = [v for v in all_vulns if v.get("source") == "credential_test"]
    for v in cred_vulns[:3]:
        phase1_actions.append({"vuln": "Default Credentials Validated", "host": v.get("host_ip", "Unknown"), "commands": ["Change default credentials immediately", "Disable accounts with default credentials", "Implement multi-factor authentication"]})
    if phase1_actions:
        for action in phase1_actions:
            action_box = Table([[Paragraph(f"<b>{action['vuln']}</b> on {action['host']}", body_style)]], colWidths=[7.5*inch])
            action_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_critical_tint"]), ('PADDING', (0,0), (-1,-1), 10),
                ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["critical"]),
            ]))
            story.append(action_box)
            for cmd in action["commands"]:
                story.append(Paragraph(f"- {cmd}", bullet_style))
            story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("Aucune action critique requise dans les 24h.", body_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph("PHASE 2: ACTIONS À COURT TERME (7 JOURS)", h2_style))
    phase2_actions = []
    high_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "high"]
    for v in high_vulns[:5]:
        commands = get_remediation_commands(v.get("name", ""))
        phase2_actions.append({"vuln": v.get("name", "Unknown"), "host": v.get("host_ip", "Unknown"), "commands": commands[:2] if commands else ["Apply vendor patch within 7 days"]})
    if phase2_actions:
        for action in phase2_actions:
            action_box = Table([[Paragraph(f"<b>{action['vuln']}</b> on {action['host']}", body_style)]], colWidths=[7.5*inch])
            action_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_high_tint"]), ('PADDING', (0,0), (-1,-1), 10),
                ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["high"]),
            ]))
            story.append(action_box)
            for cmd in action["commands"]:
                story.append(Paragraph(f"- {cmd}", bullet_style))
            story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("Aucune vulnérabilité élevée détectée.", body_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph("PHASE 3: ACTIONS À MOYEN TERME (30 JOURS)", h2_style))
    phase3_actions = []
    medium_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "medium"]
    for v in medium_vulns[:5]:
        commands = get_remediation_commands(v.get("name", ""))
        phase3_actions.append({"vuln": v.get("name", "Unknown"), "host": v.get("host_ip", "Unknown"), "commands": commands[:2] if commands else ["Apply vendor patch within 30 days"]})
    if phase3_actions:
        for action in phase3_actions:
            action_box = Table([[Paragraph(f"<b>{action['vuln']}</b> on {action['host']}", body_style)]], colWidths=[7.5*inch])
            action_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_medium_tint"]), ('PADDING', (0,0), (-1,-1), 10),
                ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["medium"]),
            ]))
            story.append(action_box)
            for cmd in action["commands"]:
                story.append(Paragraph(f"- {cmd}", bullet_style))
            story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("Aucune vulnérabilité moyenne détectée.", body_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph("PHASE 4: ACTIONS À LONG TERME (90 JOURS)", h2_style))
    phase4_actions = ["Review and update all system configurations", "Implement network segmentation", "Deploy intrusion detection systems", "Conduct regular security audits", "Train staff on security best practices", "Establish incident response procedures", "Review and update firewall rules", "Implement log monitoring and alerting"]
    for action in phase4_actions:
        story.append(Paragraph(f"- {action}", bullet_style))
    story.append(Spacer(1, 20))

    story.append(Paragraph("RÉSUMÉ DU CALENDRIER", h3_style))
    timeline_summary = f"""
    <b>Phase 1 (24h):</b> {len(phase1_actions)} actions critiques à immédiatement
    <b>Phase 2 (7j):</b> {len(phase2_actions)} actions élevées à traiter cette semaine
    <b>Phase 3 (30j):</b> {len(phase3_actions)} actions moyennes à planifier ce mois
    <b>Phase 4 (90j):</b> {len(phase4_actions)} améliorations continues à long terme
    """
    story.append(Paragraph(timeline_summary, body_style))
    story.append(PageBreak())

    # Priority Matrix
    story.append(Paragraph("MATRICE DE PRIORITÉ", h1_style))
    priority_data = [[Paragraph("<b>Vulnérabilité</b>", meta_label_style), Paragraph("<b>Sévérité</b>", meta_label_style),
                      Paragraph("<b>Effort</b>", meta_label_style), Paragraph("<b>Coût</b>", meta_label_style),
                      Paragraph("<b>Impact</b>", meta_label_style), Paragraph("<b>Priorité</b>", meta_label_style)]]
    for v in all_vulns[:10]:
        vuln_name = v.get("name", "Unknown")
        severity = v.get("severity", "info").upper()
        vuln_lower = vuln_name.lower()
        if "credential" in vuln_lower or "password" in vuln_lower: effort, effort_color = "Faible", PDF_COLORS["safe"]
        elif "ssh" in vuln_lower or "ftp" in vuln_lower: effort, effort_color = "Moyen", PDF_COLORS["medium"]
        elif "ssl" in vuln_lower or "tls" in vuln_lower: effort, effort_color = "Moyen", PDF_COLORS["medium"]
        else: effort, effort_color = "Élevé", PDF_COLORS["high"]
        if severity == "CRITICAL": cost, cost_color = "Élevé", PDF_COLORS["high"]
        elif severity == "HIGH": cost, cost_color = "Moyen", PDF_COLORS["medium"]
        else: cost, cost_color = "Faible", PDF_COLORS["safe"]
        if severity == "CRITICAL": impact, impact_color = "Critique", PDF_COLORS["critical"]
        elif severity == "HIGH": impact, impact_color = "Élevé", PDF_COLORS["high"]
        elif severity == "MEDIUM": impact, impact_color = "Moyen", PDF_COLORS["medium"]
        else: impact, impact_color = "Faible", PDF_COLORS["safe"]
        priority_score = 0
        if severity == "CRITICAL": priority_score += 4
        elif severity == "HIGH": priority_score += 3
        elif severity == "MEDIUM": priority_score += 2
        else: priority_score += 1
        if effort == "Faible": priority_score += 2
        elif effort == "Moyen": priority_score += 1
        if impact == "Critique": priority_score += 3
        elif impact == "Élevé": priority_score += 2
        elif impact == "Moyen": priority_score += 1
        if priority_score >= 7: priority, priority_color = "CRITIQUE", PDF_COLORS["critical"]
        elif priority_score >= 5: priority, priority_color = "ÉLEVÉE", PDF_COLORS["high"]
        elif priority_score >= 3: priority, priority_color = "MOYENNE", PDF_COLORS["medium"]
        else: priority, priority_color = "FAIBLE", PDF_COLORS["safe"]
        sev_color = get_severity_color(severity)
        priority_data.append([
            Paragraph(vuln_name[:40], body_style), Paragraph(f"<b color='{sev_color.hexval()}'>{severity}</b>", body_bold),
            Paragraph(f"<b color='{effort_color.hexval()}'>{effort}</b>", body_bold), Paragraph(f"<b color='{cost_color.hexval()}'>{cost}</b>", body_bold),
            Paragraph(f"<b color='{impact_color.hexval()}'>{impact}</b>", body_bold), Paragraph(f"<b color='{priority_color.hexval()}'>{priority}</b>", body_bold)
        ])
    priority_table = Table(priority_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1*inch, 1*inch, 1*inch])
    priority_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(priority_table)
    story.append(Spacer(1, 15))

    explanation_text = (
        "La priorité est calculée en combinant la sévérité, l'effort de remédiation, "
        "le coût estimé et l'impact business. Les vulnérabilités CRITIQUES avec faible effort "
        "et impact élevé sont prioritaires."
    )
    story.append(Paragraph(explanation_text, ParagraphStyle('PriorityExplanationStyle', parent=body_style, fontSize=8, textColor=PDF_COLORS["text_muted"])))
    story.append(PageBreak())

    # No Action Risk
    story.append(Paragraph("ANALYSE DES RISQUES SI AUCUNE ACTION N'EST PRISE", h1_style))
    financial_risk, financial_color = "Faible", PDF_COLORS["safe"]
    if crit_count > 0 or cred_count > 0: financial_risk, financial_color = "Élevé", PDF_COLORS["critical"]
    elif high_count > 2: financial_risk, financial_color = "Moyen", PDF_COLORS["high"]
    operational_risk, operational_color = "Faible", PDF_COLORS["safe"]
    if crit_count > 0: operational_risk, operational_color = "Critique", PDF_COLORS["critical"]
    elif high_count > 3: operational_risk, operational_color = "Élevé", PDF_COLORS["high"]
    legal_risk, legal_color = "Faible", PDF_COLORS["safe"]
    if cred_count > 0 or crit_count > 0: legal_risk, legal_color = "Élevé", PDF_COLORS["critical"]
    elif high_count > 2: legal_risk, legal_color = "Moyen", PDF_COLORS["medium"]
    reputation_risk, reputation_color = "Faible", PDF_COLORS["safe"]
    if crit_count > 0 or cred_count > 0: reputation_risk, reputation_color = "Critique", PDF_COLORS["critical"]
    elif high_count > 3: reputation_risk, reputation_color = "Élevé", PDF_COLORS["high"]

    risk_data = [
        [Paragraph("<b>Type d'Impact</b>", meta_label_style), Paragraph("<b>Niveau de Risque</b>", meta_label_style), Paragraph("<b>Description</b>", meta_label_style)],
        [Paragraph("Financier", body_bold), Paragraph(f"<b color='{financial_color.hexval()}'>{financial_risk}</b>", body_bold), Paragraph("Perte de revenus, coûts de récupération, amendes réglementaires, pertes de données.", body_style)],
        [Paragraph("Opérationnel", body_bold), Paragraph(f"<b color='{operational_color.hexval()}'>{operational_risk}</b>", body_bold), Paragraph("Interruption de services, perte de productivité, temps d'arrêt, coûts de reprise.", body_style)],
        [Paragraph("Juridique", body_bold), Paragraph(f"<b color='{legal_color.hexval()}'>{legal_risk}</b>", body_bold), Paragraph("Non-conformité RGPD, sanctions, litiges, responsabilités contractuelles.", body_style)],
        [Paragraph("Réputation", body_bold), Paragraph(f"<b color='{reputation_color.hexval()}'>{reputation_risk}</b>", body_bold), Paragraph("Perte de confiance client, dommage à la marque, impact sur les partenariats.", body_style)]
    ]
    risk_table = Table(risk_data, colWidths=[2*inch, 1.5*inch, 4*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 12),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]), ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("RÉSUMÉ DU RISQUE GLOBAL", h2_style))
    overall_risk_score = 0
    if financial_risk in ["Critique", "Élevé"]: overall_risk_score += 3
    elif financial_risk == "Moyen": overall_risk_score += 2
    else: overall_risk_score += 1
    if operational_risk == "Critique": overall_risk_score += 3
    elif operational_risk == "Élevé": overall_risk_score += 2
    elif operational_risk == "Moyen": overall_risk_score += 1
    if legal_risk in ["Critique", "Élevé"]: overall_risk_score += 3
    elif legal_risk == "Moyen": overall_risk_score += 2
    else: overall_risk_score += 1
    if reputation_risk == "Critique": overall_risk_score += 3
    elif reputation_risk == "Élevé": overall_risk_score += 2
    elif reputation_risk == "Moyen": overall_risk_score += 1

    if overall_risk_score >= 10: overall_risk, overall_risk_color, risk_recommendation = "CRITIQUE", PDF_COLORS["critical"], "Action immédiate requise. Le risque d'incident majeur est imminent."
    elif overall_risk_score >= 7: overall_risk, overall_risk_color, risk_recommendation = "ÉLEVÉ", PDF_COLORS["high"], "Action urgente requise dans les 7 jours. Risque significatif d'impact business."
    elif overall_risk_score >= 4: overall_risk, overall_risk_color, risk_recommendation = "MOYEN", PDF_COLORS["medium"], "Action recommandée dans les 30 jours. Risque modéré d'impact."
    else: overall_risk, overall_risk_color, risk_recommendation = "FAIBLE", PDF_COLORS["safe"], "Surveillance continue. Risque acceptable avec monitoring."

    risk_summary_box = Table([[Paragraph(f"<b>Risque Global: {overall_risk}</b>", ParagraphStyle('OverallRiskStyle', parent=body_bold, textColor=overall_risk_color, fontSize=14))]], colWidths=[7.5*inch])
    risk_summary_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 16), ('LINELEFT', (0,0), (-1,-1), 6, overall_risk_color),
    ]))
    story.append(risk_summary_box)
    story.append(Spacer(1, 15))
    story.append(Paragraph(f"<b>Recommandation:</b> {risk_recommendation}", body_style))
    story.append(PageBreak())

    # Overall Grade
    story.append(Paragraph("NOTE DE SÉCURITÉ GLOBALE ET PAR DOMAINE", h1_style))
    avg_score = sum(domain_scores.values()) / len(domain_scores)
    if avg_score >= 90: overall_grade, grade_color, grade_description = "A", PDF_COLORS["safe"], "Excellent - Posture de sécurité robuste"
    elif avg_score >= 80: overall_grade, grade_color, grade_description = "B", PDF_COLORS["medium"], "Bon - Posture de sécurité solide avec améliorations mineures"
    elif avg_score >= 70: overall_grade, grade_color, grade_description = "C", PDF_COLORS["high"], "Moyen - Posture de sécurité acceptable nécessitant des améliorations"
    elif avg_score >= 60: overall_grade, grade_color, grade_description = "D", PDF_COLORS["high"], "Faible - Posture de sécurité nécessitant des actions significatives"
    else: overall_grade, grade_color, grade_description = "F", PDF_COLORS["critical"], "Critique - Posture de sécurité inacceptable, action immédiate requise"

    grade_box = Table([[Paragraph(f"<b>NOTE GLOBALE: {overall_grade}</b>", ParagraphStyle('GradeStyle', parent=body_bold, textColor=grade_color, fontSize=24))]], colWidths=[7.5*inch])
    grade_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 24), ('LINELEFT', (0,0), (-1,-1), 8, grade_color), ('LINERIGHT', (0,0), (-1,-1), 8, grade_color),
    ]))
    story.append(grade_box)
    story.append(Spacer(1, 15))
    story.append(Paragraph(grade_description, ParagraphStyle('GradeDescriptionStyle', parent=body_style, fontSize=12, alignment=1)))
    story.append(Spacer(1, 20))

    domain_data = [[Paragraph("<b>Domaine de Sécurité</b>", meta_label_style), Paragraph("<b>Score</b>", meta_label_style), Paragraph("<b>Évaluation</b>", meta_label_style)]]
    for domain, score in domain_scores.items():
        if score >= 80: evaluation, eval_color = "Excellent", PDF_COLORS["safe"]
        elif score >= 60: evaluation, eval_color = "Bon", PDF_COLORS["medium"]
        elif score >= 40: evaluation, eval_color = "Moyen", PDF_COLORS["high"]
        else: evaluation, eval_color = "Critique", PDF_COLORS["critical"]
        score_color = PDF_COLORS["safe"] if score >= 80 else (PDF_COLORS["medium"] if score >= 60 else PDF_COLORS["high"] if score >= 40 else PDF_COLORS["critical"])
        domain_data.append([
            Paragraph(domain, body_style), Paragraph(f"<b color='{score_color.hexval()}'>{score}/100</b>", body_bold),
            Paragraph(f"<b color='{eval_color.hexval()}'>{evaluation}</b>", body_bold)
        ])
    domain_table = Table(domain_data, colWidths=[3*inch, 1.5*inch, 3*inch])
    domain_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 10),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]), ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(domain_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("TOP 5 ACTIONS À EFFECTUER IMMÉDIATEMENT", h2_style))
    top_actions = []
    crit_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "critical"]
    for v in crit_vulns[:3]:
        top_actions.append(f"Corriger: {v.get('name', 'Unknown')} (CRITICAL)")
    cred_vulns = [v for v in all_vulns if v.get("source") == "credential_test"]
    for v in cred_vulns[:2]:
        top_actions.append(f"Changer identifiants par défaut sur {v.get('host_ip', 'Unknown')}")
    high_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "high"]
    for v in high_vulns[:5 - len(top_actions)]:
        top_actions.append(f"Corriger: {v.get('name', 'Unknown')} (HIGH)")
    for i, action in enumerate(top_actions, 1):
        action_box = Table([[Paragraph(f"<b>{i}. {action}</b>", body_style)]], colWidths=[7.5*inch])
        action_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 10),
            ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["critical"]),
        ]))
        story.append(action_box)
        story.append(Spacer(1, 8))
    story.append(PageBreak())

    # Host Details
    story.append(Paragraph("DÉTAIL TECHNIQUE PAR MACHINE", h1_style))
    for h in hosts:
        host_elements = []
        host_title = f"{h['ip']} - {h['hostname']} - OS: {h['os']}"
        host_elements.append(Paragraph(host_title, h2_style))
        host_info_data = [
            [Paragraph("<b>Adresse MAC</b>", meta_label_style), Paragraph(h.get('mac_address', 'Unknown'), mono_style),
             Paragraph("<b>Services</b>", meta_label_style), Paragraph(str(len(h['services'])), body_bold),
             Paragraph("<b>Vulnérabilités</b>", meta_label_style), Paragraph(str(len(h['vulnerabilities'])), body_bold)]
        ]
        host_info_table = Table(host_info_data, colWidths=[1.5*inch, 2.5*inch, 1.5*inch, 1*inch, 1.5*inch, 1*inch])
        host_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        host_elements.append(host_info_table)
        host_elements.append(Spacer(1, 10))
        host_elements.append(Paragraph(build_host_methodology_line(h), methodology_style))

        if h["services"]:
            host_elements.append(Paragraph("<b>État des Ports</b>", h3_style))
            host_elements.append(build_port_status_table(h, mono_style, meta_label_style, body_style, body_bold))
            host_elements.append(Spacer(1, 12))

        evidence_items = h.get("evidence", [])
        web_screenshots = [e for e in evidence_items if e.get("type") == "web_screenshot"]
        auth_screenshots = [e for e in evidence_items if e.get("type") == "auth_screenshot"]
        text_evidences = [e for e in evidence_items if e.get("type") == "text"]
        command_evidences = [e for e in evidence_items if e.get("type") == "command"]
        used_evidence_ids = set()

        def _render_evidence_block(ev, icon, label_color, label_bg):
            blocks = []
            ev_label = ev.get("label", "Preuve")
            label_box = Table(
                [[Paragraph(f"<b>{icon} {ev_label}</b>",
                    ParagraphStyle('EvLabel', parent=body_style, textColor=label_color, fontSize=9))]],
                colWidths=[7.5*inch]
            )
            label_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), label_bg), ('PADDING', (0, 0), (-1, -1), 6),
                ('LINELEFT', (0, 0), (-1, -1), 3, label_color),
            ]))
            blocks.append(label_box)
            
            if ev.get("type") in ("web_screenshot", "auth_screenshot"):
                ev_path = ev.get("path")
                if ev_path and os.path.exists(ev_path):
                    try:
                        img = Image(ev_path, width=6.5*inch, height=3.5*inch)
                        img.hAlign = 'LEFT'
                        blocks.append(img)
                    except Exception:
                        pass
            elif ev.get("type") == "text":
                ev_content = ev.get("content", "")
                if ev_content:
                    # TRUNCATION FOR TEXT EVIDENCE
                    lines = ev_content.split('\n')
                    truncated_lines = []
                    max_lines = 30
                    max_chars = 90
                    for line in lines[:max_lines]:
                        if len(line) > max_chars:
                            truncated_lines.append(line[:max_chars-3] + "...")
                        else:
                            truncated_lines.append(line)
                    ev_content = '\n'.join(truncated_lines)
                    if len(lines) > max_lines:
                        ev_content += f"\n\n[... {len(lines) - max_lines} additional lines truncated ...]"

                    terminal_box = Table(
                        [[Paragraph(ev_content.replace('\n', '<br/>'),
                            ParagraphStyle('TerminalStyle', parent=mono_style,
                                backColor=colors.HexColor('#1E293B'), textColor=colors.HexColor('#86EFAC'),
                                fontSize=8, leading=12))]],
                        colWidths=[7.5*inch]
                    )
                    terminal_box.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1E293B')), ('PADDING', (0, 0), (-1, -1), 10),
                    ]))
                    blocks.append(terminal_box)
            elif ev.get("type") == "command":
                cmd_text = f"$ {ev.get('cmd', '')}\n\n{ev.get('output', '')}"
                # STRICT TRUNCATION FOR COMMAND EVIDENCE
                lines = cmd_text.split('\n')
                truncated_lines = []
                max_lines = 25
                max_chars_per_line = 90
                for line in lines[:max_lines]:
                    if len(line) > max_chars_per_line:
                        truncated_lines.append(line[:max_chars_per_line-3] + "...")
                    else:
                        truncated_lines.append(line)
                cmd_text = '\n'.join(truncated_lines)
                if len(lines) > max_lines:
                    cmd_text += f"\n\n[... {len(lines) - max_lines} additional lines truncated ...]"
                    
                terminal_box = Table(
                    [[Paragraph(cmd_text.replace('\n', '<br/>'),
                        ParagraphStyle('TerminalCmd', parent=mono_style,
                            backColor=colors.HexColor('#0F172A'), textColor=colors.HexColor('#94A3B8'),
                            fontSize=7.5, leading=11))]],
                    colWidths=[7.5*inch]
                )
                terminal_box.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0F172A')), ('PADDING', (0, 0), (-1, -1), 10),
                ]))
                blocks.append(terminal_box)

            if ev.get("type") == "web_screenshot":
                caption = f"Capture montrant l'état de la page web au moment du scan ({ev.get('label', '')})."
            elif ev.get("type") == "auth_screenshot":
                user = ev.get("username", "un identifiant par défaut")
                caption = f"Capture prise après authentification réussie avec {user}, montrant l'accès obtenu."
            elif ev.get("type") == "command":
                ts = ev.get("timestamp", "")
                caption = f"Commande réelle exécutée automatiquement le {ts} par le moteur d'audit — sortie non modifiée."
            else:
                ts = ev.get("timestamp", "")
                caption = f"Sortie de session réelle capturée le {ts} avec l'identifiant {ev.get('username', 'testé')}."
            blocks.append(Paragraph(caption, caption_style))
            blocks.append(Spacer(1, 6))
            return blocks

        vulns = h.get("vulnerabilities", [])
        meaningful = [v for v in vulns if v.get("severity", "info").lower() != "info"]
        info_only = [v for v in vulns if v.get("severity", "info").lower() == "info"]
        
        if meaningful:
            host_elements.append(Paragraph("<b>Constats</b>", h3_style))
            for v in meaningful:
                sev = v.get("severity", "info")
                sev_color = get_severity_color(sev)
                bg_tint = get_severity_bg_tint(sev)
                finding_header = Table(
                    [[Paragraph(f"<b>{v.get('name', 'Vulnérabilité')}</b> "
                                f"<font color='{sev_color.hexval()}'><b>[{sev.upper()}]</b></font>"
                                + (f"  CVE: {v.get('cve_id')}" if v.get('cve_id') else ""),
                                body_bold)]],
                    colWidths=[7.5*inch]
                )
                finding_header.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), bg_tint), ('PADDING', (0, 0), (-1, -1), 8),
                    ('LINELEFT', (0, 0), (-1, -1), 4, sev_color),
                ]))
                host_elements.append(finding_header)

                if v.get("source") == "credential_test":
                    match = next((e for e in command_evidences + auth_screenshots + text_evidences
                                  if id(e) not in used_evidence_ids), None)
                    if match:
                        used_evidence_ids.add(id(match))
                        if match.get("type") == "command":
                            icon, color, bg = ("💻", colors.HexColor('#0F172A'), colors.HexColor('#F1F5F9'))
                        elif match.get("type") == "auth_screenshot":
                            icon, color, bg = ("🔑", PDF_COLORS['critical'], PDF_COLORS['bg_critical_tint'])
                        else:
                            icon, color, bg = ("🖥", colors.HexColor('#92400E'), colors.HexColor('#FEF3C7'))
                        host_elements.extend(_render_evidence_block(match, icon, color, bg))

                impact_text = v.get("description") or "Impact non documenté pour ce constat."
                host_elements.append(Paragraph(f"<b>Impact :</b> {impact_text[:400]}", body_style))
                host_elements.append(Spacer(1, 6))

                meta_parts = []
                if v.get("cve_id"): meta_parts.append(f"<b>CVE :</b> {v['cve_id']}")
                if v.get("cvss_score"): meta_parts.append(f"<b>CVSS :</b> {v['cvss_score']:.1f}")
                mitre = get_mitre_mapping(v.get("name", ""))
                if mitre["mitre_techniques"]: meta_parts.append(f"<b>MITRE :</b> {mitre['mitre_techniques'][0]}")
                if mitre["cwe_ids"]: meta_parts.append(f"<b>CWE :</b> {mitre['cwe_ids'][0]}")
                if v.get("cve_id"):
                    nvd_url = f"https://nvd.nist.gov/vuln/detail/{v['cve_id']}"
                    meta_parts.append(f"<b>NVD :</b> <a href='{nvd_url}'>{nvd_url}</a>")
                if meta_parts:
                    host_elements.append(Paragraph(" | ".join(meta_parts), 
                        ParagraphStyle('VulnMeta', parent=mono_style, fontSize=8, 
                                       textColor=PDF_COLORS["text_muted"], spaceAfter=6)))
                host_elements.append(Spacer(1, 4))

        if info_only:
            host_elements.append(Paragraph(
                f"<i>{len(info_only)} constat(s) de niveau INFO supplémentaire(s) regroupé(s) "
                f"(détails informatifs sans impact de sécurité direct, disponibles en annexe).</i>",
                caption_style
            ))
            host_elements.append(Spacer(1, 8))

        leftover_web = [e for e in web_screenshots if id(e) not in used_evidence_ids]
        if leftover_web:
            host_elements.append(Paragraph("<b>Captures Web Complémentaires</b>", h3_style))
            for ev in leftover_web:
                host_elements.extend(_render_evidence_block(ev, "📷", PDF_COLORS['primary'], PDF_COLORS['bg_light']))

        leftover_auth = [e for e in auth_screenshots + text_evidences + command_evidences if id(e) not in used_evidence_ids]
        if leftover_auth:
            host_elements.append(Paragraph("<b>Preuves d'Accès Complémentaires</b>", h3_style))
            for ev in leftover_auth:
                if ev.get("type") == "command":
                    icon, color, bg = ("💻", colors.HexColor('#0F172A'), colors.HexColor('#F1F5F9'))
                elif ev.get("type") == "auth_screenshot":
                    icon, color, bg = ("🔑", PDF_COLORS['critical'], PDF_COLORS['bg_critical_tint'])
                else:
                    icon, color, bg = ("🖥", colors.HexColor('#92400E'), colors.HexColor('#FEF3C7'))
                host_elements.extend(_render_evidence_block(ev, icon, color, bg))

        cred_related = [v for v in vulns if v.get("source") == "credential_test"]
        if h.get("services") and not cred_related and not auth_screenshots and not text_evidences and not command_evidences:
            host_elements.append(Paragraph(
                "<i>Aucun identifiant par défaut n'a fonctionné sur cet hôte.</i>", caption_style
            ))

        top_vulns_for_host = sorted(
            meaningful, 
            key=lambda v: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                v.get("severity", "low").lower(), 4)
        )[:3]
        if top_vulns_for_host:
            remediation_lines = []
            for i, v in enumerate(top_vulns_for_host, 1):
                sev = v.get("severity", "").upper()
                name = v.get("name", "Vulnérabilité inconnue")
                remediation_lines.append(f"{i}. [{sev}] {name} — appliquer le correctif ou isoler le service.")
            remedbox = Table([[Paragraph(
                "<b>🔧 Actions prioritaires sur cet hôte :</b><br/>" + "<br/>".join(remediation_lines),
                body_style
            )]], colWidths=[7.5*inch])
            remedbox.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), PDF_COLORS["bg_low_tint"]),
                ('PADDING', (0, 0), (-1, -1), 12), ('LINELEFT', (0, 0), (-1, -1), 4, PDF_COLORS["low"]),
            ]))
            host_elements.append(remedbox)
            host_elements.append(Spacer(1, 8))

        attack_path = None
        host_attack_paths = (analysis or {}).get("host_attack_paths", {})
        if isinstance(host_attack_paths, dict):
            attack_path = host_attack_paths.get(h["ip"])
        if not attack_path:
            attack_path = build_host_attack_path(h)
        if attack_path:
            host_elements.append(Spacer(1, 6))
            attack_box = Table([[Paragraph(f"<b>⚔ Chemin d'Attaque Possible :</b> {attack_path}", body_style)]],
                                colWidths=[7.5*inch])
            attack_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), PDF_COLORS["bg_critical_tint"]),
                ('PADDING', (0, 0), (-1, -1), 12), ('LINELEFT', (0, 0), (-1, -1), 5, PDF_COLORS["critical"]),
            ]))
            host_elements.append(attack_box)
        story.append(KeepTogether(host_elements))
        story.append(Spacer(1, 25))
    story.append(PageBreak())

    # Recommendations
    story.append(Paragraph("RECOMMANDATIONS STRATÉGIQUES ET PLAN D'ACTION", h1_style))
    recs = analysis.get("strategic_recommendations", [])
    if not recs:
        story.append(Paragraph("Aucune recommandation stratégique requise.", body_style))
    else:
        sorted_recs = sorted(recs, key=lambda x: x.get('priority', 999))
        for idx, r in enumerate(sorted_recs, 1):
            priority = r.get('priority', idx)
            theme = r.get('theme', 'Sans thème')
            advice = r.get('advice', 'Aucun conseil disponible')
            if priority == 1: prio_color, prio_label = PDF_COLORS["critical"], "CRITIQUE"
            elif priority <= 3: prio_color, prio_label = PDF_COLORS["high"], "HAUTE"
            elif priority <= 5: prio_color, prio_label = PDF_COLORS["medium"], "MOYENNE"
            else: prio_color, prio_label = PDF_COLORS["low"], "FAIBLE"

            r_header = Table(
                [[Paragraph(f"<b>#{priority} — {theme.upper()}</b> "
                            f"<font color='{prio_color.hexval()}'>[{prio_label}]</font>",
                            h3_style)]],
                colWidths=[7.5*inch]
            )
            r_header.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 10),
                ('LINELEFT', (0,0), (-1,-1), 6, prio_color), ('LINETOP', (0,0), (-1,-1), 2, prio_color),
            ]))
            story.append(r_header)

            import re as _re
            def _extract(label, text):
                pattern = rf'\*\*{_re.escape(label)}\*\*[:\s]*(.*?)(?=\*\*[A-ZÉà-ÿ]|$)'
                m = _re.search(pattern, text, _re.DOTALL | _re.IGNORECASE)
                return m.group(1).strip() if m else None
            what = _extract('Ce que cela signifie', advice)
            where = _extract('Où', advice)
            how_fix = _extract('Comment corriger', advice)
            how_verify = _extract('Comment vérifier', advice)

            if any([what, where, how_fix, how_verify]):
                if what:
                    box = Table([[Paragraph(f"<b>💡 Ce que cela signifie :</b><br/>{what}", body_style)]], colWidths=[7.5*inch])
                    box.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS['bg_light']), ('PADDING', (0,0), (-1,-1), 12),
                        ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS['primary']),
                    ]))
                    story.append(box)
                    story.append(Spacer(1, 4))
                if where:
                    box = Table([[Paragraph(f"<b>📍 Où :</b> {where}", body_style)]], colWidths=[7.5*inch])
                    box.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F0FDF4')), ('PADDING', (0,0), (-1,-1), 10),
                        ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS['safe']),
                    ]))
                    story.append(box)
                    story.append(Spacer(1, 4))
                if how_fix:
                    steps = [s.strip() for s in how_fix.split('\n') if s.strip()]
                    step_content = '<br/>'.join(steps)
                    box = Table([[Paragraph(f"<b>🔧 Comment corriger :</b><br/>{step_content}", body_style)]], colWidths=[7.5*inch])
                    box.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS['bg_high_tint']), ('PADDING', (0,0), (-1,-1), 12),
                        ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS['high']),
                    ]))
                    story.append(box)
                    story.append(Spacer(1, 4))
                if how_verify:
                    box = Table([[Paragraph(f"<b>✅ Comment vérifier :</b><br/>{how_verify}", body_style)]], colWidths=[7.5*inch])
                    box.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F0FDF4')), ('PADDING', (0,0), (-1,-1), 10),
                        ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS['safe']),
                    ]))
                    story.append(box)
            else:
                r_table = Table([[Paragraph(advice, body_style)]], colWidths=[7.5*inch])
                r_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 12),
                    ('LINELEFT', (0,0), (-1,-1), 4, prio_color), ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ]))
                story.append(r_table)
            story.append(Spacer(1, 15))
    story.append(Spacer(1, 25))

    story.append(Paragraph("VERDICT GLOBAL DE L'AUDIT", h2_style))
    verdict_text = analysis.get("overall_verdict", "Non disponible.")
    verdict_bg = PDF_COLORS["bg_safe_tint"]
    verdict_border = PDF_COLORS["safe"]
    if "critique" in verdict_text.lower() or "urgence" in verdict_text.lower():
        verdict_bg = PDF_COLORS["bg_critical_tint"]
        verdict_border = PDF_COLORS["critical"]
    elif "acceptable" in verdict_text.lower() or "attention" in verdict_text.lower():
        verdict_bg = PDF_COLORS["bg_high_tint"]
        verdict_border = PDF_COLORS["high"]
    verdict_table = Table([[Paragraph(f"<b>Posture de Sécurité Globale :</b> {verdict_text}", body_style)]], colWidths=[7.5*inch])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), verdict_bg), ('PADDING', (0,0), (-1,-1), 20),
        ('LINELEFT', (0,0), (-1,-1), 8, verdict_border), ('LINERIGHT', (0,0), (-1,-1), 8, verdict_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 30))

    if all_vulns:
        story.append(Paragraph("ANNEXE : RÉCAPITULATIF COMPLET DES VULNÉRABILITÉS", h2_style))
        all_vuln_data = [[
            Paragraph("<b>Hote</b>", meta_label_style), Paragraph("<b>Nom</b>", meta_label_style),
            Paragraph("<b>Severite</b>", meta_label_style), Paragraph("<b>CVE</b>", meta_label_style),
            Paragraph("<b>CVSS</b>", meta_label_style)
        ]]
        for v in all_vulns:
            sev_color = get_severity_color(v["severity"]).hexval()
            cve_text = v.get("cve_id") or "—"
            cvss_val = v.get("cvss_score")
            cvss_str = f"{cvss_val:.1f}" if cvss_val is not None else "—"
            host_ip = v.get("host_ip", "Unknown")
            all_vuln_data.append([
                Paragraph(host_ip, mono_style),
                Paragraph(v["name"][:40] + "..." if len(v["name"]) > 40 else v["name"], body_style),
                Paragraph(f"<b color='{sev_color}'>{v['severity'].upper()}</b>", body_style),
                Paragraph(cve_text[:15] + "..." if len(cve_text) > 15 else cve_text, mono_style),
                Paragraph(cvss_str, body_bold)
            ])
        all_vuln_table = Table(all_vuln_data, colWidths=[1.2*inch, 2.5*inch, 1.2*inch, 1.3*inch, 1.3*inch])
        all_vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]), ('PADDING', (0,0), (-1,-1), 6),
            ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(all_vuln_table)
        story.append(Spacer(1, 20))

    story.append(Paragraph("Fin du rapport - Document généré automatiquement par Audit Réseau IA", ParagraphStyle('FinalFooter', parent=body_style, textColor=PDF_COLORS["text_muted"], alignment=1, fontSize=8)))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes