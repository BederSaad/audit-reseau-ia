import io
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

# Helper to map severity name to HexColor
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

# Helper to map timeframe to HexColor
def get_timeframe_color(tf):
    tf = str(tf).lower()
    if "immédiat" in tf: return PDF_COLORS["critical"]
    if "semaine" in tf: return PDF_COLORS["high"]
    if "mois" in tf: return PDF_COLORS["medium"]
    return PDF_COLORS["low"]

# ── Matplotlib Chart Generators ────────────────────────────────────────────────
def make_health_gauge(score):
    fig, ax = plt.subplots(figsize=(3, 2), subplot_kw={'projection': 'polar'})
    # Colors based on score
    color = "#16A34A" if score >= 80 else ("#CA8A04" if score >= 50 else "#DC2626")
    
    # Draw arc
    ax.barh(0.5, 3.14 * (score / 100.0), left=0, height=0.3, color=color, align='center')
    ax.barh(0.5, 3.14, left=0, height=0.3, color='#E2E8F0', align='center', zorder=0)
    
    ax.set_ylim(-1, 1)
    ax.set_theta_zero_location('W')
    ax.set_theta_direction(-1)
    ax.set_thetagrids([])
    ax.set_rgrids([])
    ax.spines['polar'].set_visible(False)
    
    # Text in center
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
        "critical": "#DC2626",
        "high": "#EA580C",
        "medium": "#CA8A04",
        "low": "#2563EB",
        "info": "#64748B",
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
    # Sort hosts by severity count/risk weight
    # Weight: critical=10, high=6, medium=3, low=1, info=0
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
    from services.audit_analysis import fetch_audit_analysis, generate_audit_analysis
    
    # Fetch Data
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
        
    # Format hosts for context
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
        
    # Fetch/Generate AI Analysis
    analysis = await fetch_audit_analysis(scan_id)
    if not analysis:
        analysis = await generate_audit_analysis(scan_id)
        # We might not persist it immediately here, but we will use it for report.
        
    all_vulns = [v for h in hosts for v in h["vulnerabilities"]]
    
    # Deduplicate vulnerabilities by name + severity
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
    
    # Calculate additional statistics
    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in all_vulns:
        sev = v.get("severity", "info").lower()
        if sev in vuln_counts:
            vuln_counts[sev] += 1
    
    total_services = sum(len(h["services"]) for h in hosts)
    credential_vulns = [v for v in all_vulns if v.get("source") == "credential_test"]
    
    # Calculate host security scores
    def calculate_host_score(host):
        base_score = 100
        vulns = host["vulnerabilities"]
        
        # Deduct points for vulnerabilities
        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev == "critical":
                base_score -= 25
            elif sev == "high":
                base_score -= 15
            elif sev == "medium":
                base_score -= 8
            elif sev == "low":
                base_score -= 3
        
        # Deduct for credential vulnerabilities
        cred_vulns = [v for v in vulns if v.get("source") == "credential_test"]
        base_score -= len(cred_vulns) * 20
        
        # Deduct for exposed services (more services = more attack surface)
        service_count = len(host["services"])
        base_score -= min(service_count * 2, 20)
        
        # Ensure score is between 0 and 100
        return max(0, min(100, base_score))
    
    # Add security scores to hosts and sort by score
    for h in hosts:
        h["security_score"] = calculate_host_score(h)
    hosts_sorted = sorted(hosts, key=lambda x: x["security_score"])
    
    # Generate automatic remediation commands for common services
    def get_remediation_commands(vuln_name, service_name=None):
        commands = []
        vuln_lower = vuln_name.lower()
        
        if "ftp" in vuln_lower or service_name == "ftp":
            commands.extend([
                "Disable anonymous FTP access: Edit /etc/vsftpd.conf, set anonymous_enable=NO",
                "Restrict FTP to specific users: Add userlist_enable=YES and userlist_file=/etc/vsftpd.userlist",
                "Use SFTP instead of FTP for encrypted file transfers",
                "Block FTP port 21 in firewall if not required"
            ])
        elif "ssh" in vuln_lower or service_name == "ssh":
            commands.extend([
                "Disable weak ciphers: Edit /etc/ssh/sshd_config, set Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
                "Enable key-based auth: Set PasswordAuthentication no in sshd_config",
                "Disable root login: Set PermitRootLogin no in sshd_config",
                "Restart SSH: systemctl restart sshd"
            ])
        elif "postgresql" in vuln_lower or service_name == "postgresql":
            commands.extend([
                "Remove empty passwords: ALTER USER postgres WITH PASSWORD 'strong_password'",
                "Restrict remote access: Edit pg_hba.conf, allow only specific IPs",
                "Enable SSL: Set ssl=on in postgresql.conf",
                "Update PostgreSQL to latest version"
            ])
        elif "mysql" in vuln_lower or service_name == "mysql":
            commands.extend([
                "Remove empty passwords: ALTER USER 'root'@'localhost' IDENTIFIED BY 'strong_password'",
                "Restrict remote access: Bind to 127.0.0.1 in my.cnf",
                "Enable SSL: Add require_ssl in my.cnf",
                "Update MySQL to latest version"
            ])
        elif "http" in vuln_lower or service_name in ["http", "https", "apache", "nginx"]:
            commands.extend([
                "Disable HTTP methods: Configure server to allow only GET, POST, HEAD",
                "Enable HTTPS/TLS: Install SSL certificate and redirect HTTP to HTTPS",
                "Install security headers: X-Frame-Options, X-Content-Type-Options, CSP",
                "Update web server to latest version"
            ])
        elif "smb" in vuln_lower or service_name == "smb":
            commands.extend([
                "Disable SMBv1: Set SMB1=0 in Windows registry or /etc/samba/smb.conf",
                "Require SMB signing: Set server signing = required",
                "Restrict SMB to specific networks: Use firewall rules",
                "Update Samba to latest version"
            ])
        elif "rdp" in vuln_lower or service_name == "rdp":
            commands.extend([
                "Enable Network Level Authentication (NLA)",
                "Restrict RDP to specific users via Group Policy",
                "Block RDP port 3389 in firewall if not required",
                "Use VPN for remote access instead of direct RDP"
            ])
        else:
            commands.extend([
                "Update the affected service to the latest version",
                "Check vendor advisories for security patches",
                "Restrict network access using firewall rules",
                "Monitor for suspicious activity"
            ])
        
        return commands
    
    # Map vulnerabilities to MITRE ATT&CK and CWE
    def get_mitre_mapping(vuln_name, service_name=None):
        vuln_lower = vuln_name.lower()
        
        # MITRE ATT&CK mappings
        mitre_techniques = []
        
        if "credential" in vuln_lower or "password" in vuln_lower:
            mitre_techniques.extend([
                "T1078 - Valid Accounts",
                "T1110 - Brute Force",
                "T1078.004 - Cloud Account"
            ])
        if "ssh" in vuln_lower or service_name == "ssh":
            mitre_techniques.extend([
                "T1021.004 - Remote Services: SSH",
                "T1562.001 - Impair Defenses: Disable or Modify Tools"
            ])
        if "ftp" in vuln_lower or service_name == "ftp":
            mitre_techniques.extend([
                "T1078.003 - Local Accounts",
                "T1110.003 - Password Spraying"
            ])
        if "http" in vuln_lower or service_name in ["http", "https", "apache", "nginx"]:
            mitre_techniques.extend([
                "T1190 - Exploit Public-Facing Application",
                "T1071.001 - Application Layer Protocol: Web Protocols"
            ])
        if "smb" in vuln_lower or service_name == "smb":
            mitre_techniques.extend([
                "T1021.002 - Remote Services: SMB/Windows Admin Shares",
                "T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools"
            ])
        if "rdp" in vuln_lower or service_name == "rdp":
            mitre_techniques.extend([
                "T1021.001 - Remote Services: Remote Desktop Protocol",
                "T1566.002 - Phishing: Spearphishing Link"
            ])
        if "sql" in vuln_lower or service_name in ["mysql", "postgresql", "mssql"]:
            mitre_techniques.extend([
                "T1190 - Exploit Public-Facing Application",
                "T1055 - Process Injection"
            ])
        
        if not mitre_techniques:
            mitre_techniques.append("T1059 - Command and Scripting Interpreter")
        
        # CWE mappings
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
        
        return {
            "mitre_techniques": mitre_techniques[:3],  # Limit to top 3
            "cwe_ids": cwe_ids[:2]  # Limit to top 2
        }
    
    # Map vulnerabilities to compliance frameworks
    def get_compliance_mapping(vuln_name, service_name=None):
        vuln_lower = vuln_name.lower()
        
        compliance_map = {
            "ISO 27001": [],
            "NIST CSF": [],
            "CIS Controls": [],
            "OWASP Top 10": [],
            "MITRE D3FEND": []
        }
        
        # ISO 27001 mappings
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
        
        # NIST CSF mappings
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
        
        # CIS Controls mappings
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
        
        # OWASP Top 10 mappings
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
        
        # MITRE D3FEND mappings
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
    
    # Setup document
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.5*inch, rightMargin=0.5*inch,
        topMargin=0.5*inch, bottomMargin=0.5*inch
    )
    
    # Setup Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=32,
        leading=38,
        textColor=colors.white,
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#E2E8F0"),
        spaceAfter=20
    )
    
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=PDF_COLORS["primary"],
        spaceBefore=20,
        spaceAfter=12,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=PDF_COLORS["text_dark"],
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    h3_style = ParagraphStyle(
        'SectionH3',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=PDF_COLORS["text_dark"],
        spaceBefore=10,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=PDF_COLORS["text_dark"],
        spaceAfter=8
    )
    
    body_bold = ParagraphStyle(
        'ReportBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    mono_style = ParagraphStyle(
        'ReportMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=9,
        leading=12,
        textColor=PDF_COLORS["text_dark"]
    )
    
    meta_label_style = ParagraphStyle(
        'MetaLabel',
        parent=body_style,
        fontName='Helvetica-Bold',
        textColor=PDF_COLORS["text_muted"],
        fontSize=9
    )
    
    bullet_style = ParagraphStyle(
        'BulletStyle',
        parent=body_style,
        leftIndent=20,
        spaceAfter=4
    )
    
    # ── Pre-calculate variables needed for executive summary ─────────────────────
    # Calculate vulnerability counts
    crit_count = len([v for v in all_vulns if v.get("severity", "").lower() == "critical"])
    high_count = len([v for v in all_vulns if v.get("severity", "").lower() == "high"])
    cred_count = len([v for v in all_vulns if v.get("source") == "credential_test"])
    
    # Calculate security domain scores (for overall grade)
    domain_scores = {
        "Patch Management": 100,
        "Network Security": 100,
        "Authentication": 100,
        "Access Control": 100,
        "Encryption": 100,
        "Monitoring": 100,
        "Hardening": 100,
        "Vulnerability Management": 100
    }
    
    # Deduct points based on vulnerabilities
    for v in all_vulns:
        vuln_lower = v.get("name", "").lower()
        sev = v.get("severity", "info").lower()
        
        deduction = 0
        if sev == "critical":
            deduction = 15
        elif sev == "high":
            deduction = 10
        elif sev == "medium":
            deduction = 5
        elif sev == "low":
            deduction = 2
        
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
    
    # Ensure scores are between 0 and 100
    for domain in domain_scores:
        domain_scores[domain] = max(0, min(100, domain_scores[domain]))
    
    story = []
    
    # ── Page 1: Cover Page ──────────────────────────────────────────────────────
    # Header
    cover_header = [
        [Paragraph("RAPPORT D'AUDIT DE SÉCURITÉ RÉSEAU", title_style)],
        [Paragraph("Analyse complète des vulnérabilités et recommandations de remédiation", subtitle_style)]
    ]
    cover_header_table = Table(cover_header, colWidths=[7.5*inch])
    cover_header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["primary"]),
        ('PADDING', (0,0), (-1,-1), 36),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(cover_header_table)
    story.append(Spacer(1, 20))
    
    # Scan Metadata Table
    metadata_data = [
        [Paragraph("<b>Informations du Scan</b>", h2_style)],
        [
            Paragraph("<b>Cible :</b>", meta_label_style), Paragraph(scan.target, body_style),
            Paragraph("<b>ID Scan :</b>", meta_label_style), Paragraph(scan.id[:8] + "...", mono_style)
        ],
        [
            Paragraph("<b>Date de début :</b>", meta_label_style), Paragraph(scan.started_at.strftime('%d/%m/%Y %H:%M') if scan.started_at else "N/A", body_style),
            Paragraph("<b>Date de fin :</b>", meta_label_style), Paragraph(scan.finished_at.strftime('%d/%m/%Y %H:%M') if scan.finished_at else "N/A", body_style)
        ],
        [
            Paragraph("<b>Statut :</b>", meta_label_style), Paragraph(scan.status.upper(), body_bold),
            Paragraph("<b>Durée :</b>", meta_label_style), Paragraph(f"{(scan.finished_at - scan.started_at).total_seconds():.0f}s" if scan.finished_at and scan.started_at else "N/A", body_style)
        ]
    ]
    metadata_table = Table(metadata_data, colWidths=[1.5*inch, 2.25*inch, 1.5*inch, 2.25*inch])
    metadata_table.setStyle(TableStyle([
        ('SPAN', (0,0), (-1,0)),
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,1), (-1,1), 1, colors.HexColor("#E2E8F0")),
        ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 20))
    
    # Health Score Overview
    story.append(Paragraph("SCORE GLOBAL DE SANTÉ DU RÉSEAU", h2_style))
    health_data = [
        [
            Paragraph("<b>Score de Santé</b>", meta_label_style),
            Paragraph("<b>Appareils</b>", meta_label_style),
            Paragraph("<b>Services</b>", meta_label_style),
            Paragraph("<b>Vulnérabilités</b>", meta_label_style)
        ],
        [
            Paragraph(f"<font size=24 color='{PDF_COLORS['primary'].hexval()}'><b>{int(health_score)}/100</b></font>", body_bold),
            Paragraph(f"<font size=18><b>{len(hosts)}</b></font>", body_bold),
            Paragraph(f"<font size=18><b>{total_services}</b></font>", body_bold),
            Paragraph(f"<font size=18 color='{PDF_COLORS['critical'].hexval()}'><b>{len(all_vulns)}</b></font>", body_bold)
        ]
    ]
    health_table = Table(health_data, colWidths=[1.875*inch]*4)
    health_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 16),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(health_table)
    story.append(Spacer(1, 20))
    
    # Severity Breakdown
    story.append(Paragraph("RÉPARTITION PAR SÉVÉRITÉ", h3_style))
    sev_data = [
        [Paragraph("<b>Critique</b>", meta_label_style), Paragraph("<b>Élevé</b>", meta_label_style), Paragraph("<b>Moyen</b>", meta_label_style), Paragraph("<b>Faible</b>", meta_label_style), Paragraph("<b>Info</b>", meta_label_style)],
        [
            Paragraph(f"<font size=16 color='{PDF_COLORS['critical'].hexval()}'><b>{vuln_counts['critical']}</b></font>", body_bold),
            Paragraph(f"<font size=16 color='{PDF_COLORS['high'].hexval()}'><b>{vuln_counts['high']}</b></font>", body_bold),
            Paragraph(f"<font size=16 color='{PDF_COLORS['medium'].hexval()}'><b>{vuln_counts['medium']}</b></font>", body_bold),
            Paragraph(f"<font size=16 color='{PDF_COLORS['low'].hexval()}'><b>{vuln_counts['low']}</b></font>", body_bold),
            Paragraph(f"<font size=16 color='{PDF_COLORS['info'].hexval()}'><b>{vuln_counts['info']}</b></font>", body_bold)
        ]
    ]
    sev_table = Table(sev_data, colWidths=[1.5*inch]*5)
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 12),
        ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 30))
    
    # Footer
    footer_data = [
        [Paragraph("CONFIDENTIEL — Usage interne uniquement | Rapport généré automatiquement par Audit Réseau IA", ParagraphStyle('FooterText', parent=body_style, textColor=PDF_COLORS["text_muted"], alignment=1, fontSize=8))]
    ]
    footer_table = Table(footer_data, colWidths=[7.5*inch])
    story.append(footer_table)
    story.append(PageBreak())
    
    # ── Executive Summary Page (Separate from Technical Section) ─────────────────────
    story.append(Paragraph("RÉSUMÉ EXÉCUTIF", h1_style))
    
    # Executive Summary Box for Managers
    exec_summary = analysis.get("executive_summary", "No summary available.")
    exec_box = Table([[Paragraph(exec_summary, body_style)]], colWidths=[7.5*inch])
    exec_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 20),
        ('LINELEFT', (0,0), (-1,-1), 8, PDF_COLORS["primary"]),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(exec_box)
    story.append(Spacer(1, 25))
    
    # Key Metrics for Executives
    story.append(Paragraph("MÉTRIQUES CLÉS POUR LA DIRECTION", h2_style))
    
    # Calculate overall grade for executives
    avg_score = sum(domain_scores.values()) / len(domain_scores)
    if avg_score >= 90:
        exec_grade = "A"
        exec_grade_color = PDF_COLORS["safe"]
    elif avg_score >= 80:
        exec_grade = "B"
        exec_grade_color = PDF_COLORS["medium"]
    elif avg_score >= 70:
        exec_grade = "C"
        exec_grade_color = PDF_COLORS["high"]
    elif avg_score >= 60:
        exec_grade = "D"
        exec_grade_color = PDF_COLORS["high"]
    else:
        exec_grade = "F"
        exec_grade_color = PDF_COLORS["critical"]
    
    # Risk level based on vulnerabilities
    if crit_count > 0 or cred_count > 0:
        risk_level = "CRITIQUE"
        risk_color = PDF_COLORS["critical"]
    elif high_count > 3:
        risk_level = "ÉLEVÉ"
        risk_color = PDF_COLORS["high"]
    elif high_count > 0:
        risk_level = "MODÉRÉ"
        risk_color = PDF_COLORS["medium"]
    else:
        risk_level = "FAIBLE"
        risk_color = PDF_COLORS["safe"]
    
    exec_metrics_data = [
        [Paragraph("<b>Métrique</b>", meta_label_style), Paragraph("<b>Valeur</b>", meta_label_style), Paragraph("<b>Métrique</b>", meta_label_style), Paragraph("<b>Valeur</b>", meta_label_style)],
        [
            Paragraph("Score de Sécurité", body_style),
            Paragraph(f"<b>{int(avg_score)}/100</b>", body_bold),
            Paragraph("Note Globale", body_style),
            Paragraph(f"<b color='{exec_grade_color.hexval()}'>{exec_grade}</b>", body_bold)
        ],
        [
            Paragraph("Niveau de Risque", body_style),
            Paragraph(f"<b color='{risk_color.hexval()}'>{risk_level}</b>", body_bold),
            Paragraph("Appareils Détectés", body_style),
            Paragraph(f"<b>{len(hosts)}</b>", body_bold)
        ],
        [
            Paragraph("Services Ouverts", body_style),
            Paragraph(f"<b>{total_services}</b>", body_bold),
            Paragraph("Vulnérabilités", body_style),
            Paragraph(f"<b>{len(all_vulns)}</b>", body_bold)
        ],
        [
            Paragraph("Vulnérabilités Critiques", body_style),
            Paragraph(f"<b color='{PDF_COLORS['critical'].hexval()}'>{crit_count}</b>", body_bold),
            Paragraph("Identifiants Validés", body_style),
            Paragraph(f"<b color='{PDF_COLORS['critical'].hexval()}'>{cred_count}</b>", body_bold)
        ]
    ]
    
    exec_metrics_table = Table(exec_metrics_data, colWidths=[2*inch, 1.75*inch, 2*inch, 1.75*inch])
    exec_metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 12),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(exec_metrics_table)
    story.append(Spacer(1, 25))
    
    # What Was Discovered
    story.append(Paragraph("CE QUI A ÉTÉ DÉCOUVERT", h2_style))
    
    discovered_text = f"""
    L'audit a identifié <b>{len(all_vulns)}</b> vulnérabilités sur <b>{len(hosts)}</b> appareils.
    Parmi celles-ci, <b color='{PDF_COLORS['critical'].hexval()}'>{crit_count}</b> sont critiques et <b color='{PDF_COLORS['high'].hexval()}'>{high_count}</b> sont élevées.
    <b>{cred_count}</b> identifiants par défaut ont été validés, permettant un accès direct aux systèmes.
    <b>{total_services}</b> services sont exposés sur le réseau, représentant une surface d'attaque significative.
    """
    story.append(Paragraph(discovered_text, body_style))
    story.append(Spacer(1, 20))
    
    # Why It Matters
    story.append(Paragraph("POURQUOI C'EST IMPORTANT", h2_style))
    
    why_matters_text = f"""
    Les vulnérabilités critiques peuvent permettre à des attaquants de prendre le contrôle complet des systèmes,
    d'exfiltrer des données sensibles, ou de perturber les opérations business.
    Les identifiants par défaut validés représentent un risque immédiat de compromission.
    Sans action corrective, le risque d'incident de sécurité est <b color='{risk_color.hexval()}'>{risk_level.lower()}</b>.
    """
    story.append(Paragraph(why_matters_text, body_style))
    story.append(Spacer(1, 20))
    
    # What Should Be Fixed First
    story.append(Paragraph("CE QUI DOIT ÊTRE CORRIGÉ EN PRIORITÉ", h2_style))
    
    priority_fixes = []
    if crit_count > 0:
        priority_fixes.append(f"1. Corriger les {crit_count} vulnérabilités critiques (risque immédiat)")
    if cred_count > 0:
        priority_fixes.append(f"2. Changer les {cred_count} identifiants par défaut validés")
    if high_count > 0:
        priority_fixes.append(f"3. Traiter les {high_count} vulnérabilités élevées")
    priority_fixes.append("4. Restreindre l'accès aux services non essentiels")
    priority_fixes.append("5. Mettre en place le monitoring de sécurité")
    
    for fix in priority_fixes:
        fix_box = Table([[Paragraph(fix, body_style)]], colWidths=[7.5*inch])
        fix_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
            ('PADDING', (0,0), (-1,-1), 10),
            ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["primary"]),
        ]))
        story.append(fix_box)
        story.append(Spacer(1, 8))
    
    story.append(Spacer(1, 20))
    
    # Overall Verdict
    overall_verdict = analysis.get("overall_verdict", "")
    if overall_verdict:
        verdict_box = Table([[Paragraph(f"<b>CONCLUSION GLOBALE:</b> {overall_verdict}", body_bold)]], colWidths=[7.5*inch])
        verdict_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_high_tint"]),
            ('PADDING', (0,0), (-1,-1), 16),
            ('LINELEFT', (0,0), (-1,-1), 6, PDF_COLORS["high"]),
        ]))
        story.append(verdict_box)
    
    story.append(Spacer(1, 30))
    
    # Page separator
    separator = Table([[Paragraph("— FIN DU RÉSUMÉ EXÉCUTIF — DÉTAILS TECHNIQUES SUIVANT —", ParagraphStyle('SeparatorStyle', parent=body_style, alignment=1, textColor=PDF_COLORS["text_muted"]))]], colWidths=[7.5*inch])
    story.append(separator)
    story.append(PageBreak())
    
    # ── Page 2: Executive Summary & Security Posture ───────────────────────────────
    story.append(Paragraph("EXECUTIVE SUMMARY", h1_style))
    
    # Security Score & Maturity
    security_score = analysis.get("security_score", health_score)
    maturity_level = analysis.get("maturity_level", "Unknown")
    
    score_maturity_data = [
        [Paragraph("<b>Security Score</b>", meta_label_style), Paragraph("<b>Maturity Level</b>", meta_label_style)],
        [
            Paragraph(f"<font size=20 color='{PDF_COLORS['primary'].hexval()}'><b>{security_score}/100</b></font>", body_bold),
            Paragraph(f"<b>{maturity_level}</b>", body_bold)
        ]
    ]
    score_maturity_table = Table(score_maturity_data, colWidths=[3.75*inch]*2)
    score_maturity_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 16),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(score_maturity_table)
    story.append(Spacer(1, 20))
    
    # Executive Summary Box
    exec_summary = analysis.get("executive_summary", "No summary available.")
    exec_box = Table([[Paragraph(exec_summary, body_style)]], colWidths=[7.5*inch])
    exec_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 16),
        ('LINELEFT', (0,0), (-1,-1), 6, PDF_COLORS["primary"]),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(exec_box)
    story.append(Spacer(1, 20))
    
    # Attack Vectors
    attack_vectors = analysis.get("attack_vectors", [])
    if attack_vectors:
        story.append(Paragraph("ATTACK VECTORS", h2_style))
        for av in attack_vectors:
            story.append(Paragraph(f"- {av}", bullet_style))
        story.append(Spacer(1, 15))
    
    # Business Impact
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
            ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
            ('PADDING', (0,0), (-1,-1), 10),
            ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")),
            ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(impact_table)
        story.append(Spacer(1, 15))
    
    # Likelihood of Compromise
    likelihood = analysis.get("likelihood_of_compromise", "Unknown")
    story.append(Paragraph("LIKELIHOOD OF COMPROMISE", h2_style))
    likelihood_color = PDF_COLORS["critical"] if likelihood == "Critical" else (PDF_COLORS["high"] if likelihood == "High" else PDF_COLORS["medium"])
    likelihood_style = ParagraphStyle('LikelihoodStyle', parent=body_bold, textColor=likelihood_color, fontSize=14)
    likelihood_box = Table([[Paragraph(f"<b>{likelihood}</b>", likelihood_style)]], colWidths=[7.5*inch])
    likelihood_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 12),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(likelihood_box)
    story.append(Spacer(1, 20))
    
    # Attacker Scenario
    attacker_scenario = analysis.get("attacker_scenario", "")
    if attacker_scenario:
        story.append(Paragraph("ATTACKER SCENARIO", h2_style))
        scenario_box = Table([[Paragraph(attacker_scenario, body_style)]], colWidths=[7.5*inch])
        scenario_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_critical_tint"]),
            ('PADDING', (0,0), (-1,-1), 16),
            ('LINELEFT', (0,0), (-1,-1), 6, PDF_COLORS["critical"]),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(scenario_box)
        story.append(Spacer(1, 20))
    
    # Security Strengths & Weaknesses
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
            ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
            ('PADDING', (0,0), (-1,-1), 8),
            ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(swot_table)
        story.append(Spacer(1, 20))
    
    # Global Risk Conclusion
    global_risk = analysis.get("global_risk_conclusion", "")
    if global_risk:
        story.append(Paragraph("GLOBAL RISK CONCLUSION", h2_style))
        risk_box = Table([[Paragraph(global_risk, body_style)]], colWidths=[7.5*inch])
        risk_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_high_tint"]),
            ('PADDING', (0,0), (-1,-1), 16),
            ('LINELEFT', (0,0), (-1,-1), 6, PDF_COLORS["high"]),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(risk_box)
        story.append(Spacer(1, 20))
    
    # AI Generation Info
    is_ai = analysis.get("ai_generated", False)
    ai_label = "[IA] Analysee generee par Intelligence Artificielle (Ollama / llama3.2)" if is_ai else "[AUTO] Analysee generee par Regles Automatiques de Secours"
    ai_style = ParagraphStyle('AiLabel', parent=body_style, fontName='Helvetica-Oblique', textColor=PDF_COLORS["text_muted"], fontSize=9)
    ai_box = Table([[Paragraph(ai_label, ai_style)]], colWidths=[7.5*inch])
    ai_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#FFF7ED")),
        ('PADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(ai_box)
    story.append(Spacer(1, 20))
    
    # Key Statistics Table
    story.append(Paragraph("STATISTIQUES CLÉS", h2_style))
    stats_data = [
        [
            Paragraph("<b>Métrique</b>", meta_label_style),
            Paragraph("<b>Valeur</b>", meta_label_style),
            Paragraph("<b>Métrique</b>", meta_label_style),
            Paragraph("<b>Valeur</b>", meta_label_style)
        ],
        [
            Paragraph("Appareils détectés", body_style),
            Paragraph(f"<b>{len(hosts)}</b>", body_bold),
            Paragraph("Services ouverts", body_style),
            Paragraph(f"<b>{total_services}</b>", body_bold)
        ],
        [
            Paragraph("Vulnérabilités totales", body_style),
            Paragraph(f"<b>{len(all_vulns)}</b>", body_bold),
            Paragraph("Identifiants compromis", body_style),
            Paragraph(f"<b>{len(credential_vulns)}</b>", body_bold)
        ],
        [
            Paragraph("Vulnérabilités critiques", body_style),
            Paragraph(f"<b color='{PDF_COLORS['critical'].hexval()}'>{vuln_counts['critical']}</b>", body_bold),
            Paragraph("Vulnérabilités élevées", body_style),
            Paragraph(f"<b color='{PDF_COLORS['high'].hexval()}'>{vuln_counts['high']}</b>", body_bold)
        ]
    ]
    stats_table = Table(stats_data, colWidths=[2*inch, 1.75*inch, 2*inch, 1.75*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 10),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(stats_table)
    story.append(PageBreak())
    
    # ── Page 3: Visual Risk Breakdown ───────────────────────────────────────────────
    story.append(Paragraph("ANALYSE VISUELLE DES RISQUES", h1_style))
    
    donut_img = make_severity_donut(all_vulns)
    bar_img = make_top_hosts_bar(hosts)
    
    charts_data = [
        [Image(donut_img, width=3.5*inch, height=2.8*inch), Image(bar_img, width=3.5*inch, height=2.8*inch)]
    ]
    charts_table = Table(charts_data, colWidths=[3.75*inch]*2)
    charts_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(charts_table)
    story.append(Spacer(1, 20))
    
    # Risk Analysis Summary
    story.append(Paragraph("ANALYSE DES RISQUES PAR HÔTE", h2_style))
    
    host_risk_data = [[Paragraph("<b>Adresse IP</b>", meta_label_style), Paragraph("<b>OS Détecté</b>", meta_label_style), Paragraph("<b>Services</b>", meta_label_style), Paragraph("<b>Vulnérabilités</b>", meta_label_style), Paragraph("<b>Risque Global</b>", meta_label_style)]]
    
    for h in hosts:
        vuln_count = len(h["vulnerabilities"])
        crit_count = sum(1 for v in h["vulnerabilities"] if v.get("severity", "").lower() == "critical")
        high_count = sum(1 for v in h["vulnerabilities"] if v.get("severity", "").lower() == "high")
        
        # Calculate risk level
        if crit_count > 0:
            risk = "CRITIQUE"
            risk_color = PDF_COLORS["critical"]
        elif high_count > 0:
            risk = "ÉLEVÉ"
            risk_color = PDF_COLORS["high"]
        elif vuln_count > 0:
            risk = "MODÉRÉ"
            risk_color = PDF_COLORS["medium"]
        else:
            risk = "FAIBLE"
            risk_color = PDF_COLORS["safe"]
        
        host_risk_data.append([
            Paragraph(h["ip"], mono_style),
            Paragraph(h["os"][:30] if h["os"] else "Unknown", body_style),
            Paragraph(str(len(h["services"])), body_bold),
            Paragraph(str(vuln_count), body_bold),
            Paragraph(f"<b color='{risk_color.hexval()}'>{risk}</b>", body_bold)
        ])
    
    host_risk_table = Table(host_risk_data, colWidths=[1.5*inch, 2*inch, 1*inch, 1*inch, 2*inch])
    host_risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(host_risk_table)
    story.append(Spacer(1, 20))
    
    # Host Security Scores & Ranking
    story.append(Paragraph("CLASSEMENT DES HÔTES PAR SCORE DE SÉCURITÉ", h2_style))
    
    host_score_data = [[Paragraph("<b>Rang</b>", meta_label_style), Paragraph("<b>Adresse IP</b>", meta_label_style), Paragraph("<b>Score Sécurité</b>", meta_label_style), Paragraph("<b>Services</b>", meta_label_style), Paragraph("<b>Vulnérabilités</b>", meta_label_style), Paragraph("<b>Évaluation</b>", meta_label_style)]]
    
    for rank, h in enumerate(hosts_sorted, 1):
        score = h["security_score"]
        vuln_count = len(h["vulnerabilities"])
        
        # Determine evaluation based on score
        if score >= 80:
            evaluation = "Excellent"
            eval_color = PDF_COLORS["safe"]
        elif score >= 60:
            evaluation = "Bon"
            eval_color = PDF_COLORS["medium"]
        elif score >= 40:
            evaluation = "Faible"
            eval_color = PDF_COLORS["high"]
        else:
            evaluation = "Critique"
            eval_color = PDF_COLORS["critical"]
        
        # Score color
        score_color = PDF_COLORS["safe"] if score >= 80 else (PDF_COLORS["medium"] if score >= 60 else PDF_COLORS["high"] if score >= 40 else PDF_COLORS["critical"])
        
        host_score_data.append([
            Paragraph(f"#{rank}", body_bold),
            Paragraph(h["ip"], mono_style),
            Paragraph(f"<b color='{score_color.hexval()}'>{score}/100</b>", body_bold),
            Paragraph(str(len(h["services"])), body_style),
            Paragraph(str(vuln_count), body_style),
            Paragraph(f"<b color='{eval_color.hexval()}'>{evaluation}</b>", body_bold)
        ])
    
    host_score_table = Table(host_score_data, colWidths=[0.8*inch, 1.5*inch, 1.2*inch, 1*inch, 1*inch, 2*inch])
    host_score_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(host_score_table)
    story.append(Spacer(1, 15))
    
    # Host Score Explanation
    explanation_text = (
        "Le score de sécurité est calculé sur 100 points. Les déductions sont appliquées pour: "
        "vulnérabilités critiques (-25), élevées (-15), moyennes (-8), faibles (-3), "
        "identifiants validés (-20 chacun), et surface d'attaque exposée (-2 par service, max -20)."
    )
    story.append(Paragraph(explanation_text, ParagraphStyle('ExplanationStyle', parent=body_style, fontSize=8, textColor=PDF_COLORS["text_muted"])))
    story.append(PageBreak())
    
    # ── Page 4: Key Findings & Remediation ───────────────────────────────────────────
    story.append(Paragraph("CONSTATS CLÉS ET PLAN DE REMÉDIATION", h1_style))
    
    findings = analysis.get("key_findings", [])
    if not findings:
        story.append(Paragraph("Aucun constat clé identifié.", body_style))
    else:
        for idx, f in enumerate(findings[:10], 1):
            sev = f.get("severity", "info")
            sev_color = get_severity_color(sev)
            bg_tint = get_severity_bg_tint(sev)
            
            # Finding Header with severity badge
            story.append(Paragraph(f"CONSTAT #{idx} : {f.get('finding_name', 'Inconnu')}", h2_style))
            
            # Risk Metrics Table
            metrics_data = [
                [Paragraph("<b>Sévérité</b>", meta_label_style), Paragraph("<b>Probabilité</b>", meta_label_style), Paragraph("<b>Impact</b>", meta_label_style), Paragraph("<b>Hôtes Affectés</b>", meta_label_style)],
                [
                    Paragraph(f"<b color='{sev_color.hexval()}'>{sev.upper()}</b>", body_bold),
                    Paragraph(f"<b>{f.get('likelihood', 'N/A')}</b>", body_bold),
                    Paragraph(f"<b>{f.get('impact', 'N/A')}</b>", body_bold),
                    Paragraph(", ".join(f.get('affected_hosts', [])), mono_style)
                ]
            ]
            metrics_table = Table(metrics_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 3*inch])
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), bg_tint),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('PADDING', (0,0), (-1,-1), 10),
                ('LINEBELOW', (0,0), (-1,0), 2, sev_color),
                ('LINELEFT', (0,0), (-1,-1), 4, sev_color),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(metrics_table)
            story.append(Spacer(1, 12))
            
            # Description
            story.append(Paragraph("<b>Description détaillée :</b>", h3_style))
            story.append(Paragraph(f.get('description', 'Non disponible.'), body_style))
            story.append(Spacer(1, 12))
            
            # MITRE ATT&CK & CWE Mapping
            mitre_mapping = get_mitre_mapping(f.get('finding_name', ''), f.get('service'))
            story.append(Paragraph("<b>Mappings MITRE ATT&CK & CWE :</b>", h3_style))
            
            mapping_data = [
                [Paragraph("<b>Type</b>", meta_label_style), Paragraph("<b>Identifiant</b>", meta_label_style)]
            ]
            
            for technique in mitre_mapping["mitre_techniques"]:
                mapping_data.append([
                    Paragraph("MITRE ATT&CK", body_style),
                    Paragraph(technique, mono_style)
                ])
            
            for cwe in mitre_mapping["cwe_ids"]:
                mapping_data.append([
                    Paragraph("CWE", body_style),
                    Paragraph(cwe, mono_style)
                ])
            
            mapping_table = Table(mapping_data, colWidths=[2*inch, 5.5*inch])
            mapping_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
                ('PADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")),
                ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(mapping_table)
            story.append(Spacer(1, 12))
            
            # Compliance Framework Mapping
            compliance_map = get_compliance_mapping(f.get('finding_name', ''), f.get('service'))
            story.append(Paragraph("<b>Conformité aux Standards :</b>", h3_style))
            
            compliance_data = [
                [Paragraph("<b>Framework</b>", meta_label_style), Paragraph("<b>Contrôle</b>", meta_label_style)]
            ]
            
            for framework, controls in compliance_map.items():
                for control in controls[:2]:  # Limit to 2 controls per framework
                    compliance_data.append([
                        Paragraph(framework, body_bold),
                        Paragraph(control, body_style)
                    ])
            
            compliance_table = Table(compliance_data, colWidths=[2*inch, 5.5*inch])
            compliance_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
                ('PADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")),
                ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(compliance_table)
            story.append(Spacer(1, 12))
            
            # Remediation Steps
            story.append(Paragraph("<b>Plan de remédiation détaillé :</b>", h3_style))
            remediation_steps = f.get('remediation_steps', [])
            if remediation_steps:
                for step_idx, step in enumerate(remediation_steps, 1):
                    story.append(Paragraph(f"{step_idx}. {step}", bullet_style))
            else:
                story.append(Paragraph("Aucune étape de remédiation disponible.", body_style))
            
            story.append(Spacer(1, 20))
            
    story.append(PageBreak())
    
    # ── Remediation Timeline Phases ───────────────────────────────────────────────
    story.append(Paragraph("CALENDRIER DE REMÉDIATION", h1_style))
    
    # Phase 1: Immediate (24h)
    story.append(Paragraph("PHASE 1: ACTIONS IMMÉDIATES (24 HEURES)", h2_style))
    phase1_actions = []
    
    # Critical vulnerabilities
    crit_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "critical"]
    for v in crit_vulns[:5]:
        commands = get_remediation_commands(v.get("name", ""))
        phase1_actions.append({
            "vuln": v.get("name", "Unknown"),
            "host": v.get("host_ip", "Unknown"),
            "commands": commands[:2] if commands else ["Apply vendor patch immediately"]
        })
    
    # Credential vulnerabilities
    cred_vulns = [v for v in all_vulns if v.get("source") == "credential_test"]
    for v in cred_vulns[:3]:
        phase1_actions.append({
            "vuln": "Default Credentials Validated",
            "host": v.get("host_ip", "Unknown"),
            "commands": [
                "Change default credentials immediately",
                "Disable accounts with default credentials",
                "Implement multi-factor authentication"
            ]
        })
    
    if phase1_actions:
        for action in phase1_actions:
            action_box = Table([[Paragraph(f"<b>{action['vuln']}</b> on {action['host']}", body_style)]], colWidths=[7.5*inch])
            action_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_critical_tint"]),
                ('PADDING', (0,0), (-1,-1), 10),
                ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["critical"]),
            ]))
            story.append(action_box)
            for cmd in action["commands"]:
                story.append(Paragraph(f"- {cmd}", bullet_style))
            story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("Aucune action critique requise dans les 24h.", body_style))
    
    story.append(Spacer(1, 20))
    
    # Phase 2: Short-term (7 days)
    story.append(Paragraph("PHASE 2: ACTIONS À COURT TERME (7 JOURS)", h2_style))
    phase2_actions = []
    
    high_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "high"]
    for v in high_vulns[:5]:
        commands = get_remediation_commands(v.get("name", ""))
        phase2_actions.append({
            "vuln": v.get("name", "Unknown"),
            "host": v.get("host_ip", "Unknown"),
            "commands": commands[:2] if commands else ["Apply vendor patch within 7 days"]
        })
    
    if phase2_actions:
        for action in phase2_actions:
            action_box = Table([[Paragraph(f"<b>{action['vuln']}</b> on {action['host']}", body_style)]], colWidths=[7.5*inch])
            action_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_high_tint"]),
                ('PADDING', (0,0), (-1,-1), 10),
                ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["high"]),
            ]))
            story.append(action_box)
            for cmd in action["commands"]:
                story.append(Paragraph(f"- {cmd}", bullet_style))
            story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("Aucune vulnérabilité élevée détectée.", body_style))
    
    story.append(Spacer(1, 20))
    
    # Phase 3: Medium-term (30 days)
    story.append(Paragraph("PHASE 3: ACTIONS À MOYEN TERME (30 JOURS)", h2_style))
    phase3_actions = []
    
    medium_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "medium"]
    for v in medium_vulns[:5]:
        commands = get_remediation_commands(v.get("name", ""))
        phase3_actions.append({
            "vuln": v.get("name", "Unknown"),
            "host": v.get("host_ip", "Unknown"),
            "commands": commands[:2] if commands else ["Apply vendor patch within 30 days"]
        })
    
    if phase3_actions:
        for action in phase3_actions:
            action_box = Table([[Paragraph(f"<b>{action['vuln']}</b> on {action['host']}", body_style)]], colWidths=[7.5*inch])
            action_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_medium_tint"]),
                ('PADDING', (0,0), (-1,-1), 10),
                ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["medium"]),
            ]))
            story.append(action_box)
            for cmd in action["commands"]:
                story.append(Paragraph(f"- {cmd}", bullet_style))
            story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("Aucune vulnérabilité moyenne détectée.", body_style))
    
    story.append(Spacer(1, 20))
    
    # Phase 4: Long-term (90 days)
    story.append(Paragraph("PHASE 4: ACTIONS À LONG TERME (90 JOURS)", h2_style))
    phase4_actions = [
        "Review and update all system configurations",
        "Implement network segmentation",
        "Deploy intrusion detection systems",
        "Conduct regular security audits",
        "Train staff on security best practices",
        "Establish incident response procedures",
        "Review and update firewall rules",
        "Implement log monitoring and alerting"
    ]
    
    for action in phase4_actions:
        story.append(Paragraph(f"- {action}", bullet_style))
    
    story.append(Spacer(1, 20))
    
    # Timeline Summary
    story.append(Paragraph("RÉSUMÉ DU CALENDRIER", h3_style))
    timeline_summary = f"""
    <b>Phase 1 (24h):</b> {len(phase1_actions)} actions critiques à immédiatement
    <b>Phase 2 (7j):</b> {len(phase2_actions)} actions élevées à traiter cette semaine
    <b>Phase 3 (30j):</b> {len(phase3_actions)} actions moyennes à planifier ce mois
    <b>Phase 4 (90j):</b> {len(phase4_actions)} améliorations continues à long terme
    """
    story.append(Paragraph(timeline_summary, body_style))
    story.append(PageBreak())
    
    # ── Priority Matrix ─────────────────────────────────────────────────────────
    story.append(Paragraph("MATRICE DE PRIORITÉ", h1_style))
    
    priority_data = [[Paragraph("<b>Vulnérabilité</b>", meta_label_style), Paragraph("<b>Sévérité</b>", meta_label_style), Paragraph("<b>Effort</b>", meta_label_style), Paragraph("<b>Coût</b>", meta_label_style), Paragraph("<b>Impact</b>", meta_label_style), Paragraph("<b>Priorité</b>", meta_label_style)]]
    
    for v in all_vulns[:10]:
        vuln_name = v.get("name", "Unknown")
        severity = v.get("severity", "info").upper()
        
        # Determine effort based on vulnerability type
        vuln_lower = vuln_name.lower()
        if "credential" in vuln_lower or "password" in vuln_lower:
            effort = "Faible"
            effort_color = PDF_COLORS["safe"]
        elif "ssh" in vuln_lower or "ftp" in vuln_lower:
            effort = "Moyen"
            effort_color = PDF_COLORS["medium"]
        elif "ssl" in vuln_lower or "tls" in vuln_lower:
            effort = "Moyen"
            effort_color = PDF_COLORS["medium"]
        else:
            effort = "Élevé"
            effort_color = PDF_COLORS["high"]
        
        # Determine cost based on severity
        if severity == "CRITICAL":
            cost = "Élevé"
            cost_color = PDF_COLORS["high"]
        elif severity == "HIGH":
            cost = "Moyen"
            cost_color = PDF_COLORS["medium"]
        else:
            cost = "Faible"
            cost_color = PDF_COLORS["safe"]
        
        # Impact is based on severity
        if severity == "CRITICAL":
            impact = "Critique"
            impact_color = PDF_COLORS["critical"]
        elif severity == "HIGH":
            impact = "Élevé"
            impact_color = PDF_COLORS["high"]
        elif severity == "MEDIUM":
            impact = "Moyen"
            impact_color = PDF_COLORS["medium"]
        else:
            impact = "Faible"
            impact_color = PDF_COLORS["safe"]
        
        # Calculate overall priority
        priority_score = 0
        if severity == "CRITICAL":
            priority_score += 4
        elif severity == "HIGH":
            priority_score += 3
        elif severity == "MEDIUM":
            priority_score += 2
        else:
            priority_score += 1
        
        if effort == "Faible":
            priority_score += 2
        elif effort == "Moyen":
            priority_score += 1
        
        if impact == "Critique":
            priority_score += 3
        elif impact == "Élevé":
            priority_score += 2
        elif impact == "Moyen":
            priority_score += 1
        
        if priority_score >= 7:
            priority = "CRITIQUE"
            priority_color = PDF_COLORS["critical"]
        elif priority_score >= 5:
            priority = "ÉLEVÉE"
            priority_color = PDF_COLORS["high"]
        elif priority_score >= 3:
            priority = "MOYENNE"
            priority_color = PDF_COLORS["medium"]
        else:
            priority = "FAIBLE"
            priority_color = PDF_COLORS["safe"]
        
        sev_color = get_severity_color(severity)
        
        priority_data.append([
            Paragraph(vuln_name[:40], body_style),
            Paragraph(f"<b color='{sev_color.hexval()}'>{severity}</b>", body_bold),
            Paragraph(f"<b color='{effort_color.hexval()}'>{effort}</b>", body_bold),
            Paragraph(f"<b color='{cost_color.hexval()}'>{cost}</b>", body_bold),
            Paragraph(f"<b color='{impact_color.hexval()}'>{impact}</b>", body_bold),
            Paragraph(f"<b color='{priority_color.hexval()}'>{priority}</b>", body_bold)
        ])
    
    priority_table = Table(priority_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1*inch, 1*inch, 1*inch])
    priority_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(priority_table)
    story.append(Spacer(1, 15))
    
    # Priority Matrix Explanation
    explanation_text = (
        "La priorité est calculée en combinant la sévérité, l'effort de remédiation, "
        "le coût estimé et l'impact business. Les vulnérabilités CRITIQUES avec faible effort "
        "et impact élevé sont prioritaires."
    )
    story.append(Paragraph(explanation_text, ParagraphStyle('PriorityExplanationStyle', parent=body_style, fontSize=8, textColor=PDF_COLORS["text_muted"])))
    story.append(PageBreak())
    
    # ── Risk Analysis if No Action Taken ───────────────────────────────────────────
    story.append(Paragraph("ANALYSE DES RISQUES SI AUCUNE ACTION N'EST PRISE", h1_style))
    
    # Financial Impact
    financial_risk = "Faible"
    financial_color = PDF_COLORS["safe"]
    if crit_count > 0 or cred_count > 0:
        financial_risk = "Élevé"
        financial_color = PDF_COLORS["critical"]
    elif high_count > 2:
        financial_risk = "Moyen"
        financial_color = PDF_COLORS["high"]
    
    # Operational Impact
    operational_risk = "Faible"
    operational_color = PDF_COLORS["safe"]
    if crit_count > 0:
        operational_risk = "Critique"
        operational_color = PDF_COLORS["critical"]
    elif high_count > 3:
        operational_risk = "Élevé"
        operational_color = PDF_COLORS["high"]
    
    # Legal Impact
    legal_risk = "Faible"
    legal_color = PDF_COLORS["safe"]
    if cred_count > 0 or crit_count > 0:
        legal_risk = "Élevé"
        legal_color = PDF_COLORS["critical"]
    elif high_count > 2:
        legal_risk = "Moyen"
        legal_color = PDF_COLORS["medium"]
    
    # Reputation Impact
    reputation_risk = "Faible"
    reputation_color = PDF_COLORS["safe"]
    if crit_count > 0 or cred_count > 0:
        reputation_risk = "Critique"
        reputation_color = PDF_COLORS["critical"]
    elif high_count > 3:
        reputation_risk = "Élevé"
        reputation_color = PDF_COLORS["high"]
    
    risk_data = [
        [Paragraph("<b>Type d'Impact</b>", meta_label_style), Paragraph("<b>Niveau de Risque</b>", meta_label_style), Paragraph("<b>Description</b>", meta_label_style)],
        [
            Paragraph("Financier", body_bold),
            Paragraph(f"<b color='{financial_color.hexval()}'>{financial_risk}</b>", body_bold),
            Paragraph("Perte de revenus, coûts de récupération, amendes réglementaires, pertes de données.", body_style)
        ],
        [
            Paragraph("Opérationnel", body_bold),
            Paragraph(f"<b color='{operational_color.hexval()}'>{operational_risk}</b>", body_bold),
            Paragraph("Interruption de services, perte de productivité, temps d'arrêt, coûts de reprise.", body_style)
        ],
        [
            Paragraph("Juridique", body_bold),
            Paragraph(f"<b color='{legal_color.hexval()}'>{legal_risk}</b>", body_bold),
            Paragraph("Non-conformité RGPD, sanctions, litiges, responsabilités contractuelles.", body_style)
        ],
        [
            Paragraph("Réputation", body_bold),
            Paragraph(f"<b color='{reputation_color.hexval()}'>{reputation_risk}</b>", body_bold),
            Paragraph("Perte de confiance client, dommage à la marque, impact sur les partenariats.", body_style)
        ]
    ]
    
    risk_table = Table(risk_data, colWidths=[2*inch, 1.5*inch, 4*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 12),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 20))
    
    # Risk Summary
    story.append(Paragraph("RÉSUMÉ DU RISQUE GLOBAL", h2_style))
    
    overall_risk_score = 0
    if financial_risk == "Critique" or financial_risk == "Élevé":
        overall_risk_score += 3
    elif financial_risk == "Moyen":
        overall_risk_score += 2
    else:
        overall_risk_score += 1
    
    if operational_risk == "Critique":
        overall_risk_score += 3
    elif operational_risk == "Élevé":
        overall_risk_score += 2
    elif operational_risk == "Moyen":
        overall_risk_score += 1
    
    if legal_risk == "Critique" or legal_risk == "Élevé":
        overall_risk_score += 3
    elif legal_risk == "Moyen":
        overall_risk_score += 2
    else:
        overall_risk_score += 1
    
    if reputation_risk == "Critique":
        overall_risk_score += 3
    elif reputation_risk == "Élevé":
        overall_risk_score += 2
    elif reputation_risk == "Moyen":
        overall_risk_score += 1
    
    if overall_risk_score >= 10:
        overall_risk = "CRITIQUE"
        overall_risk_color = PDF_COLORS["critical"]
        risk_recommendation = "Action immédiate requise. Le risque d'incident majeur est imminent."
    elif overall_risk_score >= 7:
        overall_risk = "ÉLEVÉ"
        overall_risk_color = PDF_COLORS["high"]
        risk_recommendation = "Action urgente requise dans les 7 jours. Risque significatif d'impact business."
    elif overall_risk_score >= 4:
        overall_risk = "MOYEN"
        overall_risk_color = PDF_COLORS["medium"]
        risk_recommendation = "Action recommandée dans les 30 jours. Risque modéré d'impact."
    else:
        overall_risk = "FAIBLE"
        overall_risk_color = PDF_COLORS["safe"]
        risk_recommendation = "Surveillance continue. Risque acceptable avec monitoring."
    
    risk_summary_box = Table([[Paragraph(f"<b>Risque Global: {overall_risk}</b>", ParagraphStyle('OverallRiskStyle', parent=body_bold, textColor=overall_risk_color, fontSize=14))]], colWidths=[7.5*inch])
    risk_summary_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 16),
        ('LINELEFT', (0,0), (-1,-1), 6, overall_risk_color),
    ]))
    story.append(risk_summary_box)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph(f"<b>Recommandation:</b> {risk_recommendation}", body_style))
    story.append(PageBreak())
    
    # ── Overall Grade & Security Domain Scores ─────────────────────────────────────
    story.append(Paragraph("NOTE DE SÉCURITÉ GLOBALE ET PAR DOMAINE", h1_style))
    
    # Calculate overall grade (domain_scores already calculated at function start)
    avg_score = sum(domain_scores.values()) / len(domain_scores)
    
    if avg_score >= 90:
        overall_grade = "A"
        grade_color = PDF_COLORS["safe"]
        grade_description = "Excellent - Posture de sécurité robuste"
    elif avg_score >= 80:
        overall_grade = "B"
        grade_color = PDF_COLORS["medium"]
        grade_description = "Bon - Posture de sécurité solide avec améliorations mineures"
    elif avg_score >= 70:
        overall_grade = "C"
        grade_color = PDF_COLORS["high"]
        grade_description = "Moyen - Posture de sécurité acceptable nécessitant des améliorations"
    elif avg_score >= 60:
        overall_grade = "D"
        grade_color = PDF_COLORS["high"]
        grade_description = "Faible - Posture de sécurité nécessitant des actions significatives"
    else:
        overall_grade = "F"
        grade_color = PDF_COLORS["critical"]
        grade_description = "Critique - Posture de sécurité inacceptable, action immédiate requise"
    
    # Overall Grade Display
    grade_box = Table([[Paragraph(f"<b>NOTE GLOBALE: {overall_grade}</b>", ParagraphStyle('GradeStyle', parent=body_bold, textColor=grade_color, fontSize=24))]], colWidths=[7.5*inch])
    grade_box.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 24),
        ('LINELEFT', (0,0), (-1,-1), 8, grade_color),
        ('LINERIGHT', (0,0), (-1,-1), 8, grade_color),
    ]))
    story.append(grade_box)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph(grade_description, ParagraphStyle('GradeDescriptionStyle', parent=body_style, fontSize=12, alignment=1)))
    story.append(Spacer(1, 20))
    
    # Security Domain Scores Table
    domain_data = [[Paragraph("<b>Domaine de Sécurité</b>", meta_label_style), Paragraph("<b>Score</b>", meta_label_style), Paragraph("<b>Évaluation</b>", meta_label_style)]]
    
    for domain, score in domain_scores.items():
        if score >= 80:
            evaluation = "Excellent"
            eval_color = PDF_COLORS["safe"]
        elif score >= 60:
            evaluation = "Bon"
            eval_color = PDF_COLORS["medium"]
        elif score >= 40:
            evaluation = "Moyen"
            eval_color = PDF_COLORS["high"]
        else:
            evaluation = "Critique"
            eval_color = PDF_COLORS["critical"]
        
        score_color = PDF_COLORS["safe"] if score >= 80 else (PDF_COLORS["medium"] if score >= 60 else PDF_COLORS["high"] if score >= 40 else PDF_COLORS["critical"])
        
        domain_data.append([
            Paragraph(domain, body_style),
            Paragraph(f"<b color='{score_color.hexval()}'>{score}/100</b>", body_bold),
            Paragraph(f"<b color='{eval_color.hexval()}'>{evaluation}</b>", body_bold)
        ])
    
    domain_table = Table(domain_data, colWidths=[3*inch, 1.5*inch, 3*inch])
    domain_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
        ('PADDING', (0,0), (-1,-1), 10),
        ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
        ('GRID', (0,1), (-1,-1), 1, colors.HexColor("#E2E8F0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(domain_table)
    story.append(Spacer(1, 20))
    
    # Top 5 Actions to Perform Immediately
    story.append(Paragraph("TOP 5 ACTIONS À EFFECTUER IMMÉDIATEMENT", h2_style))
    
    top_actions = []
    # Add critical vulnerabilities
    crit_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "critical"]
    for v in crit_vulns[:3]:
        top_actions.append(f"Corriger: {v.get('name', 'Unknown')} (CRITICAL)")
    
    # Add credential vulnerabilities
    cred_vulns = [v for v in all_vulns if v.get("source") == "credential_test"]
    for v in cred_vulns[:2]:
        top_actions.append(f"Changer identifiants par défaut sur {v.get('host_ip', 'Unknown')}")
    
    # Fill remaining with high severity
    high_vulns = [v for v in all_vulns if v.get("severity", "").lower() == "high"]
    for v in high_vulns[:5 - len(top_actions)]:
        top_actions.append(f"Corriger: {v.get('name', 'Unknown')} (HIGH)")
    
    for i, action in enumerate(top_actions, 1):
        action_box = Table([[Paragraph(f"<b>{i}. {action}</b>", body_style)]], colWidths=[7.5*inch])
        action_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
            ('PADDING', (0,0), (-1,-1), 10),
            ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS["critical"]),
        ]))
        story.append(action_box)
        story.append(Spacer(1, 8))
    
    story.append(PageBreak())
    
    # ── Page 5+: Per-Host Details ────────────────────────────────────────────────
    story.append(Paragraph("DÉTAIL TECHNIQUE PAR MACHINE", h1_style))
    
    for h in hosts:
        host_elements = []
        
        # Host Header
        host_title = f"{h['ip']} - {h['hostname']} - OS: {h['os']}"
        host_elements.append(Paragraph(host_title, h2_style))
        
        # Host Info Table
        host_info_data = [
            [Paragraph("<b>Adresse MAC</b>", meta_label_style), Paragraph(h.get('mac_address', 'Unknown'), mono_style),
             Paragraph("<b>Services</b>", meta_label_style), Paragraph(str(len(h['services'])), body_bold),
             Paragraph("<b>Vulnérabilités</b>", meta_label_style), Paragraph(str(len(h['vulnerabilities'])), body_bold)]
        ]
        host_info_table = Table(host_info_data, colWidths=[1.5*inch, 2.5*inch, 1.5*inch, 1*inch, 1.5*inch, 1*inch])
        host_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
            ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        host_elements.append(host_info_table)
        host_elements.append(Spacer(1, 12))
        
        # Services Table
        if h["services"]:
            host_elements.append(Paragraph("<b>Services Détectés</b>", h3_style))
            svc_data = [[
                Paragraph("Port", meta_label_style),
                Paragraph("État", meta_label_style),
                Paragraph("Protocole", meta_label_style),
                Paragraph("Service", meta_label_style),
                Paragraph("Version", meta_label_style)
            ]]
            for s in h["services"]:
                svc_data.append([
                    Paragraph(str(s["port"]), mono_style),
                    Paragraph(s.get("state", "open"), body_style),
                    Paragraph(s["protocol"], body_style),
                    Paragraph(s["name"] or "Unknown", body_style),
                    Paragraph(s["version"] or "Unknown", body_style)
                ])
            
            svc_table = Table(svc_data, colWidths=[0.8*inch, 1*inch, 1*inch, 2*inch, 2.7*inch])
            svc_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
                ('PADDING', (0,0), (-1,-1), 6),
                ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]])
            ]))
            host_elements.append(svc_table)
            host_elements.append(Spacer(1, 12))
            
        # Vulnerabilities Table
        if h["vulnerabilities"]:
            host_elements.append(Paragraph("<b>Vulnérabilités Identifiées</b>", h3_style))
            vuln_data = [[
                Paragraph("Nom", meta_label_style),
                Paragraph("Sévérité", meta_label_style),
                Paragraph("CVE ID", meta_label_style),
                Paragraph("CVSS", meta_label_style),
                Paragraph("Source", meta_label_style)
            ]]
            for v in h["vulnerabilities"]:
                sev_color = get_severity_color(v["severity"]).hexval()
                cve_text = v.get("cve_id") or "—"
                cvss_val = v.get("cvss_score")
                cvss_str = f"{cvss_val:.1f}" if cvss_val is not None else "—"
                source = v.get("source", "nuclei")
                
                vuln_data.append([
                    Paragraph(v["name"][:50] + "..." if len(v["name"]) > 50 else v["name"], body_style),
                    Paragraph(f"<b color='{sev_color}'>{v['severity'].upper()}</b>", body_style),
                    Paragraph(cve_text[:20] + "..." if len(cve_text) > 20 else cve_text, mono_style),
                    Paragraph(cvss_str, body_bold),
                    Paragraph(source, body_style)
                ])
                
            vuln_table = Table(vuln_data, colWidths=[2.5*inch, 1.2*inch, 1.5*inch, 0.8*inch, 1.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
                ('PADDING', (0,0), (-1,-1), 6),
                ('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor("#E2E8F0")),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]])
            ]))
            host_elements.append(vuln_table)
        
        # ── Evidence Blocks ───────────────────────────────────────────────────
        evidence_items = h.get("evidence", [])
        web_screenshots = [e for e in evidence_items if e.get("type") == "web_screenshot"]
        auth_screenshots = [e for e in evidence_items if e.get("type") == "auth_screenshot"]
        text_evidences = [e for e in evidence_items if e.get("type") == "text"]

        if evidence_items:
            host_elements.append(Spacer(1, 10))
            host_elements.append(Paragraph("<b>Preuves Capturées</b>", h3_style))

        # Web Screenshots
        for ev in web_screenshots:
            ev_path = ev.get("path")
            ev_label = ev.get("label", "Capture écran web")
            if ev_path:
                import os
                if os.path.exists(ev_path):
                    try:
                        img = Image(ev_path, width=6.5*inch, height=3.5*inch)
                        img.hAlign = 'LEFT'
                        label_box = Table(
                            [[Paragraph(f"<b>📷 {ev_label}</b>",
                                ParagraphStyle('EvidenceLabel', parent=body_style,
                                    textColor=PDF_COLORS['primary'], fontSize=9))]],
                            colWidths=[7.5*inch]
                        )
                        label_box.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS['bg_light']),
                            ('PADDING', (0,0), (-1,-1), 6),
                            ('LINELEFT', (0,0), (-1,-1), 3, PDF_COLORS['primary']),
                        ]))
                        host_elements.append(label_box)
                        host_elements.append(img)
                        host_elements.append(Spacer(1, 8))
                    except Exception:
                        pass

        # Auth Screenshots
        for ev in auth_screenshots:
            ev_path = ev.get("path")
            ev_label = ev.get("label", "Preuve d'authentification")
            if ev_path:
                import os
                if os.path.exists(ev_path):
                    try:
                        img = Image(ev_path, width=6.5*inch, height=3.5*inch)
                        img.hAlign = 'LEFT'
                        label_box = Table(
                            [[Paragraph(f"<b>🔑 {ev_label}</b>",
                                ParagraphStyle('AuthEvidenceLabel', parent=body_style,
                                    textColor=PDF_COLORS['critical'], fontSize=9))]],
                            colWidths=[7.5*inch]
                        )
                        label_box.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS['bg_critical_tint']),
                            ('PADDING', (0,0), (-1,-1), 6),
                            ('LINELEFT', (0,0), (-1,-1), 3, PDF_COLORS['critical']),
                        ]))
                        host_elements.append(label_box)
                        host_elements.append(img)
                        host_elements.append(Spacer(1, 8))
                    except Exception:
                        pass

        # Text Evidence (SSH/FTP/SMB session output)
        for ev in text_evidences:
            ev_content = ev.get("content", "")
            ev_label = ev.get("label", "Preuve de Connexion (texte)")
            if ev_content:
                label_box = Table(
                    [[Paragraph(f"<b>🖥 {ev_label}</b>",
                        ParagraphStyle('TextEvidenceLabel', parent=body_style,
                            textColor=colors.HexColor('#92400E'), fontSize=9))]],
                    colWidths=[7.5*inch]
                )
                label_box.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FEF3C7')),
                    ('PADDING', (0,0), (-1,-1), 6),
                    ('LINELEFT', (0,0), (-1,-1), 3, colors.HexColor('#F59E0B')),
                ]))
                host_elements.append(label_box)

                terminal_box = Table(
                    [[Paragraph(ev_content.replace('\n', '<br/>'),
                        ParagraphStyle('TerminalStyle', parent=mono_style,
                            backColor=colors.HexColor('#1E293B'),
                            textColor=colors.HexColor('#86EFAC'),
                            fontSize=8, leading=12))]],
                    colWidths=[7.5*inch]
                )
                terminal_box.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#1E293B')),
                    ('PADDING', (0,0), (-1,-1), 10),
                ]))
                host_elements.append(terminal_box)
                host_elements.append(Spacer(1, 8))

        story.append(KeepTogether(host_elements))
        story.append(Spacer(1, 25))
        
    story.append(PageBreak())
    
    # ── Final Page: Strategic Recommendations & Verdict ─────────────────────────--
    story.append(Paragraph("RECOMMANDATIONS STRATÉGIQUES ET PLAN D'ACTION", h1_style))
    
    recs = analysis.get("strategic_recommendations", [])
    if not recs:
        story.append(Paragraph("Aucune recommandation stratégique requise.", body_style))
    else:
        # Sort by priority
        sorted_recs = sorted(recs, key=lambda x: x.get('priority', 999))
        
        for idx, r in enumerate(sorted_recs, 1):
            priority = r.get('priority', idx)
            theme = r.get('theme', 'Sans thème')
            advice = r.get('advice', 'Aucun conseil disponible')

            # Priority color
            if priority == 1:
                prio_color = PDF_COLORS["critical"]
                prio_label = "CRITIQUE"
            elif priority <= 3:
                prio_color = PDF_COLORS["high"]
                prio_label = "HAUTE"
            elif priority <= 5:
                prio_color = PDF_COLORS["medium"]
                prio_label = "MOYENNE"
            else:
                prio_color = PDF_COLORS["low"]
                prio_label = "FAIBLE"

            # Recommendation Header
            r_header = Table(
                [[Paragraph(f"<b>#{priority} — {theme.upper()}</b> "
                            f"<font color='{prio_color.hexval()}'>[{prio_label}]</font>",
                            h3_style)]],
                colWidths=[7.5*inch]
            )
            r_header.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
                ('PADDING', (0,0), (-1,-1), 10),
                ('LINELEFT', (0,0), (-1,-1), 6, prio_color),
                ('LINETOP', (0,0), (-1,-1), 2, prio_color),
            ]))
            story.append(r_header)

            # Parse the four sections from the advice text
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
                # Section: Ce que cela signifie
                if what:
                    box = Table([[Paragraph(f"<b>💡 Ce que cela signifie :</b><br/>{what}", body_style)]], colWidths=[7.5*inch])
                    box.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS['bg_light']),
                        ('PADDING', (0,0), (-1,-1), 12),
                        ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS['primary']),
                    ]))
                    story.append(box)
                    story.append(Spacer(1, 4))

                # Section: Où
                if where:
                    box = Table([[Paragraph(f"<b>📍 Où :</b> {where}", body_style)]], colWidths=[7.5*inch])
                    box.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F0FDF4')),
                        ('PADDING', (0,0), (-1,-1), 10),
                        ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS['safe']),
                    ]))
                    story.append(box)
                    story.append(Spacer(1, 4))

                # Section: Comment corriger
                if how_fix:
                    steps = [s.strip() for s in how_fix.split('\n') if s.strip()]
                    step_content = '<br/>'.join(steps)
                    box = Table([[Paragraph(f"<b>🔧 Comment corriger :</b><br/>{step_content}", body_style)]], colWidths=[7.5*inch])
                    box.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS['bg_high_tint']),
                        ('PADDING', (0,0), (-1,-1), 12),
                        ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS['high']),
                    ]))
                    story.append(box)
                    story.append(Spacer(1, 4))

                # Section: Comment vérifier
                if how_verify:
                    box = Table([[Paragraph(f"<b>✅ Comment vérifier :</b><br/>{how_verify}", body_style)]], colWidths=[7.5*inch])
                    box.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F0FDF4')),
                        ('PADDING', (0,0), (-1,-1), 10),
                        ('LINELEFT', (0,0), (-1,-1), 4, PDF_COLORS['safe']),
                    ]))
                    story.append(box)
            else:
                # Fallback: render raw advice text
                r_table = Table([[Paragraph(advice, body_style)]], colWidths=[7.5*inch])
                r_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), PDF_COLORS["bg_light"]),
                    ('PADDING', (0,0), (-1,-1), 12),
                    ('LINELEFT', (0,0), (-1,-1), 4, prio_color),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ]))
                story.append(r_table)

            story.append(Spacer(1, 15))
            
    story.append(Spacer(1, 25))
    
    # Overall Verdict
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
        ('BACKGROUND', (0,0), (-1,-1), verdict_bg),
        ('PADDING', (0,0), (-1,-1), 20),
        ('LINELEFT', (0,0), (-1,-1), 8, verdict_border),
        ('LINERIGHT', (0,0), (-1,-1), 8, verdict_border),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 30))
    
    # Appendix: All Vulnerabilities Summary
    if all_vulns:
        story.append(Paragraph("ANNEXE : RÉCAPITULATIF COMPLET DES VULNÉRABILITÉS", h2_style))
        
        all_vuln_data = [[
            Paragraph("<b>Hote</b>", meta_label_style),
            Paragraph("<b>Nom</b>", meta_label_style),
            Paragraph("<b>Severite</b>", meta_label_style),
            Paragraph("<b>CVE</b>", meta_label_style),
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
            ('BACKGROUND', (0,0), (-1,0), PDF_COLORS["bg_light"]),
            ('PADDING', (0,0), (-1,-1), 6),
            ('LINEBELOW', (0,0), (-1,0), 2, PDF_COLORS["primary"]),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, PDF_COLORS["bg_light"]]),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(all_vuln_table)
        story.append(Spacer(1, 20))
    
    # Final Footer
    story.append(Paragraph("Fin du rapport - Document genere automatiquement par Audit Reseau IA", ParagraphStyle('FinalFooter', parent=body_style, textColor=PDF_COLORS["text_muted"], alignment=1, fontSize=8)))
    
    # Build document
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
