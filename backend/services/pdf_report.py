"""
pdf_report.py  –  Enterprise-grade Network Security Audit Report
=================================================================
Drop-in replacement for services/pdf_report.py.
Palette, imports and function signatures are unchanged; only
the visual design and structure have been upgraded.
"""

import io
import os
import re
import ipaddress
import math
from typing import Optional, List, Dict, Any
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, HRFlowable, Flowable,
)
from reportlab.platypus.flowables import KeepInFrame
from reportlab.pdfgen import canvas as rl_canvas

import logging
logger = logging.getLogger("PDFReport")

# ═══════════════════════════════════════════════════════════════════════
#  LLM VULNERABILITY DESCRIPTION FALLBACK
#  Called synchronously from vuln_impact_block when NVD description is empty.
# ═══════════════════════════════════════════════════════════════════════
_vuln_desc_cache: dict = {}   # {vuln_key: description}

def get_vuln_description_sync(name: str, cve_id: str, severity: str, cvss: str) -> str:
    """
    Ask the local Ollama LLM for a concise vulnerability description.
    Falls back to a built-in template if Ollama is unavailable.
    Result is cached per (name, cve_id) to avoid duplicate calls.
    """
    cache_key = f"{cve_id or name}"
    if cache_key in _vuln_desc_cache:
        return _vuln_desc_cache[cache_key]

    # Built-in knowledge base for the most common CVEs seen in network scans
    _KNOWN_DESCRIPTIONS = {
        "CVE-2010-2729": (
            "MS10-061 is a critical Print Spooler vulnerability in Windows that allows "
            "unauthenticated remote code execution via SMB. An attacker can write arbitrary "
            "files to the Windows directory and execute them as SYSTEM, enabling full host compromise."
        ),
        "CVE-2010-2550": (
            "MS10-054 is an SMB server vulnerability in Windows that can cause a denial-of-service "
            "condition. A specially crafted SMB request containing a malformed value triggers a "
            "null-pointer dereference, potentially crashing the target system (BSOD)."
        ),
        "CVE-2017-0144": (
            "EternalBlue / MS17-010 is a critical SMB vulnerability exploited by the WannaCry and "
            "NotPetya ransomware campaigns. It allows unauthenticated remote code execution as SYSTEM "
            "on unpatched Windows systems through a buffer overflow in the SMBv1 handler."
        ),
        "CVE-2014-0160": (
            "Heartbleed is a critical OpenSSL vulnerability that allows attackers to read up to 64 KB "
            "of memory from affected servers per request. Private keys, session tokens, and credentials "
            "can be extracted without any authentication or trace in server logs."
        ),
        "CVE-2011-2523": (
            "vsftpd 2.3.4 contains a deliberately-introduced backdoor. Sending a username containing "
            "':)' triggers a root shell on TCP port 6200, granting immediate unauthenticated root "
            "access to the system."
        ),
        "CVE-2007-2447": (
            "Samba 3.0.x 'username map script' RCE allows unauthenticated remote code execution by "
            "injecting shell metacharacters into a MS-RPC call. This is the vulnerability used by "
            "the Metasploit 'usermap_script' module and grants root-level access."
        ),
        "CVE-2014-6271": (
            "Shellshock is a critical bash vulnerability allowing remote code execution via environment "
            "variables. CGI-based web applications, DHCP clients, and SSH ForceCommand configurations "
            "are all attack vectors. Exploitation requires no authentication on vulnerable systems."
        ),
        "CVE-2007-6750": (
            "Slowloris is a denial-of-service vulnerability in HTTP servers. By opening many partial "
            "connections and holding them open with incomplete headers, an attacker can exhaust the "
            "server's connection pool, rendering it unavailable to legitimate users."
        ),
    }

    if cve_id and cve_id in _KNOWN_DESCRIPTIONS:
        desc = _KNOWN_DESCRIPTIONS[cve_id]
        _vuln_desc_cache[cache_key] = desc
        return desc

    # Try Ollama for unknown CVEs
    try:
        import httpx, json as _json
        ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")
        cve_part = f"({cve_id})" if cve_id else ""
        prompt = (
            f"You are a cybersecurity expert. Write a concise 2-3 sentence technical description "
            f"of the vulnerability '{name}' {cve_part} with severity {severity}"
            + (f" and CVSS score {cvss}" if cvss and cvss != "—" else "")
            + ". Explain what the vulnerability is, what an attacker can do with it, and what "
            "systems are affected. Be factual and technical. Do not use markdown."
        )
        payload = {
            "model": ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_ctx": 2048},
        }
        resp = httpx.post(f"{ollama_host}/api/generate", json=payload, timeout=15.0)
        if resp.status_code == 200:
            desc = resp.json().get("response", "").strip()
            if desc and len(desc) > 30:
                _vuln_desc_cache[cache_key] = desc
                return desc
    except Exception as e:
        logger.debug(f"[LLM desc] Ollama unavailable: {e}")

    # Generic intelligent fallback based on vuln name patterns
    name_lower = name.lower()
    if "smb" in name_lower or "ms10" in name_lower:
        desc = (
            f"{name} is a Windows SMB vulnerability that can be exploited remotely over the network. "
            "It may allow attackers to execute arbitrary code or cause denial-of-service conditions "
            "on unpatched systems exposed on SMB ports 139/445."
        )
    elif "ssl" in name_lower or "tls" in name_lower or "diffie" in name_lower or "dh" in name_lower:
        desc = (
            f"{name} is a cryptographic weakness in the TLS/SSL stack. Weak cipher suites or "
            "insufficient key sizes allow passive eavesdropping or active man-in-the-middle attacks, "
            "compromising the confidentiality of encrypted communications."
        )
    elif "sql" in name_lower or "injection" in name_lower:
        desc = (
            f"{name} is a SQL injection vulnerability that allows attackers to manipulate database "
            "queries. Successful exploitation can lead to data exfiltration, authentication bypass, "
            "and in some cases remote code execution through database stored procedures."
        )
    elif "xss" in name_lower:
        desc = (
            f"{name} is a cross-site scripting vulnerability that allows injection of malicious scripts "
            "into web pages viewed by other users. This can be used to steal session cookies, "
            "redirect users, or perform actions on their behalf."
        )
    elif "rce" in name_lower or "remote code" in name_lower or "execute" in name_lower:
        desc = (
            f"{name} is a remote code execution vulnerability allowing attackers to run arbitrary "
            "commands on the target system. Depending on the service's privilege level, this can "
            "result in complete system compromise."
        )
    elif "dos" in name_lower or "denial" in name_lower:
        desc = (
            f"{name} is a denial-of-service vulnerability that can crash or render the affected "
            "service unavailable. An attacker sending specially crafted requests can exhaust server "
            "resources, causing service interruption for legitimate users."
        )
    else:
        desc = (
            f"{name} is a {severity}-severity security vulnerability identified on this host. "
            "It was detected by automated scanning and should be evaluated by a security professional "
            "to assess the precise impact and exploitation risk in this specific environment."
        )

    _vuln_desc_cache[cache_key] = desc
    return desc

# ═══════════════════════════════════════════════════════════════════════
#  COLOUR PALETTE  (unchanged from original)
# ═══════════════════════════════════════════════════════════════════════
C = {
    "dark_blue":    colors.HexColor("#0B2545"),
    "gold":         colors.HexColor("#D4AF37"),
    "black":        colors.HexColor("#111111"),
    "white":        colors.white,
    "light_gray":   colors.HexColor("#F8F9FA"),
    "grid":         colors.HexColor("#DEE2E6"),
    "mid_gray":     colors.HexColor("#6C757D"),
    "green_bg":     colors.HexColor("#E8F5E9"),
    "green_border": colors.HexColor("#2E7D32"),
    "green_text":   colors.HexColor("#1B5E20"),
    "crit":         colors.HexColor("#B71C1C"),
    "high":         colors.HexColor("#E65100"),
    "med":          colors.HexColor("#F57F17"),
    "low":          colors.HexColor("#0D47A1"),
    "safe":         colors.HexColor("#2E7D32"),
    "term_bg":      colors.HexColor("#0C0C0C"),
    "term_bar":     colors.HexColor("#0B2545"),
    "term_prompt":  colors.HexColor("#D4AF37"),
    "term_text":    colors.HexColor("#E0E0E0"),
    "accent1":      colors.HexColor("#1A3A5C"),
    "accent2":      colors.HexColor("#13293D"),
    "stripe":       colors.HexColor("#EEF2F7"),
    "badge_crit":   colors.HexColor("#FFE5E5"),
    "badge_high":   colors.HexColor("#FFF3E0"),
    "badge_med":    colors.HexColor("#FFFDE7"),
    "badge_low":    colors.HexColor("#E3F2FD"),
    "badge_info":   colors.HexColor("#F3F4F6"),
}

PAGE_W = 8.5 * inch
PAGE_H = 11  * inch
M      = 0.55 * inch   # margin
BODY_W = PAGE_W - 2 * M


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════
def sev_color(sev: str) -> colors.Color:
    s = str(sev).lower()
    if s in ("critical", "critique"):  return C["crit"]
    if s in ("high", "élevé"):         return C["high"]
    if s in ("medium", "moyen"):       return C["med"]
    if s in ("low", "faible"):         return C["low"]
    return C["safe"]

def sev_badge_bg(sev: str) -> colors.Color:
    s = str(sev).lower()
    if s in ("critical", "critique"):  return C["badge_crit"]
    if s in ("high", "élevé"):         return C["badge_high"]
    if s in ("medium", "moyen"):       return C["badge_med"]
    if s in ("low", "faible"):         return C["badge_low"]
    return C["badge_info"]

def xml_escape(text: str) -> str:
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))

def hex_of(c: colors.Color) -> str:
    return c.hexval() if hasattr(c, "hexval") else "#000000"

def parse_target_range(target: str) -> list:
    target = target.strip()
    ips = []
    for part in re.split(r'[\s,]+', target):
        part = part.strip()
        if '/' in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                if net.num_addresses <= 256:
                    ips.extend(str(ip) for ip in (net.hosts() if net.prefixlen < 31 else net))
            except Exception: pass
        elif '-' in part:
            try:
                s_str, e_str = part.split('-', 1)
                s_ip = ipaddress.IPv4Address(s_str.strip())
                if '.' in e_str:
                    e_ip = ipaddress.IPv4Address(e_str.strip())
                else:
                    prefix = '.'.join(s_str.strip().split('.')[:-1])
                    e_ip   = ipaddress.IPv4Address(f"{prefix}.{e_str.strip()}")
                if int(s_ip) <= int(e_ip) <= int(s_ip) + 256:
                    ips.extend(str(ipaddress.IPv4Address(i)) for i in range(int(s_ip), int(e_ip)+1))
            except Exception: pass
        else:
            try:
                ipaddress.IPv4Address(part)
                ips.append(part)
            except Exception: pass
    return ips


# ═══════════════════════════════════════════════════════════════════════
#  STYLE FACTORY
# ═══════════════════════════════════════════════════════════════════════
def make_styles():
    base = getSampleStyleSheet()
    def S(name, parent="Normal", **kw):
        p = base[parent] if parent in base else base["Normal"]
        return ParagraphStyle(name, parent=p, **kw)

    return {
        # Cover
        "cover_title": S("cover_title", fontName="Helvetica-Bold", fontSize=46,
                          leading=52, textColor=C["gold"], alignment=TA_LEFT),
        "cover_sub":   S("cover_sub",   fontName="Helvetica",      fontSize=16,
                          leading=22, textColor=C["white"], alignment=TA_LEFT),
        "cover_meta":  S("cover_meta",  fontName="Helvetica",      fontSize=12,
                          leading=17, textColor=C["white"], alignment=TA_LEFT),
        "cover_class": S("cover_class", fontName="Helvetica-Bold", fontSize=12,
                          leading=17, textColor=C["gold"],  alignment=TA_LEFT),
        # Section banners
        "h1":          S("h1", fontName="Helvetica-Bold", fontSize=22, leading=28,
                          textColor=C["dark_blue"], spaceBefore=18, spaceAfter=10),
        "h2":          S("h2", fontName="Helvetica-Bold", fontSize=16, leading=20,
                          textColor=C["dark_blue"], spaceBefore=14, spaceAfter=6),
        "h3":          S("h3", fontName="Helvetica-Bold", fontSize=12, leading=16,
                          textColor=C["dark_blue"], spaceBefore=10, spaceAfter=4),
        # Body
        "body":        S("body", fontName="Helvetica", fontSize=10, leading=15,
                          textColor=C["black"], spaceAfter=6, alignment=TA_JUSTIFY),
        "body_bold":   S("body_bold", fontName="Helvetica-Bold", fontSize=10, leading=15,
                          textColor=C["black"]),
        "small":       S("small", fontName="Helvetica", fontSize=9, leading=13,
                          textColor=C["mid_gray"]),
        "caption":     S("caption", fontName="Helvetica-Oblique", fontSize=8,
                          leading=11, textColor=C["mid_gray"], spaceAfter=4),
        "mono":        S("mono", fontName="Courier", fontSize=9, leading=12,
                          textColor=C["black"]),
        "mono_white":  S("mono_white", fontName="Courier", fontSize=8, leading=11,
                          textColor=C["term_text"]),
        # Table headers
        "th":          S("th", fontName="Helvetica-Bold", fontSize=9, leading=12,
                          textColor=C["gold"]),
        "td":          S("td", fontName="Helvetica", fontSize=9, leading=13,
                          textColor=C["black"]),
        "td_mono":     S("td_mono", fontName="Courier", fontSize=9, leading=12,
                          textColor=C["dark_blue"]),
        # Rec box
        "rec":         S("rec", fontName="Helvetica", fontSize=10, leading=15,
                          textColor=C["green_text"]),
        "rec_bold":    S("rec_bold", fontName="Helvetica-Bold", fontSize=10, leading=15,
                          textColor=C["green_text"]),
        # Metric card
        "metric_num":  S("metric_num", fontName="Helvetica-Bold", fontSize=30, leading=34,
                          textColor=C["dark_blue"], alignment=TA_CENTER),
        "metric_lbl":  S("metric_lbl", fontName="Helvetica", fontSize=9, leading=13,
                          textColor=C["mid_gray"], alignment=TA_CENTER),
    }


# ═══════════════════════════════════════════════════════════════════════
#  CUSTOM FLOWABLES
# ═══════════════════════════════════════════════════════════════════════
class ThinRule(Flowable):
    """A single-pixel gold horizontal rule."""
    def __init__(self, width=BODY_W, color=None):
        Flowable.__init__(self)
        self.width  = width
        self.color  = color or C["gold"]
        self.height = 1.5

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.height)
        self.canv.line(0, 0, self.width, 0)


class GradientBar(Flowable):
    """Dark-blue left accent bar for host sections."""
    def __init__(self, height=4, width=BODY_W):
        Flowable.__init__(self)
        self.width  = width
        self.height = height

    def draw(self):
        c = self.canv
        c.setFillColor(C["dark_blue"])
        c.rect(0, 0, self.width * 0.6, self.height, fill=1, stroke=0)
        c.setFillColor(C["gold"])
        c.rect(self.width * 0.6, 0, self.width * 0.4, self.height, fill=1, stroke=0)


class DiagonalWeave(Flowable):
    """Thin diagonal-stripe accent bar — a small futuristic divider motif."""
    def __init__(self, width=BODY_W, height=10, stripe_color=None, gap=15, line_width=1.4):
        Flowable.__init__(self)
        self.width       = width
        self.height      = height
        self.color       = stripe_color or C["gold"]
        self.gap         = gap
        self.line_width  = line_width

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.saveState()
        p = c.beginPath()
        p.moveTo(0, 0)
        p.lineTo(self.width, 0)
        p.lineTo(self.width, self.height)
        p.lineTo(0, self.height)
        p.close()
        c.clipPath(p, stroke=0, fill=0)
        c.setStrokeColor(self.color)
        c.setLineWidth(self.line_width)
        x = -self.height
        while x < self.width + self.height:
            c.line(x, 0, x + self.height, self.height)
            x += self.gap
        c.restoreState()


class CornerFacet(Flowable):
    """A small angled gold facet — used as a decorative corner accent."""
    def __init__(self, size=60, color=None, corner="tr"):
        Flowable.__init__(self)
        self.size  = size
        self.color = color or C["gold"]
        self.corner = corner

    def wrap(self, aw, ah):
        return self.size, self.size

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(self.color)
        p = c.beginPath()
        if self.corner == "tr":
            p.moveTo(0, self.size)
            p.lineTo(self.size, self.size)
            p.lineTo(self.size, 0)
        else:
            p.moveTo(0, 0)
            p.lineTo(self.size, 0)
            p.lineTo(0, self.size)
        p.close()
        c.drawPath(p, fill=1, stroke=0)
        c.restoreState()


class SidebarPara(Flowable):
    """Paragraph with a coloured left border."""
    def __init__(self, para: Paragraph, border_color, bg_color=None, padding=8):
        Flowable.__init__(self)
        self._para        = para
        self._border      = border_color
        self._bg          = bg_color
        self._pad         = padding
        self._w, self._h  = 0, 0

    def wrap(self, aw, ah):
        w, h = self._para.wrap(aw - self._pad - 4, ah)
        self._w = aw
        self._h = h + self._pad * 2
        return aw, self._h

    def draw(self):
        c = self.canv
        if self._bg:
            c.setFillColor(self._bg)
            c.rect(4, 0, self._w - 4, self._h, fill=1, stroke=0)
        c.setFillColor(self._border)
        c.rect(0, 0, 4, self._h, fill=1, stroke=0)
        c.saveState()
        c.translate(4 + self._pad, self._pad)
        self._para.drawOn(c, 0, 0)
        c.restoreState()


# ═══════════════════════════════════════════════════════════════════════
#  SECTION BANNER BUILDER
# ═══════════════════════════════════════════════════════════════════════
def section_banner(text: str, icon: str = "▣") -> Table:
    """Full-width dark-blue banner with gold text + icon."""
    style = ParagraphStyle("_b", fontName="Helvetica-Bold", fontSize=15,
                            textColor=C["gold"], leading=20)
    t = Table([[Paragraph(f"{icon} &nbsp; {text.upper()}", style)]],
              colWidths=[BODY_W])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C["dark_blue"]),
        ("TOPPADDING",   (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0), (-1,-1), 14),
        ("LEFTPADDING",  (0,0), (-1,-1), 18),
        ("RIGHTPADDING", (0,0), (-1,-1), 18),
    ]))
    return t

def host_banner(ip: str, os_name: str, dev_class: str) -> Table:
    """Per-host gold banner."""
    style = ParagraphStyle("_hb", fontName="Helvetica-Bold", fontSize=13,
                            textColor=C["dark_blue"], leading=18)
    t = Table([[Paragraph(
        f"◈ &nbsp; {ip} &nbsp;│&nbsp; {dev_class} &nbsp;│&nbsp; {os_name}", style)]],
              colWidths=[BODY_W])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C["gold"]),
        ("TOPPADDING",   (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
        ("LEFTPADDING",  (0,0), (-1,-1), 16),
        ("RIGHTPADDING", (0,0), (-1,-1), 16),
    ]))
    return t


# ═══════════════════════════════════════════════════════════════════════
#  METRIC CARD ROW
# ═══════════════════════════════════════════════════════════════════════
def metric_cards(metrics: list) -> Table:
    """
    metrics = [(value, label, color), …]
    Renders a row of large KPI cards with dark-blue header band + white body.
    """
    n = len(metrics)
    w = BODY_W / n

    header_cells = []
    value_cells  = []

    for val, lbl, clr in metrics:
        lbl_s = ParagraphStyle(f"_mkl_{lbl}", fontName="Helvetica-Bold",
                               fontSize=8, leading=11,
                               textColor=C["gold"], alignment=TA_CENTER)
        val_s = ParagraphStyle(f"_mkv_{lbl}", fontName="Helvetica-Bold",
                               fontSize=26, leading=30,
                               textColor=clr, alignment=TA_CENTER)
        header_cells.append(Paragraph(lbl.upper(), lbl_s))
        value_cells.append(Paragraph(str(val), val_s))

    header_row = Table([header_cells], colWidths=[w] * n)
    header_row.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C["dark_blue"]),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
        ("INNERGRID",     (0,0), (-1,-1), 0.5, C["accent1"]),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))

    value_row = Table([value_cells], colWidths=[w] * n)
    value_row.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C["white"]),
        ("TOPPADDING",    (0,0), (-1,-1), 18),
        ("BOTTOMPADDING", (0,0), (-1,-1), 18),
        ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
        ("INNERGRID",     (0,0), (-1,-1), 0.5, C["grid"]),
        ("BOX",           (0,0), (-1,-1), 1.5, C["gold"]),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))

    wrapper = Table([[header_row], [value_row]], colWidths=[BODY_W])
    wrapper.setStyle(TableStyle([
        ("BOX",           (0,0), (-1,-1), 2, C["gold"]),
        ("TOPPADDING",    (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
        ("LEFTPADDING",   (0,0), (-1,-1), 0),
        ("RIGHTPADDING",  (0,0), (-1,-1), 0),
    ]))
    return wrapper


# ═══════════════════════════════════════════════════════════════════════
#  DISCOVERED-HOST VISUAL GRID
# ═══════════════════════════════════════════════════════════════════════
def build_live_hosts_visual(hosts: list) -> list:
    """
    Renders only the LIVE hosts as a card-grid – no greyed-out offline rows.
    Each card shows IP, OS family icon, device class, open-port count, severity badge.
    """
    story = []

    def severity_badge(host):
        vulns = host.get("vulnerabilities", [])
        for sev in ("critical", "high", "medium", "low"):
            if any(v.get("severity", "").lower() == sev for v in vulns):
                return sev
        return "info"

    sev_emoji = {
        "critical": "🔴 CRITICAL",
        "high":     "🟠 HIGH",
        "medium":   "🟡 MEDIUM",
        "low":      "🔵 LOW",
        "info":     "🟢 CLEAN",
    }
    os_icon = lambda os: (
        "⊞" if "windows" in (os or "").lower() else
        "🐧" if "linux"   in (os or "").lower() else
        "" if "mac"    in (os or "").lower() else
        "⬡"
    )

    COLS = 3
    row  = []
    rows = []
    for i, h in enumerate(hosts):
        sev      = severity_badge(h)
        badge_bg = sev_badge_bg(sev)
        badge_c  = sev_color(sev)
        svc_cnt  = len(h.get("services", []))
        vuln_cnt = len(h.get("vulnerabilities", []))
        icon     = os_icon(h.get("os", ""))

        ip_style  = ParagraphStyle("_ci", fontName="Helvetica-Bold", fontSize=11,
                                    textColor=C["dark_blue"])
        sub_style = ParagraphStyle("_cs", fontName="Helvetica", fontSize=8,
                                    leading=12, textColor=C["mid_gray"])
        sev_style = ParagraphStyle("_cv", fontName="Helvetica-Bold", fontSize=8,
                                    textColor=badge_c)

        card_content = [
            [Paragraph(f"{icon} {h['ip']}", ip_style)],
            [Paragraph(h.get("device_classification", "Unknown")[:28], sub_style)],
            [Paragraph((h.get("os") or "Unknown OS")[:30], sub_style)],
            [Spacer(1, 4)],
            [Table([[
                Paragraph(f"Ports: {svc_cnt}", sub_style),
                Paragraph(f"Vulns: {vuln_cnt}", sub_style),
            ]], colWidths=[1*inch, 1*inch], style=TableStyle([
                ("LEFTPADDING",  (0,0), (-1,-1), 0),
                ("RIGHTPADDING", (0,0), (-1,-1), 0),
                ("TOPPADDING",   (0,0), (-1,-1), 0),
                ("BOTTOMPADDING",(0,0), (-1,-1), 0),
            ]))],
            [Paragraph(sev_emoji.get(sev, "🟢 CLEAN"), sev_style)],
        ]
        card_inner = Table(card_content, colWidths=[BODY_W/COLS - 22])
        card_inner.setStyle(TableStyle([
            ("TOPPADDING",    (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("LEFTPADDING",   (0,0), (-1,-1), 2),
        ]))

        cell = Table([[card_inner]], colWidths=[BODY_W/COLS - 8])
        cell.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), badge_bg),
            ("BOX",           (0,0), (-1,-1), 1.5, badge_c),
            ("TOPPADDING",    (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
            ("LEFTPADDING",   (0,0), (-1,-1), 12),
            ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ]))

        row.append(cell)
        if len(row) == COLS:
            rows.append(row)
            row = []

    if row:  # pad last row
        while len(row) < COLS:
            row.append(Spacer(1, 1))
        rows.append(row)

    if not rows:
        story.append(Paragraph("No live hosts discovered.", ParagraphStyle(
            "_nl", fontName="Helvetica", fontSize=10, textColor=C["mid_gray"])))
        return story

    grid = Table(rows, colWidths=[BODY_W/COLS] * COLS)
    grid.setStyle(TableStyle([
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
    ]))
    story.append(grid)
    return story


# ═══════════════════════════════════════════════════════════════════════
#  VULNERABILITY SEVERITY DONUT CHART
# ═══════════════════════════════════════════════════════════════════════
def build_vuln_chart(all_vulns: list) -> Optional[Image]:
    try:
        sev_map   = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in all_vulns:
            sev_map[v.get("severity", "info").lower()] = sev_map.get(v.get("severity","info").lower(), 0) + 1
        labels = [k.capitalize() for k, c in sev_map.items() if c > 0]
        sizes  = [c for c in sev_map.values() if c > 0]
        palette = ["#B71C1C", "#E65100", "#F57F17", "#0D47A1", "#2E7D32"]
        clrs   = [palette[i] for i, (k,c) in enumerate(sev_map.items()) if c > 0]
        if not sizes:
            return None

        fig, ax = plt.subplots(figsize=(4, 3), facecolor="none")
        wedges, texts, autotexts = ax.pie( # type: ignore[misc]
            sizes, labels=labels, colors=clrs,
            autopct="%1.0f%%", startangle=140,
            wedgeprops=dict(width=0.55, edgecolor="white", linewidth=2),
            pctdistance=0.75, labeldistance=1.12,
        )
        for t in texts:      t.set_fontsize(9);  t.set_color("#111111")
        for a in autotexts:  a.set_fontsize(8);  a.set_color("white"); a.set_fontweight("bold")
        ax.set_title("Vulnerability Distribution", fontsize=10, color="#0B2545",
                     fontweight="bold", pad=8)
        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=140, bbox_inches="tight", transparent=True)
        plt.close(fig)
        buf.seek(0)
        return Image(buf, width=3.2*inch, height=2.4*inch)
    except Exception as e:
        logger.warning(f"Chart generation failed: {e}")
        return None


def build_risk_bar_chart(hosts: list) -> Optional[Image]:
    """Horizontal bar chart showing risk scores per host."""
    try:
        ips    = [h["ip"] for h in hosts if h.get("risk_score", 0) > 0]
        scores = [h.get("risk_score", 0) for h in hosts if h.get("risk_score", 0) > 0]
        if not ips:
            return None

        fig, ax = plt.subplots(figsize=(4, max(2, len(ips) * 0.5)), facecolor="none")
        clrs = ["#B71C1C" if s >= 75 else "#E65100" if s >= 50 else "#F57F17"
                if s >= 25 else "#0D47A1" for s in scores]
        bars = ax.barh(ips, scores, color=clrs, edgecolor="white", linewidth=0.5)
        ax.set_xlim(0, 100)
        ax.set_xlabel("Risk Score", fontsize=8, color="#6C757D")
        ax.set_title("Host Risk Scores", fontsize=10, color="#0B2545", fontweight="bold")
        ax.tick_params(axis="y", labelsize=8, colors="#111111")
        ax.tick_params(axis="x", labelsize=7, colors="#6C757D")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        for bar, score in zip(bars, scores):
            ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                    f"{score:.0f}", va="center", ha="left", fontsize=7, color="#111111")
        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=140, bbox_inches="tight", transparent=True)
        plt.close(fig)
        buf.seek(0)
        return Image(buf, width=3.2*inch, height=max(1.8, len(ips)*0.5)*inch)
    except Exception as e:
        logger.warning(f"Risk chart failed: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════
#  TERMINAL / NSE EVIDENCE BLOCKS
# ═══════════════════════════════════════════════════════════════════════
def _strip_command_from_output(output: str) -> str:
    """
    Remove the '$ <command>' line(s) from raw command output so only
    the actual result is displayed in the evidence block.
    Handles both the short preview line and the full-width wrapped line.
    """
    lines = output.split("\n")
    filtered = []
    skip_next_blank = False
    for line in lines:
        stripped = line.strip()
        # Skip lines that look like shell prompts or command repetitions
        if (stripped.startswith("$ ") or
                stripped.startswith("C:\\") or
                stripped.startswith("c:\\") or
                (stripped.startswith("[stderr]") and len(stripped) < 80)):
            skip_next_blank = True
            continue
        # Skip the blank line immediately after a command line
        if skip_next_blank and stripped == "":
            skip_next_blank = False
            continue
        skip_next_blank = False
        filtered.append(line)

    # Remove leading blank lines
    while filtered and not filtered[0].strip():
        filtered.pop(0)
    return "\n".join(filtered)


def build_terminal_snapshot(title: str, cmd: str, output: str, timestamp: str) -> list:
    """
    Dark terminal block showing ONLY the command output — no '$ cmd' line.
    The title bar names the tool/operation; the body shows the result.
    """
    # Strip the command invocation — show result only
    clean_output = _strip_command_from_output(output)

    lines = clean_output.split("\n")
    if len(lines) > 40:
        lines = lines[:40] + [f"... [{len(lines)-40} additional lines truncated]"]
    clean = xml_escape("\n".join(lines))
    clean = clean.replace("\n", "<br/>").replace("  ", "&nbsp;&nbsp;")

    text_hex = hex_of(C["term_text"])

    title_s = ParagraphStyle("_tt", fontName="Helvetica-Bold", fontSize=8,
                               textColor=C["gold"])
    body_s  = ParagraphStyle("_tb", fontName="Courier", fontSize=7.5, leading=11,
                               textColor=C["term_text"])

    title_row = Table(
        [[Paragraph(f"⬛ ⬛ ⬛  {xml_escape(title)}  │  {xml_escape(timestamp)}", title_s)]],
        colWidths=[BODY_W])
    title_row.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C["term_bar"]),
        ("TOPPADDING",   (0,0), (-1,-1), 7),
        ("BOTTOMPADDING",(0,0), (-1,-1), 7),
        ("LEFTPADDING",  (0,0), (-1,-1), 14),
    ]))
    body_row = Table(
        [[Paragraph(f"<font color='{text_hex}'>{clean}</font>", body_s)]],
        colWidths=[BODY_W])
    body_row.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C["term_bg"]),
        ("TOPPADDING",   (0,0), (-1,-1), 12),
        ("BOTTOMPADDING",(0,0), (-1,-1), 12),
        ("LEFTPADDING",  (0,0), (-1,-1), 14),
        ("RIGHTPADDING", (0,0), (-1,-1), 14),
        ("BOX",          (0,0), (-1,-1), 0.8, colors.HexColor("#2A2A2A")),
    ]))
    return [title_row, body_row]


def build_nse_evidence_block(script_id: str, output: str) -> list:
    """
    Dark terminal block for raw Nmap NSE script output.
    Faithfully preserves the | pipe formatting used by nmap.
    """
    lines = output.split("\n")
    if len(lines) > 50:
        lines = lines[:50] + [f"... [{len(lines)-50} additional lines truncated]"]
    # Escape and preserve spacing
    formatted = "<br/>".join(
        xml_escape(l).replace(" ", "&nbsp;") for l in lines
    )

    gold_hex = hex_of(C["gold"])
    title_s  = ParagraphStyle("_nt", fontName="Helvetica-Bold", fontSize=8.5,
                               textColor=C["gold"])
    body_s   = ParagraphStyle("_nb", fontName="Courier", fontSize=8, leading=11.5,
                               textColor=C["term_text"])

    title_row = Table(
        [[Paragraph(f"◈ NSE &nbsp;│&nbsp; {xml_escape(script_id.upper())}", title_s)]],
        colWidths=[BODY_W])
    title_row.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C["dark_blue"]),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("LEFTPADDING",  (0,0), (-1,-1), 14),
    ]))
    body_row = Table(
        [[Paragraph(formatted, body_s)]],
        colWidths=[BODY_W])
    body_row.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C["term_bg"]),
        ("TOPPADDING",   (0,0), (-1,-1), 12),
        ("BOTTOMPADDING",(0,0), (-1,-1), 12),
        ("LEFTPADDING",  (0,0), (-1,-1), 14),
        ("RIGHTPADDING", (0,0), (-1,-1), 14),
        ("BOX",          (0,0), (-1,-1), 1.5, C["dark_blue"]),
    ]))
    return [title_row, body_row]


def build_credential_evidence_block(ev: dict) -> list:
    """
    Renders an SSH / FTP / protocol session transcript block.
    """
    service   = (ev.get("service") or "PROTOCOL").upper()
    port      = ev.get("port", 0)
    timestamp = ev.get("timestamp", "")
    content   = ev.get("content") or ev.get("output", "")
    return build_terminal_snapshot(
        f"SESSION TRANSCRIPT  │  {service}:{port}",
        f"Authenticated session on {service} port {port}",
        content,
        timestamp,
    )


# ═══════════════════════════════════════════════════════════════════════
#  OPEN PORTS TABLE
# ═══════════════════════════════════════════════════════════════════════
def build_ports_table(services: list, styles: dict) -> Table:
    rows = [[
        Paragraph("PORT",     styles["th"]),
        Paragraph("PROTO",    styles["th"]),
        Paragraph("SERVICE",  styles["th"]),
        Paragraph("VERSION / BANNER", styles["th"]),
        Paragraph("STATE",    styles["th"]),
    ]]
    for s in services:
        ver = (s.get("version") or s.get("banner") or "-")[:50]
        rows.append([
            Paragraph(f"<b>{s['port']}</b>", styles["td_mono"]),
            Paragraph(s.get("protocol","tcp"),   styles["td"]),
            Paragraph(s.get("name","?"),          styles["td"]),
            Paragraph(xml_escape(ver),            styles["td"]),
            Paragraph(s.get("state","open"),      styles["td"]),
        ])
    t = Table(rows, colWidths=[0.65*inch, 0.6*inch, 1.3*inch, 3.6*inch, 0.7*inch])
    style_cmds = [
        ("BACKGROUND",    (0,0), (-1,0), C["dark_blue"]),
        ("TEXTCOLOR",     (0,0), (-1,0), C["gold"]),
        ("PADDING",       (0,0), (-1,-1), 7),
        ("LINEBELOW",     (0,0), (-1,0), 1.5, C["gold"]),
        ("GRID",          (0,1), (-1,-1), 0.4, C["grid"]),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0,i), (-1,i), C["stripe"]))
    t.setStyle(TableStyle(style_cmds))
    return t


# ═══════════════════════════════════════════════════════════════════════
#  VULNERABILITY TABLE
# ═══════════════════════════════════════════════════════════════════════
def build_vuln_table(vulns: list, styles: dict) -> Table:
    rows = [[
        Paragraph("SEVERITY", styles["th"]),
        Paragraph("NAME",     styles["th"]),
        Paragraph("CVE",      styles["th"]),
        Paragraph("CVSS",     styles["th"]),
        Paragraph("SOURCE",   styles["th"]),
    ]]
    for v in vulns:
        sev   = v.get("severity","info")
        sev_c = sev_color(sev)
        sev_p = ParagraphStyle("_sv", fontName="Helvetica-Bold", fontSize=8,
                                textColor=sev_c)
        rows.append([
            Paragraph(sev.upper(), sev_p),
            Paragraph(xml_escape(v.get("name","?")[:60]),  styles["td"]),
            Paragraph(v.get("cve_id") or "–",              styles["td_mono"]),
            Paragraph(f"{v['cvss_score']:.1f}" if v.get("cvss_score") else "–", styles["td"]),
            Paragraph(v.get("source","nuclei")[:12],        styles["td"]),
        ])
    t = Table(rows, colWidths=[0.85*inch, 3.2*inch, 1.2*inch, 0.65*inch, 0.95*inch])
    style_cmds = [
        ("BACKGROUND",    (0,0), (-1,0), C["dark_blue"]),
        ("TEXTCOLOR",     (0,0), (-1,0), C["gold"]),
        ("PADDING",       (0,0), (-1,-1), 7),
        ("LINEBELOW",     (0,0), (-1,0), 1.5, C["gold"]),
        ("GRID",          (0,1), (-1,-1), 0.4, C["grid"]),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0,i), (-1,i), C["stripe"]))
    t.setStyle(TableStyle(style_cmds))
    return t


# ═══════════════════════════════════════════════════════════════════════
#  RECOMMENDATION BOX
# ═══════════════════════════════════════════════════════════════════════
def rec_box(items: list, styles: dict) -> Table:
    bullets = "<br/>".join(
        f"<b>{'→'}</b> {xml_escape(item)}" for item in items
    )
    t = Table([[Paragraph(bullets, styles["rec"])]], colWidths=[BODY_W])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C["green_bg"]),
        ("PADDING",      (0,0), (-1,-1), 14),
        ("LINELEFT",     (0,0), (-1,-1), 5, C["green_border"]),
        ("BOX",          (0,0), (-1,-1), 0.8, C["green_border"]),
    ]))
    return t


# ═══════════════════════════════════════════════════════════════════════
#  PAGE CANVAS DECORATOR  (header stripe + footer)
# ═══════════════════════════════════════════════════════════════════════
def _page_decorator(canv, doc, scan_target: str, scan_date: str):
    canv.saveState()
    W, H = PAGE_W, PAGE_H

    # Top accent stripe (3 px gold)
    canv.setFillColor(C["gold"])
    canv.rect(0, H - 6, W, 6, fill=1, stroke=0)

    # Footer bar
    canv.setFillColor(C["dark_blue"])
    canv.rect(0, 0, W, 22, fill=1, stroke=0)

    canv.setFont("Helvetica", 7)
    canv.setFillColor(C["gold"])
    canv.drawString(M, 7, "CONFIDENTIAL — Network Security Audit Report")
    canv.drawRightString(W - M, 7, f"Target: {scan_target}  │  {scan_date}  │  Page {doc.page}")

    canv.restoreState()


# ═══════════════════════════════════════════════════════════════════════
#  COVER PAGE
#  Logo: place  intelligent.png  at  C:/Users/<you>/Desktop/intelligent.png
#  The code also checks  ./intelligent.png  and  ./assets/intelligent.png
#  so you can copy the file next to main.py if preferred.
# ═══════════════════════════════════════════════════════════════════════
LOGO_SEARCH_PATHS = [
    # backend/intelligent.png  (same level as main.py — where you placed it)
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "intelligent.png"),
    # backend/services/intelligent.png  (inside services/ as fallback)
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "intelligent.png"),
    # Desktop fallback
    os.path.join(os.path.expanduser("~"), "Desktop", "intelligent.png"),
    os.path.join(os.path.expanduser("~"), "Desktop", "Intelligent.png"),
    # Current working directory (wherever uvicorn is launched from)
    "intelligent.png",
]

def _find_logo() -> Optional[str]:
    for p in LOGO_SEARCH_PATHS:
        if os.path.exists(p):
            return p
    return None


def build_cover(scan, styles: dict) -> list:
    date_str = scan.started_at.strftime("%B %d, %Y") if scan.started_at else "N/A"
    duration = "N/A"
    if scan.started_at and scan.finished_at:
        secs     = int((scan.finished_at - scan.started_at).total_seconds())
        duration = f"{secs//3600}h {(secs%3600)//60}m {secs%60}s"

    logo_path = _find_logo()
    INNER_W   = BODY_W - 84   # usable width inside the dark cover panel

    # ── Top bar: classification tag (left)  +  logo pinned top-right ──
    tag_style = ParagraphStyle("_covtag", fontName="Helvetica-Bold", fontSize=8.5,
                                textColor=C["gold"], leading=12, alignment=TA_LEFT)
    tag_para  = Paragraph(
        "CONFIDENTIAL &nbsp;/&nbsp; SECURITY AUDIT REPORT", tag_style)

    if logo_path:
        try:
            logo_img = Image(logo_path, width=2.0*inch, height=0.58*inch)
            logo_img.hAlign = "RIGHT"
            logo_cell = logo_img
        except Exception as e:
            logger.warning(f"[PDF] Logo load failed: {e}")
            logo_cell = Spacer(1, 1)
    else:
        logo_cell = Spacer(1, 1)

    header_row = Table([[tag_para, logo_cell]],
                        colWidths=[INNER_W - 2.1*inch, 2.1*inch])
    header_row.setStyle(TableStyle([
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("ALIGN",         (1,0), (1,0),  "RIGHT"),
        ("LEFTPADDING",   (0,0), (-1,-1), 0),
        ("RIGHTPADDING",  (0,0), (-1,-1), 0),
        ("TOPPADDING",    (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))

    # ── Title block ────────────────────────────────────────────────────
    title_style = ParagraphStyle("_covtitle2", fontName="Helvetica-Bold", fontSize=42,
                                  leading=46, textColor=C["gold"])
    title_para = Paragraph("NETWORK SECURITY<br/>AUDIT", title_style)

    subtitle_style = ParagraphStyle("_covsub2", fontName="Helvetica", fontSize=12.5,
                                     leading=18, textColor=colors.HexColor("#C9D6E3"))
    subtitle_para = Paragraph(
        "COMPREHENSIVE VULNERABILITY &amp; RISK ASSESSMENT", subtitle_style)

    # ── Stat cards (2 × 2) ─────────────────────────────────────────────
    def stat_card(label, value, width):
        lbl_p = Paragraph(label, ParagraphStyle(
            f"_scl_{label}", fontName="Helvetica-Bold", fontSize=8,
            textColor=C["gold"], leading=11))
        val_p = Paragraph(xml_escape(str(value)), ParagraphStyle(
            f"_scv_{label}", fontName="Courier", fontSize=13,
            textColor=C["white"], leading=17))
        inner = Table([[lbl_p], [Spacer(1, 5)], [val_p]],
                      colWidths=[width - 22])
        inner.setStyle(TableStyle([
            ("LEFTPADDING", (0,0), (-1,-1), 0),
            ("TOPPADDING",  (0,0), (-1,-1), 0),
            ("BOTTOMPADDING",(0,0),(-1,-1), 0),
        ]))
        card = Table([[inner]], colWidths=[width])
        card.setStyle(TableStyle([
            ("LINEBEFORE",   (0,0), (-1,-1), 2.2, C["gold"]),
            ("TOPPADDING",   (0,0), (-1,-1), 10),
            ("BOTTOMPADDING",(0,0), (-1,-1), 14),
            ("LEFTPADDING",  (0,0), (-1,-1), 14),
        ]))
        return card

    half = INNER_W / 2
    stats_grid = Table([
        [stat_card("TARGET", scan.target, half), stat_card("REPORT DATE", date_str, half)],
        [stat_card("SCAN DURATION", duration, half), stat_card("CLASSIFICATION", "CONFIDENTIAL", half)],
    ], colWidths=[half, half])
    stats_grid.setStyle(TableStyle([
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 0),
        ("RIGHTPADDING",  (0,0), (-1,-1), 0),
    ]))

    disclaimer_style = ParagraphStyle("_covdisc2", fontName="Helvetica-Oblique", fontSize=8,
                                       leading=11.5, textColor=colors.HexColor("#8FA3B8"))
    disclaimer_para = Paragraph(
        "This report was generated automatically by an AI-powered audit engine, based "
        "on real-time network probing data captured during the assessment window.",
        disclaimer_style)

    # ── Assemble the full dark cover panel ─────────────────────────────
    panel_rows = [
        [Spacer(1, 8)],
        [header_row],
        [Spacer(1, 46)],
        [title_para],
        [Spacer(1, 8)],
        [ThinRule(2.4*inch, C["gold"])],
        [Spacer(1, 12)],
        [subtitle_para],
        [Spacer(1, 46)],
        [DiagonalWeave(INNER_W, 11)],
        [Spacer(1, 34)],
        [stats_grid],
        [Spacer(1, 46)],
        [disclaimer_para],
        [Spacer(1, 6)],
    ]
    cover_panel = Table(panel_rows, colWidths=[BODY_W])
    cover_panel.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C["dark_blue"]),
        ("LEFTPADDING",   (0,0), (-1,-1), 42),
        ("RIGHTPADDING",  (0,0), (-1,-1), 42),
        ("TOPPADDING",    (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))

    # ── Edge-to-edge techy footer strip (tools used) ───────────────────
    tools_style = ParagraphStyle("_covtools2", fontName="Helvetica-Bold", fontSize=8.5,
                                  textColor=C["gold"], leading=13)
    tools_para = Paragraph(
        "NMAP&nbsp;7.99 &nbsp;·&nbsp; NUCLEI &nbsp;·&nbsp; AI ANALYSIS ENGINE "
        "&nbsp;·&nbsp; EVIDENCE CAPTURE MODULE", tools_style)
    tools_row = Table([[tools_para]], colWidths=[BODY_W])
    tools_row.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C["accent2"]),
        ("TOPPADDING",    (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("LEFTPADDING",   (0,0), (-1,-1), 42),
    ]))

    return [cover_panel, tools_row, PageBreak()]


# ═══════════════════════════════════════════════════════════════════════
#  HOST NARRATIVE GENERATOR
# ═══════════════════════════════════════════════════════════════════════
def generate_host_narrative(h: dict) -> str:
    ip       = h["ip"]
    os_name  = h.get("os") or "an unidentified operating system"
    dev      = h.get("device_classification") or "network device"
    svcs     = h.get("services", [])
    vulns    = h.get("vulnerabilities", [])
    hostname = h.get("hostname", "Unknown")

    web_ports = [s["port"] for s in svcs if s["port"] in {80,443,8080,8443,3000,8000}]
    db_ports  = [s["port"] for s in svcs if s["port"] in {3306,5432,1521,27017,6379}]
    crit_v    = [v for v in vulns if v.get("severity","").lower() == "critical"]
    high_v    = [v for v in vulns if v.get("severity","").lower() == "high"]

    parts = [f"Host <b>{ip}</b>"]
    if hostname and hostname not in ("Unknown", ""):
        parts[0] += f" (hostname: <b>{hostname}</b>)"
    parts[0] += f" is classified as a <b>{dev}</b> running <b>{os_name}</b>."

    if svcs:
        parts.append(f"A total of <b>{len(svcs)} TCP/UDP services</b> are reachable on this host, "
                     "widening the network attack surface.")
        if web_ports:
            parts.append(f"Web-facing interfaces on ports <b>{', '.join(map(str,web_ports))}</b> "
                         "present an application-layer exposure vector susceptible to injection, "
                         "XSS, and authentication-bypass attacks.")
        if db_ports:
            parts.append(f"Database services on ports <b>{', '.join(map(str,db_ports))}</b> "
                         "represent a high-value target for data exfiltration if not properly segmented.")
    else:
        parts.append("No open TCP/UDP services were discovered — this host may be behind "
                     "strict egress filtering or is currently dormant.")

    if crit_v:
        parts.append(f"<b>⚠ {len(crit_v)} CRITICAL vulnerability(ies)</b> were confirmed — "
                     "immediate remediation is mandatory.")
    if high_v:
        parts.append(f"<b>{len(high_v)} high-severity finding(s)</b> also require prioritised attention.")
    if not vulns:
        parts.append("No known vulnerabilities were matched by automated scanning tools — "
                     "manual penetration testing is still recommended.")

    return " ".join(parts)


# ═══════════════════════════════════════════════════════════════════════
#  IMPACT NARRATIVE (per vulnerability)
# ═══════════════════════════════════════════════════════════════════════
def vuln_impact_block(v: dict, styles: dict) -> list:
    sev   = v.get("severity","info")
    sev_c = sev_color(sev)
    bg    = sev_badge_bg(sev)
    name  = xml_escape(v.get("name","Unknown Vulnerability"))
    cve   = v.get("cve_id") or "—"
    cvss  = f"{v['cvss_score']:.1f}" if v.get("cvss_score") else "—"
    raw_desc = v.get("description") or ""
    # If NVD returned no description or the placeholder string, ask the LLM
    _nvd_empty = (
        not raw_desc.strip()
        or "Aucune description" in raw_desc
        or "No description available" in raw_desc
        or len(raw_desc.strip()) < 20
    )
    if _nvd_empty:
        raw_desc = get_vuln_description_sync(
            v.get("name",""), cve if cve != "—" else "", sev, cvss
        )
    desc  = xml_escape(raw_desc[:600])
    rem   = xml_escape((v.get("remediation") or "Apply vendor patch; restrict service access.")[:300])

    header_style = ParagraphStyle("_vh", fontName="Helvetica-Bold", fontSize=10,
                                   textColor=C["white"])
    header = Table(
        [[Paragraph(f"[{sev.upper()}]  {name}", header_style)]],
        colWidths=[BODY_W])
    header.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), sev_c),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("LEFTPADDING",  (0,0), (-1,-1), 12),
    ]))

    meta_parts = [f"CVE: <b>{cve}</b>", f"CVSS: <b>{cvss}</b>",
                  f"Source: <b>{v.get('source','nuclei')}</b>"]
    meta_style = ParagraphStyle("_vm", fontName="Courier", fontSize=8,
                                 textColor=C["dark_blue"])
    body = Table(
        [[Paragraph(f"<b>Impact:</b> {desc}", styles["body"])],
         [Paragraph("&nbsp;".join(f" {p} " for p in meta_parts), meta_style)],
         [Paragraph(f"<b>Fix:</b> {rem}", styles["body"])],
        ], colWidths=[BODY_W])
    body.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), bg),
        ("TOPPADDING",   (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 6),
        ("LEFTPADDING",  (0,0), (-1,-1), 12),
        ("RIGHTPADDING", (0,0), (-1,-1), 12),
        ("LINELEFT",     (0,0), (-1,-1), 4, sev_c),
    ]))
    return [header, body, Spacer(1, 8)]


# ═══════════════════════════════════════════════════════════════════════
#  EVIDENCE SELECTOR
#  Picks 1-2 high-value evidence items per host (NSE > cmd > text > web)
# ═══════════════════════════════════════════════════════════════════════
def pick_best_evidence(evidence_items: list, max_items: int = 2) -> list:
    """
    Priority order: nse_script with VULNERABLE keyword > auth_screenshot
    > nse_script (any) > text > command > web_screenshot
    """
    nse_vuln  = [e for e in evidence_items if e.get("type")=="nse_script"
                 and "VULNERABLE" in (e.get("output") or "")]
    auth_ss   = [e for e in evidence_items if e.get("type")=="auth_screenshot"]
    nse_other = [e for e in evidence_items if e.get("type")=="nse_script"
                 and "VULNERABLE" not in (e.get("output") or "")
                 and (e.get("output") or "").strip()
                 and "false" not in (e.get("output") or "").strip().lower()
                 and "error" not in (e.get("output") or "").strip().lower()[:20]]
    text_ev   = [e for e in evidence_items if e.get("type")=="text"]
    cmd_ev    = [e for e in evidence_items if e.get("type")=="command"]
    web_ss    = [e for e in evidence_items if e.get("type")=="web_screenshot"]

    chosen = []
    for bucket in (nse_vuln, auth_ss, nse_other, text_ev, cmd_ev, web_ss):
        for item in bucket:
            if len(chosen) >= max_items:
                break
            chosen.append(item)
        if len(chosen) >= max_items:
            break
    return chosen


def render_evidence_item(ev: dict, host_ip: str, styles: dict) -> list:
    elems = []
    t = ev.get("type","")

    if t == "nse_script":
        elems.extend(build_nse_evidence_block(ev.get("script_id","unknown"), ev.get("output","")))
        elems.append(Paragraph(
            f"Fig: Nmap NSE — {ev.get('script_id','')} on {host_ip}  │  {ev.get('timestamp','')}",
            styles["caption"]))

    elif t == "command":
        elems.extend(build_terminal_snapshot(
            "COMMAND EXECUTION", ev.get("cmd",""), ev.get("output",""), ev.get("timestamp","")))
        elems.append(Paragraph(
            f"Fig: {ev.get('label','')}  │  {ev.get('timestamp','')}", styles["caption"]))

    elif t == "text":
        elems.extend(build_credential_evidence_block(ev))
        elems.append(Paragraph(
            f"Fig: {ev.get('label','')}  │  {ev.get('timestamp','')}", styles["caption"]))

    elif t in ("web_screenshot", "auth_screenshot"):
        path = ev.get("path","")
        if path and os.path.exists(path):
            try:
                img = Image(path, width=BODY_W, height=3.6*inch)
                img.hAlign = "LEFT"
                frame = Table([[img]], colWidths=[BODY_W])
                frame.setStyle(TableStyle([
                    ("BOX",        (0,0), (-1,-1), 2, C["dark_blue"]),
                    ("PADDING",    (0,0), (-1,-1), 3),
                    ("BACKGROUND", (0,0), (-1,-1), C["light_gray"]),
                ]))
                elems.append(frame)
                elems.append(Paragraph(
                    f"Fig: Live capture — {ev.get('label','')}", styles["caption"]))
            except Exception:
                pass

    if elems:
        elems.append(Spacer(1, 10))
    return elems


# ═══════════════════════════════════════════════════════════════════════
#  TOC  — styled card-based design
# ═══════════════════════════════════════════════════════════════════════
def build_toc(hosts: list, styles: dict) -> list:
    """
    Modern, single-page index. Deliberately does NOT enumerate individual
    hosts (that quick-nav strip was dropped — it was visually noisy and
    pushed the report onto an extra, half-empty page). Host-level detail
    still lives in full in §4 Host-by-Host Deep Dive.
    """
    story = []

    # ── Header bar ──────────────────────────────────────────────────────
    toc_title_s = ParagraphStyle("_toch2", fontName="Helvetica-Bold", fontSize=22,
                                  textColor=C["gold"], alignment=TA_LEFT)
    toc_sub_s   = ParagraphStyle("_tochsub2", fontName="Helvetica-Bold", fontSize=9,
                                  textColor=colors.HexColor("#9FB3C8"), alignment=TA_RIGHT,
                                  leading=12)
    toc_header = Table(
        [[Paragraph("TABLE OF CONTENTS", toc_title_s),
          Paragraph(f"{len(hosts)} HOST(S)<br/>AUDITED", toc_sub_s)]],
        colWidths=[BODY_W * 0.72, BODY_W * 0.28])
    toc_header.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C["dark_blue"]),
        ("TOPPADDING",    (0,0), (-1,-1), 22),
        ("BOTTOMPADDING", (0,0), (-1,-1), 22),
        ("LEFTPADDING",   (0,0), (-1,-1), 24),
        ("RIGHTPADDING",  (0,0), (-1,-1), 24),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",         (1,0), (1,0), "RIGHT"),
    ]))
    story.append(toc_header)
    story.append(DiagonalWeave(BODY_W, 8))
    story.append(Spacer(1, 24))

    # ── Section index ────────────────────────────────────────────────────
    main_sections = [
        ("01", "Executive Summary",
         "High-level overview of findings, key risks, and overall security verdict."),
        ("02", "Scan Overview & Metrics",
         "KPI dashboard, vulnerability distribution charts, and scan metadata."),
        ("03", "Discovered Hosts — Network Map",
         "Visual inventory of all live devices found on the network."),
        ("04", "Host-by-Host Deep Dive",
         "Granular per-asset analysis: ports, vulnerabilities, evidence, remediation."),
        ("05", "Vulnerability Analysis",
         "Consolidated registry of all findings across the entire network."),
        ("06", "Strategic Roadmap & Recommendations",
         "Prioritised action plan to address identified security gaps."),
        ("07", "Conclusion & Sign-Off",
         "Final verdict, likelihood of compromise assessment, and auditor sign-off."),
    ]

    title_s = ParagraphStyle("_tt3", fontName="Helvetica-Bold", fontSize=12.5,
                              textColor=C["dark_blue"], leading=16)
    desc_s  = ParagraphStyle("_td3", fontName="Helvetica", fontSize=9.3,
                              textColor=C["mid_gray"], leading=13)
    num_dark_s = ParagraphStyle("_tnd", fontName="Helvetica-Bold", fontSize=18,
                                 textColor=C["white"], alignment=TA_CENTER, leading=22)
    num_gold_s = ParagraphStyle("_tng", fontName="Helvetica-Bold", fontSize=18,
                                 textColor=C["dark_blue"], alignment=TA_CENTER, leading=22)

    NUM_W = 0.62 * inch
    for i, (num, title, desc) in enumerate(main_sections):
        chip_style, chip_bg = (num_gold_s, C["gold"]) if i % 2 else (num_dark_s, C["dark_blue"])
        chip = Table([[Paragraph(num, chip_style)]], colWidths=[NUM_W], rowHeights=[NUM_W])
        chip.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), chip_bg),
            ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ]))

        text_cell = Table(
            [[Paragraph(title, title_s)], [Spacer(1, 3)], [Paragraph(desc, desc_s)]],
            colWidths=[BODY_W - NUM_W - 30])
        text_cell.setStyle(TableStyle([
            ("LEFTPADDING",   (0,0), (-1,-1), 0),
            ("TOPPADDING",    (0,0), (-1,-1), 0),
            ("BOTTOMPADDING", (0,0), (-1,-1), 0),
        ]))

        row = Table([[chip, text_cell]], colWidths=[NUM_W, BODY_W - NUM_W])
        row.setStyle(TableStyle([
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING",   (1,0), (1,0), 18),
            ("LEFTPADDING",   (0,0), (0,0), 0),
            ("RIGHTPADDING",  (0,0), (-1,-1), 0),
            ("TOPPADDING",    (0,0), (-1,-1), 13),
            ("BOTTOMPADDING", (0,0), (-1,-1), 13),
            ("LINEBELOW",     (0,0), (-1,-1), 0.6,
             C["grid"] if i < len(main_sections) - 1 else colors.transparent),
        ]))
        story.append(row)

    story.append(Spacer(1, 22))
    story.append(ThinRule(BODY_W, C["gold"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Every discovered host receives a full dedicated write-up inside "
        "§ 04 — Host-by-Host Deep Dive, including open ports, vulnerabilities, "
        "forensic evidence, and targeted remediation guidance.",
        ParagraphStyle("_tocfoot", fontName="Helvetica-Oblique", fontSize=8.5,
                        textColor=C["mid_gray"], leading=12)))
    story.append(PageBreak())
    return story


# ═══════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════
async def generate_pdf_report(scan_id: str) -> bytes:
    # ── Lazy imports (avoids circular deps) ────────────────────────────
    from main import AsyncSessionLocal, Scan, Host, select, selectinload, compute_health_score
    from services.audit_analysis import (
        fetch_audit_analysis, generate_audit_analysis,
        persist_audit_analysis, build_scan_context, build_fallback_analysis,
    )

    # 1.  Fetch scan data ──────────────────────────────────────────────
    async with AsyncSessionLocal() as session:
        s_res = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan  = s_res.scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        h_res = await session.execute(
            select(Host).where(Host.scan_id == scan_id)
            .options(selectinload(Host.services), selectinload(Host.vulnerabilities))
        )
        hosts_orm = h_res.scalars().unique().all()

    hosts = [{
        "ip":                  h.ip,
        "hostname":            h.hostname or "Unknown",
        "os":                  h.os or "Unknown",
        "os_family":           h.os_family or "Unknown",
        "mac_address":         h.mac_address or "Unknown",
        "mac_vendor":          h.mac_vendor or "",
        "device_type":         h.device_type or "Unknown",
        "device_classification": h.device_classification or "Unknown Device",
        "risk_score":          h.risk_score or 0.0,
        "criticality":         h.criticality or "Unknown",
        "is_gateway":          h.is_gateway,
        "scanned":             len(h.services) > 0,
        "screenshot_path":     h.screenshot_path,
        "evidence":            h.evidence or [],
        "services": [
            {"port": s.port, "protocol": s.protocol, "name": s.name,
             "version": s.version, "state": s.state, "banner": s.banner}
            for s in sorted(h.services, key=lambda x: x.port)
        ],
        "vulnerabilities": [
            {"template_id": v.template_id, "name": v.name, "severity": v.severity,
             "cve_id": v.cve_id, "cvss_score": v.cvss_score, "description": v.description,
             "source": v.source, "matcher_name": v.matcher_name,
             "remediation": v.remediation, "exploit_available": v.exploit_available}
            for v in h.vulnerabilities
        ],
    } for h in hosts_orm]

    # Sort: most critical first
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    def host_severity(h):
        vulns = h.get("vulnerabilities", [])
        if not vulns: return 5
        return min(sev_rank.get(v["severity"].lower(), 4) for v in vulns)
    hosts.sort(key=host_severity)

    # 2.  AI analysis ──────────────────────────────────────────────────
    analysis = await fetch_audit_analysis(scan_id)
    if not analysis:
        try:
            analysis = await generate_audit_analysis(scan_id)
            if analysis: await persist_audit_analysis(scan_id, analysis)
        except Exception as e:
            logger.warning(f"[PDF] LLM failed: {e}")
            try:
                ctx = await build_scan_context(scan_id)
                analysis = build_fallback_analysis(ctx) if ctx else None
            except Exception:
                analysis = None
    if not analysis:
        analysis = {
            "executive_summary": "Analysis unavailable.",
            "security_score": 50, "maturity_level": "Unknown",
            "key_findings": [], "strategic_recommendations": [],
            "overall_verdict": "Pending Review.",
        }

    # 3.  Aggregates ───────────────────────────────────────────────────
    all_vulns  = [v for h in hosts for v in h["vulnerabilities"]]
    health_score = compute_health_score([{"severity": v["severity"]} for v in all_vulns])
    crit_count = sum(1 for v in all_vulns if v["severity"].lower() == "critical")
    high_count = sum(1 for v in all_vulns if v["severity"].lower() == "high")
    med_count  = sum(1 for v in all_vulns if v["severity"].lower() == "medium")
    scan_date  = scan.started_at.strftime("%Y-%m-%d") if scan.started_at else "N/A"

    # 4.  Styles ───────────────────────────────────────────────────────
    styles = make_styles()

    # 5.  Document ─────────────────────────────────────────────────────
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=M, rightMargin=M,
        topMargin=M + 12, bottomMargin=M + 18,
    )

    decorator = lambda canv, d: _page_decorator(canv, d, scan.target, scan_date)

    # ══════════════════════════════════════════════════════════════════
    #  STORY ASSEMBLY
    # ══════════════════════════════════════════════════════════════════
    story = []

    # ── COVER ─────────────────────────────────────────────────────────
    story.extend(build_cover(scan, styles))

    # ── TABLE OF CONTENTS ─────────────────────────────────────────────
    story.extend(build_toc(hosts, styles))

    # ── §1  EXECUTIVE SUMMARY ─────────────────────────────────────────
    story.append(section_banner("1  ·  Executive Summary", "◈"))
    story.append(Spacer(1, 16))

    exec_text = analysis.get("executive_summary", "No summary available.")
    story.append(Paragraph(exec_text, styles["body"]))
    story.append(Spacer(1, 20))

    # Key findings list
    key_findings = analysis.get("key_findings", [])
    if key_findings:
        story.append(Paragraph("Key Findings", styles["h3"]))
        for kf in key_findings[:6]:
            text = kf if isinstance(kf, str) else kf.get("finding", str(kf))
            story.append(Paragraph(f"→ {xml_escape(text)}", styles["body"]))
    story.append(Spacer(1, 16))

    # Verdict badge
    verdict = analysis.get("overall_verdict", "")
    if verdict:
        v_style = ParagraphStyle("_vrd", fontName="Helvetica-Bold", fontSize=11,
                                  textColor=C["dark_blue"])
        v_box = Table([[Paragraph(f"OVERALL VERDICT: {xml_escape(verdict)}", v_style)]],
                      colWidths=[BODY_W])
        v_box.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), C["gold"]),
            ("PADDING",      (0,0), (-1,-1), 14),
            ("LEFTPADDING",  (0,0), (-1,-1), 18),
        ]))
        story.append(v_box)

    story.append(PageBreak())

    # ── §2  METRICS ───────────────────────────────────────────────────
    story.append(section_banner("2  ·  Scan Overview & Metrics", "◈"))
    story.append(Spacer(1, 16))

    story.append(metric_cards([
        (f"{int(health_score)}/100", "Security Score",  C["safe"] if health_score>70 else C["high"]),
        (crit_count,  "Critical Findings", C["crit"]),
        (high_count,  "High Findings",     C["high"]),
        (med_count,   "Medium Findings",   C["med"]),
        (len(hosts),  "Hosts Audited",     C["dark_blue"]),
        (len(all_vulns), "Total Findings", C["mid_gray"]),
    ]))
    story.append(Spacer(1, 24))

    # Charts inside a framed analytics panel
    donut = build_vuln_chart(all_vulns)
    bars  = build_risk_bar_chart(hosts)
    if donut or bars:
        chart_cells  = []
        chart_widths = []
        if donut:
            chart_cells.append(donut)
            chart_widths.append(BODY_W / 2)
        if bars:
            chart_cells.append(bars)
            chart_widths.append(BODY_W / 2)
        if len(chart_cells) == 1:
            chart_widths = [BODY_W]
        chart_inner = Table([chart_cells], colWidths=chart_widths)
        chart_inner.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("ALIGN",  (0,0), (-1,-1), "CENTER"),
        ]))
        panel_lbl = ParagraphStyle("_clbl", fontName="Helvetica-Bold", fontSize=9,
                                    textColor=C["gold"])
        chart_panel = Table(
            [[Paragraph("▸ VISUAL ANALYTICS", panel_lbl)],
             [chart_inner]],
            colWidths=[BODY_W])
        chart_panel.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), C["dark_blue"]),
            ("BACKGROUND",   (0,1), (-1,1), C["white"]),
            ("BOX",          (0,0), (-1,-1), 1.5, C["gold"]),
            ("TOPPADDING",   (0,0), (-1,0), 8),
            ("BOTTOMPADDING",(0,0), (-1,0), 8),
            ("LEFTPADDING",  (0,0), (-1,-1), 12),
            ("RIGHTPADDING", (0,0), (-1,-1), 12),
            ("TOPPADDING",   (0,1), (-1,1), 28),
            ("BOTTOMPADDING",(0,1), (-1,1), 28),
        ]))
        story.append(chart_panel)
        story.append(Spacer(1, 14))

    # Scan metadata table
    dur_str = "N/A"
    if scan.started_at and scan.finished_at:
        secs = int((scan.finished_at - scan.started_at).total_seconds())
        dur_str = f"{secs//3600}h {(secs%3600)//60}m {secs%60}s"

    meta_rows = [
        [Paragraph("FIELD", styles["th"]), Paragraph("VALUE", styles["th"])],
        [Paragraph("Scan ID",       styles["td"]), Paragraph(scan_id[:8], styles["td_mono"])],
        [Paragraph("Target",        styles["td"]), Paragraph(scan.target, styles["td_mono"])],
        [Paragraph("Start Time",    styles["td"]),
         Paragraph(scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.started_at else "N/A",
                   styles["td"])],
        [Paragraph("Finish Time",   styles["td"]),
         Paragraph(scan.finished_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.finished_at else "N/A",
                   styles["td"])],
        [Paragraph("Duration",      styles["td"]), Paragraph(dur_str, styles["td"])],
        [Paragraph("Hosts Found",   styles["td"]), Paragraph(str(len(hosts)), styles["td"])],
        [Paragraph("Total Vulns",   styles["td"]), Paragraph(str(len(all_vulns)), styles["td"])],
        [Paragraph("Security Score",styles["td"]), Paragraph(f"{int(health_score)}/100", styles["td"])],
    ]
    meta_table = Table(meta_rows, colWidths=[2*inch, BODY_W - 2*inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), C["dark_blue"]),
        ("PADDING",       (0,0), (-1,-1), 8),
        ("LINEBELOW",     (0,0), (-1,0), 1.5, C["gold"]),
        ("GRID",          (0,1), (-1,-1), 0.4, C["grid"]),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C["white"], C["stripe"]]),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(Spacer(1, 10))
    story.append(meta_table)
    story.append(PageBreak())

    # ── §3  NETWORK MAP ───────────────────────────────────────────────
    story.append(section_banner("3  ·  Discovered Hosts — Network Map", "◈"))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"The scan discovered <b>{len(hosts)} live host(s)</b> on <b>{scan.target}</b>. "
        "Each card below summarises the device's identity, exposure level, and worst "
        "vulnerability severity at a glance.", styles["body"]))
    story.append(Spacer(1, 16))
    story.extend(build_live_hosts_visual(hosts))
    story.append(PageBreak())

    # ── §4  HOST-BY-HOST DEEP DIVE ────────────────────────────────────
    story.append(section_banner("4  ·  Host-by-Host Deep Dive", "◈"))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "This section provides a granular, per-asset analysis: device profile, exposed services, "
        "confirmed vulnerabilities with business impact, forensic evidence, and targeted "
        "remediation actions.", styles["body"]))
    story.append(PageBreak())

    for idx, h in enumerate(hosts, 1):
        host_elems = []

        # Host header
        host_elems.append(host_banner(h["ip"], h.get("os","Unknown"),
                                      h.get("device_classification","Unknown")))
        host_elems.append(GradientBar(4, BODY_W))
        host_elems.append(Spacer(1, 12))

        # Sub-section label
        sub_lbl = ParagraphStyle("_slbl", fontName="Helvetica-Bold", fontSize=9,
                                  textColor=C["mid_gray"])
        host_elems.append(Paragraph(
            f"HOST {idx} OF {len(hosts)}  │  {h['ip']}  │  "
            f"Risk Score: {h.get('risk_score',0):.0f}/100  │  "
            f"Criticality: {h.get('criticality','Unknown').upper()}",
            sub_lbl))
        host_elems.append(Spacer(1, 10))

        # ── Device Profile metadata strip ─────────────────────────────
        profile_data = [
            [Paragraph("ATTRIBUTE", styles["th"]), Paragraph("VALUE", styles["th"]),
             Paragraph("ATTRIBUTE", styles["th"]), Paragraph("VALUE", styles["th"])],
            [Paragraph("Hostname",   styles["td"]),
             Paragraph(xml_escape(h.get("hostname","Unknown")), styles["td_mono"]),
             Paragraph("MAC Address",styles["td"]),
             Paragraph(xml_escape(h.get("mac_address","Unknown")), styles["td_mono"])],
            [Paragraph("OS",         styles["td"]),
             Paragraph(xml_escape((h.get("os") or "Unknown")[:40]), styles["td"]),
             Paragraph("MAC Vendor", styles["td"]),
             Paragraph(xml_escape((h.get("mac_vendor") or "Unknown")[:30]), styles["td"])],
            [Paragraph("Device Type",styles["td"]),
             Paragraph(xml_escape(h.get("device_type","Unknown")), styles["td"]),
             Paragraph("Gateway",    styles["td"]),
             Paragraph("Yes" if h.get("is_gateway") else "No", styles["td"])],
        ]
        cw = BODY_W / 4
        profile_table = Table(profile_data, colWidths=[cw]*4)
        profile_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), C["dark_blue"]),
            ("PADDING",       (0,0), (-1,-1), 7),
            ("LINEBELOW",     (0,0), (-1,0), 1, C["gold"]),
            ("GRID",          (0,1), (-1,-1), 0.4, C["grid"]),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [C["white"], C["stripe"]]),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ]))
        host_elems.append(profile_table)
        host_elems.append(Spacer(1, 14))

        # ── Description ───────────────────────────────────────────────
        host_elems.append(Paragraph("Device Profile & Risk Narrative", styles["h3"]))
        host_elems.append(ThinRule(BODY_W, C["grid"]))
        host_elems.append(Spacer(1, 4))
        host_elems.append(Paragraph(generate_host_narrative(h), styles["body"]))
        host_elems.append(Spacer(1, 14))

        # ── Open Ports ────────────────────────────────────────────────
        if h["services"]:
            host_elems.append(Paragraph("Open Ports & Services", styles["h3"]))
            host_elems.append(ThinRule(BODY_W, C["grid"]))
            host_elems.append(Spacer(1, 4))
            host_elems.append(build_ports_table(h["services"], styles))
            host_elems.append(Spacer(1, 14))

        # ── Vulnerabilities ───────────────────────────────────────────
        meaningful = [v for v in h["vulnerabilities"]
                      if v.get("severity","info").lower() != "info"]
        if meaningful:
            host_elems.append(Paragraph("Vulnerabilities & Business Impact", styles["h3"]))
            host_elems.append(ThinRule(BODY_W, C["grid"]))
            host_elems.append(Spacer(1, 6))

            # Summary table first
            host_elems.append(build_vuln_table(meaningful, styles))
            host_elems.append(Spacer(1, 12))

            # Detailed impact per vulnerability
            host_elems.append(Paragraph("Detailed Impact Analysis", styles["h3"]))
            for v in meaningful:
                host_elems.extend(vuln_impact_block(v, styles))
            host_elems.append(Spacer(1, 6))

        # ── Evidence Vault ────────────────────────────────────────────
        evidence_items = h.get("evidence", [])
        best = pick_best_evidence(evidence_items, max_items=2)
        if best:
            host_elems.append(Paragraph("Evidence Vault", styles["h3"]))
            host_elems.append(ThinRule(BODY_W, C["grid"]))
            host_elems.append(Spacer(1, 6))
            for ev in best:
                host_elems.extend(render_evidence_item(ev, h["ip"], styles))
            host_elems.append(Spacer(1, 6))

        # ── Web screenshots (all, after other evidence) ────────────────
        web_shots = [e for e in evidence_items if e.get("type") in ("web_screenshot","auth_screenshot")]
        for ev in web_shots[:1]:   # max 1 screenshot per host to keep report lean
            path = ev.get("path","")
            if path and os.path.exists(path):
                try:
                    img = Image(path, width=BODY_W, height=3.6*inch)
                    img.hAlign = "LEFT"
                    frame = Table([[img]], colWidths=[BODY_W])
                    frame.setStyle(TableStyle([
                        ("BOX",     (0,0), (-1,-1), 2, C["dark_blue"]),
                        ("PADDING", (0,0), (-1,-1), 3),
                    ]))
                    host_elems.append(frame)
                    host_elems.append(Paragraph(
                        f"Fig: Live web capture — {ev.get('label','')}", styles["caption"]))
                    host_elems.append(Spacer(1, 8))
                except Exception:
                    pass

        # ── Remediation ───────────────────────────────────────────────
        host_elems.append(Paragraph("Remediation Strategy", styles["h3"]))
        host_elems.append(ThinRule(BODY_W, C["grid"]))
        host_elems.append(Spacer(1, 6))
        recs = [
            "Immediately patch or isolate services with Critical/High CVEs.",
            "Apply firewall rules to restrict service access to authorised subnets only.",
            "Enforce multi-factor authentication on all management interfaces.",
            "Disable or remove legacy protocols (Telnet, FTP) — replace with SSH/SFTP.",
            "Schedule monthly automated scans to track remediation progress.",
        ]
        if meaningful:
            cve_ids = [v["cve_id"] for v in meaningful if v.get("cve_id")]
            if cve_ids:
                recs.insert(0, f"Apply vendor patches for {', '.join(cve_ids[:3])} immediately.")
        host_elems.append(rec_box(recs, styles))

        story.append(KeepTogether(host_elems[:12]))  # keep first block together
        story.extend(host_elems[12:])                # rest flows naturally
        story.append(PageBreak())

    # ── §5  VULNERABILITY ANALYSIS ────────────────────────────────────
    story.append(section_banner("5  ·  Vulnerability Analysis", "◈"))
    story.append(Spacer(1, 16))

    if all_vulns:
        story.append(Paragraph(
            f"Across all {len(hosts)} audited hosts, the scanner identified "
            f"<b>{len(all_vulns)} total findings</b> — "
            f"<b>{crit_count} critical</b>, <b>{high_count} high</b>, "
            f"<b>{med_count} medium</b>.", styles["body"]))
        story.append(Spacer(1, 12))

        # Full consolidated table
        story.append(Paragraph("Consolidated Vulnerability Registry", styles["h3"]))
        all_rows = [[Paragraph("HOST",     styles["th"]),
                     Paragraph("SEVERITY", styles["th"]),
                     Paragraph("NAME",     styles["th"]),
                     Paragraph("CVE",      styles["th"]),
                     Paragraph("CVSS",     styles["th"])]]
        for h in hosts:
            for v in h["vulnerabilities"]:
                sev   = v.get("severity","info")
                sev_c = sev_color(sev)
                sev_p = ParagraphStyle("_sv2", fontName="Helvetica-Bold", fontSize=8,
                                        textColor=sev_c)
                all_rows.append([
                    Paragraph(h["ip"],                                styles["td_mono"]),
                    Paragraph(sev.upper(),                            sev_p),
                    Paragraph(xml_escape(v.get("name","?")[:50]),     styles["td"]),
                    Paragraph(v.get("cve_id") or "—",                 styles["td_mono"]),
                    Paragraph(f"{v['cvss_score']:.1f}" if v.get("cvss_score") else "—", styles["td"]),
                ])
        all_vuln_table = Table(all_rows,
                               colWidths=[1.1*inch, 0.85*inch, 3.1*inch, 1.2*inch, 0.6*inch])
        vs_cmds = [
            ("BACKGROUND",    (0,0), (-1,0), C["dark_blue"]),
            ("PADDING",       (0,0), (-1,-1), 7),
            ("LINEBELOW",     (0,0), (-1,0), 1.5, C["gold"]),
            ("GRID",          (0,1), (-1,-1), 0.4, C["grid"]),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ]
        for i in range(1, len(all_rows)):
            if i % 2 == 0:
                vs_cmds.append(("BACKGROUND", (0,i), (-1,i), C["stripe"]))
        all_vuln_table.setStyle(TableStyle(vs_cmds))
        story.append(all_vuln_table)
    else:
        story.append(Paragraph(
            "No vulnerabilities were detected across the scanned hosts. "
            "The network currently presents a clean posture under automated assessment; "
            "manual penetration testing is still recommended to validate this result.",
            styles["body"]))

    story.append(PageBreak())

    # ── §6  STRATEGIC ROADMAP ─────────────────────────────────────────
    story.append(section_banner("6  ·  Strategic Roadmap & Recommendations", "◈"))
    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "The following strategic initiatives are ordered by priority. Each directly "
        "addresses the attack surface and vulnerabilities identified during this assessment.",
        styles["body"]))
    story.append(Spacer(1, 14))

    recs_list = analysis.get("strategic_recommendations", [])
    if recs_list:
        for ri, r in enumerate(recs_list[:8], 1):
            theme  = r.get("theme","") if isinstance(r, dict) else str(r)
            advice = r.get("advice","") if isinstance(r, dict) else ""
            prio   = r.get("priority", ri) if isinstance(r, dict) else ri

            theme_style = ParagraphStyle("_ts", fontName="Helvetica-Bold", fontSize=11,
                                          textColor=C["dark_blue"])
            prio_badge_t = Table(
                [[Paragraph(f"PRIORITY {prio}", ParagraphStyle("_pb", fontName="Helvetica-Bold",
                             fontSize=9, textColor=C["white"])),
                  Paragraph(xml_escape(theme.upper()), theme_style)]],
                colWidths=[0.9*inch, BODY_W - 0.9*inch])
            prio_badge_t.setStyle(TableStyle([
                ("BACKGROUND",   (0,0), (0,0), C["dark_blue"]),
                ("BACKGROUND",   (1,0), (1,0), C["gold"]),
                ("TOPPADDING",   (0,0), (-1,-1), 8),
                ("BOTTOMPADDING",(0,0), (-1,-1), 8),
                ("LEFTPADDING",  (0,0), (-1,-1), 10),
                ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ]))
            story.append(prio_badge_t)
            if advice:
                clean = xml_escape(advice.replace("**","").replace("*",""))
                story.append(rec_box(
                    [line.strip() for line in clean.split("\n") if line.strip()][:5],
                    styles))
            story.append(Spacer(1, 12))
    else:
        story.append(rec_box([
            "Maintain patch cycles — apply OS and application updates weekly.",
            "Review firewall rules quarterly; remove unused ALLOW entries.",
            "Deploy an Intrusion Detection System (IDS/IPS) on the perimeter.",
            "Implement network segmentation to limit lateral movement.",
            "Conduct an internal red-team exercise within the next 90 days.",
        ], styles))

    story.append(PageBreak())

    # ── §7  CONCLUSION ────────────────────────────────────────────────
    story.append(section_banner("7  ·  Conclusion & Auditor Sign-Off", "◈"))
    story.append(Spacer(1, 16))

    verdict_text = analysis.get("overall_verdict","The assessment is complete.")
    likelihood   = analysis.get("likelihood_of_compromise", "")

    story.append(Paragraph(
        f"This comprehensive security audit evaluated the network infrastructure at "
        f"<b>{scan.target}</b> on <b>{scan_date}</b>. "
        f"A total of <b>{len(hosts)} hosts</b> were discovered and subjected to "
        f"deep scanning, vulnerability analysis, credential testing, and evidence capture.",
        styles["body"]))
    story.append(Spacer(1, 10))

    if likelihood:
        story.append(Paragraph(
            f"<b>Likelihood of Compromise:</b> {xml_escape(likelihood)}", styles["body"]))
        story.append(Spacer(1, 10))

    # Final verdict box
    verdict_style = ParagraphStyle("_vf", fontName="Helvetica-Bold", fontSize=12,
                                    textColor=C["dark_blue"])
    verdict_box = Table(
        [[Paragraph(f"FINAL VERDICT", ParagraphStyle("_vfl", fontName="Helvetica-Bold",
                     fontSize=10, textColor=C["gold"])),
          Paragraph(xml_escape(verdict_text), verdict_style)]],
        colWidths=[1.3*inch, BODY_W - 1.3*inch])
    verdict_box.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,0), C["dark_blue"]),
        ("BACKGROUND",   (1,0), (1,0), C["light_gray"]),
        ("TOPPADDING",   (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0), (-1,-1), 14),
        ("LEFTPADDING",  (0,0), (-1,-1), 14),
        ("BOX",          (0,0), (-1,-1), 1.5, C["gold"]),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(verdict_box)
    story.append(Spacer(1, 30))

    story.append(Paragraph(
        "It is strongly recommended that the IT Governance Board reviews these findings "
        "and allocates resources to execute the Strategic Roadmap. Continuous automated "
        "auditing should be scheduled quarterly to track remediation progress and detect "
        "newly emerging threats.",
        styles["body"]))
    story.append(Spacer(1, 40))

    # Sign-off block
    signoff = Table(
        [[Paragraph("AUDITOR", styles["th"]),
          Paragraph("METHOD",  styles["th"]),
          Paragraph("DATE ISSUED", styles["th"])],
         [Paragraph("Automated AI Audit Engine", styles["td"]),
          Paragraph("Nmap 7.99 + Nuclei + AI Analysis", styles["td"]),
          Paragraph(
              scan.finished_at.strftime("%Y-%m-%d") if scan.finished_at
              else datetime.utcnow().strftime("%Y-%m-%d"),
              styles["td"])]],
        colWidths=[2.5*inch, 3*inch, 2*inch])
    signoff.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0), C["dark_blue"]),
        ("PADDING",      (0,0), (-1,-1), 12),
        ("LINEBELOW",    (0,0), (-1,0), 1.5, C["gold"]),
        ("GRID",         (0,1), (-1,-1), 0.4, C["grid"]),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C["light_gray"]]),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(signoff)
    story.append(Spacer(1, 20))
    story.append(ThinRule(BODY_W, C["gold"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "CLASSIFICATION: CONFIDENTIAL — This document is intended solely for authorised "
        "personnel. Unauthorised disclosure is prohibited.",
        ParagraphStyle("_disc", fontName="Helvetica-Oblique", fontSize=8,
                        textColor=C["mid_gray"], alignment=TA_CENTER)))

    # ── Build ──────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=decorator, onLaterPages=decorator)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes