# =============================================================================
# .env.example
# DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/audit_db
# =============================================================================

# ── 1. Stdlib imports ─────────────────────────────────────────────────────────
import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# ── 2. Optional dotenv ────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── 3. Third-party imports ────────────────────────────────────────────────────
from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import (
    Column, DateTime, ForeignKey, Float, Integer, String,
    UniqueConstraint, delete, update, Boolean, Text, JSON,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.future import select
from sqlalchemy.orm import declarative_base, relationship, selectinload

# ── 4. Service module imports ───────────────────────────────────────────────
from services.credential_testing import run_credential_tests, credential_results_to_vulnerabilities
from services.cve_enrichment import enrich_vulnerabilities_list
from services.risk_scoring import calculate_host_risk_score, criticality_from_score

# ── 5. NEW: Evidence capture ─────────────────────────────────────────────────
from services.evidence_capture import (
    capture_web_screenshot,
    capture_host_screenshot,
    capture_auth_screenshot,
    capture_credential_text,
)

# =============================================================================
# LOGGING
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# =============================================================================
# TOOL RESOLUTION — Windows-safe
# =============================================================================
def resolve_tool(name: str, fallbacks: list[str]) -> str:
    path = shutil.which(name)
    if path:
        return path
    for fb in fallbacks:
        if Path(fb).exists():
            return fb
    raise RuntimeError(
        f"Tool '{name}' not found in PATH or fallback paths: {fallbacks}. "
        "Please install it or add it to PATH."
    )

try:
    NMAP_PATH = resolve_tool("nmap", [
        "C:/Program Files (x86)/Nmap/nmap.exe",
        "C:/Program Files/Nmap/nmap.exe",
    ])
    NUCLEI_PATH = resolve_tool("nuclei", [
        str(Path.home() / "go/bin/nuclei.exe"),
        "C:/tools/nuclei/nuclei.exe",
    ])
except RuntimeError as exc:
    logger.critical(str(exc))
    sys.exit(1)

# =============================================================================
# DATABASE
# =============================================================================
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/audit_db",
)

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# =============================================================================
# ORM MODELS (inlined for clarity)
# =============================================================================
class Scan(Base):
    __tablename__ = "scans"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target      = Column(String, nullable=False)
    status      = Column(String, default="running")
    fail_reason = Column(String, nullable=True)
    hosts_found = Column(Integer, default=0)
    started_at  = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    hosts       = relationship("Host", back_populates="scan", cascade="all, delete-orphan")


class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("scan_id", "ip"),)
    id                = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id           = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    ip                = Column(String, nullable=False)
    ipv6              = Column(String, nullable=True)
    hostname          = Column(String, nullable=True)
    hostname_source   = Column(String, nullable=True)
    hostname_confidence = Column(Float, default=0.0)
    os                = Column(String, nullable=True)
    os_family         = Column(String, nullable=True)
    os_version        = Column(String, nullable=True)
    os_confidence     = Column(String, nullable=True)
    device_type       = Column(String, nullable=True)
    device_classification = Column(String, nullable=True)
    manufacturer      = Column(String, nullable=True)
    mac_address       = Column(String, nullable=True)
    mac_vendor        = Column(String, nullable=True)
    network_interface = Column(String, nullable=True)
    architecture      = Column(String, nullable=True)
    uptime            = Column(String, nullable=True)
    is_gateway        = Column(Boolean, default=False)
    is_local_machine  = Column(Boolean, default=False)
    is_vm             = Column(Boolean, default=False)
    is_docker         = Column(Boolean, default=False)
    is_wsl            = Column(Boolean, default=False)
    is_mobile         = Column(Boolean, default=False)
    scan_type         = Column(String, nullable=True)
    status            = Column(String, default="up")
    audit_status      = Column(String, default="pending")
    last_scan         = Column(DateTime, nullable=True)
    risk_score        = Column(Float, default=0.0)
    criticality       = Column(String, default="Unknown")
    discovery_method  = Column(String, nullable=True)
    running_applications = Column(JSON, default=list)
    screenshot_path      = Column(String, nullable=True)
    evidence             = Column(JSON, default=list)
    scan              = relationship("Scan", back_populates="hosts")
    services          = relationship("Service", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities   = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"
    id       = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id  = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port     = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    name     = Column(String, nullable=True)
    version  = Column(String, nullable=True)
    state    = Column(String, default="open")
    banner   = Column(Text, nullable=True)
    host     = relationship("Host", back_populates="services")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id              = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id         = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    template_id     = Column(String, nullable=True)
    name            = Column(String, nullable=False)
    severity        = Column(String, default="info")
    cve_id          = Column(String, nullable=True)
    description     = Column(Text, nullable=True)
    matcher_name    = Column(String, nullable=True)
    cvss_score      = Column(Float, nullable=True)
    cvss_estimated  = Column(Boolean, default=False)
    source          = Column(String, default="nuclei")
    discovered_at   = Column(DateTime, default=datetime.utcnow)
    matched_at      = Column(DateTime, default=datetime.utcnow)
    remediation     = Column(Text, nullable=True)
    exploit_available = Column(Boolean, default=False)
    references      = Column(JSON, default=list)
    host            = relationship("Host", back_populates="vulnerabilities")


class AuditAnalysis(Base):
    __tablename__ = "audit_analysis"
    id                = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id           = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), unique=True, nullable=False)
    security_score    = Column(Integer, nullable=True)
    maturity_level    = Column(String, nullable=True)
    executive_summary = Column(Text, nullable=False, default="")
    attack_vectors    = Column(JSON, nullable=False, default=list)
    most_dangerous_vulnerabilities = Column(JSON, nullable=False, default=list)
    business_impact   = Column(JSON, nullable=False, default=dict)
    likelihood_of_compromise = Column(String, nullable=True)
    attacker_scenario = Column(Text, nullable=False, default="")
    security_strengths = Column(JSON, nullable=False, default=list)
    security_weaknesses = Column(JSON, nullable=False, default=list)
    global_risk_conclusion = Column(Text, nullable=False, default="")
    key_findings      = Column(JSON, nullable=False, default=list)
    strategic_recommendations = Column(JSON, nullable=False, default=list)
    overall_verdict   = Column(String, nullable=False, default="")
    ai_generated      = Column(Boolean, default=False)
    generated_at      = Column(DateTime, default=datetime.utcnow)


class LLMDecisionLog(Base):
    __tablename__ = "llm_decision_logs"
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id       = Column(String, nullable=True)
    host_ip       = Column(String, nullable=True)
    decision_type = Column(String, nullable=True)
    input_summary = Column(Text, nullable=True)
    output_summary= Column(Text, nullable=True)
    status        = Column(String, nullable=True)
    duration_ms   = Column(Integer, nullable=True)
    created_at    = Column(DateTime, default=datetime.utcnow)


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================
class ScanRequest(BaseModel):
    target: str

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str

class StatusResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    hosts_found: int
    started_at: datetime | None
    finished_at: datetime | None

# =============================================================================
# HELPERS — XML / JSON PARSING
# =============================================================================
def _parse_discovery_xml(path: Path) -> set[str]:
    ips: set[str] = set()
    if not path.exists():
        return ips
    try:
        tree = ET.parse(path)
        for host_el in tree.findall("host"):
            st = host_el.find("status")
            if st is None or st.get("state") != "up":
                continue
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "ipv4":
                    ips.add(addr_el.get("addr", ""))
    except Exception as exc:
        logger.warning(f"Discovery XML parse error: {exc}")
    return ips


def _extract_hostscript_outputs(host_el) -> dict[str, str]:
    outputs: dict[str, str] = {}
    for script_el in host_el.findall("hostscript/script"):
        sid = script_el.get("id")
        out = script_el.get("output", "")
        if sid:
            outputs[sid] = out
    for script_el in host_el.findall(".//port/script"):
        sid = script_el.get("id")
        out = script_el.get("output", "")
        if sid and sid not in outputs:
            outputs[sid] = out
    return outputs


# ── Known NSE script → severity mapping ───────────────────────────────────────
# These are well-known, exploitable vulnerabilities whose NSE output may not
# contain explicit CVSS scores or severity keywords, but are definitively severe.
KNOWN_NSE_SCRIPT_SEVERITIES: dict[str, tuple[str, float | None, str | None]] = {
    # (severity, cvss_score, cve_id)
    "smb-vuln-ms17-010":        ("critical", 9.3,  "CVE-2017-0144"),   # EternalBlue
    "smb-vuln-ms08-067":        ("critical", 10.0, "CVE-2008-4250"),
    "smb-vuln-cve2009-3103":    ("critical", 7.8,  "CVE-2009-3103"),
    "smb-vuln-ms10-054":        ("medium",   4.9,  "CVE-2010-2550"),
    "smb-vuln-ms10-061":        ("high",     6.9,  "CVE-2010-2729"),
    "smb-vuln-regsvc-dos":      ("medium",   4.0,  None),
    "ftp-vsftpd-backdoor":       ("critical", 10.0, "CVE-2011-2523"),
    "ftp-proftpd-backdoor":      ("critical", 9.0,  "CVE-2010-4221"),
    "irc-unrealircd-backdoor":   ("critical", 10.0, "CVE-2010-2075"),
    "rmi-vuln-classloader":      ("high",     7.5,  None),
    "http-shellshock":           ("critical", 10.0, "CVE-2014-6271"),
    "ssl-heartbleed":            ("critical", 9.8,  "CVE-2014-0160"),
    "ssl-poodle":                ("medium",   4.3,  "CVE-2014-3566"),
    "http-csrf":                 ("medium",   6.8,  None),
    "http-dombased-xss":         ("medium",   4.3,  None),
    "http-stored-xss":           ("high",     7.5,  None),
    "http-sql-injection":        ("high",     7.5,  None),
    "vulners":                   ("medium",   5.0,  None),
}

# ── Known-dangerous service signatures → auto-generated vulnerabilities ────────
# These catch specific banners/versions/ports that are definitively backdoored
# or critically exposed, regardless of what Nmap NSE scripts say.
DANGEROUS_SERVICE_SIGNATURES: list[dict] = [
    {
        "match_port": 1524,
        "match_banner_contains": None,   # any service on port 1524 = bindshell
        "name": "Metasploitable Root Bindshell (port 1524)",
        "severity": "critical",
        "cvss_score": 10.0,
        "cve_id": None,
        "description": "Port 1524 is reserved for a Metasploitable-installed root backdoor shell. Any unauthenticated attacker can obtain root access by connecting to this port.",
        "template_id": "dangerous-service-bindshell-1524",
    },
    {
        "match_port": 21,
        "match_banner_contains": "vsftpd 2.3.4",
        "name": "vsftpd 2.3.4 Backdoor Command Execution",
        "severity": "critical",
        "cvss_score": 10.0,
        "cve_id": "CVE-2011-2523",
        "description": "vsftpd 2.3.4 contains a deliberately-inserted backdoor. A smiley face ':)' in the username triggers a root shell on port 6200.",
        "template_id": "dangerous-service-vsftpd-2.3.4-backdoor",
    },
    {
        "match_port": None,
        "match_banner_contains": "UnrealIRCd",
        "name": "UnrealIRCd Backdoor Command Execution",
        "severity": "critical",
        "cvss_score": 10.0,
        "cve_id": "CVE-2010-2075",
        "description": "Certain builds of UnrealIRCd 3.2.8.1 contain a backdoor that executes arbitrary commands as root.",
        "template_id": "dangerous-service-unrealircd-backdoor",
    },
    {
        "match_port": 2121,
        "match_banner_contains": "ProFTPD 1.3.1",
        "name": "ProFTPD 1.3.1 SQL Injection (CVE-2009-0543)",
        "severity": "high",
        "cvss_score": 7.5,
        "cve_id": "CVE-2009-0543",
        "description": "ProFTPD 1.3.1 is vulnerable to SQL injection in the mod_sql module.",
        "template_id": "dangerous-service-proftpd-1.3.1",
    },
    {
        "match_port": None,
        "match_banner_contains": "Samba 3.0",
        "name": "Samba 3.0.x - 'username map script' RCE (CVE-2007-2447)",
        "severity": "critical",
        "cvss_score": 9.3,
        "cve_id": "CVE-2007-2447",
        "description": "Samba 3.0.20 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters.",
        "template_id": "dangerous-service-samba-username-map-script",
    },
    {
        "match_port": 23,
        "match_banner_contains": None,
        "name": "Telnet Service Exposed (Cleartext Protocol)",
        "severity": "high",
        "cvss_score": 7.5,
        "cve_id": None,
        "description": "Telnet transmits credentials and data in cleartext. Any attacker on the network can intercept usernames, passwords, and session data.",
        "template_id": "dangerous-service-telnet-cleartext",
    },
]


def detect_dangerous_services(services: list[dict]) -> list[dict]:
    """Scan a host's service list for known-dangerous banners/versions/ports.
    Returns a list of vulnerability dicts to inject into nse_vulns."""
    findings: list[dict] = []
    seen_templates: set[str] = set()

    for svc in services:
        port = svc.get("port")
        version = (svc.get("version") or "").lower()
        banner = (svc.get("banner") or "").lower()
        combined_text = f"{version} {banner}"

        for sig in DANGEROUS_SERVICE_SIGNATURES:
            tid = sig["template_id"]
            if tid in seen_templates:
                continue

            port_match = (sig["match_port"] is None) or (sig["match_port"] == port)
            banner_match = (
                sig["match_banner_contains"] is None
                or sig["match_banner_contains"].lower() in combined_text
            )

            if port_match and banner_match:
                seen_templates.add(tid)
                findings.append({
                    "template_id": tid,
                    "name": sig["name"],
                    "severity": sig["severity"],
                    "cve_id": sig["cve_id"],
                    "cvss_score": sig["cvss_score"],
                    "cvss_estimated": False,
                    "matcher_name": tid,
                    "description": sig["description"],
                    "source": "signature_detection",
                    "remediation": "Upgrade or remove this service immediately.",
                    "exploit_available": True,
                    "references": [f"https://nvd.nist.gov/vuln/detail/{sig['cve_id']}"] if sig["cve_id"] else [],
                })

    return findings


def _parse_vulnerabilities_from_nmap_xml(host_el, host_ip: str) -> list[dict]:
    vulns = []
    for script_el in host_el.findall("hostscript/script"):
        sid = script_el.get("id", "")
        output = script_el.get("output", "")
        if "vuln" in sid.lower() or "VULNERABLE" in output:
            vuln = _extract_vuln_from_script_output(sid, output, host_ip)
            if vuln:
                vulns.append(vuln)
    for port_el in host_el.findall(".//port"):
        for script_el in port_el.findall("script"):
            sid = script_el.get("id", "")
            output = script_el.get("output", "")
            if "vuln" in sid.lower() or "VULNERABLE" in output:
                vuln = _extract_vuln_from_script_output(sid, output, host_ip)
                if vuln:
                    vulns.append(vuln)
    return vulns


def _extract_vuln_from_script_output(script_id: str, output: str, host_ip: str) -> dict | None:
    # ── Step 1: Check known script severity mapping first ──────────────────────
    known = KNOWN_NSE_SCRIPT_SEVERITIES.get(script_id.lower())
    if known:
        known_sev, known_cvss, known_cve = known
        # Only use if output doesn't explicitly say "NOT VULNERABLE"
        if "NOT VULNERABLE" in output and "VULNERABLE" not in output.replace("NOT VULNERABLE", ""):
            return None  # explicitly not vulnerable
        severity = known_sev
        cvss_score = known_cvss
        cve_id = known_cve
        # Still try to extract CVE from output if not in mapping
        if not cve_id:
            cve_match = re.search(r'(CVE-\d{4}-\d{4,})', output, re.I)
            cve_id = cve_match.group(1) if cve_match else None
        # Also try CVSS from output
        cvss_match = re.search(r'CVSS\s+([\d\.]+)', output, re.I)
        if cvss_match:
            cvss_score = float(cvss_match.group(1))
    else:
        # ── Step 2: Generic extraction ─────────────────────────────────────────
        cvss_match = re.search(r'CVSS\s+([\d\.]+)', output, re.I)
        cvss_score = float(cvss_match.group(1)) if cvss_match else None

        severity = "info"
        if cvss_score is not None:
            if cvss_score >= 9.0:  severity = "critical"
            elif cvss_score >= 7.0: severity = "high"
            elif cvss_score >= 4.0: severity = "medium"
            elif cvss_score > 0:   severity = "low"
        else:
            if "critical" in output.lower():  severity = "critical"
            elif "high" in output.lower():    severity = "high"
            elif "medium" in output.lower():  severity = "medium"
            elif "low" in output.lower():     severity = "low"
            # Key fix: if output explicitly says VULNERABLE but no severity keyword found,
            # default to medium (not info) — it IS a finding.
            elif "VULNERABLE" in output and "NOT VULNERABLE" not in output:
                severity = "medium"
                cvss_score = 5.0  # conservative CVSS estimate

        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', output, re.I)
        cve_id = cve_match.group(1) if cve_match else None

    # ── Step 3: Skip if not actually vulnerable ────────────────────────────────
    if "NOT VULNERABLE" in output and "VULNERABLE" not in output.replace("NOT VULNERABLE", ""):
        return None

    name = script_id.replace("-", " ").replace("_", " ").title()
    title_match = re.search(r'VULNERABLE:\s*([^\n]+)', output, re.I)
    if title_match:
        name = title_match.group(1).strip()

    desc = output.strip()
    if len(desc) > 500:
        desc = desc[:500] + "..."

    return {
        "template_id": script_id,
        "name": name,
        "severity": severity,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "cvss_estimated": cvss_score is None,
        "matcher_name": script_id,
        "description": desc,
        "source": "nmap_nse",
        "remediation": "",
        "exploit_available": known is not None,  # known scripts are more likely exploitable
        "references": ([f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id else []),
    }


def _parse_service_xml(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        tree = ET.parse(path)
        host_el = tree.find("host")
        if host_el is None:
            return None
        st = host_el.find("status")
        if st is None or st.get("state") != "up":
            return None

        ttl = None
        raw_ttl = st.get("reason_ttl")
        if raw_ttl:
            try:
                ttl = int(raw_ttl)
            except ValueError:
                ttl = None

        ip = ""
        ipv6 = None
        mac = None
        mac_vendor = None
        for addr_el in host_el.findall("address"):
            atype = addr_el.get("addrtype")
            if atype == "ipv4":
                ip = addr_el.get("addr", "")
            elif atype == "ipv6":
                ipv6 = addr_el.get("addr")
            elif atype == "mac":
                mac = addr_el.get("addr")
                mac_vendor = addr_el.get("vendor") or None
        if not ip:
            return None

        hostname = None
        for hn in host_el.findall("hostnames/hostname"):
            name = hn.get("name")
            if not name:
                continue
            if hn.get("type") == "PTR":
                hostname = name
                break
            if hostname is None:
                hostname = name

        os_name = None
        os_accuracy = 0
        for osm in host_el.findall("os/osmatch"):
            try:
                accuracy = int(osm.get("accuracy", "0"))
            except ValueError:
                accuracy = 0
            if accuracy >= 50 and accuracy > os_accuracy:
                os_name = osm.get("name")
                os_accuracy = accuracy

        uptime = None
        for ut_el in host_el.findall("uptime"):
            uptime = ut_el.get("lastboot")

        services = []
        running_apps = []
        for port_el in host_el.findall(".//port"):
            st_el = port_el.find("state")
            if st_el is None or st_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""
            banner = f"{product} {version} {extrainfo}".strip()
            svc_name = svc_el.get("name") if svc_el is not None else None

            services.append({
                "port":     int(port_el.get("portid", 0)),
                "protocol": port_el.get("protocol", "tcp"),
                "name":     svc_name,
                "version":  f"{product} {version}".strip() or None,
                "state":    "open",
                "banner":   banner or None,
            })

            if product:
                running_apps.append({
                    "name": product,
                    "version": version or "Unknown",
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                })

        hostscripts = _extract_hostscript_outputs(host_el)
        nse_vulns = _parse_vulnerabilities_from_nmap_xml(host_el, ip)

        return {
            "ip": ip,
            "ipv6": ipv6,
            "hostname": hostname,
            "os": os_name,
            "os_accuracy": os_accuracy,
            "mac": mac,
            "mac_vendor": mac_vendor,
            "uptime": uptime,
            "ttl": ttl,
            "hostscripts": hostscripts,
            "services": services,
            "running_applications": running_apps,
            "nse_vulns": nse_vulns,
        }
    except Exception as exc:
        logger.warning(f"Service XML parse error ({path}): {exc}")
        return None


def _get_mac_from_arp(ip: str) -> str | None:
    try:
        output = subprocess.check_output(["arp", "-a", ip], text=True, creationflags=0x08000000)
        for line in output.splitlines():
            if ip in line:
                parts = line.strip().split()
                if len(parts) >= 2 and "-" in parts[1]:
                    return parts[1].replace("-", ":").upper()
    except Exception:
        pass
    return None


def snapshot_arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, creationflags=0x08000000)
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and "-" in parts[1]:
                ip_candidate = parts[0]
                try:
                    ipaddress.IPv4Address(ip_candidate)
                except ValueError:
                    continue
                table[ip_candidate] = parts[1].replace("-", ":").upper()
    except Exception as exc:
        logger.warning(f"ARP table snapshot failed: {exc}")
    return table


# =============================================================================
# MAC VENDOR LOOKUP
# =============================================================================
try:
    from mac_vendor_lookup import AsyncMacLookup
    _mac_lookup = AsyncMacLookup()
    _MAC_LOOKUP_AVAILABLE = True
except ImportError:
    _mac_lookup = None
    _MAC_LOOKUP_AVAILABLE = False
    logger.warning("mac-vendor-lookup not installed — MAC vendor guesses will be skipped.")

_mac_vendor_db_ready = False

async def ensure_mac_vendor_db_loaded() -> None:
    global _mac_vendor_db_ready
    if not _MAC_LOOKUP_AVAILABLE or _mac_vendor_db_ready:
        return
    try:
        await _mac_lookup.load_vendors()
        _mac_vendor_db_ready = True
        logger.info("MAC vendor database (IEEE OUI) loaded")
    except Exception as exc:
        logger.warning(f"MAC vendor DB load failed: {exc}")

async def guess_vendor_from_mac(mac: str | None) -> str | None:
    if not mac or not _MAC_LOOKUP_AVAILABLE or not _mac_vendor_db_ready:
        return None
    try:
        return await _mac_lookup.lookup(mac)
    except Exception:
        return None


PRIVATE_MAC_LABEL = "Private/Randomized (vendor hidden by device)"


def _is_locally_administered_mac(mac: str | None) -> bool:
    if not mac:
        return False
    try:
        first_octet = mac.replace("-", ":").split(":")[0]
        val = int(first_octet, 16)
        return bool(val & 0b00000010)
    except Exception:
        return False


# =============================================================================
# LOCAL INTERFACE MAC DETECTION
# =============================================================================
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    _PSUTIL_AVAILABLE = False

def get_local_interface_macs() -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not _PSUTIL_AVAILABLE:
        return mapping
    try:
        addrs = psutil.net_if_addrs()
        for iface_addrs in addrs.values():
            mac = None
            ips: list[str] = []
            for a in iface_addrs:
                if a.family == socket.AF_INET:
                    ips.append(a.address)
                else:
                    addr_str = a.address or ""
                    if len(addr_str) in (17, 12) and (":" in addr_str or "-" in addr_str):
                        mac = addr_str.upper().replace("-", ":")
            if mac:
                for ip in ips:
                    mapping[ip] = mac
    except Exception as exc:
        logger.debug(f"Could not enumerate local interfaces: {exc}")
    return mapping


def _resolve_hostname_via_dns(ip: str, timeout: float = 3.0) -> str | None:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hn = socket.gethostbyaddr(ip)
        return hn[0] if hn and hn[0] else None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


# =============================================================================
# ACTIVE mDNS DISCOVERY
# =============================================================================
try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    _ZEROCONF_AVAILABLE = True
except ImportError:
    Zeroconf = ServiceBrowser = ServiceListener = None
    _ZEROCONF_AVAILABLE = False

_MDNS_SERVICE_TYPES = [
    "_device-info._tcp.local.",
    "_airplay._tcp.local.",
    "_companion-link._tcp.local.",
    "_rdlink._tcp.local.",
    "_http._tcp.local.",
    "_ipp._tcp.local.",
    "_workstation._tcp.local.",
    "_smb._tcp.local.",
]

def snapshot_mdns_names(wait_seconds: float = 4.0) -> dict[str, str]:
    if not _ZEROCONF_AVAILABLE:
        return {}

    results: dict[str, str] = {}

    class _Listener(ServiceListener):
        def add_service(self, zc, service_type, name):
            try:
                info = zc.get_service_info(service_type, name, timeout=1500)
                if info and info.addresses:
                    device_name = (info.server or name).rstrip(".")
                    for raw in info.addresses:
                        try:
                            ip = socket.inet_ntoa(raw)
                        except Exception:
                            continue
                        results.setdefault(ip, device_name)
            except Exception:
                pass

        def update_service(self, zc, service_type, name):
            pass

        def remove_service(self, zc, service_type, name):
            pass

    zc = None
    try:
        zc = Zeroconf()
        listener = _Listener()
        browsers = [ServiceBrowser(zc, st, listener) for st in _MDNS_SERVICE_TYPES]
        time.sleep(wait_seconds)
    except Exception as exc:
        logger.warning(f"mDNS snapshot failed: {exc}")
    finally:
        if zc is not None:
            try:
                zc.close()
            except Exception:
                pass

    return results


# =============================================================================
# INTELLIGENCE & CLASSIFICATION ENGINE
# =============================================================================

def _get_default_gateway() -> str | None:
    try:
        if sys.platform == "win32":
            output = subprocess.check_output(["ipconfig"], text=True, creationflags=0x08000000)
            for line in output.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        gw = parts[1].strip()
                        try:
                            ipaddress.IPv4Address(gw)
                            return gw
                        except ValueError:
                            continue
        else:
            output = subprocess.check_output(["ip", "route"], text=True)
            for line in output.splitlines():
                if "default" in line:
                    parts = line.split()
                    for p in parts:
                        try:
                            ipaddress.IPv4Address(p)
                            return p
                        except ValueError:
                            continue
    except Exception:
        pass
    return None


def _get_local_ips() -> set[str]:
    ips = set()
    if not _PSUTIL_AVAILABLE:
        try:
            hn = socket.gethostname()
            ips.add(socket.gethostbyname(hn))
        except Exception:
            pass
        return ips
    try:
        for iface_addrs in psutil.net_if_addrs().values():
            for a in iface_addrs:
                if a.family == socket.AF_INET:
                    ips.add(a.address)
    except Exception:
        pass
    return ips


def _infer_os_from_ttl(ttl: int | None, mac_vendor: str | None) -> str | None:
    if ttl is None:
        return None
    if 110 <= ttl <= 128:
        return "Windows (inferred from ICMP TTL)"
    if 50 <= ttl <= 64:
        if mac_vendor and "apple" in mac_vendor.lower():
            return "iOS / macOS — Apple device (inferred from ICMP TTL + MAC vendor)"
        return "Linux / Android / Unix-like (inferred from ICMP TTL)"
    if 200 <= ttl <= 255:
        return "Network appliance / embedded Unix (inferred from ICMP TTL)"
    return None


def _infer_os_from_ports(ports: list[int]) -> str | None:
    port_set = set(ports)
    windows_ports = {135, 139, 445, 3389}
    linux_ports = {22}
    macos_ports = {548, 5000, 7000}
    if port_set & windows_ports:
        return "Windows (inferred from SMB/RDP ports)"
    if port_set & macos_ports and not (port_set & windows_ports):
        return "macOS (inferred from AFP/Bonjour ports)"
    if port_set & linux_ports:
        return "Linux/Unix (inferred from SSH port)"
    return None


def parse_os_details(os_name: str | None) -> tuple[str | None, str | None, str | None]:
    if not os_name:
        return None, None, None

    os_lower = os_name.lower()
    family = "Unknown"
    version = None

    if "windows" in os_lower:
        family = "Windows"
        m = re.search(r'windows\s+(xp|vista|7|8|8\.1|10|11|2000|2003|2008|2012|2016|2019|2022|nt)', os_lower)
        if m:
            version = m.group(1).upper() if m.group(1) in ['nt', 'xp'] else m.group(1)
    elif "linux" in os_lower or "ubuntu" in os_lower or "debian" in os_lower or "fedora" in os_lower or "centos" in os_lower or "red hat" in os_lower or "arch" in os_lower or "kali" in os_lower:
        family = "Linux"
        m = re.search(r'ubuntu[\s\/]([\d\.]+)', os_lower)
        if m:
            version = m.group(1)
        else:
            m = re.search(r'centos[\s\/]([\d\.]+)', os_lower)
            if m:
                version = m.group(1)
    elif "macos" in os_lower or "os x" in os_lower or "mac os" in os_lower:
        family = "macOS"
        m = re.search(r'(\d+\.\d+)', os_name)
        if m:
            version = m.group(1)
    elif "ios" in os_lower and "cisco" not in os_lower:
        family = "iOS"
        m = re.search(r'(\d+\.\d+)', os_name)
        if m:
            version = m.group(1)
    elif "android" in os_lower:
        family = "Android"
        m = re.search(r'(\d+\.\d+)', os_name)
        if m:
            version = m.group(1)
    elif "freebsd" in os_lower or "openbsd" in os_lower or "netbsd" in os_lower:
        family = "BSD"
    elif "cisco" in os_lower:
        family = "Cisco IOS"
    elif "mikrotik" in os_lower or "routeros" in os_lower:
        family = "MikroTik RouterOS"
    elif "openwrt" in os_lower:
        family = "OpenWRT"
    elif "pfsense" in os_lower or "freebsd" in os_lower:
        family = "pfSense/FreeBSD"
    elif "synology" in os_lower:
        family = "Synology DSM"
    elif "truenas" in os_lower or "freenas" in os_lower:
        family = "TrueNAS"

    return family, version, os_name


def detect_vm_docker_wsl(mac_vendor: str | None, hostscripts: dict, services: list, hostname: str | None) -> tuple[bool, bool, bool]:
    is_vm = False
    is_docker = False
    is_wsl = False

    hname = (hostname or "").lower()
    mv = (mac_vendor or "").lower()

    vm_vendors = ["vmware", "virtualbox", "parallels", "xen", "qemu", "red hat", "microsoft hyper-v", "citrix"]
    for v in vm_vendors:
        if v in mv:
            is_vm = True
            break

    docker_ports = {2375, 2376, 2377}
    for s in services:
        if s.get("port") in docker_ports:
            is_docker = True
        if "docker" in (s.get("name") or "").lower():
            is_docker = True

    if "docker" in hname:
        is_docker = True

    if "wsl" in hname or "microsoft" in mv:
        linux_ports = {22, 80}
        has_linux = any(s.get("port") in linux_ports for s in services)
        if has_linux and not is_vm:
            is_wsl = True

    for sid, output in hostscripts.items():
        out_lower = output.lower()
        if "vmware" in out_lower or "virtual machine" in out_lower:
            is_vm = True
        if "docker" in out_lower:
            is_docker = True

    return is_vm, is_docker, is_wsl


def classify_device(
    os_name: str | None, os_family: str | None, mac_vendor: str | None,
    services: list, hostname: str | None, is_vm: bool, is_docker: bool, is_wsl: bool
) -> tuple[str, str]:
    hname = (hostname or "").lower()
    mv = (mac_vendor or "").lower()
    ports = {s.get("port") for s in services}

    if is_docker:
        return "Container", "Docker Container"
    if is_wsl:
        return "VM", "WSL Instance"
    if is_vm:
        return "VM", "Virtual Machine"

    if mv == PRIVATE_MAC_LABEL.lower() and not ports and (not os_name or os_name == "Unknown"):
        return "Mobile", "Likely Mobile/IoT Device (Private, Randomized MAC)"

    printer_ports = {515, 631, 9100, 9290}
    if ports & printer_ports or "printer" in hname or "canon" in mv or "hp" in mv or "epson" in mv or "xerox" in mv:
        if "canon" in mv:
            return "Printer", "Canon Printer"
        if "hp" in mv or "hewlett" in mv:
            return "Printer", "HP Printer"
        return "Printer", "Network Printer"

    nas_ports = {5000, 5001, 8200, 111, 2049}
    if ports & nas_ports or "synology" in hname or "synology" in mv or "qnap" in hname or "qnap" in mv or "nas" in hname:
        if "synology" in hname or "synology" in mv:
            return "NAS", "Synology NAS"
        if "qnap" in hname or "qnap" in mv:
            return "NAS", "QNAP NAS"
        return "NAS", "Network Attached Storage"

    if "camera" in hname or "cam" in hname or "hikvision" in mv or "dahua" in mv or "axis" in mv:
        return "Camera", "IP Camera"

    if "tv" in hname or "samsung" in mv or "lg" in mv or "roku" in mv or "chromecast" in hname:
        if "samsung" in mv or "samsung" in hname:
            return "TV", "Samsung Smart TV"
        if "lg" in mv:
            return "TV", "LG Smart TV"
        return "TV", "Smart TV / Media Player"

    if "iphone" in hname or "ipad" in hname or "apple" in mv:
        if "ipad" in hname:
            return "Tablet", "Apple iPad"
        return "Phone", "Apple iPhone"
    if "android" in hname or "samsung" in mv or "google" in mv or "pixel" in hname:
        if "tablet" in hname or "tab" in hname:
            return "Tablet", "Android Tablet"
        return "Phone", "Android Phone"

    router_ports = {53, 80, 443, 8080, 8443}
    if ports & {53, 67, 68} or "router" in hname or "gateway" in hname or "tplink" in mv or "netgear" in mv or "asus" in mv or "linksys" in mv or "cisco" in mv or "mikrotik" in mv or "ubiquiti" in mv:
        if "mikrotik" in mv or "mikrotik" in hname:
            return "Router", "MikroTik Router"
        if "ubiquiti" in mv:
            return "Router", "Ubiquiti Access Point / Router"
        if "cisco" in mv:
            return "Router", "Cisco Network Device"
        return "Router", "Router / Gateway / Firewall"

    if "switch" in hname or "netgear" in mv:
        return "Switch", "Network Switch"

    if "iot" in hname or "esp" in hname or "arduino" in hname or "raspberry" in hname:
        if "raspberry" in hname or "raspberry" in mv:
            return "IoT", "Raspberry Pi"
        return "IoT", "IoT / Embedded Device"

    if os_family == "Windows":
        server_ports = {53, 88, 135, 389, 443, 445, 593, 636, 3268, 3269, 9389}
        if ports & server_ports:
            return "Server", "Windows Server"
        return "Workstation", "Windows Workstation"

    if os_family == "Linux":
        server_indicators = {53, 111, 2049, 3306, 5432, 6379, 8080, 8443, 9090}
        if ports & server_indicators or "server" in hname:
            return "Server", "Linux Server"
        return "Workstation", "Linux Workstation"

    if os_family == "macOS":
        if "macbook" in hname or "imac" in hname or "macmini" in hname:
            return "Workstation", "Apple Mac"
        return "Workstation", "macOS Device"

    if len(ports) > 15:
        return "Server", "Multi-Service Server"
    if len(ports) > 0:
        return "Workstation", "General Purpose Host"

    return "Unknown", "Unknown Device"


async def resolve_os_multi(
    os_name: str | None, os_accuracy: int, hostscripts: dict, open_ports: list[int],
    mac_vendor: str | None = None, ttl: int | None = None,
) -> tuple[str, str, str | None, str | None]:
    family, version, clean_name = parse_os_details(os_name)

    if os_name and os_accuracy >= 85:
        return os_name, "confirmed", family, version

    smb_output = hostscripts.get("smb-os-discovery")
    if smb_output:
        m = re.search(r"OS:\s*([^\r\n]+)", smb_output)
        if m:
            smb_os = m.group(1).strip()
            f, v, _ = parse_os_details(smb_os)
            return smb_os, "confirmed", f, v

    if os_name:
        return os_name, "inferred", family, version

    inferred = _infer_os_from_ports(open_ports)
    if inferred:
        f, v, _ = parse_os_details(inferred)
        return inferred, "inferred", f, v

    ttl_guess = _infer_os_from_ttl(ttl, mac_vendor)
    if ttl_guess:
        f, v, _ = parse_os_details(ttl_guess)
        return ttl_guess, "inferred", f, v

    if mac_vendor:
        clean_vendor = mac_vendor.split(",")[0].strip()
        return f"{clean_vendor} device (inferred from MAC vendor)", "inferred", "Unknown", None

    return "Unknown", "unknown", "Unknown", None


HOSTNAME_CONFIDENCE = {
    "ptr": 0.75,
    "netbios": 0.80,
    "smb": 0.85,
    "mdns": 0.70,
    "ssh": 0.65,
    "http": 0.60,
    "unknown": 0.0,
}

def resolve_hostname_multi(
    ip: str, nmap_hostname: str | None, hostscripts: dict, mdns_names: dict[str, str] | None = None,
) -> tuple[str, str, float]:
    if nmap_hostname:
        return nmap_hostname, "ptr", HOSTNAME_CONFIDENCE["ptr"]

    nbstat_output = hostscripts.get("nbstat")
    if nbstat_output:
        m = re.search(r"NetBIOS name:\s*([^,\r\n]+)", nbstat_output)
        if m:
            return m.group(1).strip(), "netbios", HOSTNAME_CONFIDENCE["netbios"]

    smb_output = hostscripts.get("smb-os-discovery")
    if smb_output:
        m = re.search(r"Computer name:\s*([^\r\n]+)", smb_output)
        if m:
            return m.group(1).strip(), "smb", HOSTNAME_CONFIDENCE["smb"]

    mdns_name = (mdns_names or {}).get(ip)
    if mdns_name:
        return mdns_name, "mdns", HOSTNAME_CONFIDENCE["mdns"]

    ssh_output = hostscripts.get("ssh-hostkey")
    if ssh_output:
        m = re.search(r"Host:\s*([^\s\r\n]+)", ssh_output)
        if m:
            return m.group(1).strip(), "ssh", HOSTNAME_CONFIDENCE["ssh"]

    http_title = hostscripts.get("http-title")
    if http_title:
        clean = http_title.strip().split("\n")[0][:30]
        if clean and clean != "Site doesn't have a title":
            return clean, "http", HOSTNAME_CONFIDENCE["http"]

    dns_name = _resolve_hostname_via_dns(ip)
    if dns_name:
        return dns_name, "ptr", HOSTNAME_CONFIDENCE["ptr"]

    return "Unknown", "unknown", 0.0


import ctypes

_SEVERITY_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}

def extract_cve_from_template_id(template_id: str) -> str | None:
    if not template_id:
        return None
    m = re.fullmatch(r'(?i)cve-(\d{4})-(\d+)', template_id.strip())
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    return None


def compute_health_score(all_vulns: list[dict]) -> int:
    """Compute a 0-100 health score from discovered vulnerabilities.
    Weights are calibrated so that a single critical vuln drops the score
    significantly (e.g. 1 critical → ~75, 3 criticals → ~25).
    """
    weights = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
    risk = sum(weights.get((v.get("severity") or "info").lower(), 0) for v in all_vulns)
    return max(0, 100 - risk)


def _parse_nuclei_jsonl(path: Path) -> list[dict]:
    vulns = []
    if not path.exists():
        return vulns
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info         = data.get("info", {})
                classification = info.get("classification", {})
                template_id  = data.get("template-id", "") or ""
                severity     = (info.get("severity") or "info").lower()

                cve_list = classification.get("cve-id") or []
                cve_from_class = cve_list[0] if cve_list else None
                cve_from_tmpl  = extract_cve_from_template_id(template_id)
                cve_id = cve_from_class or cve_from_tmpl

                raw_cvss = classification.get("cvss-score")
                if raw_cvss is not None:
                    try:
                        cvss_score     = float(raw_cvss)
                        cvss_estimated = False
                    except (ValueError, TypeError):
                        cvss_score     = _SEVERITY_CVSS.get(severity, 0.5)
                        cvss_estimated = True
                else:
                    cvss_score     = _SEVERITY_CVSS.get(severity, 0.5)
                    cvss_estimated = True

                matcher_name = (
                    data.get("matcher-name")
                    or template_id
                    or "default"
                )

                refs = []
                if classification.get("cwe-id"):
                    refs.append(f"CWE-{classification['cwe-id'][0]}" if isinstance(classification['cwe-id'], list) else f"CWE-{classification['cwe-id']}")

                tags = info.get("tags", [])
                exploit_available = any(t in str(tags).lower() for t in ["rce", "exploit", "cve"])

                vulns.append({
                    "template_id":    template_id,
                    "name":           info.get("name") or "Unknown vulnerability",
                    "severity":       severity,
                    "description":    info.get("description") or "",
                    "cve_id":         cve_id,
                    "matcher_name":   matcher_name,
                    "cvss_score":     cvss_score,
                    "cvss_estimated": cvss_estimated,
                    "source":         "nuclei",
                    "remediation":    info.get("remediation") or "",
                    "exploit_available": exploit_available,
                    "references":     refs,
                })
            except json.JSONDecodeError as exc:
                logger.warning(f"Nuclei JSONL parse error: {exc}")
    return vulns

# =============================================================================
# SEMAPHORE
# =============================================================================
_sem = asyncio.Semaphore(15)

# =============================================================================
# NMAP SCRIPT SETS
# =============================================================================
# Full script set used for ALL hosts (deep scan)
NMAP_SCRIPT_SET = (
    "default,discovery,auth,vuln,banner,"
    "http-*,ssl-*,ftp-anon,"
    "smb-os-discovery,smb-enum-shares,nbstat,snmp-info,"
    "ssh-hostkey,ssh-brute,dns-service-discovery,"
    "upnp-info,nbstat,smb-security-mode"
)

# =============================================================================
# PIPELINE STEPS
# =============================================================================

async def _run_discovery_probe(target: str, flags: list[str]) -> set[str]:
    tmp = Path(tempfile.mktemp(suffix=".xml"))
    try:
        cmd = [NMAP_PATH] + flags + ["-oX", str(tmp), target]
        await asyncio.to_thread(
            subprocess.run, cmd,
            capture_output=True, check=False, timeout=300,
        )
        return _parse_discovery_xml(tmp)
    except Exception as exc:
        logger.warning(f"Discovery probe failed ({flags}): {exc}")
        return set()
    finally:
        tmp.unlink(missing_ok=True)


async def _ping_host(ip: str):
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-n", "1", "-w", "500", ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            creationflags=0x08000000
        )
        await proc.wait()
    except Exception:
        pass

async def run_arp_cache_discovery(target: str) -> set[str]:
    live_ips = set()
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.prefixlen >= 23:
            logger.info(f"[DISCOVERY] Running native ping sweep on {net.num_addresses} addresses to populate ARP cache...")
            tasks = [_ping_host(str(ip)) for ip in net.hosts()]
            for i in range(0, len(tasks), 50):
                await asyncio.gather(*tasks[i:i+50])

        output = await asyncio.to_thread(subprocess.check_output, ["arp", "-a"], text=True)
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                ip_str = parts[0]
                try:
                    ip_obj = ipaddress.IPv4Address(ip_str)
                    if ip_obj in net and ip_str != str(net.broadcast_address) and ip_str != str(net.network_address):
                        live_ips.add(ip_str)
                except ValueError:
                    pass
    except Exception as e:
        logger.warning(f"ARP cache discovery failed: {e}")
    return live_ips


async def discover_hosts(target: str) -> set[str]:
    results = await asyncio.gather(
        _run_discovery_probe(target, ["-sn", "-PR", "-T5", "--min-parallelism", "100", "--max-retries", "1"]),
        _run_discovery_probe(target, ["-sn", "-PE", "-PP", "-T4", "--min-parallelism", "50", "--max-retries", "1"]),
        _run_discovery_probe(target, ["-sn", "-PS21,22,23,80,443,3389,8080", "-T4", "--min-parallelism", "50", "--max-retries", "1"]),
        run_arp_cache_discovery(target),
        return_exceptions=True
    )

    layer1 = results[0] if isinstance(results[0], set) else set()
    layer2 = results[1] if isinstance(results[1], set) else set()
    layer3 = results[2] if isinstance(results[2], set) else set()
    layer4 = results[3] if isinstance(results[3], set) else set()

    logger.info(f"[DISCOVERY] Layer 1 (Nmap ARP): {len(layer1)} hosts")
    logger.info(f"[DISCOVERY] Layer 2 (Nmap ICMP): {len(layer2)} hosts")
    logger.info(f"[DISCOVERY] Layer 3 (Nmap TCP): {len(layer3)} hosts")
    logger.info(f"[DISCOVERY] Layer 4 (OS ARP Cache): {len(layer4)} hosts")

    all_ips = layer1 | layer2 | layer3 | layer4
    logger.info(f"[DISCOVERY] Total unique live hosts: {len(all_ips)}")
    return all_ips


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except Exception:
        return False


async def _enrich_host_result(
    result: dict, ip: str, arp_snapshot: dict[str, str] | None,
    mdns_names: dict[str, str] | None, gateway_ip: str | None, local_ips: set[str] | None,
) -> dict:
    open_ports = [s["port"] for s in result.get("services", [])]

    if not result.get("mac"):
        result["mac"] = (arp_snapshot or {}).get(ip) or await asyncio.to_thread(_get_mac_from_arp, ip)
    if not result.get("mac_vendor"):
        result["mac_vendor"] = await guess_vendor_from_mac(result.get("mac"))
    if not result.get("mac_vendor") and _is_locally_administered_mac(result.get("mac")):
        result["mac_vendor"] = PRIVATE_MAC_LABEL

    hostname, hostname_source, hostname_confidence = resolve_hostname_multi(
        ip, result.get("hostname"), result.get("hostscripts", {}), mdns_names
    )
    result["hostname"] = hostname
    result["hostname_source"] = hostname_source
    result["hostname_confidence"] = hostname_confidence

    os_name, os_confidence, os_family, os_version = await resolve_os_multi(
        result.get("os"), result.get("os_accuracy", 0),
        result.get("hostscripts", {}), open_ports,
        result.get("mac_vendor"), result.get("ttl"),
    )
    result["os"] = os_name
    result["os_confidence"] = os_confidence
    result["os_family"] = os_family
    result["os_version"] = os_version

    is_vm, is_docker, is_wsl = detect_vm_docker_wsl(
        result.get("mac_vendor"), result.get("hostscripts", {}),
        result.get("services", []), hostname
    )
    result["is_vm"] = is_vm
    result["is_docker"] = is_docker
    result["is_wsl"] = is_wsl

    dev_type, dev_class = classify_device(
        os_name, os_family, result.get("mac_vendor"),
        result.get("services", []), hostname, is_vm, is_docker, is_wsl
    )
    result["device_type"] = dev_type
    result["device_classification"] = dev_class
    result["manufacturer"] = result.get("mac_vendor") or "Unknown"

    result["is_gateway"] = (gateway_ip is not None and ip == gateway_ip)
    result["is_local_machine"] = (local_ips is not None and ip in local_ips)

    return result


async def service_scan_host(ip: str, arp_snapshot: dict[str, str] | None = None,
                           mdns_names: dict[str, str] | None = None,
                           gateway_ip: str | None = None, local_ips: set[str] | None = None,
                           attempt: int = 1, max_attempts: int = 2) -> dict | None:
    """
    EXTREME DEEP scan for ALL hosts.
    Scans ALL 65535 ports, uses -A, and is very aggressive.
    No hard timeout on the subprocess – Nmap's --host-timeout is set to 60 minutes.
    """
    async with _sem:
        logger.info(f"[SERVICE SCAN - EXTREME] Starting EXTREME scan → {ip} (attempt {attempt}/{max_attempts})")
        t0 = asyncio.get_event_loop().time()
        tmp = Path(tempfile.mktemp(suffix=f"_{ip.replace('.','_')}.xml"))
        try:
            # Build the most aggressive Nmap command possible
            cmd = [
                NMAP_PATH,
                "-Pn",           # Treat all hosts as up
                "-sS",           # SYN stealth scan (faster)
                "-sV",           # Version detection
                "--version-all", # Try all version probes
                "-A",            # OS detection, traceroute, and script scan
                "-p-",           # ALL 65535 ports
                "--min-rate", "100",   # Minimum packet rate
                "--max-retries", "2",
                "--min-parallelism", "50",
                "--script", NMAP_SCRIPT_SET,
                "--script-timeout", "5m",
                "-T4",           # Aggressive timing
                "--open",        # Only show open ports
                "--host-timeout", "60m",   # 1 hour per host – you can increase or remove
                "-oX", str(tmp),
                ip,
            ]

            # Add OS detection with higher confidence if admin
            if is_admin():
                cmd += ["-O", "--osscan-guess", "--max-os-tries", "3"]
            else:
                logger.info(f"[{ip}] Running without Admin rights — skipping OS detection (-O).")

            # Run subprocess with no timeout (None) – we rely on Nmap's --host-timeout
            proc = await asyncio.to_thread(
                subprocess.run, cmd,
                capture_output=True, check=False, timeout=None,  # No subprocess timeout
            )
            result = _parse_service_xml(tmp)

            if result is not None:
                result = await _enrich_host_result(result, ip, arp_snapshot, mdns_names, gateway_ip, local_ips)
                result["discovery_method"] = "deep-scan-extreme"
                # Inject dangerous-service signature findings into nse_vulns
                sig_vulns = detect_dangerous_services(result.get("services", []))
                result["nse_vulns"] = result.get("nse_vulns", []) + sig_vulns
                if sig_vulns:
                    logger.warning(
                        f"[SERVICE SCAN] {ip} — {len(sig_vulns)} dangerous service signature(s) detected: "
                        + ", ".join(v['name'] for v in sig_vulns)
                    )

                duration = asyncio.get_event_loop().time() - t0
                logger.info(
                    f"[SERVICE SCAN - EXTREME] {ip} — {len(result['services'])} ports open, "
                    f"OS: {result['os']} ({result['os_confidence']}), device: {result['device_classification']}, "
                    f"hostname: {result['hostname']} ({result['hostname_source']}) — {duration:.1f}s"
                )
                return result

            stderr_tail = (proc.stderr or b"").decode(errors="replace")[-400:] if proc else ""
            logger.warning(f"[SERVICE SCAN - EXTREME] No XML/host-up result for {ip} (rc={getattr(proc, 'returncode', '?')}). stderr: {stderr_tail!r}")

            if attempt < max_attempts:
                logger.warning(f"[SERVICE SCAN - EXTREME] Empty/failed result for {ip}, retrying once")
                return await service_scan_host(ip, arp_snapshot, mdns_names, gateway_ip, local_ips, attempt + 1, max_attempts)
            logger.error(f"[SERVICE SCAN - EXTREME] Giving up on {ip} after {max_attempts} attempts")
            return None

        except subprocess.TimeoutExpired:
            # This shouldn't happen since timeout=None, but keep it for safety.
            duration = asyncio.get_event_loop().time() - t0
            logger.error(f"[SERVICE SCAN - EXTREME] Subprocess timeout (unexpected) on {ip} after {duration:.0f}s — not retrying")
            return None
        except Exception as exc:
            logger.error(f"[SERVICE SCAN - EXTREME] Error on {ip}: {exc}")
            if attempt < max_attempts:
                return await service_scan_host(ip, arp_snapshot, mdns_names, gateway_ip, local_ips, attempt + 1, max_attempts)
            return None
        finally:
            tmp.unlink(missing_ok=True)


WEB_PORTS = {80, 443, 8080, 8443, 3000, 8000, 8888, 9090, 9443, 4443}
HTTPS_PORTS = {443, 8443, 9443, 4443}
# Non-web service ports that nuclei can still test with network-level CVE templates
NETWORK_NUCLEI_PORTS = {21, 22, 23, 25, 53, 110, 143, 3306, 5432, 6379, 5900, 2049, 1099, 2121}

async def nuclei_scan_host(ip: str, open_ports: list[int]) -> list[dict]:
    web_ports = [p for p in open_ports if p in WEB_PORTS]
    # Also scan known non-web ports for CVE-tagged network templates
    network_ports = [p for p in open_ports if p in NETWORK_NUCLEI_PORTS and p not in WEB_PORTS]

    if not web_ports and not network_ports:
        return []

    async def _scan_web_port(port: int, attempt: int = 1, max_attempts: int = 2) -> list[dict]:
        scheme = "https" if port in HTTPS_PORTS else "http"
        url = f"{scheme}://{ip}:{port}"
        tmp = Path(tempfile.mktemp(suffix=f"_nuclei_{ip.replace('.','_')}_{port}.json"))
        try:
            cmd = [
                NUCLEI_PATH,
                "-u", url,
                "-tags", "cve,vuln,default-login,panel,rce,lfi,sqli,xss,exposure,misconfig,auth-bypass",
                "-severity", "critical,high,medium,low,info",
                "-jsonl",
                "-o", str(tmp),
                "-silent",
                "-ni",
                "-duc",
                "-timeout", "10",
                "-retries", "1",
            ]
            async with _sem:
                await asyncio.to_thread(
                    subprocess.run, cmd,
                    capture_output=True, check=False, timeout=180,
                )
            vulns = _parse_nuclei_jsonl(tmp)
            logger.info(f"[NUCLEI] {ip}:{port} (web) — {len(vulns)} vulnerabilities found")
            return vulns
        except subprocess.TimeoutExpired:
            logger.error(f"[NUCLEI] Timed out on {ip}:{port} — not retrying")
            return []
        except Exception as exc:
            logger.error(f"[NUCLEI] Error on {ip}:{port}: {exc}")
            if attempt < max_attempts:
                return await _scan_web_port(port, attempt + 1, max_attempts)
            return []
        finally:
            tmp.unlink(missing_ok=True)

    async def _scan_network_port(port: int) -> list[dict]:
        """Run nuclei CVE templates against non-web services (FTP, SSH, MySQL, etc.)."""
        target_url = f"{ip}:{port}"
        tmp = Path(tempfile.mktemp(suffix=f"_nuclei_net_{ip.replace('.','_')}_{port}.json"))
        try:
            cmd = [
                NUCLEI_PATH,
                "-u", target_url,
                "-tags", "cve,default-login,network",
                "-severity", "critical,high,medium,low",
                "-jsonl",
                "-o", str(tmp),
                "-silent",
                "-ni",
                "-duc",
                "-timeout", "8",
                "-retries", "0",
            ]
            async with _sem:
                await asyncio.to_thread(
                    subprocess.run, cmd,
                    capture_output=True, check=False, timeout=120,
                )
            vulns = _parse_nuclei_jsonl(tmp)
            if vulns:
                logger.info(f"[NUCLEI] {ip}:{port} (network) — {len(vulns)} CVE findings")
            return vulns
        except Exception as exc:
            logger.debug(f"[NUCLEI] Network scan skipped for {ip}:{port}: {exc}")
            return []
        finally:
            tmp.unlink(missing_ok=True)

    web_tasks = [_scan_web_port(p) for p in web_ports]
    net_tasks = [_scan_network_port(p) for p in network_ports]
    results = await asyncio.gather(*(web_tasks + net_tasks), return_exceptions=True)
    all_vulns: list[dict] = []
    for r in results:
        if isinstance(r, list):
            all_vulns.extend(r)
    return all_vulns


async def persist_results(scan_id: str, host_results: list[dict]) -> None:
    logger.info(f"[PERSIST] Saving {len(host_results)} hosts to database")
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(delete(Host).where(Host.scan_id == scan_id))

            for hr in host_results:
                host = Host(
                    scan_id=scan_id,
                    ip=hr["ip"],
                    ipv6=hr.get("ipv6"),
                    hostname=hr.get("hostname") or "Unknown",
                    hostname_source=hr.get("hostname_source") or "unknown",
                    hostname_confidence=hr.get("hostname_confidence", 0.0),
                    os=hr.get("os") or "Unknown",
                    os_family=hr.get("os_family") or "Unknown",
                    os_version=hr.get("os_version") or "Unknown",
                    os_confidence=hr.get("os_confidence") or "unknown",
                    device_type=hr.get("device_type") or "Unknown",
                    device_classification=hr.get("device_classification") or "Unknown Device",
                    manufacturer=hr.get("manufacturer") or "Unknown",
                    mac_address=hr.get("mac") or "Unknown",
                    mac_vendor=hr.get("mac_vendor"),
                    network_interface=hr.get("network_interface"),
                    architecture=hr.get("architecture"),
                    uptime=hr.get("uptime"),
                    is_gateway=hr.get("is_gateway", False),
                    is_local_machine=hr.get("is_local_machine", False),
                    is_vm=hr.get("is_vm", False),
                    is_docker=hr.get("is_docker", False),
                    is_wsl=hr.get("is_wsl", False),
                    status="up",
                    audit_status="completed",
                    last_scan=datetime.utcnow(),
                    risk_score=hr.get("risk_score", 0.0),
                    criticality=hr.get("criticality") or "Unknown",
                    discovery_method=hr.get("discovery_method") or "unknown",
                    running_applications=hr.get("running_applications", []),
                    screenshot_path=hr.get("screenshot_path"),
                    evidence=hr.get("evidence", []),
                )
                session.add(host)
                await session.flush()





                for svc in hr.get("services", []):
                    session.add(Service(
                        host_id=host.id,
                        port=svc["port"],
                        protocol=svc.get("protocol") or "tcp",
                        name=svc.get("name") or "Unknown",
                        version=svc.get("version") or "Unknown",
                        state=svc.get("state") or "open",
                        banner=svc.get("banner"),
                    ))

                all_vulns = []
                all_vulns.extend(hr.get("nse_vulns", []))
                all_vulns.extend(hr.get("vulns", []))
                all_vulns.extend(hr.get("cred_vulns", []))

                for vuln in all_vulns:
                    sev = (vuln.get("severity") or "info").lower()
                    raw_cvss = vuln.get("cvss_score")
                    try:
                        cvss_score = float(raw_cvss) if raw_cvss is not None else None
                    except (ValueError, TypeError):
                        cvss_score = None
                    cvss_estimated = bool(vuln.get("cvss_estimated", False))
                    matcher_name = (
                        vuln.get("matcher_name")
                        or vuln.get("template_id")
                        or "default"
                    )
                    session.add(Vulnerability(
                        host_id=host.id,
                        template_id=vuln.get("template_id") or "unknown",
                        name=vuln.get("name") or "Unknown vulnerability",
                        severity=sev,
                        cve_id=vuln.get("cve_id"),
                        description=vuln.get("description") or "",
                        matcher_name=matcher_name,
                        cvss_score=cvss_score,
                        cvss_estimated=cvss_estimated,
                        source=vuln.get("source") or "nuclei",
                        discovered_at=datetime.utcnow(),
                        remediation=vuln.get("remediation"),
                        exploit_available=vuln.get("exploit_available", False),
                        references=vuln.get("references", []),
                    ))

            await session.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(
                    status="done",
                    hosts_found=len(host_results),
                    finished_at=datetime.utcnow(),
                )
            )


# =============================================================================
# FIXED: async fallback host result (no asyncio.run)
# =============================================================================
async def _fallback_host_result(
    ip: str, arp_snapshot: dict, mdns_names: dict, gateway_ip: str | None, local_ips: set,
    mac: str | None, mac_vendor: str | None,
) -> dict:
    """Async fallback record for a host that couldn't be scanned."""
    hostname, hostname_source, hostname_confidence = resolve_hostname_multi(ip, None, {}, mdns_names)
    os_name, os_confidence, os_family, os_version = await resolve_os_multi(None, 0, {}, [], mac_vendor, None)
    is_vm, is_docker, is_wsl = detect_vm_docker_wsl(mac_vendor, {}, [], hostname)
    dev_type, dev_class = classify_device(os_name, os_family, mac_vendor, [], hostname, is_vm, is_docker, is_wsl)

    return {
        "ip": ip,
        "hostname": hostname,
        "hostname_source": hostname_source,
        "hostname_confidence": hostname_confidence,
        "os": os_name,
        "os_confidence": os_confidence,
        "os_family": os_family,
        "os_version": os_version,
        "mac": mac,
        "mac_vendor": mac_vendor,
        "device_type": dev_type,
        "device_classification": dev_class,
        "manufacturer": mac_vendor or "Unknown",
        "is_gateway": (gateway_ip is not None and ip == gateway_ip),
        "is_local_machine": (ip in local_ips) if local_ips else False,
        "is_vm": is_vm,
        "is_docker": is_docker,
        "is_wsl": is_wsl,
        "services": [],
        "vulns": [],
        "cred_vulns": [],
        "nse_vulns": [],
        "discovery_method": "fallback-unreachable",
        "risk_score": 0.0,
        "criticality": "Low",
    }


# =============================================================================
# run_pipeline with async fallback calls and EVIDENCE CAPTURE
# =============================================================================
async def run_pipeline(scan_id: str, target: str) -> None:
    logger.info(f"[SCAN START] scan_id={scan_id} target={target}")
    t0 = asyncio.get_event_loop().time()

    async def _mark_failed(reason: str) -> None:
        async with AsyncSessionLocal() as s:
            async with s.begin():
                await s.execute(
                    update(Scan).where(Scan.id == scan_id).values(
                        status="failed", fail_reason=reason, finished_at=datetime.utcnow()
                    )
                )

    try:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses == 1:
                target_ip = str(net.network_address)
                octets = target_ip.split('.')
                discovery_target = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                logger.info(f"[PIPELINE] Target is single IP {target_ip}. Discovering on subnet {discovery_target}")
            else:
                target_ip = None
                discovery_target = target
        except ValueError:
            target_ip = None
            discovery_target = target

        gateway_ip = await asyncio.to_thread(_get_default_gateway)
        local_ips = await asyncio.to_thread(_get_local_ips)
        logger.info(f"[PIPELINE] Gateway detected: {gateway_ip}, Local IPs: {local_ips}")

        live_ips = await discover_hosts(discovery_target)
        if not live_ips:
            await _mark_failed("no_hosts_found")
            logger.warning(f"[SCAN] No live hosts found for {discovery_target}")
            return

        live_ips_list = list(live_ips)
        if target_ip and target_ip in live_ips_list:
            live_ips_list.remove(target_ip)
            live_ips_list.insert(0, target_ip)

        logger.info(
            f"[PIPELINE] {len(live_ips_list)} host(s) discovered. "
            f"ALL hosts will receive an EXTREME deep scan (nmap -Pn -sS -sV -A -p- --script full)."
        )

        mdns_names = await asyncio.to_thread(snapshot_mdns_names, 4.0)
        arp_snapshot = await asyncio.to_thread(snapshot_arp_table)
        local_macs = await asyncio.to_thread(get_local_interface_macs)
        arp_snapshot.update(local_macs)
        logger.info(f"[PIPELINE] ARP snapshot captured: {len(arp_snapshot)} entries")

        await ensure_mac_vendor_db_loaded()

        # EXTREME deep scan for EVERY host
        scan_tasks = [service_scan_host(ip, arp_snapshot, mdns_names, gateway_ip, local_ips) for ip in live_ips_list]
        scan_raw = await asyncio.gather(*scan_tasks, return_exceptions=True)

        host_results: list[dict] = []
        for i, res in enumerate(scan_raw):
            ip = live_ips_list[i]
            if isinstance(res, Exception):
                logger.error(f"[SERVICE SCAN] Unexpected error for {ip}: {res}")
                mac = arp_snapshot.get(ip) or await asyncio.to_thread(_get_mac_from_arp, ip)
                mac_vendor = await guess_vendor_from_mac(mac)
                host_results.append(await _fallback_host_result(ip, arp_snapshot, mdns_names, gateway_ip, local_ips, mac, mac_vendor))
            elif res is not None:
                host_results.append(res)
            else:
                mac = arp_snapshot.get(ip) or await asyncio.to_thread(_get_mac_from_arp, ip)
                mac_vendor = await guess_vendor_from_mac(mac)
                host_results.append(await _fallback_host_result(ip, arp_snapshot, mdns_names, gateway_ip, local_ips, mac, mac_vendor))

        if len(host_results) != len(live_ips_list):
            logger.warning(
                f"[PIPELINE] host_results ({len(host_results)}) != discovered hosts ({len(live_ips_list)}) — reconciling"
            )
            seen_ips = {hr["ip"] for hr in host_results}
            for ip in live_ips_list:
                if ip not in seen_ips:
                    host_results.append(await _fallback_host_result(ip, arp_snapshot, mdns_names, gateway_ip, local_ips, arp_snapshot.get(ip), None))

        # Nuclei on web ports for ALL hosts
        nuclei_tasks = [
            nuclei_scan_host(hr["ip"], [s["port"] for s in hr.get("services", [])])
            for hr in host_results
        ]
        nuclei_raw = await asyncio.gather(*nuclei_tasks, return_exceptions=True)

        for i, res in enumerate(nuclei_raw):
            if isinstance(res, Exception):
                logger.error(f"[NUCLEI] Unexpected error for host {host_results[i]['ip']}: {res}")
                host_results[i]["vulns"] = []
            else:
                host_results[i]["vulns"] = res

        # Credential testing
        logger.info("[CRED TEST] Starting credential testing stage")
        cred_test_tasks = [run_credential_tests(hr) for hr in host_results]
        cred_results_raw = await asyncio.gather(*cred_test_tasks, return_exceptions=True)

        for i, res in enumerate(cred_results_raw):
            if isinstance(res, Exception):
                logger.error(f"[CRED TEST] Error for host {host_results[i]['ip']}: {res}")
                host_results[i]["cred_vulns"] = []
            else:
                host_results[i]["cred_vulns"] = res if res else []

        # ── EVIDENCE CAPTURE ────────────────────────────────────────────────
        logger.info("[EVIDENCE] Capturing screenshots and text evidence")
        for hr in host_results:
            hr["evidence"] = []
            hr["screenshot_path"] = None
            # 1. Web screenshots for each open web port
            for svc in hr.get("services", []):
                port = svc.get("port")
                if port in WEB_PORTS:
                    scheme = "https" if port in HTTPS_PORTS else "http"
                    url = f"{scheme}://{hr['ip']}:{port}"
                    screenshot_path = await capture_host_screenshot(scan_id, hr['ip'], port, url)
                    if screenshot_path:
                        path_str = str(screenshot_path)
                        hr["evidence"].append({
                            "type": "web_screenshot",
                            "path": path_str,
                            "label": f"Capture écran web {hr['ip']}:{port}"
                        })
                        if not hr["screenshot_path"]:
                            hr["screenshot_path"] = path_str

            # 2. Credential evidence (auth screenshots for web, text for others)
            for cred in hr.get("cred_vulns", []):
                if cred.get("vulnerable") and cred.get("credentials_found"):
                    service = cred.get("service", "")
                    port = cred.get("port", 0)
                    if port in WEB_PORTS and service.lower() in ["http", "https", "web"]:
                        # Try auth screenshot for each found credential
                        for c in cred["credentials_found"]:
                            url = f"http://{hr['ip']}:{port}" if port != 443 else f"https://{hr['ip']}:{port}"
                            auth_path = await capture_auth_screenshot(
                                scan_id, hr['ip'], port, url,
                                c["username"], c["password"]
                            )
                            if auth_path:
                                path_str = str(auth_path)
                                hr["evidence"].append({
                                    "type": "auth_screenshot",
                                    "path": path_str,
                                    "label": f"Authentification réussie sur {service}:{port} avec {c['username']}"
                                })
                                if not hr["screenshot_path"]:
                                    hr["screenshot_path"] = path_str
                                break  # stop after first success
                    else:
                        # Non-web: text evidence
                        text_ev = capture_credential_text(
                            scan_id, hr['ip'], port, service,
                            cred["credentials_found"]
                        )
                        hr["evidence"].append(text_ev)

        # CVE enrichment
        logger.info("[CVE ENRICH] Starting CVE enrichment stage")
        all_vulns = []
        for hr in host_results:
            all_vulns.extend(hr.get("vulns", []))
            all_vulns.extend(hr.get("cred_vulns", []))
            all_vulns.extend(hr.get("nse_vulns", []))

        if all_vulns:
            enriched_vulns = await enrich_vulnerabilities_list(all_vulns)
            vuln_index = 0
            for hr in host_results:
                total_vulns = len(hr.get("vulns", [])) + len(hr.get("cred_vulns", [])) + len(hr.get("nse_vulns", []))
                if total_vulns > 0:
                    hr["all_enriched_vulns"] = enriched_vulns[vuln_index:vuln_index + total_vulns]
                    vuln_index += total_vulns
                else:
                    hr["all_enriched_vulns"] = []

        # Risk scoring
        for hr in host_results:
            all_vulns_for_host = hr.get("vulns", []) + hr.get("cred_vulns", []) + hr.get("nse_vulns", [])
            score = calculate_host_risk_score(
                all_vulns_for_host,
                hr.get("services", []),
                hr.get("cred_vulns", [])
            )
            hr["risk_score"] = score
            hr["criticality"] = criticality_from_score(score)

        # Persist
        await persist_results(scan_id, host_results)

        # AI Audit Analysis (fallback if Ollama not available)
        logger.info("[AI ANALYSIS] Generating scan-level audit analysis")
        try:
            from services.audit_analysis import generate_audit_analysis, persist_audit_analysis
            analysis = await asyncio.wait_for(generate_audit_analysis(scan_id), timeout=90)
            if analysis:
                await persist_audit_analysis(scan_id, analysis)
                mode = "AI" if analysis.get("ai_generated") else "fallback"
                logger.info(f"[AI ANALYSIS] Completed ({mode} mode)")
            else:
                logger.warning("[AI ANALYSIS] generate_audit_analysis returned None/empty")
        except Exception as exc:
            logger.exception(f"[AI ANALYSIS] Failed (non-fatal): {exc}")
            try:
                from services.audit_analysis import build_fallback_analysis, build_scan_context, persist_audit_analysis
                context = await build_scan_context(scan_id)
                if context:
                    fallback = build_fallback_analysis(context)
                    await persist_audit_analysis(scan_id, fallback)
                    logger.info("[AI ANALYSIS] Fallback analysis persisted")
            except Exception as fallback_exc:
                logger.error(f"[AI ANALYSIS] Fallback also failed: {fallback_exc}")

        duration = asyncio.get_event_loop().time() - t0
        logger.info(f"[SCAN DONE] scan_id={scan_id} duration={duration:.1f}s hosts_audited={len(host_results)}")

    except Exception as exc:
        logger.exception(f"[PIPELINE ERROR] scan_id={scan_id}: {exc}")
        await _mark_failed(str(exc))


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    try:
        net = ipaddress.ip_network(raw, strict=False)
        return str(net)
    except ValueError:
        if "-" in raw:
            return raw
        raise ValueError(f"Invalid target format: '{raw}'. Use an IP, CIDR, or range.")

# =============================================================================
# FASTAPI APPLICATION
# =============================================================================
app = FastAPI(
    title="Network Audit API",
    description="Automated host discovery, service scanning, credential testing, and vulnerability assessment with CVE enrichment.",
    version="5.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
os.makedirs("data/screenshots", exist_ok=True)
app.mount("/screenshots", StaticFiles(directory="data/screenshots"), name="screenshots")



@app.on_event("startup")
async def startup() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready.")
    logger.info(f"nmap   → {NMAP_PATH}")
    logger.info(f"nuclei → {NUCLEI_PATH}")
    await ensure_mac_vendor_db_loaded()
    logger.info("ALL hosts receive an EXTREME deep scan (nmap -Pn -sS -sV -A -p- --script full).")


def _host_to_dict(h: "Host") -> dict:
    return {
        "host_id":              h.id,
        "ip":                   h.ip,
        "ipv6":                 h.ipv6,
        "hostname":             h.hostname or "Unknown",
        "hostname_source":      h.hostname_source or "unknown",
        "hostname_confidence":  h.hostname_confidence,
        "os":                   h.os or "Unknown",
        "os_family":            h.os_family or "Unknown",
        "os_version":           h.os_version or "Unknown",
        "os_confidence":        h.os_confidence or "unknown",
        "device_type":          h.device_type or "Unknown",
        "device_classification": h.device_classification or "Unknown Device",
        "manufacturer":         h.manufacturer or "Unknown",
        "mac_address":          h.mac_address or "Unknown",
        "mac_vendor":           h.mac_vendor,
        "network_interface":    h.network_interface,
        "architecture":         h.architecture,
        "uptime":               h.uptime,
        "is_gateway":           h.is_gateway,
        "is_local_machine":     h.is_local_machine,
        "is_vm":                h.is_vm,
        "is_docker":            h.is_docker,
        "is_wsl":               h.is_wsl,
        "status":               h.status or "up",
        "audit_status":         h.audit_status or "pending",
        "last_scan":            h.last_scan.isoformat() if h.last_scan else None,
        "risk_score":           h.risk_score,
        "criticality":          h.criticality or "Unknown",
        "discovery_method":     h.discovery_method,
        "scanned":              len(h.services) > 0,
        "running_applications": h.running_applications or [],
        "screenshot_path":      h.screenshot_path,
        "evidence":             h.evidence or [],

        "services": [
            {
                "port":     s.port,
                "protocol": s.protocol or "tcp",
                "name":     s.name or "Unknown",
                "version":  s.version or "Unknown",
                "state":    s.state or "open",
                "banner":   s.banner,
            }
            for s in sorted(h.services, key=lambda svc: svc.port)
        ],
        "vulnerabilities": [
            {
                "template_id":       v.template_id,
                "name":              v.name,
                "severity":          v.severity,
                "cve_id":            v.cve_id,
                "cvss_score":        float(v.cvss_score) if v.cvss_score else None,
                "cvss_estimated":    bool(v.cvss_estimated),
                "description":       v.description or "",
                "matcher_name":      v.matcher_name or v.template_id or "default",
                "source":            v.source or "nuclei",
                "remediation":       v.remediation,
                "exploit_available": v.exploit_available,
                "references":        v.references or [],
                "discovered_at":     v.discovered_at,
            }
            for v in h.vulnerabilities
        ],
    }


@app.post("/scan", response_model=ScanResponse, status_code=202)
async def create_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    try:
        norm_target = normalize_target(req.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    scan_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        async with session.begin():
            session.add(Scan(id=scan_id, target=norm_target, status="running"))

    background_tasks.add_task(run_pipeline, scan_id, norm_target)
    logger.info(f"[API] Scan {scan_id} queued for target={norm_target}")
    return ScanResponse(scan_id=scan_id, status="running", target=norm_target)


@app.get("/scan/{scan_id}/status", response_model=StatusResponse)
async def get_status(scan_id: str):
    async with AsyncSessionLocal() as session:
        res = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return StatusResponse(
        scan_id=scan.id,
        target=scan.target,
        status=scan.status,
        hosts_found=scan.hosts_found or 0,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )


@app.get("/scan/{scan_id}/results")
async def get_results(scan_id: str):
    async with AsyncSessionLocal() as session:
        s_res = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = s_res.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status == "running":
            raise HTTPException(status_code=202, detail="Scan is still running.")

        h_res = await session.execute(
            select(Host)
            .where(Host.scan_id == scan_id)
            .options(
                selectinload(Host.services),
                selectinload(Host.vulnerabilities),
            )
        )
        hosts = h_res.scalars().unique().all()

    all_vulns_flat = [
        {"severity": v.severity}
        for h in hosts for v in h.vulnerabilities
    ]
    health_score = compute_health_score(all_vulns_flat)

    return {
        "scan_id":      scan.id,
        "target":       scan.target,
        "status":       scan.status,
        "fail_reason":  scan.fail_reason,
        "hosts_found":  scan.hosts_found or 0,
        "health_score": health_score,
        "started_at":   scan.started_at,
        "finished_at":  scan.finished_at,
        "hosts":        [_host_to_dict(h) for h in hosts],
    }


@app.get("/scans")
async def list_scans():
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            select(Scan)
            .options(
                selectinload(Scan.hosts).selectinload(Host.services),
                selectinload(Scan.hosts).selectinload(Host.vulnerabilities)
            )
            .order_by(Scan.started_at.desc())
            .limit(1)
        )
        latest_scan = res.scalar_one_or_none()

    if not latest_scan:
        return []

    sorted_hosts = sorted(latest_scan.hosts, key=lambda x: ipaddress.IPv4Address(x.ip))
    all_vulns_flat = [
        {"severity": v.severity}
        for h in latest_scan.hosts for v in h.vulnerabilities
    ]
    health_score = compute_health_score(all_vulns_flat)

    return [
        {
            "id":          latest_scan.id,
            "scan_id":     latest_scan.id,
            "target":      latest_scan.target,
            "status":      latest_scan.status,
            "fail_reason": latest_scan.fail_reason,
            "hosts_found": latest_scan.hosts_found or 0,
            "health_score": health_score,
            "started_at":  latest_scan.started_at,
            "finished_at": latest_scan.finished_at,
            "discovered_ips": [_host_to_dict(h) for h in sorted_hosts],
        }
    ]


@app.get("/scan/{scan_id}/analysis")
async def get_scan_analysis(scan_id: str):
    from services.audit_analysis import fetch_audit_analysis
    analysis = await fetch_audit_analysis(scan_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not available — scan may still be running.")
    return analysis


@app.get("/scan/{scan_id}/report.pdf")
async def get_scan_report(scan_id: str):
    try:
        from services.pdf_report import generate_pdf_report
        pdf_bytes = await generate_pdf_report(scan_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=audit_report_{scan_id[:8]}.pdf"},
        )
    except Exception as exc:
        logger.error(f"[PDF] Generation failed for {scan_id}: {exc}")
        raise HTTPException(status_code=500, detail=f"PDF generation error: {exc}")


@app.get("/health")
async def health():
    return {
        "status":      "ok",
        "nmap_path":   NMAP_PATH,
        "nuclei_path": NUCLEI_PATH,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)