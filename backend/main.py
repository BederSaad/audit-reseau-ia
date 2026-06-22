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
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# ── 2. Optional dotenv ────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; use environment variables directly

# ── 3. Third-party imports ────────────────────────────────────────────────────
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import (
    Column, DateTime, ForeignKey, Float, Integer, String,
    UniqueConstraint, delete, update, Boolean, Text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.future import select
from sqlalchemy.orm import declarative_base, relationship, selectinload

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
# ORM MODELS
# =============================================================================
class Scan(Base):
    __tablename__ = "scans"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target      = Column(String, nullable=False)
    status      = Column(String, default="running")   # running / done / failed
    fail_reason = Column(String, nullable=True)
    hosts_found = Column(Integer, default=0)
    started_at  = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    hosts       = relationship("Host", back_populates="scan", cascade="all, delete-orphan")


class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("scan_id", "ip"),)
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id     = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    ip          = Column(String, nullable=False)
    hostname    = Column(String, nullable=True)
    os          = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    status      = Column(String, default="up")
    scan            = relationship("Scan", back_populates="hosts")
    services        = relationship("Service", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"
    id       = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id  = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port     = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    name     = Column(String, nullable=True)
    version  = Column(String, nullable=True)
    state    = Column(String, default="open")
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
    cvss_score      = Column(Float, nullable=True)      # exact float from nuclei or estimated
    cvss_estimated  = Column(Boolean, default=False)    # True = estimated from severity
    source          = Column(String, default="nuclei")  # "nuclei" | "nvd"
    discovered_at   = Column(DateTime, default=datetime.utcnow)
    matched_at      = Column(DateTime, default=datetime.utcnow)  # kept for compat
    host            = relationship("Host", back_populates="vulnerabilities")

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
    """Return set of IPs with state=up from a Nmap discovery XML."""
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


def _parse_service_xml(path: Path) -> dict | None:
    """
    Parse a per-host Nmap service-scan XML.
    Returns a dict with ip, hostname, os, mac, and services list — or None.
    """
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

        # IP
        ip = ""
        mac = None
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                ip = addr_el.get("addr", "")
            elif addr_el.get("addrtype") == "mac":
                mac = addr_el.get("addr")
        if not ip:
            return None

        # Hostname (PTR preferred)
        hostname = None
        for hn in host_el.findall("hostnames/hostname"):
            if hn.get("type") == "PTR":
                hostname = hn.get("name")
                break
            hostname = hn.get("name")  # fallback: first found

        # OS (accuracy >= 50%)
        os_name = None
        for osm in host_el.findall("os/osmatch"):
            if int(osm.get("accuracy", "0")) >= 50:
                os_name = osm.get("name")
                break

        # Open ports / services
        services = []
        for port_el in host_el.findall(".//port"):
            st_el = port_el.find("state")
            if st_el is None or st_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            services.append({
                "port":     int(port_el.get("portid", 0)),
                "protocol": port_el.get("protocol", "tcp"),
                "name":     svc_el.get("name") if svc_el is not None else None,
                "version":  f"{product} {version}".strip() or None,
                "state":    "open",
            })

        return {"ip": ip, "hostname": hostname, "os": os_name, "mac": mac, "services": services}
    except Exception as exc:
        logger.warning(f"Service XML parse error ({path}): {exc}")
        return None


def _get_mac_from_arp(ip: str) -> str | None:
    """Natively resolve MAC address from Windows ARP table if Nmap misses it."""
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

import socket
import re as _re

# Severity → estimated CVSS score when the tool doesn't provide one
_SEVERITY_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}

def extract_cve_from_template_id(template_id: str) -> str | None:
    """If template-id matches 'cve-YYYY-NNNNN', return normalised 'CVE-YYYY-NNNNN'."""
    if not template_id:
        return None
    m = _re.fullmatch(r'(?i)cve-(\d{4})-(\d+)', template_id.strip())
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    return None


def compute_health_score(all_vulns: list[dict]) -> int:
    """Network health score: 100 - weighted risk, clamped [0, 100].
    Weights: critical=10, high=6, medium=3, low=1, info=0
    """
    weights = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
    risk = sum(weights.get((v.get("severity") or "info").lower(), 0) for v in all_vulns)
    return max(0, 100 - risk)


def _parse_nuclei_jsonl(path: Path) -> list[dict]:
    """Parse Nuclei JSONL file — one JSON object per line.
    Fixes applied:
    - cve_id extracted from template-id when classification.cve-id is absent
    - matcher_name falls back to template-id ('default' as last resort)
    - cvss_score extracted from classification, or estimated from severity
    - cvss_estimated flag set True when score is estimated
    """
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

                # ── CVE ID: prefer classification list, fall back to template-id pattern
                cve_list = classification.get("cve-id") or []
                cve_from_class = cve_list[0] if cve_list else None
                cve_from_tmpl  = extract_cve_from_template_id(template_id)
                cve_id = cve_from_class or cve_from_tmpl  # None only if neither matches

                # ── CVSS score: try tool-provided, else estimate from severity
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

                # ── matcher_name: explicit field → template-id → 'default'
                matcher_name = (
                    data.get("matcher-name")
                    or template_id
                    or "default"
                )

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
                })
            except json.JSONDecodeError as exc:
                logger.warning(f"Nuclei JSONL parse error: {exc}")
    return vulns

# =============================================================================
# SEMAPHORE — cap concurrent host operations
# =============================================================================
_sem = asyncio.Semaphore(10)

# =============================================================================
# PIPELINE STEPS
# =============================================================================

# ── Step 1a: single Nmap discovery probe ──────────────────────────────────────
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


# ── Step 1b: Windows native ARP cache (Fallback) ─────────────────────────────
async def _ping_host(ip: str):
    """Native Windows ping to force OS ARP resolution."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-n", "1", "-w", "500", ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        await proc.wait()
    except Exception:
        pass

async def run_arp_cache_discovery(target: str) -> set[str]:
    """Reads the Windows ARP cache after forcefully populating it."""
    live_ips = set()
    try:
        net = ipaddress.ip_network(target, strict=False)
        
        # 1. Force populate ARP cache by pinging every IP natively
        if net.prefixlen >= 23: # Prevent overloading on massive subnets
            logger.info(f"[DISCOVERY] Running native ping sweep on {net.num_addresses} addresses to populate ARP cache...")
            tasks = [_ping_host(str(ip)) for ip in net.hosts()]
            # Batch concurrent pings to avoid crashing Windows subprocess limits
            for i in range(0, len(tasks), 50):
                await asyncio.gather(*tasks[i:i+50])

        # 2. Read the resulting ARP cache
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


# ── Step 1c: 4-layer parallel host discovery ─────────────────────────────────
async def discover_hosts(target: str) -> set[str]:
    # Run all probes in parallel. Nmap will trigger network traffic that populates the OS ARP cache,
    # and the ARP cache layer will read it natively (bypassing Nmap's Admin/Npcap requirements).
    results = await asyncio.gather(
        # Layer 1 — ARP (fastest, LAN only)
        _run_discovery_probe(target, ["-sn", "-PR", "-T5", "--min-parallelism", "100", "--max-retries", "1"]),
        # Layer 2 — ICMP echo and timestamp (cross-subnet)
        _run_discovery_probe(target, ["-sn", "-PE", "-PP", "-T4", "--min-parallelism", "50", "--max-retries", "1"]),
        # Layer 3 — TCP SYN on common ports (catches ICMP-blocked hosts)
        _run_discovery_probe(target, ["-sn", "-PS21,22,23,80,443,3389,8080", "-T4", "--min-parallelism", "50", "--max-retries", "1"]),
        # Layer 4 — Windows native ARP cache
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


import ctypes

def is_admin() -> bool:
    """Check if the current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except Exception:
        return False

# ── Step 2: deep service scan per host ───────────────────────────────────────
async def service_scan_host(ip: str) -> dict | None:
    async with _sem:
        logger.info(f"[SERVICE SCAN] Starting → {ip}")
        t0 = asyncio.get_event_loop().time()
        tmp = Path(tempfile.mktemp(suffix=f"_{ip.replace('.','_')}.xml"))
        try:
            cmd = [
                NMAP_PATH,
                "-Pn",               # force scan (skip host discovery, assume UP)
                "-sV",               # service version detection
                "-T4",               # aggressive but reliable timing
                "-F",                # fast mode — top 100 ports (quicker than -p-)
                "--open",            # only show open ports
                "--min-parallelism", "100",
                "--max-retries", "1",
                "-oX", str(tmp),
                ip,
            ]
            
            # OS Detection strictly requires Administrator privileges on Windows.
            # If not admin, Nmap will fatally crash when using -O.
            if is_admin():
                cmd.insert(3, "-O")
                cmd.insert(4, "--osscan-guess")
            else:
                logger.info(f"[{ip}] Running without Admin rights — skipping OS detection (-O) to prevent Nmap crash.")

            await asyncio.to_thread(
                subprocess.run, cmd,
                capture_output=True, check=False, timeout=300,
            )
            result = _parse_service_xml(tmp)
            
            # Apply defaults to avoid nulls
            if result is not None:
                if not result.get("mac"):
                    result["mac"] = await asyncio.to_thread(_get_mac_from_arp, ip)
                if not result.get("os"):
                    result["os"] = "Unknown"
                if not result.get("hostname") or result["hostname"] == "Unknown":
                    try:
                        hn = await asyncio.to_thread(socket.gethostbyaddr, ip)
                        result["hostname"] = hn[0] if hn else "Unknown"
                    except Exception:
                        result["hostname"] = "Unknown"
                
                duration = asyncio.get_event_loop().time() - t0
                logger.info(
                    f"[SERVICE SCAN] {ip} — {len(result['services'])} ports open, "
                    f"OS: {result['os']} — {duration:.1f}s"
                )
            return result
        except Exception as exc:
            logger.error(f"[SERVICE SCAN] Error on {ip}: {exc}")
            return None
        finally:
            tmp.unlink(missing_ok=True)

async def fast_os_scan_host(ip: str) -> dict | None:
    """Lightweight scan for secondary targets to get OS, Hostname and basic ports."""
    async with _sem:
        tmp = Path(tempfile.mktemp(suffix=f"_fast_{ip.replace('.','_')}.xml"))
        try:
            cmd = [
                NMAP_PATH,
                "-Pn",               # skip discovery
                "-F",                # top 100 ports
                "-T5",               # insane timing for speed
                "--max-retries", "1",
                "--min-parallelism", "100",
                "-oX", str(tmp),
                ip,
            ]
            
            if is_admin():
                cmd.insert(3, "-O")
                cmd.insert(4, "--osscan-guess")
                
            await asyncio.to_thread(
                subprocess.run, cmd,
                capture_output=True, check=False, timeout=120,
            )
            result = _parse_service_xml(tmp)
            
            if result is not None:
                if not result.get("mac"):
                    result["mac"] = await asyncio.to_thread(_get_mac_from_arp, ip)
                if not result.get("os"):
                    result["os"] = "Unknown"
                if not result.get("hostname") or result["hostname"] == "Unknown":
                    try:
                        hn = await asyncio.to_thread(socket.gethostbyaddr, ip)
                        result["hostname"] = hn[0] if hn else "Unknown"
                    except Exception:
                        result["hostname"] = "Unknown"
            return result
        except Exception as exc:
            logger.error(f"[FAST SCAN] Error on {ip}: {exc}")
            return None
        finally:
            tmp.unlink(missing_ok=True)


# ── Step 3: Nuclei on web ports ───────────────────────────────────────────────
WEB_PORTS = {80, 443, 8080, 8443, 3000, 8000, 8888, 9090, 9443, 4443}
HTTPS_PORTS = {443, 8443, 9443, 4443}

async def nuclei_scan_host(ip: str, open_ports: list[int]) -> list[dict]:
    """Run Nuclei on every web port found for this host concurrently. Failures are isolated."""
    web_ports = [p for p in open_ports if p in WEB_PORTS]
    if not web_ports:
        return []

    async def _scan_single_port(port: int) -> list[dict]:
        scheme = "https" if port in HTTPS_PORTS else "http"
        url = f"{scheme}://{ip}:{port}"
        tmp = Path(tempfile.mktemp(suffix=f"_nuclei_{ip.replace('.','_')}_{port}.json"))
        try:
            cmd = [
                NUCLEI_PATH,
                "-u", url,
                "-tags", "cve,vuln,default-login,panel,rce,lfi,sqli,xss",
                "-severity", "critical,high,medium,low,info",
                "-jsonl",
                "-o", str(tmp),
                "-silent",
                "-ni",               # no interactive prompts
                "-duc",              # disable update checks that could freeze
                "-timeout", "5",     # reduced timeout for faster execution
                "-retries", "1",
            ]
            async with _sem:
                await asyncio.to_thread(
                    subprocess.run, cmd,
                    capture_output=True, check=False, timeout=300,
                )
            vulns = _parse_nuclei_jsonl(tmp)
            logger.info(f"[NUCLEI] {ip}:{port} — {len(vulns)} vulnerabilities found")
            return vulns
        except Exception as exc:
            # Nuclei failure on one port must NOT crash the overall scan
            logger.error(f"[NUCLEI] Error on {ip}:{port}: {exc}")
            return []
        finally:
            tmp.unlink(missing_ok=True)

    # Run scans for all web ports on this host concurrently
    results = await asyncio.gather(*[_scan_single_port(p) for p in web_ports])
    
    all_vulns: list[dict] = []
    for r in results:
        all_vulns.extend(r)
    return all_vulns


# ── Step 4: atomic DB persistence ─────────────────────────────────────────────
async def persist_results(scan_id: str, host_results: list[dict]) -> None:
    logger.info(f"[PERSIST] Saving {len(host_results)} hosts to database")
    async with AsyncSessionLocal() as session:
        async with session.begin():
            # Delete previous data for this scan (cascade removes services + vulns)
            await session.execute(delete(Host).where(Host.scan_id == scan_id))

            for hr in host_results:
                # ── Guarantee no null hostname/os — every Host row must have a value
                host = Host(
                    scan_id=scan_id,
                    ip=hr["ip"],
                    hostname=hr.get("hostname") or "Unknown",
                    os=hr.get("os")           or "Unknown",
                    mac_address=hr.get("mac") or "Unknown",
                    status="up",
                )
                session.add(host)
                await session.flush()  # populate host.id before children

                for svc in hr.get("services", []):
                    session.add(Service(
                        host_id=host.id,
                        port=svc["port"],
                        protocol=svc.get("protocol") or "tcp",
                        name=svc.get("name")         or "Unknown",
                        version=svc.get("version")   or "Unknown",
                        state=svc.get("state")       or "open",
                    ))

                for vuln in hr.get("vulns", []):
                    sev = (vuln.get("severity") or "info").lower()
                    # ── cvss_score: float or None
                    raw_cvss = vuln.get("cvss_score")
                    try:
                        cvss_score = float(raw_cvss) if raw_cvss is not None else None
                    except (ValueError, TypeError):
                        cvss_score = None
                    cvss_estimated = bool(vuln.get("cvss_estimated", False))
                    # ── matcher_name: never empty
                    matcher_name = (
                        vuln.get("matcher_name")
                        or vuln.get("template_id")
                        or "default"
                    )
                    session.add(Vulnerability(
                        host_id=host.id,
                        template_id=vuln.get("template_id") or "unknown",
                        name=vuln.get("name")               or "Unknown vulnerability",
                        severity=sev,
                        cve_id=vuln.get("cve_id"),
                        description=vuln.get("description") or "",
                        matcher_name=matcher_name,
                        cvss_score=cvss_score,
                        cvss_estimated=cvss_estimated,
                        source=vuln.get("source")            or "nuclei",
                        discovered_at=datetime.utcnow(),
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


# ── Full orchestrator ─────────────────────────────────────────────────────────
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
        # Determine target_ip and discovery_target
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

        # Step 1 — discover live hosts
        live_ips = await discover_hosts(discovery_target)
        if not live_ips:
            await _mark_failed("no_hosts_found")
            logger.warning(f"[SCAN] No live hosts found for {discovery_target}")
            return

        # Step 2 — parallel deep service scan (capped by semaphore)
        live_ips_list = list(live_ips)
        
        scan_tasks = []
        for ip in live_ips_list:
            if target_ip is None or ip == target_ip:
                scan_tasks.append(service_scan_host(ip))
            else:
                scan_tasks.append(fast_os_scan_host(ip))

        scan_raw = await asyncio.gather(*scan_tasks, return_exceptions=True)

        host_results: list[dict] = []
        for i, res in enumerate(scan_raw):
            ip = live_ips_list[i]
            if isinstance(res, Exception):
                logger.error(f"[SERVICE SCAN] Unexpected error for {ip}: {res}")
                mac = await asyncio.to_thread(_get_mac_from_arp, ip)
                host_results.append({"ip": ip, "hostname": "Unknown", "os": "Unknown", "mac": mac, "services": [], "vulns": []})
            elif res is not None:
                host_results.append(res)
            else:
                # Nmap didn't return an XML for this host, but we know it's alive from discovery
                mac = await asyncio.to_thread(_get_mac_from_arp, ip)
                host_results.append({"ip": ip, "hostname": "Unknown", "os": "Unknown", "mac": mac, "services": [], "vulns": []})

        # Step 3 — Nuclei on web ports for each host (per-host errors isolated)
        nuclei_tasks = []
        for hr in host_results:
            ip = hr["ip"]
            if target_ip is None or ip == target_ip:
                nuclei_tasks.append(nuclei_scan_host(ip, [s["port"] for s in hr.get("services", [])]))
            else:
                async def _empty_nuclei():
                    return []
                nuclei_tasks.append(_empty_nuclei())

        nuclei_raw = await asyncio.gather(*nuclei_tasks, return_exceptions=True)

        for i, res in enumerate(nuclei_raw):
            if isinstance(res, Exception):
                logger.error(f"[NUCLEI] Unexpected error for host {host_results[i]['ip']}: {res}")
                host_results[i]["vulns"] = []
            else:
                host_results[i]["vulns"] = res

        # Step 4 — atomic DB write
        await persist_results(scan_id, host_results)

        duration = asyncio.get_event_loop().time() - t0
        logger.info(f"[SCAN DONE] scan_id={scan_id} duration={duration:.1f}s")

    except Exception as exc:
        logger.exception(f"[PIPELINE ERROR] scan_id={scan_id}: {exc}")
        await _mark_failed(str(exc))

# =============================================================================
# INPUT NORMALISATION
# =============================================================================
def normalize_target(raw: str) -> str:
    raw = raw.strip()
    try:
        net = ipaddress.ip_network(raw, strict=False)
        return str(net)
    except ValueError:
        # Allow nmap range notation like 192.168.1.1-50
        if "-" in raw:
            return raw
        raise ValueError(f"Invalid target format: '{raw}'. Use an IP, CIDR, or range (e.g. 192.168.1.1-50).")

# =============================================================================
# FASTAPI APPLICATION
# =============================================================================
app = FastAPI(
    title="Network Audit API",
    description="Automated host discovery, service scanning, and vulnerability assessment.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables ready.")
    logger.info(f"📡 nmap   → {NMAP_PATH}")
    logger.info(f"🔍 nuclei → {NUCLEI_PATH}")


# ── POST /scan ────────────────────────────────────────────────────────────────
@app.post("/scan", response_model=ScanResponse, status_code=202)
async def create_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Accepts a target (IP, CIDR, or range) and immediately returns a scan_id.
    The full pipeline runs in the background — the caller polls /scan/{id}/status.
    """
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


# ── GET /scan/{scan_id}/status ────────────────────────────────────────────────
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


# ── GET /scan/{scan_id}/results ───────────────────────────────────────────────
@app.get("/scan/{scan_id}/results")
async def get_results(scan_id: str):
    """
    Returns a fully nested structure: Scan → Hosts → Services + Vulnerabilities.
    Uses selectinload to avoid N+1 queries.
    """
    async with AsyncSessionLocal() as session:
        # Load scan
        s_res = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = s_res.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status == "running":
            raise HTTPException(status_code=202, detail="Scan is still running.")

        # Load hosts with services and vulnerabilities in 2 extra SELECT statements
        h_res = await session.execute(
            select(Host)
            .where(Host.scan_id == scan_id)
            .options(
                selectinload(Host.services),
                selectinload(Host.vulnerabilities),
            )
        )
        hosts = h_res.scalars().unique().all()

    # Collect all vulns for health-score calculation
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
        "hosts": [
            {
                "host_id":     h.id,
                "ip":          h.ip,
                "hostname":    h.hostname or "Unknown",
                "os":          h.os       or "Unknown",
                "mac_address": h.mac_address or "Unknown",
                "status":      h.status or "up",
                "scanned":     len(h.services) > 0,
                "services": [
                    {
                        "port":     s.port,
                        "protocol": s.protocol or "tcp",
                        "name":     s.name     or "Unknown",
                        "version":  s.version  or "Unknown",
                        "state":    s.state    or "open",
                    }
                    for s in h.services
                ],
                "vulnerabilities": [
                    {
                        "template_id":    v.template_id,
                        "name":           v.name,
                        "severity":       v.severity,
                        "cve_id":         v.cve_id,
                        "cvss_score":     float(v.cvss_score) if v.cvss_score else None,
                        "cvss_estimated": bool(v.cvss_estimated),
                        "description":    v.description or "",
                        "matcher_name":   v.matcher_name or v.template_id or "default",
                        "source":         v.source or "nuclei",
                        "discovered_at":  v.discovered_at,
                    }
                    for v in h.vulnerabilities
                ],
            }
            for h in hosts
        ],
    }


# ── GET /scans ────────────────────────────────────────────────────────────────
@app.get("/scans")
async def list_scans():
    """Returns the most recent scan ONLY, with full detailed host information."""
    async with AsyncSessionLocal() as session:
        # 1. Fetch only the most recent scan, but load all its related data
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

    # 2. Format the response with each IP in its own dictionary containing full info
    # We sort the hosts by their IP mathematically to keep them perfectly organized
    import ipaddress
    
    sorted_hosts = sorted(latest_scan.hosts, key=lambda x: ipaddress.IPv4Address(x.ip))
    
    # Collect all vulns for health-score calculation
    all_vulns_flat = [
        {"severity": v.severity}
        for h in latest_scan.hosts for v in h.vulnerabilities
    ]
    health_score = compute_health_score(all_vulns_flat)
    
    return [
        {
            "id":          latest_scan.id,
            "target":      latest_scan.target,
            "status":      latest_scan.status,
            "fail_reason": latest_scan.fail_reason,
            "hosts_found": latest_scan.hosts_found or 0,
            "health_score": health_score,
            "started_at":  latest_scan.started_at,
            "finished_at": latest_scan.finished_at,
            "discovered_ips": [
                {
                    "host_id":     h.id,
                    "ip":          h.ip,
                    "hostname":    h.hostname or "Unknown",
                    "os":          h.os       or "Unknown",
                    "mac_address": h.mac_address or "Unknown",
                    "status":      h.status or "up",
                    "scanned":     len(h.services) > 0,
                    "services": [
                        {
                            "port": s.port,
                            "protocol": s.protocol or "tcp",
                            "name": s.name or "Unknown",
                            "version": s.version or "Unknown",
                            "state": s.state or "open"
                        } for s in sorted(h.services, key=lambda svc: svc.port)
                    ],
                    "vulnerabilities": [
                        {
                            "template_id":    v.template_id,
                            "name":           v.name,
                            "severity":       v.severity,
                            "cve_id":         v.cve_id,
                            "cvss_score":     float(v.cvss_score) if v.cvss_score else None,
                            "cvss_estimated": bool(v.cvss_estimated),
                            "description":    v.description or "",
                            "matcher_name":   v.matcher_name or v.template_id or "default",
                            "source":         v.source or "nuclei",
                            "discovered_at":  v.discovered_at,
                        } for v in h.vulnerabilities
                    ]
                } for h in sorted_hosts
            ]
        }
    ]


# ── GET /health ───────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":      "ok",
        "nmap_path":   NMAP_PATH,
        "nuclei_path": NUCLEI_PATH,
    }


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)