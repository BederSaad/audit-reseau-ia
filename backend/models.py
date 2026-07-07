import uuid
from datetime import datetime

from sqlalchemy import (
    Column, DateTime, ForeignKey, Integer, String,
    UniqueConstraint, Text, Float, Boolean, JSON
)
from sqlalchemy.orm import relationship

from database import Base

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
    
    # ── Network Identity ──
    ip                = Column(String, nullable=False)
    ipv6              = Column(String, nullable=True)
    hostname          = Column(String, nullable=True)
    hostname_source   = Column(String, nullable=True)      # ptr | netbios | smb | mdns | ssh | http | unknown
    hostname_confidence = Column(Float, default=0.0)       # 0.0 – 1.0
    
    # ── OS ──
    os                = Column(String, nullable=True)
    os_family         = Column(String, nullable=True)       # Windows | Linux | macOS | Android | iOS | Embedded | Unknown
    os_version        = Column(String, nullable=True)
    os_confidence     = Column(String, nullable=True)      # confirmed | inferred | unknown
    
    # ── Hardware / Vendor ──
    device_type       = Column(String, nullable=True)       # Workstation | Server | Phone | Tablet | Printer | NAS | Router | Switch | Camera | TV | IoT | VM | Container | Unknown
    device_classification = Column(String, nullable=True)   # Human-readable, e.g. "Samsung TV"
    manufacturer      = Column(String, nullable=True)
    mac_address       = Column(String, nullable=True)
    mac_vendor        = Column(String, nullable=True)
    network_interface = Column(String, nullable=True)
    architecture      = Column(String, nullable=True)      # x86_64 | ARM | MIPS | etc.
    uptime            = Column(String, nullable=True)
    
    # ── Environment Flags ──
    is_gateway        = Column(Boolean, default=False)
    is_local_machine  = Column(Boolean, default=False)
    is_vm             = Column(Boolean, default=False)
    is_docker         = Column(Boolean, default=False)
    is_wsl            = Column(Boolean, default=False)
    is_mobile         = Column(Boolean, default=False)   # ← ADD THIS
    scan_type         = Column(String, nullable=True) 
    
    # ── Audit Metadata ──
    status            = Column(String, default="up")         # up | down | unreachable
    audit_status      = Column(String, default="pending")  # pending | scanning | completed | failed
    last_scan         = Column(DateTime, nullable=True)
    risk_score        = Column(Float, default=0.0)         # 0.0 – 100.0
    criticality       = Column(String, default="Unknown")  # Low | Medium | High | Critical | Severe
    
    # ── Relations ──
    scan              = relationship("Scan", back_populates="hosts")
    services          = relationship("Service", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities   = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")
    
    # ── Enriched Data ──
    running_applications = Column(JSON, default=list)      # [{name, version, port, protocol}]
    discovery_method     = Column(String, nullable=True)   # arp | icmp | tcp | arp_cache
    screenshot_path      = Column(String, nullable=True)
    evidence             = Column(JSON, default=list)


class Service(Base):
    __tablename__ = "services"
    id       = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id  = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port     = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    name     = Column(String, nullable=True)
    version  = Column(String, nullable=True)
    state    = Column(String, default="open")
    banner   = Column(Text, nullable=True)                 # Raw banner grab
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
    source          = Column(String, default="nuclei")     # nuclei | nvd | credential_test | nse
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