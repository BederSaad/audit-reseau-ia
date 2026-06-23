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
    id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id      = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    template_id  = Column(String, nullable=True)
    name         = Column(String, nullable=False)
    severity     = Column(String, default="info")
    cve_id       = Column(String, nullable=True)
    description  = Column(Text, nullable=True)
    matcher_name  = Column(String, nullable=True)
    cvss_score    = Column(Float, nullable=True)
    cvss_estimated= Column(Boolean, default=False)
    source        = Column(String, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    matched_at    = Column(DateTime, default=datetime.utcnow)
    host          = relationship("Host", back_populates="vulnerabilities")


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
