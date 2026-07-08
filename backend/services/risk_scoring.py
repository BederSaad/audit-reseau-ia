"""
Per-host risk scoring + scan-wide priority list.
"""
import logging
from typing import List, Dict
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

logger = logging.getLogger("RiskScoring")

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 5,
    "low": 2,
    "info": 0,
}

DANGEROUS_PORTS = {21, 23, 53, 135, 139, 445, 3389, 5900, 6379, 9200}


def calculate_host_risk_score(vulns: List[dict], services: List[dict], cred_vulns: List[dict]) -> float:
    """Calculate a 0-100 risk score for a single host."""
    score = 0.0
    
    # Vulnerability weights
    for v in vulns:
        sev = (v.get("severity") or "info").lower()
        score += SEVERITY_WEIGHTS.get(sev, 0)
    
    # Credential findings are severe
    for c in cred_vulns:
        sev = (c.get("severity") or "info").lower()
        score += SEVERITY_WEIGHTS.get(sev, 0) * 1.5
    
    # Dangerous exposed ports
    for s in services:
        port = s.get("port", 0)
        if port in DANGEROUS_PORTS:
            score += 3.0
    
    # Cap at 100
    return min(100.0, round(score, 1))


def criticality_from_score(score: float) -> str:
    if score >= 81: return "Severe"
    if score >= 61: return "Critical"
    if score >= 41: return "High"
    if score >= 21: return "Medium"
    return "Low"


async def build_priority_list(scan_id: str) -> List[Dict]:
    """Build a scan-wide prioritized vulnerability list."""
    from main import AsyncSessionLocal, Host, Vulnerability
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            select(Host)
            .where(Host.scan_id == scan_id)
            .options(selectinload(Host.vulnerabilities))
        )
        hosts = res.scalars().unique().all()
    
    severity_fr_map = {
        "critical": "Critique",
        "high": "Élevé",
        "medium": "Moyen",
        "low": "Faible",
        "info": "Info",
    }
    
    priorities = []
    for h in hosts:
        for v in h.vulnerabilities:
            urgency = 0
            if v.cvss_score:
                urgency = float(v.cvss_score) * 10
            else:
                urgency = SEVERITY_WEIGHTS.get(v.severity.lower(), 0) * 3
            
            sev_lower = (v.severity or "info").lower()
            risk_cat = severity_fr_map.get(sev_lower, sev_lower.capitalize())
            
            priorities.append({
                "host_ip": h.ip,
                "name": v.name,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "risk_category": risk_cat,
                "urgency_score": min(100, round(urgency, 1)),
                "source": v.source,
                "template_id": v.template_id,
            })
    
    priorities.sort(key=lambda x: x["urgency_score"], reverse=True)
    return priorities