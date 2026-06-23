def compute_exposure_factor(service: dict, host: dict) -> float:
    """
    Exposure factor 0.0–1.0: how reachable/exposed is this finding.
    """
    factor = 0.5  # baseline: internal network exposure
    if service.get("port") in {80, 443, 8080, 8443}:
        factor += 0.3  # web-facing services are higher exposure
    # In DB context, scanned is whether host has services
    # If the input is directly from pipeline, we check if 'services' exist
    # The prompt expects host.get("scanned") and service.get("state") == "open"
    is_scanned = host.get("scanned") or (host.get("services") is not None and len(host.get("services", [])) > 0)
    if is_scanned and service.get("state", "open") == "open":
        factor += 0.2  # confirmed open and reachable right now
    return min(1.0, factor)

def compute_exploitability_factor(vuln: dict) -> float:
    """
    Exploitability factor 0.0–1.0: how easy is this to actually exploit.
    """
    if vuln.get("source") == "credential_test" and vuln.get("severity") == "critical":
        # Working default creds = trivial exploitation, no skill needed
        return 1.0
    severity_map = {"critical": 0.9, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.05}
    return severity_map.get(vuln.get("severity", "info").lower(), 0.1)

def compute_urgency_score(cvss: float, exposure: float, exploitability: float) -> float:
    """
    Final urgency score, normalized to 0-100 for easy display.
    """
    cvss_val = cvss if cvss is not None else 0.0
    raw = cvss_val * exposure * exploitability  # max possible: 10 * 1.0 * 1.0 = 10
    return round(min(100.0, raw * 10), 1)  # scale to 0-100

def categorize_risk(urgency_score: float) -> str:
    if urgency_score >= 75:
        return "Critique"
    elif urgency_score >= 50:
        return "Élevé"
    elif urgency_score >= 25:
        return "Moyen"
    else:
        return "Faible"

async def fetch_all_vulns_with_context(scan_id: str) -> list[dict]:
    # Lazy import to avoid circular dependency
    from main import AsyncSessionLocal, Host, Service, Vulnerability
    from sqlalchemy.future import select
    from sqlalchemy.orm import selectinload
    
    async with AsyncSessionLocal() as session:
        h_res = await session.execute(
            select(Host)
            .where(Host.scan_id == scan_id)
            .options(
                selectinload(Host.services),
                selectinload(Host.vulnerabilities),
            )
        )
        hosts = h_res.scalars().unique().all()
        
    vulns_with_context = []
    for h in hosts:
        host_dict = {
            "ip": h.ip,
            "scanned": len(h.services) > 0,
            "services": [
                {
                    "port": s.port,
                    "state": s.state,
                    "name": s.name
                } for s in h.services
            ]
        }
        for v in h.vulnerabilities:
            # Match service to vuln (simple port match if available, otherwise fallback)
            # Vulnerabilities might not be tied to a specific service explicitly in DB schema
            # We'll approximate by checking if there's a web port or taking the first service
            matched_service = {}
            if h.services:
                matched_service = {"port": h.services[0].port, "state": h.services[0].state}
                # Try to refine if NVD CPE or nuclei indicates port (difficult to know from current schema)
                # For simplicity, if we have web ports and it's a nuclei vuln, assume it's web.
                if v.source == "nuclei":
                    for s in h.services:
                        if s.port in {80, 443, 8080, 8443}:
                            matched_service = {"port": s.port, "state": s.state}
                            break
            
            vuln_dict = {
                "id": v.id,
                "template_id": v.template_id,
                "name": v.name,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "source": v.source,
                "cve_id": v.cve_id
            }
            vulns_with_context.append({
                "host": host_dict,
                "service": matched_service,
                "vuln": vuln_dict
            })
    return vulns_with_context

async def build_priority_list(scan_id: str) -> list[dict]:
    vulns = await fetch_all_vulns_with_context(scan_id)
    prioritized = []
    for v in vulns:
        exposure = compute_exposure_factor(v["service"], v["host"])
        exploitability = compute_exploitability_factor(v["vuln"])
        urgency = compute_urgency_score(v["vuln"]["cvss_score"], exposure, exploitability)
        prioritized.append({
            **v["vuln"],
            "host_ip": v["host"]["ip"],
            "exposure_factor": exposure,
            "exploitability_factor": exploitability,
            "urgency_score": urgency,
            "risk_category": categorize_risk(urgency)
        })
    return sorted(prioritized, key=lambda x: x["urgency_score"], reverse=True)
