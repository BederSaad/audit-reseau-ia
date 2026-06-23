"""
backend/services/audit_analysis.py
Scan-level AI audit synthesis — reads all pipeline output, produces one
coherent judgment (executive summary, key findings, recommendations),
persists it in audit_analysis table, and serves /scan/{id}/analysis.
"""

import json
import logging
import uuid
from datetime import datetime

logger = logging.getLogger("AuditAnalysis")

# ── System Prompt ─────────────────────────────────────────────────────────────
AUDIT_ANALYSIS_SYSTEM_PROMPT = """You are a Senior Cybersecurity Auditor and CISO consultant.

Generate a complete AI Security Analysis section for every audit report.

Do NOT summarize the scan. Analyze it.

Your analysis must include:

Overall security posture score (0-100)
Security maturity level: Critical, Weak, Moderate, Good, Excellent
Executive summary written for non-technical managers
Main attack vectors discovered
Most dangerous vulnerabilities
Business impact if exploited: Data theft, Remote code execution, Service interruption, Credential compromise, Lateral movement, Ransomware risk
Likelihood of compromise: Very Low, Low, Medium, High, Critical
Attacker scenario: Describe step-by-step how an attacker could compromise the infrastructure using the vulnerabilities found
Security strengths discovered
Security weaknesses discovered
Global risk conclusion

The AI must write detailed paragraphs, not one-line summaries.
The report must be understandable by both cybersecurity experts and business managers.

Respond ONLY in valid JSON with EXACTLY this structure:
{
  "security_score": 75,
  "maturity_level": "Moderate",
  "executive_summary": "200-word summary for management describing global security posture, number of devices, and business risk level without excessive technical jargon.",
  "attack_vectors": ["Vector 1", "Vector 2"],
  "most_dangerous_vulnerabilities": ["Vuln 1", "Vuln 2"],
  "business_impact": {
    "data_theft": "High",
    "remote_code_execution": "Medium",
    "service_interruption": "Low",
    "credential_compromise": "High",
    "lateral_movement": "Medium",
    "ransomware_risk": "High"
  },
  "likelihood_of_compromise": "High",
  "attacker_scenario": "Detailed step-by-step description of how an attacker could compromise the infrastructure using the discovered vulnerabilities.",
  "security_strengths": ["Strength 1", "Strength 2"],
  "security_weaknesses": ["Weakness 1", "Weakness 2"],
  "global_risk_conclusion": "Detailed conclusion about the overall risk level.",
  "key_findings": [
    {
      "finding_name": "Clear technical name",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "likelihood": "HIGH|MEDIUM|LOW",
      "impact": "HIGH|MEDIUM|LOW",
      "affected_hosts": ["192.168.x.x"],
      "description": "Detailed 3-4 sentence explanation of the vulnerability. Why is it dangerous?",
      "remediation_steps": [
        "Step 1: Immediate and precise action (e.g., modify config file).",
        "Step 2: Service restart or patch application.",
        "Step 3: Long-term hardening measure."
      ]
    }
  ],
  "strategic_recommendations": [
    {
      "priority": 1,
      "theme": "Recommendation theme (e.g., Access Management)",
      "advice": "Global recommendation to prevent these vulnerabilities from recurring."
    }
  ],
  "overall_verdict": "One impactful sentence summarizing the audit conclusion."
}

STRICT RULES:
1. "key_findings": Detail the 5 most critical vulnerabilities. "remediation_steps" MUST be clear and sequential actions.
2. If default credentials were validated, this is ALWAYS finding #1.
3. DO NOT invent ANY vulnerability. Base your analysis ONLY on the provided context.
4. Write in professional English without fluff.
5. Provide detailed paragraphs, not one-line summaries."""


# ── Data Fetchers ─────────────────────────────────────────────────────────────
async def fetch_scan(scan_id: str) -> dict | None:
    """Fetch scan row + compute dynamic health_score."""
    from main import AsyncSessionLocal, Scan, Host, compute_health_score
    from sqlalchemy.future import select
    from sqlalchemy.orm import selectinload

    async with AsyncSessionLocal() as session:
        res = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = res.scalar_one_or_none()
        if not scan:
            return None

        h_res = await session.execute(
            select(Host)
            .where(Host.scan_id == scan_id)
            .options(selectinload(Host.vulnerabilities))
        )
        hosts = h_res.scalars().unique().all()
        all_vulns_flat = [{"severity": v.severity} for h in hosts for v in h.vulnerabilities]
        health_score = compute_health_score(all_vulns_flat)

        return {
            "target": scan.target,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "hosts_found": scan.hosts_found or 0,
            "health_score": health_score,
        }


async def fetch_hosts_with_relations(scan_id: str) -> list[dict]:
    """Fetch all hosts with services + vulnerabilities."""
    from main import AsyncSessionLocal, Host
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

    STANDARD_PORTS = {21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080, 8443}

    return [
        {
            "ip": h.ip,
            "os": h.os,
            "os_enriched": None,  # placeholder if we ever add os_enriched column
            "scanned": len(h.services) > 0,
            "services": [
                {
                    "port": s.port,
                    "name": s.name,
                    "version": s.version,
                    "nonstandard": s.port not in STANDARD_PORTS and s.port is not None,
                }
                for s in h.services
            ],
            "vulnerabilities": [
                {
                    "severity": v.severity,
                    "source": v.source,
                    "template_id": v.template_id,
                    "vulnerable": True,   # every stored vuln is "found"
                    "name": v.name,
                    "service": v.template_id,       # best approximation
                    "matcher_name": v.matcher_name,
                    "host_ip": h.ip,
                }
                for v in h.vulnerabilities
            ],
        }
        for h in hosts
    ]


# ── Scan Context Builder ──────────────────────────────────────────────────────
async def build_scan_context(scan_id: str) -> dict:
    """Aggregates everything needed for a holistic audit judgment."""
    from services.risk_scoring import build_priority_list

    scan = await fetch_scan(scan_id)
    if not scan:
        return {}

    hosts = await fetch_hosts_with_relations(scan_id)
    priority_list = await build_priority_list(scan_id)

    working_credentials = [
        v for h in hosts for v in h["vulnerabilities"]
        if v.get("source") == "credential_test" and v.get("vulnerable")
    ]
    nonstandard_services = [
        s for h in hosts for s in h["services"] if s.get("nonstandard")
    ]

    duration = 0.0
    if scan["finished_at"] and scan["started_at"]:
        duration = (scan["finished_at"] - scan["started_at"]).total_seconds()

    return {
        "target": scan["target"],
        "duration_seconds": duration,
        "hosts_found": scan["hosts_found"],
        "health_score": scan["health_score"],
        "hosts_summary": [
            {
                "ip": h["ip"],
                "os": h.get("os_enriched") or h["os"] or "Unknown",
                "scanned": h["scanned"],
                "critical_count": sum(1 for v in h["vulnerabilities"] if v["severity"] == "critical"),
                "high_count": sum(1 for v in h["vulnerabilities"] if v["severity"] == "high"),
                "total_vulns": len(h["vulnerabilities"]),
            }
            for h in hosts
        ],
        "top_10_priorities": priority_list[:10],
        "working_credentials": working_credentials,
        "nonstandard_services": nonstandard_services,
    }


# ── Deterministic Fallback ────────────────────────────────────────────────────
def build_fallback_analysis(context: dict) -> dict:
    """Rule-based fallback if Ollama is unreachable or returns invalid JSON."""
    crit_count = sum(h["critical_count"] for h in context.get("hosts_summary", []))
    high_count = sum(h["high_count"] for h in context.get("hosts_summary", []))
    has_weak_creds = len(context.get("working_credentials", [])) > 0

    recommendations = []
    priority_counter = 1

    if has_weak_creds:
        for cred in context["working_credentials"][:3]:
            recommendations.append({
                "priority": priority_counter,
                "action": (
                    f"Changer immédiatement les identifiants par défaut sur le service "
                    f"{cred.get('service', 'inconnu')} ({cred.get('host_ip', 'inconnu')})"
                ),
                "timeframe": "immédiat",
                "justification": "Identifiants par défaut fonctionnels confirmés — accès non autorisé immédiat possible.",
                "affected_hosts": [cred.get("host_ip", "inconnu")],
            })
            priority_counter += 1

    if crit_count > 0:
        recommendations.append({
            "priority": priority_counter,
            "action": f"Corriger les {crit_count} vulnérabilités critiques identifiées en priorité",
            "timeframe": "cette semaine",
            "justification": "Score CVSS critique (≥9.0) indique un risque d'exploitation élevé.",
            "affected_hosts": [h["ip"] for h in context.get("hosts_summary", []) if h["critical_count"] > 0],
        })
        priority_counter += 1

    if high_count > 0:
        recommendations.append({
            "priority": priority_counter,
            "action": f"Planifier le correctif des {high_count} vulnérabilités élevées",
            "timeframe": "cette semaine",
            "justification": "Score CVSS élevé (≥7.0) représente un vecteur d'attaque significatif.",
            "affected_hosts": [h["ip"] for h in context.get("hosts_summary", []) if h["high_count"] > 0],
        })

    if not recommendations:
        recommendations = [{
            "priority": 1,
            "action": "Aucune action critique identifiée — maintenir la surveillance régulière.",
            "timeframe": "ce trimestre",
            "justification": "Aucune vulnérabilité critique ou identifiant faible détecté.",
            "affected_hosts": [],
        }]

    if has_weak_creds or crit_count > 2:
        posture = "critique, action immédiate requise"
    elif crit_count > 0 or high_count > 0:
        posture = "acceptable avec points d'attention sérieux"
    else:
        posture = "globalement saine"

    # Calculate security score and maturity
    security_score = context.get("health_score", 50)
    if has_weak_creds:
        security_score = max(0, security_score - 30)
    if crit_count > 0:
        security_score = max(0, security_score - 20)
    if high_count > 0:
        security_score = max(0, security_score - 10)

    if security_score >= 80:
        maturity_level = "Good"
    elif security_score >= 60:
        maturity_level = "Moderate"
    elif security_score >= 40:
        maturity_level = "Weak"
    else:
        maturity_level = "Critical"

    # Business impact assessment
    business_impact = {
        "data_theft": "High" if has_weak_creds or crit_count > 0 else "Low",
        "remote_code_execution": "High" if crit_count > 0 else "Medium",
        "service_interruption": "Medium",
        "credential_compromise": "High" if has_weak_creds else "Low",
        "lateral_movement": "Medium" if high_count > 0 else "Low",
        "ransomware_risk": "High" if has_weak_creds else "Medium"
    }

    # Likelihood of compromise
    if has_weak_creds or crit_count > 2:
        likelihood = "Critical"
    elif crit_count > 0 or high_count > 2:
        likelihood = "High"
    elif high_count > 0:
        likelihood = "Medium"
    else:
        likelihood = "Low"

    # Attack vectors
    attack_vectors = []
    if has_weak_creds:
        attack_vectors.append("Default credentials exploitation")
    if crit_count > 0:
        attack_vectors.append("Critical vulnerability exploitation")
    if high_count > 0:
        attack_vectors.append("High-severity vulnerability exploitation")
    if not attack_vectors:
        attack_vectors.append("Information disclosure")

    # Most dangerous vulnerabilities
    most_dangerous = [v.get("name", "Unknown") for v in context.get("top_10_priorities", [])[:3]]

    # Attacker scenario
    attacker_scenario = (
        "An attacker could initially scan the network to identify open ports and services. "
    )
    if has_weak_creds:
        attacker_scenario += (
            "Using default credentials, they could gain unauthorized access to services. "
            "This could lead to credential compromise and lateral movement across the network. "
        )
    if crit_count > 0:
        attacker_scenario += (
            "Critical vulnerabilities could be exploited to achieve remote code execution, "
            "potentially leading to full system compromise and data theft. "
        )
    attacker_scenario += "The combination of these factors creates a significant security risk."

    # Security strengths and weaknesses
    security_strengths = []
    security_weaknesses = []
    if has_weak_creds:
        security_weaknesses.append("Default credentials in use")
    if crit_count > 0:
        security_weaknesses.append(f"{crit_count} critical vulnerabilities present")
    if high_count > 0:
        security_weaknesses.append(f"{high_count} high-severity vulnerabilities present")
    if not security_weaknesses:
        security_strengths.append("No critical or high-severity vulnerabilities detected")
    security_strengths.append("Network scanning completed successfully")

    # Global risk conclusion
    if has_weak_creds or crit_count > 2:
        global_risk = "The infrastructure faces critical security risks requiring immediate remediation. Default credentials and critical vulnerabilities present a high likelihood of compromise."
    elif crit_count > 0 or high_count > 0:
        global_risk = "The infrastructure has significant security concerns that should be addressed promptly to reduce the risk of exploitation."
    else:
        global_risk = "The infrastructure maintains a reasonable security posture with no critical issues detected. Regular monitoring and maintenance are recommended."

    # Key findings
    key_findings = []
    if has_weak_creds:
        key_findings.append({
            "finding_name": "Default Credentials Validated",
            "severity": "CRITICAL",
            "likelihood": "HIGH",
            "impact": "HIGH",
            "affected_hosts": [cred.get("host_ip", "Unknown") for cred in context.get("working_credentials", [])],
            "description": "Default or weak credentials were successfully validated on one or more services. This allows immediate unauthorized access.",
            "remediation_steps": [
                "Immediately change all default credentials to strong, unique passwords.",
                "Disable any accounts with default credentials.",
                "Implement multi-factor authentication where possible.",
                "Review and update credential management policies."
            ]
        })

    for v in context.get("top_10_priorities", [])[:5]:
        key_findings.append({
            "finding_name": v.get("name", "Unknown"),
            "severity": (v.get("risk_category") or "MEDIUM").upper(),
            "likelihood": "MEDIUM",
            "impact": "MEDIUM",
            "affected_hosts": [v.get("host_ip", "?")],
            "description": f"Vulnerability with CVSS score {v.get('cvss_score', 'N/A')} detected. See technical details for more information.",
            "remediation_steps": [
                "Apply security patches provided by the software vendor.",
                "Restrict network access to the service if patch is not immediately applicable.",
                "Monitor for suspicious activity related to this vulnerability."
            ]
        })

    # Strategic recommendations
    strategic_recs = []
    priority_counter = 1

    if has_weak_creds:
        strategic_recs.append({
            "priority": priority_counter,
            "theme": "Credential Management",
            "advice": "Implement a comprehensive credential management policy. Eliminate all default credentials, enforce strong password policies, and implement multi-factor authentication for all critical services."
        })
        priority_counter += 1

    if crit_count > 0:
        strategic_recs.append({
            "priority": priority_counter,
            "theme": "Vulnerability Management",
            "advice": f"Immediately address {crit_count} critical vulnerabilities. Establish a patch management process to ensure timely remediation of security issues."
        })
        priority_counter += 1

    if high_count > 0:
        strategic_recs.append({
            "priority": priority_counter,
            "theme": "Security Hardening",
            "advice": f"Plan remediation for {high_count} high-severity vulnerabilities within the next 7 days. Prioritize based on business impact and exploitability."
        })
        priority_counter += 1

    if not strategic_recs:
        strategic_recs.append({
            "priority": 1,
            "theme": "Continuous Monitoring",
            "advice": "Maintain regular security scanning and monitoring. Implement a vulnerability management program to track and remediate issues as they arise."
        })

    return {
        "security_score": security_score,
        "maturity_level": maturity_level,
        "executive_summary": f"Security scan of {context.get('target', 'target')} completed in {context.get('duration_seconds', 0):.0f}s. Security score: {security_score}/100 ({maturity_level}). {len(context.get('hosts_summary', []))} hosts scanned with {crit_count} critical and {high_count} high-severity vulnerabilities.",
        "attack_vectors": attack_vectors,
        "most_dangerous_vulnerabilities": most_dangerous,
        "business_impact": business_impact,
        "likelihood_of_compromise": likelihood,
        "attacker_scenario": attacker_scenario,
        "security_strengths": security_strengths,
        "security_weaknesses": security_weaknesses,
        "global_risk_conclusion": global_risk,
        "key_findings": key_findings,
        "strategic_recommendations": strategic_recs,
        "overall_verdict": f"Security posture is {maturity_level.lower()} with a score of {security_score}/100. {'Immediate action required.' if has_weak_creds or crit_count > 0 else 'Regular maintenance recommended.'}",
        "ai_generated": False
    }


# ── Main Generator ────────────────────────────────────────────────────────────
async def generate_audit_analysis(scan_id: str) -> dict:
    """Builds context → calls LLM (with fallback) → returns analysis dict."""
    from services.llm_service import call_ollama, safe_llm_call

    context = await build_scan_context(scan_id)
    if not context:
        return {}

    context_text = f"""
AUDIT TARGET: {context['target']}
DURATION: {context['duration_seconds']:.0f} seconds

ATTACK SURFACE SUMMARY:
{context['hosts_found']} devices discovered.
{chr(10).join(f"- {h['ip']} ({h['os']}): {h['total_vulns']} vulnerabilities detected." for h in context['hosts_summary'])}

CREDENTIAL COMPROMISE VALIDATION:
{len(context['working_credentials'])} direct access confirmed.
{chr(10).join(f"- {c.get('host_ip')}: Successful login on {c.get('service')} with '{c.get('matcher_name')}'" for c in context['working_credentials']) or "No functioning default credentials detected."}

TOP TECHNICAL VULNERABILITIES (CVSS & URGENCY):
{chr(10).join(f"- {v.get('name')} on {v.get('host_ip')} | CVSS: {v.get('cvss_score')} | Urgency: {v.get('urgency_score')}/100" for v in context['top_10_priorities'])}
"""

    async def _call():
        raw = await call_ollama(context_text, system=AUDIT_ANALYSIS_SYSTEM_PROMPT, timeout=60.0)
        # Extract JSON even if LLM wraps it in markdown code fences
        import re
        json_match = re.search(r'\{[\s\S]*\}', raw)
        if not json_match:
            raise ValueError("No JSON object found in LLM response")
        parsed = json.loads(json_match.group())
        parsed["ai_generated"] = True
        return parsed

    fallback = build_fallback_analysis(context)
    result = await safe_llm_call(
        _call(),
        fallback_value=fallback,
        context=f"audit_analysis:{scan_id}",
    )
    return result


# ── DB Persistence ────────────────────────────────────────────────────────────
async def persist_audit_analysis(scan_id: str, analysis: dict) -> None:
    """Upsert analysis into audit_analysis table."""
    from main import AsyncSessionLocal, AuditAnalysis
    from sqlalchemy.future import select

    async with AsyncSessionLocal() as session:
        async with session.begin():
            # Check for existing record
            res = await session.execute(
                select(AuditAnalysis).where(AuditAnalysis.scan_id == scan_id)
            )
            existing = res.scalar_one_or_none()

            if existing:
                existing.security_score = analysis.get("security_score")
                existing.maturity_level = analysis.get("maturity_level")
                existing.executive_summary = analysis.get("executive_summary", "")
                existing.attack_vectors = analysis.get("attack_vectors", [])
                existing.most_dangerous_vulnerabilities = analysis.get("most_dangerous_vulnerabilities", [])
                existing.business_impact = analysis.get("business_impact", {})
                existing.likelihood_of_compromise = analysis.get("likelihood_of_compromise")
                existing.attacker_scenario = analysis.get("attacker_scenario", "")
                existing.security_strengths = analysis.get("security_strengths", [])
                existing.security_weaknesses = analysis.get("security_weaknesses", [])
                existing.global_risk_conclusion = analysis.get("global_risk_conclusion", "")
                existing.key_findings = analysis.get("key_findings", [])
                existing.strategic_recommendations = analysis.get("strategic_recommendations", [])
                existing.overall_verdict = analysis.get("overall_verdict", "")
                existing.ai_generated = bool(analysis.get("ai_generated", False))
                existing.generated_at = datetime.utcnow()
            else:
                session.add(AuditAnalysis(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    security_score=analysis.get("security_score"),
                    maturity_level=analysis.get("maturity_level"),
                    executive_summary=analysis.get("executive_summary", ""),
                    attack_vectors=analysis.get("attack_vectors", []),
                    most_dangerous_vulnerabilities=analysis.get("most_dangerous_vulnerabilities", []),
                    business_impact=analysis.get("business_impact", {}),
                    likelihood_of_compromise=analysis.get("likelihood_of_compromise"),
                    attacker_scenario=analysis.get("attacker_scenario", ""),
                    security_strengths=analysis.get("security_strengths", []),
                    security_weaknesses=analysis.get("security_weaknesses", []),
                    global_risk_conclusion=analysis.get("global_risk_conclusion", ""),
                    key_findings=analysis.get("key_findings", []),
                    strategic_recommendations=analysis.get("strategic_recommendations", []),
                    overall_verdict=analysis.get("overall_verdict", ""),
                    ai_generated=bool(analysis.get("ai_generated", False)),
                    generated_at=datetime.utcnow(),
                ))


async def fetch_audit_analysis(scan_id: str) -> dict | None:
    """Fetch stored analysis for a scan. Returns None if not found."""
    from main import AsyncSessionLocal, AuditAnalysis
    from sqlalchemy.future import select

    async with AsyncSessionLocal() as session:
        res = await session.execute(
            select(AuditAnalysis).where(AuditAnalysis.scan_id == scan_id)
        )
        rec = res.scalar_one_or_none()

    if not rec:
        return None

    return {
        "scan_id": scan_id,
        "security_score": rec.security_score,
        "maturity_level": rec.maturity_level,
        "executive_summary": rec.executive_summary,
        "attack_vectors": rec.attack_vectors,
        "most_dangerous_vulnerabilities": rec.most_dangerous_vulnerabilities,
        "business_impact": rec.business_impact,
        "likelihood_of_compromise": rec.likelihood_of_compromise,
        "attacker_scenario": rec.attacker_scenario,
        "security_strengths": rec.security_strengths,
        "security_weaknesses": rec.security_weaknesses,
        "global_risk_conclusion": rec.global_risk_conclusion,
        "key_findings": rec.key_findings,
        "strategic_recommendations": rec.strategic_recommendations,
        "overall_verdict": rec.overall_verdict,
        "ai_generated": rec.ai_generated,
        "generated_at": rec.generated_at.isoformat() if rec.generated_at else None,
    }
