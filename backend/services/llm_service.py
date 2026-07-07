import httpx
import os
import json
import logging
import asyncio

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:14b")   # <-- changed here

logger = logging.getLogger("LLMService")

async def call_ollama(prompt: str, system: str = "", timeout: float = 30.0) -> str:
    """
    Calls local Ollama instance. Returns raw text response.
    Raises httpx.TimeoutException or httpx.ConnectError on failure — caller must handle.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {"temperature": 0.2}
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "").strip()

async def safe_llm_call(coro, fallback_value, context: str = "", host_ip: str = "unknown", scan_id: str = "unknown", input_summary: str = ""):
    """Wraps any LLM enrichment call with timeout + error handling + fallback."""
    start_time = asyncio.get_event_loop().time()
    status = "success"
    output_summary = ""
    try:
        result = await asyncio.wait_for(coro, timeout=45.0)
        logger.info(f"[LLM DECISION] context='{context}' status=success")
        output_summary = str(result)[:200]
        return result
    except asyncio.TimeoutError:
        logger.warning(f"[LLM DECISION] context='{context}' status=timeout, using fallback")
        status = "timeout"
        output_summary = str(fallback_value)[:200]
        return fallback_value
    except Exception as e:
        logger.error(f"[LLM DECISION] context='{context}' status=error error={e}, using fallback")
        status = "error"
        output_summary = str(fallback_value)[:200]
        return fallback_value
    finally:
        duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
        try:
            from main import AsyncSessionLocal, LLMDecisionLog
            async with AsyncSessionLocal() as session:
                async with session.begin():
                    session.add(LLMDecisionLog(
                        scan_id=scan_id,
                        host_ip=host_ip,
                        decision_type=context,
                        input_summary=input_summary[:200],
                        output_summary=output_summary,
                        status=status,
                        duration_ms=duration_ms
                    ))
        except Exception as e:
            logger.error(f"[LLM LOG DB] Failed to save decision log: {e}")

OS_FINGERPRINT_SYSTEM_PROMPT = """Tu es un expert en sécurité réseau spécialisé dans le fingerprinting d'OS.
Tu reçois des données brutes de détection Nmap (OS match approximatif + ports/services ouverts).
Ta tâche : donner une estimation plus précise et justifiée du système d'exploitation probable.
Réponds UNIQUEMENT en JSON valide, sans aucun texte avant ou après, avec ce format exact :
{"os_guess": "...", "confidence": "high|medium|low", "reasoning": "..."}
Si les données sont insuffisantes pour affiner l'estimation, renvoie la donnée Nmap originale avec confidence: "low"."""

async def enrich_os_fingerprint(nmap_os_guess: str, open_ports: list[dict]) -> dict:
    ports_summary = ", ".join(f"{p['port']}/{p['name']} {p.get('version','')}" for p in open_ports[:10])
    prompt = f"""Détection Nmap brute : "{nmap_os_guess}"
Services détectés : {ports_summary}

Donne ton estimation affinée."""

    async def _call():
        raw_response = await call_ollama(prompt, system=OS_FINGERPRINT_SYSTEM_PROMPT, timeout=20.0)
        parsed = json.loads(raw_response)
        return {
            "os_guess": parsed.get("os_guess", nmap_os_guess),
            "confidence": parsed.get("confidence", "low"),
            "reasoning": parsed.get("reasoning", "Donnée brute Nmap, non enrichie."),
            "enriched": True
        }

    fallback = {
        "os_guess": nmap_os_guess,
        "confidence": "low",
        "reasoning": "Enrichissement IA indisponible, donnée brute Nmap utilisée.",
        "enriched": False
    }

    return await safe_llm_call(_call(), fallback_value=fallback, context="os_fingerprint_single", input_summary=prompt)

async def batch_enrich_os_fingerprints(scan_id: str, hosts: list[dict]) -> dict:
    """Single LLM call for all hosts in a scan instead of N calls."""
    if not hosts:
        return {}
        
    hosts_summary = "\n".join(f"- IP {h['ip']}: Nmap guess='{h.get('os', 'Unknown')}', ports={[s['port'] for s in h.get('services', [])][:5]}" for h in hosts)
    prompt = f"""Voici plusieurs hôtes détectés lors d'un scan réseau:
{hosts_summary}

Pour CHAQUE hôte, donne ton estimation affinée de l'OS. Réponds en JSON, un tableau d'objets:
[{{\"ip\": \"...\", \"os_guess\": \"...\", \"confidence\": \"high|medium|low\", \"reasoning\": \"...\"}}]"""

    async def _call():
        raw = await call_ollama(prompt, system=OS_FINGERPRINT_SYSTEM_PROMPT, timeout=40.0)
        results = json.loads(raw)
        return {r["ip"]: r for r in results}

    return await safe_llm_call(_call(), fallback_value={}, context="os_fingerprint_batch", scan_id=scan_id, input_summary=prompt)

STANDARD_PORT_SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 443: "https", 3306: "mysql", 5432: "postgresql"}

def is_nonstandard_service(port: int, detected_name: str) -> bool:
    expected = STANDARD_PORT_SERVICES.get(port)
    if expected is None or not detected_name:
        return False
    return expected.lower() not in detected_name.lower()

NONSTANDARD_SERVICE_SYSTEM_PROMPT = """Tu es un expert en sécurité réseau. Un service tourne sur un port où on attendrait normalement un autre service.
Analyse la bannière/version fournie et explique ce que ce service est probablement réellement, et si ce détournement de port est suspect ou juste une configuration légitime mais inhabituelle.
Réponds en JSON : {"likely_service": "...", "is_suspicious": true|false, "explanation": "..."}"""

async def analyze_nonstandard_service(port: int, expected: str, detected_name: str, version: str) -> dict:
    prompt = f'Port {port} (normalement "{expected}") fait tourner : "{detected_name} {version}". Analyse.'
    
    async def _call():
        raw = await call_ollama(prompt, system=NONSTANDARD_SERVICE_SYSTEM_PROMPT, timeout=20.0)
        return json.loads(raw)
        
    fallback = {"likely_service": detected_name, "is_suspicious": False, "explanation": "Analyse IA indisponible."}
    return await safe_llm_call(_call(), fallback_value=fallback, context=f"nonstandard_service_{port}", input_summary=prompt)

JUSTIFICATION_SYSTEM_PROMPT = """Tu es un analyste sécurité senior rédigeant un rapport d'audit.
Pour chaque vulnérabilité, rédige une justification concise (2-3 phrases max) expliquant pourquoi elle a ce niveau de priorité, en mentionnant le score CVSS, le contexte d'exposition, et la facilité d'exploitation. Sois factuel et direct, sans superlatifs inutiles. Réponds en français, en texte brut (pas de JSON ici)."""

async def generate_priority_justification(vuln: dict) -> str:
    prompt = f"""Vulnérabilité: {vuln['name']}
CVSS: {vuln['cvss_score']} | Catégorie de risque: {vuln['risk_category']} | Score d'urgence: {vuln['urgency_score']}/100
Exposition: {vuln['exposure_factor']} | Facilité d'exploitation: {vuln['exploitability_factor']}
Source de détection: {vuln['source']}

Rédige la justification."""

    async def _call():
        return await call_ollama(prompt, system=JUSTIFICATION_SYSTEM_PROMPT, timeout=20.0)

    return await safe_llm_call(
        _call(), 
        fallback_value="Justification automatique indisponible — voir score CVSS et catégorie de risque.", 
        context="risk_justification",
        scan_id=vuln.get('scan_id', 'unknown'),
        host_ip=vuln.get('host_ip', 'unknown'),
        input_summary=prompt
    )