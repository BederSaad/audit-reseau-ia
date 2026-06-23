"""
CVE Enrichment Module for Network Audit Pipeline

Queries the official NIST NVD API v2 for CVE details and enriches vulnerability data
with CVSS scores, severity ratings, and official descriptions.
Implements Redis caching with in-memory fallback to respect NVD rate limits.
"""

import asyncio
import httpx
import logging
from datetime import datetime
from typing import Optional, List, Dict
import json
import time

logger = logging.getLogger("CVEEnrichment")

# =============================================================================
# REDIS CACHING WITH IN-MEMORY FALLBACK (reuse existing pattern)
# =============================================================================
try:
    import redis.asyncio as redis
    redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False

cve_memory_cache = {}


async def get_cached_cve(cve_id: str) -> Optional[dict]:
    """Get cached CVE data from Redis or in-memory fallback."""
    key = f"cve_enrich:{cve_id}"
    
    if REDIS_AVAILABLE:
        try:
            cached = await redis_client.get(key)
            if cached:
                logger.info(f"[CVE CACHE HIT] Redis -> {cve_id}")
                return json.loads(cached)
        except Exception:
            pass
    
    if key in cve_memory_cache:
        data, expiry = cve_memory_cache[key]
        if time.time() < expiry:
            logger.info(f"[CVE CACHE HIT] Memory -> {cve_id}")
            return data
    
    return None


async def set_cached_cve(cve_id: str, data: dict):
    """Cache CVE data in Redis with 24-hour TTL (in-memory fallback)."""
    key = f"cve_enrich:{cve_id}"
    
    if REDIS_AVAILABLE:
        try:
            await redis_client.set(key, json.dumps(data), ex=86400)  # 24 hours
            return
        except Exception:
            pass
    
    cve_memory_cache[key] = (data, time.time() + 86400)


# =============================================================================
# CORE NVD API V2 FETCH FUNCTION
# =============================================================================
async def fetch_cve_details(cve_id: str) -> Dict:
    """
    Queries the official NIST NVD API v2 for a specific CVE ID.
    Implements a 24-hour cache layer to adhere to NVD rate limits.
    
    Args:
        cve_id: CVE ID in format CVE-YYYY-NNNNN
        
    Returns:
        Dictionary containing CVE details including cvss_score, severity, description
    """
    # 1. Check Cache first
    cached = await get_cached_cve(cve_id)
    if cached:
        return cached

    # Default placeholder structure if API fails or CVE is missing
    result = {
        "cve_id": cve_id,
        "cvss_score": 0.0,
        "severity": "UNKNOWN",
        "description": "Aucune description disponible via l'API NVD pour le moment.",
        "enriched_at": datetime.utcnow().isoformat()
    }

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    # 2. Network Request with explicit safety limits
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if vulnerabilities:
                    cve_item = vulnerabilities[0].get("cve", {})
                    
                    # Extract English description
                    descriptions = cve_item.get("descriptions", [])
                    description_text = next(
                        (d.get("value") for d in descriptions if d.get("lang") == "en"), 
                        "No description found."
                    )
                    result["description"] = description_text
                    
                    # Extract CVSS Metrics (Prioritizing CVSS v3.1 over v3.0)
                    metrics = cve_item.get("metrics", {})
                    cvss_data = None
                    
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    
                    if cvss_data:
                        result["cvss_score"] = float(cvss_data.get("baseScore", 0.0))
                        result["severity"] = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                        
            elif response.status_code == 403:
                logger.warning(f"[NVD API] Rate limit hit (403 Forbidden) while checking {cve_id}.")
            elif response.status_code == 404:
                logger.debug(f"[NVD API] CVE {cve_id} not found in NVD database.")
    except Exception as e:
        logger.error(f"[NVD API] Connection error for {cve_id}: {e}")

    # 3. Commit back to cache (even failures are cached short-term to avoid spamming loops)
    await set_cached_cve(cve_id, result)
    return result


# =============================================================================
# ORCHESTRATOR FOR BULK PIPELINE RUNS
# =============================================================================
async def enrich_vulnerabilities_list(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Iterates through a list of scanned findings, extracts unique CVE IDs,
    fetches raw NVD metrics, and updates the references in place.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries from Nuclei/credential testing
        
    Returns:
        Enriched list of vulnerability dictionaries with CVSS data from NVD
    """
    # Isolate unique CVE IDs to avoid duplicate API calls in the same scan session
    unique_cve_ids = {v["cve_id"] for v in vulnerabilities if v.get("cve_id")}
    
    if not unique_cve_ids:
        return vulnerabilities

    logger.info(f"[CVE ENRICH] Enriching {len(unique_cve_ids)} unique CVE vectors discovered during scan.")
    
    # Fetch details concurrently while respecting a small artificial delay to stay safe
    tasks = []
    for cve_id in unique_cve_ids:
        tasks.append(fetch_cve_details(cve_id))
        await asyncio.sleep(0.6)  # Standard courtesy window between task initializations

    nvd_results = await asyncio.gather(*tasks, return_exceptions=True)
    cve_map = {r["cve_id"]: r for r in nvd_results if isinstance(r, dict)}

    # Map the fresh data metrics right back into the main list for UI consumption
    for vuln in vulnerabilities:
        cve_id = vuln.get("cve_id")
        if cve_id in cve_map:
            vuln["cvss_score"] = cve_map[cve_id]["cvss_score"]
            vuln["description"] = cve_map[cve_id]["description"]
            # Map NVD severity rules to maintain consistent dashboard UI classifications
            if cve_map[cve_id]["severity"] != "UNKNOWN":
                vuln["severity"] = cve_map[cve_id]["severity"]

    return vulnerabilities
