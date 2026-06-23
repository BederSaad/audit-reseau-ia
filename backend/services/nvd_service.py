import httpx
import logging
import re
import os
import time
import asyncio
from typing import List, Dict, Optional

logger = logging.getLogger("NVDService")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_CACHE_TTL = 86400  # 24 hours
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# We need a caching mechanism. I'll use the in-memory cache if redis is not available.
try:
    import redis.asyncio as redis
    redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False

nvd_memory_cache = {}

async def get_cached(key: str) -> Optional[List[Dict]]:
    if REDIS_AVAILABLE:
        try:
            import json
            cached = await redis_client.get(key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass
    if key in nvd_memory_cache:
        result, expiry = nvd_memory_cache[key]
        if time.time() < expiry:
            return result
        else:
            del nvd_memory_cache[key]
    return None

async def set_cached(key: str, data: List[Dict], ttl: int = CVE_CACHE_TTL):
    if REDIS_AVAILABLE:
        try:
            import json
            await redis_client.set(key, json.dumps(data), ex=ttl)
            return
        except Exception:
            pass
    nvd_memory_cache[key] = (data, time.time() + ttl)

last_nvd_call = 0.0
nvd_lock = asyncio.Lock()

async def respect_nvd_rate_limit():
    global last_nvd_call
    async with nvd_lock:
        now = time.time()
        delay = 0.6 if NVD_API_KEY else 6.0
        elapsed = now - last_nvd_call
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        last_nvd_call = time.time()

def extract_version_number(version_str: str) -> Optional[str]:
    if not version_str:
        return None
    match = re.search(r'(\d+(?:\.\d+)+)', version_str)
    if match:
        return match.group(1)
    return None

def build_cpe_string(service_name: str, version: str) -> Optional[str]:
    """
    Best-effort CPE 2.3 builder for common services.
    Returns None if we can't confidently build one — caller falls back to keyword search.
    """
    CPE_PRODUCT_MAP = {
        "vsftpd": ("vsftpd_project", "vsftpd"),
        "openssh": ("openbsd", "openssh"),
        "apache": ("apache", "http_server"),
        "mysql": ("mysql", "mysql"),
        "postgresql": ("postgresql", "postgresql"),
        "samba": ("samba", "samba"),
        "proftpd": ("proftpd", "proftpd"),
    }
    service_key = service_name.lower().strip()
    if service_key not in CPE_PRODUCT_MAP:
        return None
    vendor, product = CPE_PRODUCT_MAP[service_key]
    clean_version = extract_version_number(version)
    if not clean_version:
        return None
    return f"cpe:2.3:a:{vendor}:{product}:{clean_version}:*:*:*:*:*:*:*"

def parse_nvd_response(data: dict) -> List[Dict]:
    results = []
    vulnerabilities = data.get("vulnerabilities", [])
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        metrics = cve.get("metrics", {})
        
        cvss_data = None
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            
        cvss_score = cvss_data.get("baseScore", 0.0) if cvss_data else 0.0
        
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
                
        severity = "info"
        if cvss_score >= 9.0: severity = "critical"
        elif cvss_score >= 7.0: severity = "high"
        elif cvss_score >= 4.0: severity = "medium"
        elif cvss_score > 0: severity = "low"
        
        results.append({
            "template_id": cve_id,
            "name": f"NVD CVE: {cve_id}",
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "cvss_estimated": False,
            "description": desc,
            "severity": severity,
            "source": "nvd_cpe",
            "matcher_name": "nvd_match"
        })
    return results

async def get_cves_for_service(service_name: str, version: str) -> List[Dict]:
    if not service_name or not version:
        return []
    
    cache_key = f"nvd_cache:{service_name}:{version}"
    cached = await get_cached(cache_key)
    if cached:
        logger.info(f"[NVD CACHE HIT] {cache_key}")
        return cached

    cpe = build_cpe_string(service_name, version)
    params = {"cpeMatchString": cpe} if cpe else {"keywordSearch": f"{service_name} {version}"}

    await respect_nvd_rate_limit()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
            resp = await client.get(NVD_BASE, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        results = parse_nvd_response(data)
        await set_cached(cache_key, results, ttl=CVE_CACHE_TTL)
        logger.info(f"[NVD API] {service_name} {version} -> {len(results)} CVEs ({'CPE match' if cpe else 'keyword fallback'})")
        return results
    except Exception as e:
        logger.warning(f"[NVD API] Failed to fetch CVEs for {service_name} {version}: {e}")
        return []
