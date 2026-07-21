"""
Credential Testing Module for Network Audit Pipeline

Tests default/weak credentials against common network services.
Only runs against services already confirmed open by Nmap.
Implements Redis caching with in-memory fallback, rate limiting, and comprehensive error handling.

WARNING: This module should only be used in authorized lab environments or with explicit written authorization.
"""

import asyncio
import ftplib
import logging
import json
import time
import httpx
import urllib3
from datetime import datetime
from typing import Dict, List, Optional

# Suppress SSL warnings for self-signed certificates on network devices
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import re
try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None
    logging.warning("playwright not installed - Web interface credential testing will use HTTP fallback")



# Service-specific libraries (will be installed as dependencies)
try:
    import paramiko
except ImportError:
    paramiko = None
    logging.warning("paramiko not installed - SSH credential testing will be skipped")

try:
    import telnetlib3
except ImportError:
    telnetlib3 = None
    logging.warning("telnetlib3 not installed - Telnet credential testing will be skipped")

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None
    logging.warning("impacket not installed - SMB credential testing will be skipped")

try:
    import pymysql
except ImportError:
    pymysql = None
    logging.warning("pymysql not installed - MySQL credential testing will be skipped")

try:
    import asyncpg
except ImportError:
    asyncpg = None
    logging.warning("asyncpg not installed - PostgreSQL credential testing will be skipped")

logger = logging.getLogger("CredentialTesting")

# =============================================================================
# REDIS CACHING WITH IN-MEMORY FALLBACK
# =============================================================================
try:
    import redis.asyncio as redis
    redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)
    REDIS_AVAILABLE = True
except Exception as e:
    REDIS_AVAILABLE = False
    logger.warning(f"Redis not available: {e}. Using in-memory caching with manual TTL.")


cred_memory_cache = {}


async def get_cached_cred_result(ip: str, port: int, service: str) -> Optional[Dict]:
    """Get cached credential test result from Redis or in-memory fallback."""
    key = f"cred_test:{ip}:{port}:{service}"
    
    # Try Redis first
    if REDIS_AVAILABLE:
        try:
            cached = await redis_client.get(key)
            if cached:
                logger.info(f"[CRED CACHE HIT] Redis -> {key}")
                return json.loads(cached)
        except Exception as e:
            logger.debug(f"Redis cache error for {key}: {e}")
    
    # Fallback to in-memory cache with manual TTL checking
    if key in cred_memory_cache:
        result, expiry = cred_memory_cache[key]
        if time.time() < expiry:
            logger.info(f"[CRED CACHE HIT] Memory -> {key}")
            return result
        else:
            # Expired, remove from memory
            del cred_memory_cache[key]
    
    return None


async def set_cached_cred_result(ip: str, port: int, service: str, result: Dict):
    """Cache credential test result in Redis with 1-hour TTL (in-memory fallback)."""
    key = f"cred_test:{ip}:{port}:{service}"
    
    # Try Redis first
    if REDIS_AVAILABLE:
        try:
            await redis_client.set(key, json.dumps(result), ex=3600)  # 1 hour TTL
            return
        except Exception as e:
            logger.debug(f"Redis cache set error for {key}: {e}")
    
    # Fallback to in-memory cache
    cred_memory_cache[key] = (result, time.time() + 3600)  # 1 hour TTL


# =============================================================================
# DEFAULT CREDENTIALS WORDLIST
# =============================================================================
DEFAULT_CREDENTIALS = {
    "ftp": [("anonymous", "anonymous"), ("ftp", "ftp"), ("msfadmin", "msfadmin"), ("admin", "admin"), ("admin", "password")],
    "ssh": [("root", "root"), ("msfadmin", "msfadmin"), ("admin", "admin"), ("root", "toor"), ("admin", "password"), ("pi", "raspberry")],
    "telnet": [("admin", "admin"), ("msfadmin", "msfadmin"), ("root", "root"), ("admin", ""), ("root", "")],
    "smb": [("admin", "admin"), ("guest", ""), ("administrator", "password")],
    "mysql": [("root", ""), ("root", "root"), ("root", "password")],
    "postgresql": [("postgres", "postgres"), ("postgres", "password"), ("postgres", "")],
}

WEB_PORTS = {80, 443, 8080, 8443, 3000, 8000, 8888, 9090, 9443, 4443}
HTTPS_PORTS = {443, 8443, 9443, 4443}

# Comprehensive list of default credentials for Web Interfaces (Routers, Cameras, NAS, Switches, Huawei, TP-Link, etc.)
WEB_DEFAULT_CREDENTIALS = [
    ("topadmin", "topadmin"), ("telecomadmin", "admintelecom"),
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"), 
    ("admin", "12345"), ("admin", "123456"), ("admin", "12345678"), 
    ("admin", "1234567890"), ("admin", ""), ("admin", "admin123"), 
    ("admin", "Admin@123"), ("admin", "root"), ("admin", "hikvision"), 
    ("admin", "h3c"), ("admin", "ubnt"), ("admin", "cisco"), 
    ("admin", "mikrotik"), ("admin", "synology"), ("admin", "qnap"), 
    ("root", "root"), ("root", "admin"), ("root", ""), ("root", "1234"), 
    ("user", "user"), ("user", "1234"), ("guest", "guest"), ("guest", ""), 
    ("support", "support"), ("cisco", "cisco"), ("sa", ""), 
    ("administrator", ""), ("administrator", "password"), ("admin", "admin1234"),
    ("admin", "changeme"), ("admin", "letmein"), ("admin", "welcome")
]




# =============================================================================
# SERVICE-SPECIFIC CREDENTIAL TESTING FUNCTIONS
# =============================================================================

async def test_ftp_credentials(ip: str, port: int = 21) -> Dict:
    """
    Test FTP credentials against target host.
    Returns structured result with vulnerability status and credentials found.
    """
    cached = await get_cached_cred_result(ip, port, "ftp")
    if cached:
        return cached

    result = {
        "service": "ftp",
        "port": port,
        "tested": True,
        "vulnerable": False,
        "credentials_found": [],
        "attempts_made": 0,
        "tested_at": datetime.utcnow().isoformat()
    }

    if not DEFAULT_CREDENTIALS.get("ftp"):
        logger.warning("[CRED TEST] No FTP credentials configured")
        return result

    for username, password in DEFAULT_CREDENTIALS["ftp"]:
        result["attempts_made"] += 1
        try:
            def _try_login():
                ftp = ftplib.FTP(timeout=5)
                ftp.connect(ip, port)
                ftp.login(username, password)
                ftp.quit()
                return True

            success = await asyncio.to_thread(_try_login)
            if success:
                result["vulnerable"] = True
                result["credentials_found"].append({"username": username, "password": password})
                logger.warning(f"[CRED TEST] WEAK LOGIN FOUND: ftp://{username}:{password}@{ip}:{port}")
        except Exception as e:
            logger.debug(f"[CRED TEST] ftp {ip}:{port} {username}:{password} failed: {e}")
        finally:
            await asyncio.sleep(1)  # Rate limit between attempts

    await set_cached_cred_result(ip, port, "ftp", result)
    return result


async def test_ssh_credentials(ip: str, port: int = 22) -> Dict:
    """
    Test SSH credentials against target host using paramiko.
    Returns structured result with vulnerability status and credentials found.
    """
    if paramiko is None:
        logger.warning("[CRED TEST] paramiko not installed, skipping SSH credential testing")
        return {
            "service": "ssh",
            "port": port,
            "tested": False,
            "vulnerable": False,
            "credentials_found": [],
            "attempts_made": 0,
            "tested_at": datetime.utcnow().isoformat(),
            "error": "paramiko not installed"
        }

    cached = await get_cached_cred_result(ip, port, "ssh")
    if cached:
        return cached

    result = {
        "service": "ssh",
        "port": port,
        "tested": True,
        "vulnerable": False,
        "credentials_found": [],
        "attempts_made": 0,
        "tested_at": datetime.utcnow().isoformat()
    }

    if not DEFAULT_CREDENTIALS.get("ssh"):
        logger.warning("[CRED TEST] No SSH credentials configured")
        return result

    for username, password in DEFAULT_CREDENTIALS["ssh"]:
        result["attempts_made"] += 1
        try:
            def _try_login():
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port, username, password, timeout=5, banner_timeout=5)
                ssh.close()
                return True

            success = await asyncio.to_thread(_try_login)
            if success:
                result["vulnerable"] = True
                result["credentials_found"].append({"username": username, "password": password})
                logger.warning(f"[CRED TEST] WEAK LOGIN FOUND: ssh://{username}:{password}@{ip}:{port}")
        except Exception as e:
            logger.debug(f"[CRED TEST] ssh {ip}:{port} {username}:{password} failed: {e}")
        finally:
            await asyncio.sleep(1)  # Rate limit between attempts

    await set_cached_cred_result(ip, port, "ssh", result)
    return result


async def test_telnet_credentials(ip: str, port: int = 23) -> Dict:
    """
    Test Telnet credentials against target host using telnetlib3.
    Returns structured result with vulnerability status and credentials found.
    """
    if telnetlib3 is None:
        logger.warning("[CRED TEST] telnetlib3 not installed, skipping Telnet credential testing")
        return {
            "service": "telnet",
            "port": port,
            "tested": False,
            "vulnerable": False,
            "credentials_found": [],
            "attempts_made": 0,
            "tested_at": datetime.utcnow().isoformat(),
            "error": "telnetlib3 not installed"
        }

    cached = await get_cached_cred_result(ip, port, "telnet")
    if cached:
        return cached

    result = {
        "service": "telnet",
        "port": port,
        "tested": True,
        "vulnerable": False,
        "credentials_found": [],
        "attempts_made": 0,
        "tested_at": datetime.utcnow().isoformat()
    }

    if not DEFAULT_CREDENTIALS.get("telnet"):
        logger.warning("[CRED TEST] No Telnet credentials configured")
        return result

    for username, password in DEFAULT_CREDENTIALS["telnet"]:
        result["attempts_made"] += 1
        try:
            # Fully async telnet login using telnetlib3
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(ip, port),
                timeout=5
            )
            
            # Send username
            writer.write(f"{username}\n")
            await asyncio.wait_for(writer.drain(), timeout=3)
            await asyncio.sleep(0.5)
            
            # Send password
            writer.write(f"{password}\n")
            await asyncio.wait_for(writer.drain(), timeout=3)
            await asyncio.sleep(0.5)
            
            # Read response to check for failure
            success = True
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                if any(x in data.lower() for x in ["login incorrect", "fail", "invalid", "incorrect", "login:"]):
                    success = False
            except asyncio.TimeoutError:
                # Timeout implies connection remains open and didn't immediately reject us
                pass
                
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except Exception:
                pass
                
            if success:
                result["vulnerable"] = True
                result["credentials_found"].append({"username": username, "password": password})
                logger.warning(f"[CRED TEST] WEAK LOGIN FOUND: telnet://{username}:{password}@{ip}:{port}")
        except Exception as e:
            logger.debug(f"[CRED TEST] telnet {ip}:{port} {username}:{password} failed: {e}")
        finally:
            await asyncio.sleep(1)  # Rate limit between attempts

    await set_cached_cred_result(ip, port, "telnet", result)
    return result


async def test_smb_credentials(ip: str, port: int = 445) -> Dict:
    """
    Test SMB credentials against target host using impacket.
    Returns structured result with vulnerability status and credentials found.
    """
    if SMBConnection is None:
        logger.warning("[CRED TEST] impacket not installed, skipping SMB credential testing")
        return {
            "service": "smb",
            "port": port,
            "tested": False,
            "vulnerable": False,
            "credentials_found": [],
            "attempts_made": 0,
            "tested_at": datetime.utcnow().isoformat(),
            "error": "impacket not installed"
        }

    cached = await get_cached_cred_result(ip, port, "smb")
    if cached:
        return cached

    result = {
        "service": "smb",
        "port": port,
        "tested": True,
        "vulnerable": False,
        "credentials_found": [],
        "attempts_made": 0,
        "tested_at": datetime.utcnow().isoformat()
    }

    if not DEFAULT_CREDENTIALS.get("smb"):
        logger.warning("[CRED TEST] No SMB credentials configured")
        return result

    for username, password in DEFAULT_CREDENTIALS["smb"]:
        result["attempts_made"] += 1
        try:
            def _try_login():
                try:
                    smb = SMBConnection(
                        remoteName=ip,
                        remoteHost=ip,
                        sess_port=port,
                        timeout=5
                    )
                    smb.login(username, password)
                    try:
                        smb.logoff()
                    except Exception:
                        pass
                    return True
                except Exception:
                    return False

            success = await asyncio.to_thread(_try_login)
            if success:
                result["vulnerable"] = True
                result["credentials_found"].append({"username": username, "password": password})
                logger.warning(f"[CRED TEST] WEAK LOGIN FOUND: smb://{username}:{password}@{ip}:{port}")
        except Exception as e:
            logger.debug(f"[CRED TEST] smb {ip}:{port} {username}:{password} failed: {e}")
        finally:
            await asyncio.sleep(1)  # Rate limit between attempts

    await set_cached_cred_result(ip, port, "smb", result)
    return result


async def test_mysql_credentials(ip: str, port: int = 3306) -> Dict:
    """
    Test MySQL credentials against target host using pymysql.
    Returns structured result with vulnerability status and credentials found.
    """
    if pymysql is None:
        logger.warning("[CRED TEST] pymysql not installed, skipping MySQL credential testing")
        return {
            "service": "mysql",
            "port": port,
            "tested": False,
            "vulnerable": False,
            "credentials_found": [],
            "attempts_made": 0,
            "tested_at": datetime.utcnow().isoformat(),
            "error": "pymysql not installed"
        }

    cached = await get_cached_cred_result(ip, port, "mysql")
    if cached:
        return cached

    result = {
        "service": "mysql",
        "port": port,
        "tested": True,
        "vulnerable": False,
        "credentials_found": [],
        "attempts_made": 0,
        "tested_at": datetime.utcnow().isoformat()
    }

    if not DEFAULT_CREDENTIALS.get("mysql"):
        logger.warning("[CRED TEST] No MySQL credentials configured")
        return result

    for username, password in DEFAULT_CREDENTIALS["mysql"]:
        result["attempts_made"] += 1
        try:
            def _try_login():
                connection = pymysql.connect(
                    host=ip,
                    port=port,
                    user=username,
                    password=password,
                    connect_timeout=5
                )
                connection.close()
                return True

            success = await asyncio.to_thread(_try_login)
            if success:
                result["vulnerable"] = True
                result["credentials_found"].append({"username": username, "password": password})
                logger.warning(f"[CRED TEST] WEAK LOGIN FOUND: mysql://{username}:{password}@{ip}:{port}")
        except Exception as e:
            logger.debug(f"[CRED TEST] mysql {ip}:{port} {username}:{password} failed: {e}")
        finally:
            await asyncio.sleep(1)  # Rate limit between attempts

    await set_cached_cred_result(ip, port, "mysql", result)
    return result


async def test_postgresql_credentials(ip: str, port: int = 5432) -> Dict:
    """
    Test PostgreSQL credentials against target host using asyncpg.
    Returns structured result with vulnerability status and credentials found.
    """
    if asyncpg is None:
        logger.warning("[CRED TEST] asyncpg not installed, skipping PostgreSQL credential testing")
        return {
            "service": "postgresql",
            "port": port,
            "tested": False,
            "vulnerable": False,
            "credentials_found": [],
            "attempts_made": 0,
            "tested_at": datetime.utcnow().isoformat(),
            "error": "asyncpg not installed"
        }

    cached = await get_cached_cred_result(ip, port, "postgresql")
    if cached:
        return cached

    result = {
        "service": "postgresql",
        "port": port,
        "tested": True,
        "vulnerable": False,
        "credentials_found": [],
        "attempts_made": 0,
        "tested_at": datetime.utcnow().isoformat()
    }

    if not DEFAULT_CREDENTIALS.get("postgresql"):
        logger.warning("[CRED TEST] No PostgreSQL credentials configured")
        return result

    for username, password in DEFAULT_CREDENTIALS["postgresql"]:
        result["attempts_made"] += 1
        try:
            conn = await asyncio.wait_for(
                asyncpg.connect(
                    host=ip,
                    port=port,
                    user=username,
                    password=password,
                    timeout=5
                ),
                timeout=5
            )
            await conn.close()
            result["vulnerable"] = True
            result["credentials_found"].append({"username": username, "password": password})
            logger.warning(f"[CRED TEST] WEAK LOGIN FOUND: postgresql://{username}:{password}@{ip}:{port}")
        except Exception as e:
            logger.debug(f"[CRED TEST] postgresql {ip}:{port} {username}:{password} failed: {e}")
        finally:
            await asyncio.sleep(1)  # Rate limit between attempts

    await set_cached_cred_result(ip, port, "postgresql", result)
    return result


async def test_rdp_exposure(ip: str, port: int = 3389) -> Dict:
    """
    Flag RDP exposure without attempting credentials (too noisy/risky).
    Returns exposure finding with medium severity.
    """
    cached = await get_cached_cred_result(ip, port, "rdp")
    if cached:
        return cached

    result = {
        "service": "rdp",
        "port": port,
        "tested": True,
        "vulnerable": True,  # Exposure itself is the vulnerability
        "credentials_found": [],  # No credentials tested
        "attempts_made": 0,
        "tested_at": datetime.utcnow().isoformat(),
        "exposure_only": True,
        "reason": "RDP exposure flagged - credential testing skipped due to noise/risk"
    }

    await set_cached_cred_result(ip, port, "rdp", result)
    return result


async def test_vnc_exposure(ip: str, port: int = 5900) -> Dict:
    """
    Flag VNC exposure without attempting credentials (too noisy/risky).
    Returns exposure finding with medium severity.
    """
    cached = await get_cached_cred_result(ip, port, "vnc")
    if cached:
        return cached

    result = {
        "service": "vnc",
        "port": port,
        "tested": True,
        "vulnerable": True,  # Exposure itself is the vulnerability
        "credentials_found": [],  # No credentials tested
        "attempts_made": 0,
        "tested_at": datetime.utcnow().isoformat(),
        "exposure_only": True,
        "reason": "VNC exposure flagged - credential testing skipped due to noise/risk"
    }

    await set_cached_cred_result(ip, port, "vnc", result)
    return result


async def test_web_credentials(ip: str, port: int, scheme: str) -> Dict:
    """
    Test default web credentials against target host.
    Tries Playwright browser-based login first (to handle JS-based single-page apps),
    and falls back to HTTP Basic Auth and common POST endpoints if Playwright fails.
    """
    cached = await get_cached_cred_result(ip, port, "web")
    if cached:
        return cached

    result = {
        "service": "web",
        "port": port,
        "tested": True,
        "vulnerable": False,
        "credentials_found": [],
        "attempts_made": 0,
        "tested_at": datetime.utcnow().isoformat()
    }

    url = f"{scheme}://{ip}:{port}"

    # Try browser-based credential testing first if Playwright is available
    if async_playwright:
        logger.info(f"[CRED TEST] Starting browser-based credential test for {url}")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                await page.set_viewport_size({"width": 1280, "height": 1024})
                
                # Navigate to the page
                try:
                    await page.goto(url, timeout=12000, wait_until="domcontentloaded")
                    await page.wait_for_timeout(1000)
                except Exception as e:
                    logger.debug(f"[CRED TEST] Browser navigation failed to {url}: {e}")
                    await browser.close()
                    raise e
                
                # Find input fields
                user_selectors = [
                    "input[type='text'][name*='user' i]", "input[type='text'][name*='login' i]",
                    "input[type='text'][id*='user' i]", "input[type='text'][id*='login' i]",
                    "input[name*='username' i]", "input[name*='user' i]", "input[name*='login' i]",
                    "input[id*='username' i]", "input[id*='user' i]", "input[id*='login' i]",
                    "input[placeholder*='username' i]", "input[placeholder*='user' i]", "input[placeholder*='login' i]"
                ]
                pass_selectors = [
                    "input[type='password']",
                    "input[name*='password' i]", "input[name*='pass' i]",
                    "input[id*='password' i]", "input[id*='pass' i]",
                    "input[placeholder*='password' i]", "input[placeholder*='pass' i]"
                ]

                user_input = None
                for sel in user_selectors:
                    try:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            user_input = el
                            break
                    except Exception:
                        pass
                
                if not user_input:
                    try:
                        inputs = await page.query_selector_all("input")
                        for inp in inputs:
                            inp_type = await inp.get_attribute("type") or "text"
                            if inp_type in ["text", "email"] and await inp.is_visible():
                                user_input = inp
                                break
                    except Exception:
                        pass

                pass_input = None
                for sel in pass_selectors:
                    try:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            pass_input = el
                            break
                    except Exception:
                        pass

                if not user_input or not pass_input:
                    logger.debug(f"[CRED TEST] Browser could not find username/password inputs on {url}. Falling back to HTTP.")
                    await browser.close()
                else:
                    # Try default credentials one by one
                    for username, password in WEB_DEFAULT_CREDENTIALS:
                        result["attempts_made"] += 1
                        try:
                            # Clean the fields and fill new credentials
                            await user_input.fill("")
                            await user_input.type(username)
                            await pass_input.fill("")
                            await pass_input.type(password)
                            await page.wait_for_timeout(200)

                            # Find and click submit button
                            submit_clicked = False
                            submit_selectors = [
                                "input[type='submit']", "button[type='submit']",
                                "button", "input[type='button']",
                                "a:has-text('login')", "a:has-text('Login')", "a:has-text('Sign')",
                                "div[role='button']", "span[role='button']"
                            ]
                            for sel in submit_selectors:
                                try:
                                    el = await page.query_selector(sel)
                                    if el and await el.is_visible():
                                        el_tag = await el.evaluate("node => node.tagName")
                                        if el_tag.lower() == "input":
                                            el_type = await el.get_attribute("type")
                                            if el_type in ["text", "password"]:
                                                continue
                                        await el.click(timeout=1500)
                                        submit_clicked = True
                                        break
                                except Exception:
                                    pass

                            if not submit_clicked:
                                try:
                                    await pass_input.press("Enter")
                                except Exception:
                                    pass

                            # Wait for redirect or DOM updates
                            await page.wait_for_timeout(2500)

                            # Check success criteria
                            pw_visible = False
                            try:
                                pw_el = await page.query_selector("input[type='password']")
                                if pw_el and await pw_el.is_visible():
                                    pw_visible = True
                            except Exception:
                                pass

                            body_text = ""
                            try:
                                body_el = await page.query_selector("body")
                                if body_el:
                                    body_text = await body_el.inner_text()
                            except Exception:
                                pass
                            body_text_lower = body_text.lower()

                            # Detect failure strings
                            has_error = False
                            if pw_visible:
                                error_keywords = ["incorrect", "fail", "invalid", "wrong", "erreur", "échec", "tentative", "authentification échouée"]
                                if any(kw in body_text_lower for kw in error_keywords):
                                    has_error = True

                            success = False
                            if not pw_visible and not has_error:
                                success = True
                            elif not has_error and any(kw in body_text_lower for kw in ["logout", "déconnexion", "dashboard", "status", "statut", "system", "router info", "configuration"]):
                                success = True

                            if success:
                                result["vulnerable"] = True
                                result["credentials_found"].append({"username": username, "password": password})
                                logger.warning(f"[CRED TEST] BROWSER LOGIN SUCCESS: {url} with {username}:{password}")
                                break
                            else:
                                logger.debug(f"[CRED TEST] Browser login failed for {username}:{password} on {url}")
                                
                                # If we navigated away but it failed, return to login page
                                if page.url != url:
                                    try:
                                        await page.goto(url, timeout=8000, wait_until="domcontentloaded")
                                        await page.wait_for_timeout(1000)
                                    except Exception:
                                        pass
                                    # Re-find input elements
                                    user_input = None
                                    for sel in user_selectors:
                                        try:
                                            el = await page.query_selector(sel)
                                            if el and await el.is_visible():
                                                user_input = el
                                                break
                                        except Exception:
                                            pass
                                    if not user_input:
                                        try:
                                            inputs = await page.query_selector_all("input")
                                            for inp in inputs:
                                                inp_type = await inp.get_attribute("type") or "text"
                                                if inp_type in ["text", "email"] and await inp.is_visible():
                                                    user_input = inp
                                                    break
                                        except Exception:
                                            pass

                                    pass_input = None
                                    for sel in pass_selectors:
                                        try:
                                            el = await page.query_selector(sel)
                                            if el and await el.is_visible():
                                                pass_input = el
                                                break
                                        except Exception:
                                            pass
                        except Exception as e:
                            logger.debug(f"[CRED TEST] Browser login error during {username}:{password} on {url}: {e}")
                    
                    await browser.close()
                    await set_cached_cred_result(ip, port, "web", result)
                    return result
        except Exception as e:
            logger.warning(f"[CRED TEST] Browser-based credential test failed for {url}: {e}. Falling back to HTTP client.")

    # Fallback to HTTP client requests (Basic Auth & standard POST endpoints)
    async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
        for username, password in WEB_DEFAULT_CREDENTIALS:
            result["attempts_made"] += 1
            try:
                # 1. Try HTTP Basic Auth
                resp = await client.get(url, auth=(username, password))
                if resp.status_code == 200:
                    content_lower = resp.text.lower()
                    if "invalid" not in content_lower and "failed" not in content_lower and "incorrect" not in content_lower:
                        result["vulnerable"] = True
                        result["credentials_found"].append({"username": username, "password": password})
                        logger.warning(f"[CRED TEST] WEAK WEB LOGIN FOUND (Basic Auth): {scheme}://{username}:{password}@{ip}:{port}")
                        break
                
                # 2. Try form POST endpoints
                for endpoint in ["/login", "/api/login", "/cgi-bin/login"]:
                    try:
                        json_resp = await client.post(f"{url}{endpoint}", json={"username": username, "password": password, "user": username, "pass": password})
                        if json_resp.status_code == 200:
                            j_text = json_resp.text.lower()
                            if "success" in j_text or "token" in j_text or ("invalid" not in j_text and "failed" not in j_text):
                                result["vulnerable"] = True
                                result["credentials_found"].append({"username": username, "password": password})
                                logger.warning(f"[CRED TEST] WEAK WEB LOGIN FOUND (JSON POST): {url}{endpoint}")
                                break
                    except Exception:
                        pass
                    
                    try:
                        form_resp = await client.post(f"{url}{endpoint}", data={"username": username, "password": password, "user": username, "pass": password})
                        if form_resp.status_code == 200:
                            f_text = form_resp.text.lower()
                            if "success" in f_text or "token" in f_text or ("invalid" not in f_text and "failed" not in f_text):
                                result["vulnerable"] = True
                                result["credentials_found"].append({"username": username, "password": password})
                                logger.warning(f"[CRED TEST] WEAK WEB LOGIN FOUND (Form POST): {url}{endpoint}")
                                break
                    except Exception:
                        pass
                
                if result["vulnerable"]:
                    break

            except Exception as e:
                logger.debug(f"[CRED TEST] HTTP web {url} {username}:{password} failed: {e}")
            
            await asyncio.sleep(0.5)

    await set_cached_cred_result(ip, port, "web", result)
    return result



# =============================================================================
# SERVICE PORT MAPPING AND ORCHESTRATOR
# =============================================================================
SERVICE_PORT_MAP = {
    21: ("ftp", test_ftp_credentials),
    22: ("ssh", test_ssh_credentials),
    23: ("telnet", test_telnet_credentials),
    445: ("smb", test_smb_credentials),
    3306: ("mysql", test_mysql_credentials),
    5432: ("postgresql", test_postgresql_credentials),
    3389: ("rdp", test_rdp_exposure),
    5900: ("vnc", test_vnc_exposure),
}


async def run_credential_tests(host_result: Dict) -> List[Dict]:
    """
    Run credential tests against all matching open services on this host.
    Only tests services that are confirmed open in the host_result.
    
    Args:
        host_result: Dictionary containing host information with 'ip' and 'services' keys
        
    Returns:
        List of credential test results dictionaries
    """
    ip = host_result.get("ip")
    if not ip:
        logger.warning("[CRED TEST] Host result missing IP address")
        return []

    services = host_result.get("services", [])
    if not services:
        logger.debug(f"[CRED TEST] No services found for host {ip}")
        return []

    tasks = []
    for service in services:
        port = service.get("port")
        state = service.get("state")
        
        if port in SERVICE_PORT_MAP and state == "open":
            service_name, test_func = SERVICE_PORT_MAP[port]
            logger.info(f"[CRED TEST] Scheduling {service_name} test for {ip}:{port}")
            tasks.append(test_func(ip, port))
        elif port in WEB_PORTS and state == "open":
            scheme = "https" if port in HTTPS_PORTS else "http"
            logger.info(f"[CRED TEST] Scheduling web test for {ip}:{port}")
            tasks.append(test_web_credentials(ip, port, scheme))

    if not tasks:
        logger.debug(f"[CRED TEST] No matching services to test for host {ip}")
        return []

    logger.info(f"[CRED TEST] Starting credential tests for {ip} — {len(tasks)} services to test")
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    clean_results = []
    vulnerable_count = 0
    
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            logger.error(f"[CRED TEST] Test {i} failed with exception: {r}")
        elif isinstance(r, dict):
            clean_results.append(r)
            if r.get("vulnerable"):
                vulnerable_count += 1
                if r.get("credentials_found"):
                    for cred in r["credentials_found"]:
                        logger.info(f"[CRED TEST] {r['service']}:{r['port']} — VULNERABLE — {cred['username']}:{cred['password']} works")
                else:
                    logger.info(f"[CRED TEST] {r['service']}:{r['port']} — EXPOSURE FLAGGED")
            else:
                logger.info(f"[CRED TEST] {r['service']}:{r['port']} — {r.get('attempts_made', 0)} attempts, not vulnerable")
    
    logger.info(f"[CRED TEST] Completed for {ip} — {vulnerable_count} weak credential/exposure findings, results cached for 1h")
    return clean_results


# =============================================================================
# VULNERABILITY CONVERSION
# =============================================================================
def credential_results_to_vulnerabilities(host_id: str, cred_results: List[Dict]) -> List[Dict]:
    """
    Convert credential test results to Vulnerability database objects.
    
    Args:
        host_id: The database ID of the host
        cred_results: List of credential test result dictionaries
        
    Returns:
        List of vulnerability dictionaries ready for database insertion
    """
    vulns = []
    
    for result in cred_results:
        if not result.get("vulnerable"):
            continue
            
        service = result.get("service", "unknown")
        port = result.get("port", 0)
        
        # Handle exposure-only findings (RDP/VNC)
        if result.get("exposure_only"):
            vulns.append({
                "host_id": host_id,
                "template_id": f"exposure-{service}",
                "name": f"Service {service.upper()} exposé sur le port {port}",
                "severity": "medium",  # Exposure is medium severity
                "cve_id": None,
                "cvss_score": 5.0,
                "cvss_estimated": True,
                "matcher_name": f"{service}-exposure",
                "description": (
                    f"Le service {service.upper()} est exposé sur le port {port}. "
                    f"{result.get('reason', 'Cela peut présenter un risque de sécurité.')}"
                ),
                "source": "credential_test",
                "discovered_at": datetime.utcnow(),
            })
            continue
        
        # Handle actual credential findings
        for cred in result.get("credentials_found", []):
            username = cred.get("username", "")
            password = cred.get("password", "")
            
            # Custom naming and description for Web Interfaces
            if service == "web":
                name = f"Identifiants par défaut détectés sur l'interface Web (Port {port})"
                desc = (
                    f"L'interface web sur le port {port} accepte les identifiants par défaut "
                    f"'{username}/{password}'. Cela permet un accès non autorisé immédiat à l'interface d'administration."
                )
            else:
                name = f"Identifiants par défaut détectés sur {service.upper()}"
                desc = (
                    f"Le service {service.upper()} sur le port {port} "
                    f"accepte les identifiants par défaut '{username}/{password}'. "
                    f"Cela permet un accès non autorisé immédiat sans exploitation technique."
                )

            vulns.append({
                "host_id": host_id,
                "template_id": f"weak-cred-{service}",
                "name": name,
                "severity": "critical",  # Working default login is always critical
                "cve_id": None,
                "cvss_score": 9.8,
                "cvss_estimated": True,
                "matcher_name": f"{username}:{password}",
                "description": desc,
                "source": "credential_test",
                "discovered_at": datetime.utcnow(),
            })
    
    return vulns
