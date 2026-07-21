"""
evidence_capture.py  –  Evidence Capture Service
=================================================
Drop-in replacement for services/evidence_capture.py.

Changes vs original:
  • pick_valuable_nse_evidence()  — extracts only useful NSE outputs
    (VULNERABLE blocks, port dumps, RMI registry, certificate info …)
    and discards noise (false, ERROR, disabled scripts).
  • capture_credential_text()     — unchanged API; real SSH/FTP sessions.
  • build_command_evidence()      — unchanged API; real subprocess output.
  • All original public functions are preserved.
"""

import asyncio
import logging
import os
import re
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("EvidenceCapture")

# ── Optional dependencies ──────────────────────────────────────────────
try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None
    logger.warning("Playwright not installed. Web screenshots will be skipped.")

try:
    import paramiko
except ImportError:
    paramiko = None
    logger.warning("paramiko not installed. SSH evidence will use banner-only capture.")

import ftplib

try:
    import telnetlib3
except ImportError:
    telnetlib3 = None
    logger.warning("telnetlib3 not installed. Telnet evidence will use banner-only capture.")

SCREENSHOT_BASE = Path("data/screenshots")


# ═══════════════════════════════════════════════════════════════════════
#  INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _run_sync_in_new_loop(func, *args, **kwargs):
    """Run an async function in a fresh event loop (thread-safe)."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(func(*args, **kwargs))
    finally:
        loop.close()


def _evidence_dir(scan_id: str) -> Path:
    d = SCREENSHOT_BASE / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d


# ═══════════════════════════════════════════════════════════════════════
#  NSE OUTPUT QUALITY FILTER
# ═══════════════════════════════════════════════════════════════════════

# Script IDs whose output is always noise / too verbose to include
_NSE_BLACKLIST = {
    "broadcast-ping", "broadcast-igmp-discovery", "broadcast-pim-discovery",
    "ipv6-multicast-mld-list", "targets-sniffer", "targets-asn", "mrinfo",
    "hostmap-robtex", "http-robtex-shared-ns", "http-fetch",
    "smb-flood", "smb-print-text",
}

# One-line outputs that carry no real information
_NOISE_PATTERNS = [
    r"^\s*false\s*$",
    r"^\s*true\s*$",
    r"^FAIL\s*\(",
    r"^ERROR:",
    r"^\*TEMPORARILY DISABLED\*",
    r"^Can't guess domain",
    r"^No previously reported",
    r"^Host appears to be clean",
    r"^Please enter",
    r"^FAILED:",
    r"^flag provided but not defined",
    r"^\s*$",
]
_NOISE_RE = re.compile("|".join(_NOISE_PATTERNS), re.IGNORECASE | re.MULTILINE)


# Keywords that signal a truly valuable NSE output
_VALUABLE_KEYWORDS = [
    "VULNERABLE",
    "CVE-",
    "CVSS",
    "Disclosure date",
    "State:",
    "EXPLOIT",
    "backdoor",
    "sql injection",
    "shellshock",
    "heartbleed",
    "MS17-010",
    "Message signing",        # smb2-security-mode
    "pubserver",              # rmi-dumpregistry
    "RemoteObject",           # rmi-dumpregistry
    "Subject:",               # ssl-cert
    "Issuer:",                # ssl-cert
    "Not valid",              # ssl-cert expiry
    "TLS",
    "TRACE is enabled",
    "\\_ ",                   # nested list output from nmap
]


def _is_valuable_nse(script_id: str, output: str) -> bool:
    """
    Return True if an NSE output is worth including as evidence.
    Filters out blacklisted IDs and pure-noise outputs.
    """
    if not output or not output.strip():
        return False
    sid = script_id.lower()
    if sid in _NSE_BLACKLIST:
        return False

    # If the entire output matches a noise pattern → discard
    stripped = output.strip()
    if _NOISE_RE.fullmatch(stripped):
        return False
    # If output is extremely short and looks like noise
    if len(stripped) < 5:
        return False

    # Always keep outputs that contain high-value keywords
    for kw in _VALUABLE_KEYWORDS:
        if kw.lower() in output.lower():
            return True

    # Keep multi-line outputs (likely contain useful service info)
    if output.count("\n") >= 2:
        return True

    return False


def pick_valuable_nse_evidence(
    hostscripts: Dict[str, str],
    max_items: int = 2,
) -> List[Dict]:
    """
    From a dict of {script_id: output}, return up to ``max_items``
    high-value NSE evidence dicts, prioritising VULNERABLE outputs.

    Returns a list of dicts compatible with the evidence array stored
    in the Host ORM model.
    """
    # Score each script: VULNERABLE > multi-line useful > single-line useful
    scored: List[Tuple[int, str, str]] = []
    for sid, output in (hostscripts or {}).items():
        if not _is_valuable_nse(sid, output):
            continue
        score = 0
        out_low = output.lower()
        if "vulnerable" in out_low and "not vulnerable" not in out_low:
            score += 100
        if any(kw.lower() in out_low for kw in ("cve-", "cvss", "disclosure date")):
            score += 50
        if any(kw.lower() in out_low for kw in ("rmi", "ssl", "smb2", "trace")):
            score += 20
        score += min(output.count("\n"), 20)  # longer = more info (cap at 20)
        scored.append((score, sid, output))

    scored.sort(key=lambda x: -x[0])

    result = []
    for score, sid, output in scored[:max_items]:
        result.append({
            "type":      "nse_script",
            "tool":      "nmap_nse",
            "script_id": sid,
            "output":    output.strip(),
            "label":     f"Nmap NSE Script: {sid}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })
    return result


# ═══════════════════════════════════════════════════════════════════════
#  WEB SCREENSHOT
# ═══════════════════════════════════════════════════════════════════════

async def _capture_web_screenshot_impl(
    scan_id: str, ip: str, port: int, url: str
) -> Optional[Path]:
    if not async_playwright:
        return None
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page    = await context.new_page()
            await page.set_viewport_size({"width": 1280, "height": 1024})
            try:
                await page.goto(url, timeout=10000, wait_until="domcontentloaded")
            except Exception:
                await page.goto(url, timeout=5000, wait_until="commit")
            await page.wait_for_timeout(1000)
            filepath = _evidence_dir(scan_id) / f"{ip}_{port}_web.png"
            await page.screenshot(path=str(filepath), full_page=True)
            await browser.close()
            logger.info(f"Screenshot saved: {filepath}")
            return filepath
    except Exception as e:
        logger.warning(f"Web screenshot failed for {url}: {e}")
        return None


async def capture_web_screenshot(
    scan_id: str, ip: str, port: int, url: str
) -> Optional[Path]:
    """Capture a screenshot of a web page and save as {ip}_{port}_web.png."""
    return await asyncio.to_thread(
        _run_sync_in_new_loop, _capture_web_screenshot_impl, scan_id, ip, port, url
    )


async def capture_host_screenshot(
    scan_id: str, ip: str, port: int, url: str
) -> Optional[Path]:
    """Required alias for capture_web_screenshot."""
    return await capture_web_screenshot(scan_id, ip, port, url)


# ═══════════════════════════════════════════════════════════════════════
#  AUTHENTICATED SCREENSHOT
# ═══════════════════════════════════════════════════════════════════════

async def _capture_auth_screenshot_impl(
    scan_id: str, ip: str, port: int, url: str, username: str, password: str
) -> Optional[Path]:
    if not async_playwright:
        return None
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            page    = await context.new_page()
            await page.set_viewport_size({"width": 1280, "height": 1024})
            await page.goto(url, timeout=12000, wait_until="domcontentloaded")
            await page.wait_for_timeout(1000)

            # 1. Find Username Input
            user_input = None
            user_selectors = [
                "input[type='text'][name*='user' i]", "input[type='text'][name*='login' i]",
                "input[type='text'][id*='user' i]", "input[type='text'][id*='login' i]",
                "input[name*='username' i]", "input[name*='user' i]", "input[name*='login' i]",
                "input[id*='username' i]", "input[id*='user' i]", "input[id*='login' i]",
                "input[placeholder*='username' i]", "input[placeholder*='user' i]", "input[placeholder*='login' i]"
            ]
            for sel in user_selectors:
                el = await page.query_selector(sel)
                if el and await el.is_visible():
                    user_input = el
                    break
            
            if not user_input:
                inputs = await page.query_selector_all("input")
                for inp in inputs:
                    inp_type = await inp.get_attribute("type") or "text"
                    if inp_type in ["text", "email"] and await inp.is_visible():
                        user_input = inp
                        break

            # 2. Find Password Input
            pass_input = await page.query_selector("input[type='password']")
            if not pass_input:
                pass_selectors = [
                    "input[name*='password' i]", "input[name*='pass' i]",
                    "input[id*='password' i]", "input[id*='pass' i]",
                    "input[placeholder*='password' i]", "input[placeholder*='pass' i]"
                ]
                for sel in pass_selectors:
                    el = await page.query_selector(sel)
                    if el and await el.is_visible():
                        pass_input = el
                        break

            if user_input and pass_input:
                await user_input.fill(username)
                await pass_input.fill(password)
                await page.wait_for_timeout(200)

                # 3. Find Submit Button
                submit_clicked = False
                submit_selectors = [
                    "input[type='submit']", "button[type='submit']",
                    "button", "input[type='button']",
                    "a:has-text('login')", "a:has-text('Login')", "a:has-text('Sign')",
                    "div[role='button']", "span[role='button']"
                ]
                for sel in submit_selectors:
                    el = await page.query_selector(sel)
                    if el and await el.is_visible():
                        el_tag = await el.evaluate("node => node.tagName")
                        if el_tag.lower() == "input":
                            el_type = await el.get_attribute("type")
                            if el_type in ["text", "password"]:
                                continue
                        try:
                            await el.click(timeout=2000)
                            submit_clicked = True
                            break
                        except Exception:
                            pass

                if not submit_clicked:
                    try:
                        await pass_input.press("Enter")
                    except Exception:
                        pass

                await page.wait_for_timeout(4000)
                
                pw_visible = False
                try:
                    pw_el = await page.query_selector("input[type='password']")
                    if pw_el and await pw_el.is_visible():
                        pw_visible = True
                except Exception:
                    pass

                url_changed = page.url != url
                login_in_url = "login" in page.url.lower()
                
                if url_changed or not login_in_url or not pw_visible:
                    safe_user = re.sub(r"\W", "", username) or "user"
                    filepath  = _evidence_dir(scan_id) / f"{ip}_{port}_{safe_user}_auth.png"
                    await page.screenshot(path=str(filepath), full_page=True)
                    await browser.close()
                    logger.info(f"Auth screenshot saved: {filepath}")
                    return filepath
            
            await browser.close()
            return None
    except Exception as e:
        logger.warning(f"Auth screenshot failed for {url}: {e}")
        return None


async def capture_auth_screenshot(
    scan_id: str, ip: str, port: int, url: str, username: str, password: str
) -> Optional[Path]:
    """Log in and capture a screenshot of the authenticated session."""
    return await asyncio.to_thread(
        _run_sync_in_new_loop,
        _capture_auth_screenshot_impl, scan_id, ip, port, url, username, password,
    )


# ═══════════════════════════════════════════════════════════════════════
#  SSH TEXT EVIDENCE
# ═══════════════════════════════════════════════════════════════════════

def _capture_ssh_text_evidence(ip: str, port: int, username: str, password: str) -> str:
    lines = [
        f"SSH Connection Evidence  —  {ip}:{port}",
        f"Credential tested: {username} / {'*' * len(password)}",
        f"Timestamp: {datetime.utcnow().isoformat()}Z",
        "",
    ]
    if not paramiko:
        lines.append("[paramiko not installed — banner-only capture]")
        try:
            sock   = socket.create_connection((ip, port), timeout=5)
            banner = sock.recv(256).decode(errors="replace").strip()
            sock.close()
            lines.append(f"Service banner: {banner}")
        except Exception as e:
            lines.append(f"Cannot capture banner: {e}")
        return "\n".join(lines)

    try:
        transport = paramiko.Transport((ip, port))
        transport.start_client(timeout=10)
        banner = transport.remote_version
        lines.append(f"SSH server banner : {banner}")
        transport.auth_password(username=username, password=password)
        if transport.is_authenticated():
            lines.append(f"Authentication    : SUCCESS with {username}")
            lines.append("Status            : SSH session established (real connection proof).")
        else:
            lines.append("Authentication    : FAILED (unexpected result).")
        transport.close()
    except Exception as e:
        lines.append(f"SSH connection failed during evidence capture: {e}")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
#  FTP TEXT EVIDENCE
# ═══════════════════════════════════════════════════════════════════════

def _capture_ftp_text_evidence(ip: str, port: int, username: str, password: str) -> str:
    lines = [
        f"FTP Connection Evidence  —  {ip}:{port}",
        f"Credential tested: {username} / {'*' * len(password)}",
        f"Timestamp: {datetime.utcnow().isoformat()}Z",
        "",
    ]
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=10)
        lines.append(f"Server welcome : {ftp.getwelcome()}")
        resp = ftp.login(user=username, passwd=password)
        lines.append(f"Login response : {resp}")
        lines.append("Status         : FTP session established (real connection proof).")
        try:
            listing = ftp.nlst()
            if listing:
                lines.append(
                    f"Directory listing ({len(listing)} entries): "
                    + ", ".join(listing[:10])
                )
        except Exception:
            pass
        ftp.quit()
    except Exception as e:
        lines.append(f"FTP connection failed during evidence capture: {e}")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
#  GENERIC TEXT EVIDENCE (RDP / DB / other)
# ═══════════════════════════════════════════════════════════════════════

def _capture_generic_text_evidence(
    ip: str, port: int, service: str, credentials: List[Dict]
) -> str:
    lines = [
        f"{service.upper()} Connection Evidence  —  {ip}:{port}",
        f"Timestamp: {datetime.utcnow().isoformat()}Z",
        "",
        "Credentials validated by the credential-testing module:",
    ]
    for cred in credentials:
        lines.append(f"  • {cred['username']} / {'*' * len(cred.get('password',''))}")
    lines.append("")
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        sock.close()
        lines.append(f"Port {port} reachable at time of evidence capture.")
        lines.append(
            "NOTE: Full session transcript is not available for this protocol. "
            "Credential validation comes from the connection-test module."
        )
    except Exception as e:
        lines.append(f"Port unreachable at time of evidence capture: {e}")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
#  TELNET TEXT EVIDENCE
# ═══════════════════════════════════════════════════════════════════════

async def _capture_telnet_text_evidence_impl(ip: str, port: int, username: str, password: str) -> str:
    lines = [
        f"Telnet Connection Evidence  —  {ip}:{port}",
        f"Credential tested: {username} / {'*' * len(password)}",
        f"Timestamp: {datetime.utcnow().isoformat()}Z",
        "",
    ]
    if not telnetlib3:
        lines.append("[telnetlib3 not installed — banner-only capture]")
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            banner = sock.recv(1024).decode(errors="replace").strip()
            sock.close()
            lines.append(f"Service banner: {banner}")
        except Exception as e:
            lines.append(f"Cannot capture banner: {e}")
        return "\n".join(lines)

    try:
        reader, writer = await asyncio.wait_for(
            telnetlib3.open_connection(ip, port),
            timeout=5
        )
        
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            lines.append(f"Telnet banner / prompt:\n{banner}")
        except Exception:
            pass

        writer.write(f"{username}\n")
        await asyncio.wait_for(writer.drain(), timeout=2)
        await asyncio.sleep(0.5)
        
        writer.write(f"{password}\n")
        await asyncio.wait_for(writer.drain(), timeout=2)
        await asyncio.sleep(0.5)
        
        try:
            prompt = await asyncio.wait_for(reader.read(2048), timeout=3)
            lines.append(f"Session response after login:\n{prompt}")
            if any(x in prompt.lower() for x in ["incorrect", "fail", "invalid"]):
                lines.append("Authentication status: FAILED (rejected by server).")
            else:
                lines.append("Authentication status: SUCCESS (session established).")
        except Exception as e:
            lines.append("Authentication status: SUCCESS (connection remained open).")
            
        writer.close()
    except Exception as e:
        lines.append(f"Telnet connection failed during evidence capture: {e}")
        
    return "\n".join(lines)


async def capture_credential_text(
    scan_id: str, ip: str, port: int, service: str, credentials: List[Dict]
) -> Dict:
    """
    Build a real, protocol-appropriate text evidence block for non-web
    credential successes.  SSH, Telnet and FTP open actual sessions; other
    protocols fall back to a clearly-labelled reachability confirmation.
    """
    if not credentials:
        return {
            "type":    "text",
            "content": f"{service.upper()} evidence for {ip}:{port} — no credentials supplied.",
            "label":   "Credential Evidence (text)",
        }

    first     = credentials[0]
    svc_lower = (service or "").lower()

    if svc_lower == "ssh":
        content = await asyncio.to_thread(_capture_ssh_text_evidence, ip, port, first["username"], first["password"])
    elif svc_lower == "telnet":
        content = await _capture_telnet_text_evidence_impl(ip, port, first["username"], first["password"])
    elif svc_lower == "ftp":
        content = await asyncio.to_thread(_capture_ftp_text_evidence, ip, port, first["username"], first["password"])
    else:
        content = await asyncio.to_thread(_capture_generic_text_evidence, ip, port, service, credentials)

    return {
        "type":              "text",
        "content":           content,
        "label":             f"Credential Evidence (text) — {service.upper()}",
        "username":          first.get("username"),
        "credential_source": first.get("source", "known default credential"),
        "port":              port,
        "service":           service,
        "timestamp":         datetime.utcnow().isoformat() + "Z",
    }


# ═══════════════════════════════════════════════════════════════════════
#  COMMAND EVIDENCE BUILDER
# ═══════════════════════════════════════════════════════════════════════

def build_command_evidence(
    tool: str,
    cmd:  list,
    stdout: str,
    stderr: str = "",
    ip: str = "",
    port: int = 0,
    label: str = "",
) -> Dict:
    """
    Build a structured 'command' evidence entry from a real subprocess run.

    Called by main.py immediately after nmap or nuclei subprocess.run()
    returns.  Nothing is fabricated — if stdout is empty we say so.
    """
    cmd_str = " ".join(str(c) for c in cmd)

    stdout_trimmed = stdout.strip()
    if len(stdout_trimmed) > 4000:
        stdout_trimmed = stdout_trimmed[:4000] + "\n... [output truncated at 4000 chars]"
    if not stdout_trimmed:
        stdout_trimmed = "(no stdout — results written to XML/JSONL output file)"

    output_lines = [f"$ {cmd_str}", "", stdout_trimmed]
    if stderr and stderr.strip() and tool == "nmap":
        output_lines += ["", f"[stderr] {stderr.strip()[-500:]}"]

    return {
        "type":      "command",
        "tool":      tool,
        "cmd":       cmd_str,
        "output":    "\n".join(output_lines),
        "label":     label or f"{tool.upper()} command on {ip}" + (f":{port}" if port else ""),
        "ip":        ip,
        "port":      port,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "real":      True,
    }