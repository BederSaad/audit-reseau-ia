import asyncio
import os
import logging
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger("EvidenceCapture")

try:
    from playwright.async_api import async_playwright
except ImportError:
    logger.warning("Playwright not installed. Web screenshots will be skipped.")
    async_playwright = None

try:
    import paramiko
except ImportError:
    paramiko = None
    logger.warning("paramiko not installed. Real SSH evidence capture will fall back to banner-only.")

import ftplib

SCREENSHOT_BASE = Path("data/screenshots")


def _run_sync_in_new_loop(func, *args, **kwargs):
    """Helper to run an async function in a new event loop in a background thread."""
    if sys.platform == 'win32':
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


# =============================================================================
# WEB SCREENSHOT
# =============================================================================
async def _capture_web_screenshot_impl(scan_id: str, ip: str, port: int, url: str) -> Optional[Path]:
    if not async_playwright:
        return None
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1280, "height": 1024})
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


async def capture_web_screenshot(scan_id: str, ip: str, port: int, url: str) -> Optional[Path]:
    """Capture a screenshot of a web page and save as {host_ip}_{port}_web.png."""
    return await asyncio.to_thread(_run_sync_in_new_loop, _capture_web_screenshot_impl, scan_id, ip, port, url)


async def capture_host_screenshot(scan_id: str, ip: str, port: int, url: str) -> Optional[Path]:
    """Capture host screenshot (required alias)."""
    return await capture_web_screenshot(scan_id, ip, port, url)


# =============================================================================
# CREDENTIAL SUCCESS SCREENSHOT (web-based only)
# =============================================================================
async def _capture_auth_screenshot_impl(
    scan_id: str, ip: str, port: int, url: str, username: str, password: str
) -> Optional[Path]:
    if not async_playwright:
        return None
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1280, "height": 1024})
            await page.goto(url, timeout=10000, wait_until="domcontentloaded")
            form = await page.query_selector("form")
            if not form:
                form = await page.query_selector("form[action*='login']")
            if form:
                user_input = await page.query_selector(
                    "input[name='user'], input[name='username'], input[type='text']"
                )
                pass_input = await page.query_selector(
                    "input[name='pass'], input[name='password'], input[type='password']"
                )
                if user_input and pass_input:
                    await user_input.fill(username)
                    await pass_input.fill(password)
                    submit = await page.query_selector("input[type='submit'], button[type='submit']")
                    if submit:
                        await submit.click()
                        await page.wait_for_timeout(3000)
                        current_url = page.url
                        if current_url != url or "login" not in current_url.lower():
                            safe_user = "".join(c for c in username if c.isalnum()) or "user"
                            filepath = _evidence_dir(scan_id) / f"{ip}_{port}_{safe_user}_auth.png"
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
    """Attempt to log in and capture a screenshot after successful authentication."""
    return await asyncio.to_thread(
        _run_sync_in_new_loop, _capture_auth_screenshot_impl, scan_id, ip, port, url, username, password
    )


# =============================================================================
# REAL SSH EVIDENCE — uses paramiko to open an actual session
# =============================================================================
def _capture_ssh_text_evidence(ip: str, port: int, username: str, password: str) -> str:
    """Open a real SSH session with the validated credentials and capture the
    banner + auth confirmation. Requires paramiko."""
    lines = [f"Preuve de connexion - SSH sur {ip}:{port}", f"Identifiant testé : {username}"]
    if not paramiko:
        lines.append("[paramiko non installé — capture de bannière brute uniquement]")
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            banner = sock.recv(256).decode(errors="replace").strip()
            sock.close()
            lines.append(f"Bannière du service : {banner}")
        except Exception as e:
            lines.append(f"Impossible de capturer la bannière : {e}")
        return "\n".join(lines)

    try:
        transport = paramiko.Transport((ip, port))
        transport.start_client(timeout=10)
        banner = transport.remote_version
        lines.append(f"Bannière du serveur SSH : {banner}")
        transport.auth_password(username=username, password=password)
        if transport.is_authenticated():
            lines.append(f"Authentification réussie avec {username} / {'*' * len(password)}")
            lines.append("Statut : session SSH ouverte avec succès (preuve réelle de connexion).")
        else:
            lines.append("Authentification échouée lors de la vérification finale (résultat inattendu).")
        transport.close()
    except Exception as e:
        lines.append(f"Connexion SSH réelle échouée pendant la capture de preuve : {e}")
    return "\n".join(lines)


# =============================================================================
# REAL FTP EVIDENCE — uses ftplib to open an actual session
# =============================================================================
def _capture_ftp_text_evidence(ip: str, port: int, username: str, password: str) -> str:
    """Open a real FTP session with the validated credentials and capture the
    login response verbatim."""
    lines = [f"Preuve de connexion - FTP sur {ip}:{port}", f"Identifiant testé : {username}"]
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=10)
        welcome = ftp.getwelcome()
        lines.append(f"Message d'accueil du serveur : {welcome}")
        resp = ftp.login(user=username, passwd=password)
        lines.append(f"Réponse du serveur à l'authentification : {resp}")
        lines.append("Statut : connexion FTP réussie (preuve réelle de connexion).")
        try:
            listing = ftp.nlst()
            if listing:
                lines.append(f"Contenu visible après connexion ({len(listing)} entrées) : {', '.join(listing[:10])}")
        except Exception:
            pass
        ftp.quit()
    except Exception as e:
        lines.append(f"Connexion FTP réelle échouée pendant la capture de preuve : {e}")
    return "\n".join(lines)


# =============================================================================
# GENERIC TEXT EVIDENCE — for RDP/DB/other protocols
# =============================================================================
def _capture_generic_text_evidence(ip: str, port: int, service: str, credentials: List[Dict]) -> str:
    """Fallback for protocols without a native capture path.
    Explicitly states this is TCP reachability confirmation, not a full session transcript."""
    lines = [f"Preuve de connexion - {service.upper()} sur {ip}:{port}"]
    lines.append("Identifiants testés et validés par le module de test (voir résultats credential_testing) :")
    for cred in credentials:
        lines.append(f"  - {cred['username']} / {'*' * len(cred.get('password', ''))}")
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        sock.close()
        lines.append(f"Port {port} confirmé ouvert au moment de la capture de preuve ({datetime.utcnow().isoformat()}Z UTC).")
        lines.append(
            "Remarque : capture de session complète non encore implémentée pour ce protocole ; "
            "la validation des identifiants provient du module de test de connexion, pas d'une "
            "transcription de session ici."
        )
    except Exception as e:
        lines.append(f"Port injoignable au moment de la capture de preuve : {e}")
    return "\n".join(lines)


# =============================================================================
# MAIN ENTRY POINT — credential text evidence dispatcher
# =============================================================================
def capture_credential_text(scan_id: str, ip: str, port: int, service: str, credentials: List[Dict]) -> Dict:
    """Build a real, protocol-appropriate text evidence block for non-web
    credential successes. Uses the first validated credential pair to open
    an actual session where a native capture path exists (SSH, FTP); falls
    back to a clearly-labeled reachability confirmation otherwise."""
    if not credentials:
        content = f"Preuve de connexion - {service.upper()} sur {ip}:{port}\nAucun identifiant fourni pour la capture."
        return {"type": "text", "content": content, "label": "Preuve de Connexion (texte)"}

    first = credentials[0]
    svc_lower = (service or "").lower()

    if svc_lower == "ssh":
        content = _capture_ssh_text_evidence(ip, port, first["username"], first["password"])
    elif svc_lower == "ftp":
        content = _capture_ftp_text_evidence(ip, port, first["username"], first["password"])
    else:
        content = _capture_generic_text_evidence(ip, port, service, credentials)

    return {
        "type": "text",
        "content": content,
        "label": f"Preuve de Connexion (texte) - {service.upper()}",
        "username": first.get("username"),
        "credential_source": first.get("source", "identifiant par défaut connu"),
        "port": port,
        "service": service,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# =============================================================================
# COMMAND EVIDENCE BUILDER — called from main.py after nmap/nuclei runs
# =============================================================================
def build_command_evidence(
    tool: str,
    cmd: list,
    stdout: str,
    stderr: str = "",
    ip: str = "",
    port: int = 0,
    label: str = "",
) -> Dict:
    """
    Build a structured 'command' evidence entry from a real subprocess run.

    This is called by main.py immediately after nmap or nuclei subprocess.run()
    returns, storing the ACTUAL command executed and its ACTUAL stdout.
    Nothing is fabricated — if stdout is empty we say so explicitly.

    Args:
        tool:   "nmap" | "nuclei"
        cmd:    The exact list passed to subprocess.run (e.g. [NMAP_PATH, "-Pn", ...])
        stdout: proc.stdout decoded — the real terminal output
        stderr: proc.stderr decoded — included if non-empty for debugging
        ip:     Target IP
        port:   Target port (0 for nmap host scans)
        label:  Human-readable label for the PDF evidence block
    """
    cmd_str = " ".join(str(c) for c in cmd)

    # Trim stdout to a reasonable length for the PDF but keep it complete enough to be useful
    stdout_trimmed = stdout.strip()
    if len(stdout_trimmed) > 4000:
        stdout_trimmed = stdout_trimmed[:4000] + "\n... [sortie tronquée à 4000 caractères]"

    if not stdout_trimmed:
        stdout_trimmed = "(aucune sortie stdout — les résultats ont été écrits dans le fichier XML/JSONL)"

    output_lines = [f"$ {cmd_str}", "", stdout_trimmed]

    if stderr and stderr.strip() and tool == "nmap":
        stderr_tail = stderr.strip()[-500:]
        output_lines += ["", f"[stderr] {stderr_tail}"]

    return {
        "type": "command",
        "tool": tool,
        "cmd": cmd_str,
        "output": "\n".join(output_lines),
        "label": label or f"Commande {tool.upper()} exécutée sur {ip}" + (f":{port}" if port else ""),
        "ip": ip,
        "port": port,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "real": True,  # explicit flag: this is NOT fabricated
    }