import asyncio
import os
import logging
import sys
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger("EvidenceCapture")

# Ensure Playwright is installed:
# pip install playwright && playwright install

try:
    from playwright.async_api import async_playwright
except ImportError:
    logger.warning("Playwright not installed. Web screenshots will be skipped.")
    async_playwright = None

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

async def _capture_web_screenshot_impl(scan_id: str, ip: str, port: int, url: str) -> Optional[Path]:
    """Internal implementation of web screenshot capture."""
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
            
            dir_path = SCREENSHOT_BASE / scan_id
            dir_path.mkdir(parents=True, exist_ok=True)
            filename = f"{ip}_web.png"
            filepath = dir_path / filename
            await page.screenshot(path=str(filepath), full_page=True)
            await browser.close()
            logger.info(f"Screenshot saved: {filepath}")
            return filepath
    except Exception as e:
        logger.warning(f"Web screenshot failed for {url}: {e}")
        return None

async def capture_web_screenshot(scan_id: str, ip: str, port: int, url: str) -> Optional[Path]:
    """Capture a screenshot of a web page and save as {host_ip}_web.png."""
    return await asyncio.to_thread(_run_sync_in_new_loop, _capture_web_screenshot_impl, scan_id, ip, port, url)

async def capture_host_screenshot(scan_id: str, ip: str, port: int, url: str) -> Optional[Path]:
    """Capture host screenshot (required alias)."""
    return await capture_web_screenshot(scan_id, ip, port, url)

async def _capture_auth_screenshot_impl(scan_id: str, ip: str, port: int, url: str, username: str, password: str) -> Optional[Path]:
    """Internal implementation of auth screenshot capture."""
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
                user_input = await page.query_selector("input[name='user'], input[name='username'], input[type='text']")
                pass_input = await page.query_selector("input[name='pass'], input[name='password'], input[type='password']")
                if user_input and pass_input:
                    await user_input.fill(username)
                    await pass_input.fill(password)
                    submit = await page.query_selector("input[type='submit'], button[type='submit']")
                    if submit:
                        await submit.click()
                        await page.wait_for_timeout(3000)
                        current_url = page.url
                        if current_url != url or "login" not in current_url.lower():
                            dir_path = SCREENSHOT_BASE / scan_id
                            dir_path.mkdir(parents=True, exist_ok=True)
                            filename = f"{ip}_auth.png"
                            filepath = dir_path / filename
                            await page.screenshot(path=str(filepath), full_page=True)
                            await browser.close()
                            logger.info(f"Auth screenshot saved: {filepath}")
                            return filepath
            await browser.close()
            return None
    except Exception as e:
        logger.warning(f"Auth screenshot failed for {url}: {e}")
        return None

async def capture_auth_screenshot(scan_id: str, ip: str, port: int, url: str, username: str, password: str) -> Optional[Path]:
    """Attempt to log in and capture a screenshot after successful authentication and save as {host_ip}_auth.png."""
    return await asyncio.to_thread(_run_sync_in_new_loop, _capture_auth_screenshot_impl, scan_id, ip, port, url, username, password)

def capture_credential_text(scan_id: str, ip: str, port: int, service: str, credentials: List[Dict]) -> Dict:
    """Format credential success evidence as text block for non-web services."""
    # Build a terminal-style block
    lines = [
        f"Preuve de connexion - {service.upper()} sur {ip}:{port}",
        f"Identifiants testés et validés :",
    ]
    for cred in credentials:
        lines.append(f"  - {cred['username']} / {cred['password']}")
    lines.append("Connexion réussie (sortie de session) :")
    lines.append("  (le service a accepté les identifiants et a ouvert une session)")
    return {
        "type": "text",
        "content": "\n".join(lines),
        "label": "Preuve de Connexion (texte)"
    }