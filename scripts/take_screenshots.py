"""Run NetScope locally and capture reproducible synthetic-data screenshots."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from playwright.sync_api import Browser, Page, Playwright, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SCREENSHOT_DIR = ROOT / "docs" / "screenshots"
SYNTHETIC_DIR = ROOT / "samples" / "synthetic"
CAPTURES = (
    SYNTHETIC_DIR / "synthetic_normal_traffic.pcap",
    SYNTHETIC_DIR / "port_scan.pcap",
)
MAX_WAIT_SECONDS = 120
MAX_SCREENSHOT_BYTES = 500 * 1024


def free_port() -> int:
    """Reserve an ephemeral local port briefly and return its number."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(url: str) -> dict[str, Any] | list[Any]:
    """Fetch and decode a JSON API response."""
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read())


def upload_capture(base_url: str, path: Path) -> int:
    """Upload one local synthetic PCAP through the public multipart endpoint."""
    boundary = f"netscope-{uuid.uuid4().hex}"
    payload = path.read_bytes()
    body = b"".join((
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'.encode(),
        b"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n",
        payload,
        f"\r\n--{boundary}--\r\n".encode(),
    ))
    request = urllib.request.Request(
        f"{base_url}/api/sessions/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        session = json.loads(response.read())
    return int(session["id"])


def wait_for_processing(base_url: str, session_id: int) -> dict[str, Any]:
    """Poll the session endpoint until analysis completes or fails."""
    deadline = time.monotonic() + MAX_WAIT_SECONDS
    while time.monotonic() < deadline:
        session = request_json(f"{base_url}/api/sessions/{session_id}")
        if session["status"] == "completed":
            return session
        if session["status"] == "failed":
            raise RuntimeError(f"Processing failed for session {session_id}: {session}")
        time.sleep(0.25)
    raise TimeoutError(f"Session {session_id} did not finish within {MAX_WAIT_SECONDS} seconds")


def wait_until_ready(base_url: str) -> None:
    """Wait for the Uvicorn process to expose the sessions API."""
    deadline = time.monotonic() + MAX_WAIT_SECONDS
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            request_json(f"{base_url}/api/sessions")
            return
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(0.25)
    raise TimeoutError(f"NetScope server did not become ready: {last_error}")


def upload_and_wait(base_url: str) -> dict[str, int]:
    """Upload the synthetic normal and scan captures, waiting for each result."""
    for path in CAPTURES:
        if not path.is_file():
            raise FileNotFoundError(f"Required synthetic capture is missing: {path}")
    session_ids: dict[str, int] = {}
    for path in CAPTURES:
        session_id = upload_capture(base_url, path)
        wait_for_processing(base_url, session_id)
        session_ids[path.name] = session_id
    return session_ids


def select_session(page: Page, filename: str) -> None:
    """Select one uploaded session and wait for its dashboard to render."""
    session_button = page.locator("button.session-item").filter(has_text=filename)
    session_button.wait_for(state="visible", timeout=15_000)
    session_button.click()
    page.locator("#page-loading").wait_for(state="hidden", timeout=MAX_WAIT_SECONDS * 1000)
    page.locator("#dashboard-content").wait_for(state="visible", timeout=15_000)
    page.locator(".alerts-panel").wait_for(state="visible", timeout=15_000)
    page.wait_for_timeout(1_000)


def verify_chart_library(page: Page) -> None:
    """Fail clearly if the CDN chart library did not load for screenshots."""
    page.wait_for_function("() => typeof window.Chart === 'function'", timeout=20_000)
    page.wait_for_timeout(500)


def save_screenshot(page: Page, path: Path, *, full_page: bool = False) -> None:
    """Save a PNG and enforce the documented per-file size limit."""
    path.parent.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(path), full_page=full_page, animations="disabled")
    size = path.stat().st_size
    if size >= MAX_SCREENSHOT_BYTES:
        raise RuntimeError(
            f"{path.relative_to(ROOT)} is {size / 1024:.0f} KB; each screenshot must be under 500 KB"
        )


def capture_images(browser: Browser, base_url: str) -> list[Path]:
    """Capture the desktop overview, dashboard panels, and mobile view."""
    page = browser.new_page(viewport={"width": 1440, "height": 1050}, device_scale_factor=1)
    page.goto(base_url, wait_until="networkidle", timeout=45_000)
    select_session(page, "synthetic_normal_traffic.pcap")
    verify_chart_library(page)

    normal_button = page.locator("button.session-item").filter(has_text="synthetic_normal_traffic.pcap")
    normal_session_id = normal_button.get_attribute("data-session-id")
    if normal_session_id is None:
        raise RuntimeError("Could not locate the mixed synthetic traffic session")
    normal_session = request_json(f"{base_url}/api/sessions/{normal_session_id}")
    protocols = request_json(
        f"{base_url}/api/sessions/{normal_session_id}/summary?bucket_size=1"
    )["protocol_distribution"]
    expected_protocols = {"TCP", "UDP", "DNS", "ICMP"}
    if not expected_protocols.issubset(protocols):
        raise RuntimeError(f"Synthetic overview is missing expected protocols: {protocols}")
    normal_alerts = request_json(f"{base_url}/api/sessions/{normal_session_id}/alerts")
    if normal_session["packet_count"] < 500 or normal_alerts:
        raise RuntimeError("Synthetic normal traffic must contain at least 500 packets and produce no alerts")

    overview = SCREENSHOT_DIR / "dashboard-overview.png"
    alerts = SCREENSHOT_DIR / "alerts-panel.png"
    charts = SCREENSHOT_DIR / "charts.png"
    document_height = page.evaluate("document.documentElement.scrollHeight")
    page.set_viewport_size({"width": 1440, "height": max(1050, document_height)})
    sidebar_height = page.evaluate("document.querySelector('.sidebar').getBoundingClientRect().height")
    if sidebar_height < document_height - 2:
        raise RuntimeError("Desktop sidebar does not fill the full overview screenshot height")
    save_screenshot(page, overview, full_page=True)

    select_session(page, "port_scan.pcap")
    port_scan_id = page.locator("button.session-item").filter(has_text="port_scan.pcap").get_attribute("data-session-id")
    if port_scan_id is None:
        raise RuntimeError("Could not locate the synthetic port-scan session")
    scan_alerts = request_json(f"{base_url}/api/sessions/{port_scan_id}/alerts")
    if not any(alert["rule"] == "port_scan" for alert in scan_alerts):
        raise RuntimeError("The synthetic port-scan session did not produce a port_scan alert")
    page.locator(".alerts-panel").screenshot(path=str(alerts), animations="disabled")
    page.locator(".chart-grid").screenshot(path=str(charts), animations="disabled")

    select_session(page, "synthetic_normal_traffic.pcap")
    page.set_viewport_size({"width": 390, "height": 844})
    page.wait_for_timeout(400)
    overflow = page.evaluate("""() => ({
      viewport: window.innerWidth,
      document: document.documentElement.scrollWidth,
      offenders: [...document.querySelectorAll('body *')]
        .map((el) => ({tag: el.tagName, className: String(el.className), right: el.getBoundingClientRect().right, width: el.getBoundingClientRect().width}))
        .filter((el) => el.right > window.innerWidth + 1)
        .slice(0, 8),
    })""")
    if overflow["document"] > overflow["viewport"]:
        raise RuntimeError(f"The mobile dashboard overflows horizontally at 390px: {overflow}")
    mobile = SCREENSHOT_DIR / "mobile.png"
    save_screenshot(page, mobile, full_page=True)

    page.close()
    generated = [overview, alerts, charts, mobile]
    for path in generated:
        size = path.stat().st_size
        if size >= MAX_SCREENSHOT_BYTES:
            raise RuntimeError(
                f"{path.relative_to(ROOT)} is {size / 1024:.0f} KB; each screenshot must be under 500 KB"
            )
    return generated


def start_server(port: int, database_path: Path, log_path: Path) -> subprocess.Popen[bytes]:
    """Start Uvicorn on localhost with a fresh temporary SQLite database."""
    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite:///{database_path.as_posix()}"
    environment["ENABLE_LIVE_CAPTURE"] = "false"
    with log_path.open("wb") as log_file:
        return subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT,
            env=environment,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )


def run(playwright: Playwright) -> list[Path]:
    """Run an isolated NetScope instance and create all requested screenshots."""
    subprocess.run(
        [sys.executable, "scripts/generate_sample_pcaps.py"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    with tempfile.TemporaryDirectory(prefix="netscope-screenshots-") as temp_dir:
        temporary_path = Path(temp_dir)
        port = free_port()
        base_url = f"http://127.0.0.1:{port}"
        log_path = temporary_path / "uvicorn.log"
        server = start_server(port, temporary_path / "netscope.sqlite3", log_path)
        try:
            wait_until_ready(base_url)
            upload_and_wait(base_url)
            browser = playwright.chromium.launch(headless=True)
            try:
                return capture_images(browser, base_url)
            finally:
                browser.close()
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            if server.returncode not in (0, -15, 1) and log_path.exists():
                print(log_path.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)


def main() -> int:
    """Create screenshots or print an actionable error and return nonzero."""
    try:
        with sync_playwright() as playwright:
            images = run(playwright)
        print("Generated screenshots:")
        for image in images:
            print(f"- {image.relative_to(ROOT)} ({image.stat().st_size / 1024:.1f} KB)")
        return 0
    except Exception as exc:
        print(f"Screenshot generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
