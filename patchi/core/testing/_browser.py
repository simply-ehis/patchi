"""
Shared Playwright helpers for Patchi's live testers.

This module replaces the copy-pasted, broken discovery logic that every UI
testing agent used to repeat:

  * discover pages by ``rglob('*.html')`` on disk and hit
    ``base_url/<file>.html`` -> 404s against a server-rendered SPA;
  * probe ports ``[3000, 5173, 8080, ...]`` but *not* Patchi's own
    ``p web`` default (1612) -> never finds the server;
  * ``goto(wait_until='domcontentloaded')`` -> screenshots of loading /
    unstyled pages;
  * never record HTTP status or console errors -> silent, low-value output.

The helpers here fix all of that and produce *linked*, viewable evidence.
"""

from __future__ import annotations

import json
import logging
import socket
from pathlib import Path

_log = logging.getLogger("patchi.testing.browser")

# Patchi's own server-rendered UI routes. Used as the default discovery set
# when no explicit route list is supplied via config / agent input.
DEFAULT_UI_ROUTES = [
    "/", "/brain", "/brain-map", "/council", "/findings", "/guard",
    "/assurance", "/live-tests", "/attack-timeline", "/history",
    "/review", "/self-improvement", "/settings", "/chat", "/tokens",
    "/hosted", "/charter", "/smart",
]

# Patchi's `p web` default is 1612; the rest are common dev-server ports.
WEB_PORTS = [1612, 3000, 5173, 8080, 4200, 8000, 4321, 5189]


def read_web_port(root: Path) -> int | None:
    """Read the configured `p web` port from .patchi/config.json."""
    cfg = root / ".patchi" / "config.json"
    if cfg.exists():
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
            port = (data.get("web") or {}).get("port")
            if isinstance(port, int):
                return port
        except Exception:  # pragma: no cover - corrupt config is non-fatal
            _log.warning("read_web_port: could not parse %s", cfg)
    return None


def find_server(root: Path, config: dict, extra: dict | None = None) -> str | None:
    """Return a base URL for a running dev server, or None.

    Resolution order: explicit ``base_url`` (extra/config) -> configured
    ``p web`` port -> common dev ports.
    """
    extra = extra or {}
    base = extra.get("base_url") or (config.get("test_config") or {}).get("base_url")
    if base:
        return base.rstrip("/")

    if extra.get("web_port"):
        return f"http://127.0.0.1:{extra['web_port']}"

    port = read_web_port(root)
    ports = [port] + WEB_PORTS if port else list(WEB_PORTS)
    for p in ports:
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=1):
                return f"http://127.0.0.1:{p}"
        except OSError:
            continue
    return None


def discover_routes(config: dict, extra: dict | None = None) -> list[str]:
    """Resolve the list of routes/URL paths to test."""
    extra = extra or {}
    if extra.get("routes"):
        return [r if r.startswith("/") else f"/{r}" for r in extra["routes"]]
    tc = config.get("test_config") or {}
    if tc.get("routes"):
        return [r if r.startswith("/") else f"/{r}" for r in tc["routes"]]
    return list(DEFAULT_UI_ROUTES)


class PageSession:
    """Result of opening a URL: the page plus captured diagnostics."""

    __slots__ = ("page", "url", "status", "console_errors", "page_errors")

    def __init__(self, page, url, status, console_errors, page_errors):
        self.page = page
        self.url = url
        self.status = status  # HTTP status (0/-1 if unknown/failed)
        self.console_errors = console_errors
        self.page_errors = page_errors


def open_page(browser, url: str, timeout: int = 30000, viewport: dict | None = None) -> PageSession:
    """Open ``url`` with a real render wait and full error capture.

    Waits for ``load`` + a visible ``<body>`` + a short settle window so
    charts/websocket-driven UI have painted before we screenshot or assert.
    Console errors and uncaught page exceptions are captured for findings.
    """
    console_errors: list[str] = []
    page_errors: list[str] = []
    page = browser.new_page(viewport=viewport or {"width": 1440, "height": 900})
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: page_errors.append(str(e)))

    status = 0
    try:
        resp = page.goto(url, wait_until="load", timeout=timeout)
        status = resp.status if resp is not None else 0
        try:
            page.wait_for_selector("body", state="visible", timeout=10000)
        except Exception:
            pass
        page.wait_for_timeout(700)  # let client JS (charts, ws feed) settle
    except Exception as e:  # navigation/timeout -> still return session w/ status
        _log.warning("open_page failed for %s: %s", url, e)
        if status == 0:
            status = -1
    return PageSession(page, url, status, console_errors, page_errors)


def save_screenshot(page, evidence_dir: Path, name: str) -> Path | None:
    """Save a full-page screenshot; returns the path or None on failure."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    safe = (
        name.replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace(" ", "_")
    )
    path = evidence_dir / f"{safe}.png"
    try:
        page.screenshot(path=str(path), full_page=True)
        return path
    except Exception as e:  # pragma: no cover - screenshot infra failure
        _log.warning("save_screenshot failed for %s: %s", name, e)
        return None
