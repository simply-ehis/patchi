"""SPARouteInventoryAgent — extracts SPA route definitions and detects dead links.

Covers §3.3.1-2:
- Parse react-router (createBrowserRouter, <Route path=>)
- Parse vue-router (createRouter, routes: [])
- Parse SvelteKit (file-based /src/routes/)
- Parse Next.js (file-based /app/ or /pages/)
- Cross-ref link usages (<Link to=>, navigate()) against route inventory
"""

from __future__ import annotations

import re
from pathlib import Path

from ..brain.languages import DEFAULT_IGNORE_DIRS
from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

_ROUTE_PATTERNS = {
    "react-router": [
        re.compile(r"createBrowserRouter\s*\(\[([^\]]+)\]", re.DOTALL),
        re.compile(r"<Route\s+path=[\"']([^\"']+)[\"']"),
        re.compile(r"path:\s*[\"']([^\"']+)[\"']"),
    ],
    "vue-router": [
        re.compile(r"createRouter\s*\(\s*\{[^}]*routes\s*:\s*\[([^\]]+)\]", re.DOTALL),
        re.compile(r"path:\s*[\"']([^\"']+)[\"']"),
        re.compile(r"routes\s*:\s*\[([^\]]+)\]", re.DOTALL),
    ],
    "nextjs-pages": None,
    "nextjs-app": None,
    "sveltekit": None,
}

_LINK_PATTERNS = [
    re.compile(r"<Link\s+to=[\"']([^\"']+)[\"']"),
    re.compile(r"navigate\s*\(\s*[\"']([^\"']+)[\"']"),
    re.compile(r"router\.push\s*\(\s*[\"']([^\"']+)[\"']"),
    re.compile(r"href=[\"']([^\"']+)[\"']"),
]


import logging
_log = logging.getLogger("patchi.agents.spa_route_inventory")

def _extract_file_based_routes(root: Path, base_dir: str) -> list[str]:
    routes: list[str] = []
    routes_dir = root / base_dir
    if not routes_dir.exists():
        return routes
    for fp in sorted(routes_dir.rglob("*")):
        if fp.is_file() and fp.suffix in (".js", ".jsx", ".ts", ".tsx", ".svelte", ".vue"):
            rel = fp.relative_to(root).as_posix()
            route = rel.replace(base_dir + "/", "/").replace("\\", "/")
            route = route.replace("/index.", "/").replace("/page.", "/")
            route = route.replace("/(.)", "").replace("/[...", "/:").replace("/[", "/:").replace("]", "")
            route = re.sub(r"\.[a-z]+$", "", route)
            if route not in ("", "/"):
                routes.append(route)
        if fp.name.startswith("+page.svelte") or fp.name.startswith("page.tsx") or fp.name.startswith("page.jsx"):
            rel = fp.relative_to(root).as_posix()
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            route = "/" + parent.replace(base_dir + "/", "")
            routes.append(route)
    return sorted(set(routes))


def _find_links(content: str) -> list[str]:
    links: list[str] = []
    for pat in _LINK_PATTERNS:
        for m in pat.finditer(content):
            link = m.group(1)
            if link and not link.startswith(("http", "#", "mailto:", "tel:")):
                links.append(link)
    return links


@register
class SPARouteInventoryAgent(BaseAgent):
    """Extracts SPA routes and detects dead links across frameworks."""

    group = AgentGroup.SCANNER
    name = "SPARouteInventoryAgent"
    description = "Parse react-router, vue-router, SvelteKit, Next.js routes; detect dead links"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        routes: list[str] = []
        dead_links: list[dict] = []
        files_scanned = 0

        has_router = False
        for ext in (".js", ".jsx", ".ts", ".tsx"):
            for fp in safe_rglob(inp.root, f"*{ext}"):
                rel = fp.relative_to(inp.root).as_posix()
                if any(seg in DEFAULT_IGNORE_DIRS for seg in Path(rel).parts):
                    continue
                files_scanned += 1
                try:
                    content = fp.read_text(encoding="utf-8")
                except Exception as e:
                    _log.warning("SPARouteInventoryAgent._run failed: %s", e)
                    continue

                for framework, patterns in _ROUTE_PATTERNS.items():
                    if patterns is None:
                        continue
                    for pat in patterns:
                        for m in pat.finditer(content):
                            has_router = True
                            route = m.group(1).strip().strip("'\"")
                            if route not in routes:
                                routes.append(route)

        # File-based routing
        for base in ("src/routes", "app", "pages"):
            file_routes = _extract_file_based_routes(inp.root, base)
            if file_routes:
                has_router = True
                routes.extend(file_routes)

        routes = sorted(set(routes))

        if not has_router:
            result.findings.append(
                make_finding(
                    self.name,
                    "no_router_detected",
                    Severity.INFO,
                    "",
                    "No SPA router or file-based routing detected",
                )
            )
            result.data["routes"] = []
            result.data["dead_links"] = []
            result.status = AgentStatus.DONE
            return

        # Collect all <Link to=> usages and check against routes
        for ext in (".js", ".jsx", ".ts", ".tsx", ".svelte", ".vue", ".html"):
            for fp in safe_rglob(inp.root, f"*{ext}"):
                rel = fp.relative_to(inp.root).as_posix()
                if any(seg in DEFAULT_IGNORE_DIRS for seg in Path(rel).parts):
                    continue
                try:
                    content = fp.read_text(encoding="utf-8")
                except Exception as e:
                    _log.warning("SPARouteInventoryAgent._run failed: %s", e)
                    continue
                for link in _find_links(content):
                    if link not in routes and not any(
                        route.startswith(link.rstrip("/")) for route in routes
                    ):
                        dead_links.append({"file": rel, "link": link})

        result.data["routes"] = routes
        result.data["dead_links"] = dead_links
        result.data["total_routes"] = len(routes)
        result.data["total_dead_links"] = len(dead_links)

        for r in routes[:50]:
            result.findings.append(
                make_finding(
                    self.name,
                    "spa_route",
                    Severity.INFO,
                    "",
                    f"SPA route: {r}",
                )
            )

        for dl in dead_links:
            result.findings.append(
                make_finding(
                    self.name,
                    "dead_link",
                    Severity.MEDIUM,
                    dl["file"],
                    f"Dead link: {dl['link']} — no matching route found",
                )
            )

        result.files_scanned = files_scanned
        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE
