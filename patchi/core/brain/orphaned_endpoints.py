"""
Orphaned Endpoint Detection (§3.1.5).

Finds:
- Backend routes never called from frontend code ("orphaned endpoints")
- Frontend HTTP calls that don't match any backend route ("dead calls")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from patchi.core.agents.base import Finding, Severity, safe_rglob
from patchi.core.brain.framework import StackInfo
from patchi.core.brain.route_mapper import RouteInfo, RouteMapper
from patchi.core.brain.scanner import FileScanner

# ── Frontend HTTP call patterns ─────────────────────────────────────────────

# Fetch / Axios / Ky / plain XHR / jQuery / Apollo / urql / TanStack Query etc.
_FRONTEND_PATTERNS: list[re.Pattern] = [
    # fetch('/path') or fetch(`/path`)
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]"""),
    # axios.get/post/put/delete/patch('/path')
    re.compile(r"""axios\.(?:get|post|put|delete|patch|head|options)\s*\(\s*['"`]([^'"`]+)['"`]"""),
    # $.get/post/ajax('/path')
    re.compile(r"""\$\s*\.\s*(?:get|post|ajax|getJSON)\s*\(\s*['"`]([^'"`]+)['"`]"""),
    # ky.get/post('/path')
    re.compile(r"""ky\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]"""),
    # new XMLHttpRequest() with .open('GET', '/path')
    re.compile(r"""\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"`]\s*,\s*['"`]([^'"`]+)['"`]"""),
    # urql / graphql-request — useQuery/useMutation with string URL
    re.compile(r"""(?:useQuery|useMutation|client\.query|client\.mutation)\s*\(.*?['"`]([^'"`]+\/api\/[^'"`]+)['"`]"""),
    # TanStack / React Query — queryKey or url in object
    re.compile(r"""url\s*:\s*['"`]([^'"`]+)['"`]"""),
    # app Router server action imports
    re.compile(r"""['"`]([^'"`]*\/api\/[^'"`]+)['"`]"""),
]

# File extensions to scan for frontend calls
_FRONTEND_EXTENSIONS = (
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".vue",
    ".svelte",
    ".html",
    ".htm",
    ".ejs",
    ".hbs",
    ".njk",
)


_log = logging.getLogger("patchi.brain.orphaned_endpoints")


@dataclass
class FrontendCall:
    """An HTTP call detected in frontend code."""

    url: str
    file: str
    line: int
    raw: str


def _normalize_path(path: str) -> str:
    """Normalize a URL path for comparison.

    - Strips query strings and fragments
    - Replaces concrete values in path segments (e.g. /users/42 → /users/:id)
    - Removes trailing slashes
    """
    # Strip query string and fragment
    path = path.split("?")[0].split("#")[0]
    # Remove leading ./ or relative prefixes
    path = re.sub(r"^\.\.?/", "", path)
    # Normalize path param patterns from various frameworks
    # Replace :id, {id}, [id] with :param
    path = re.sub(r":\w+", ":param", path)
    path = re.sub(r"\{\w+\}", ":param", path)
    path = re.sub(r"\[\w+\]", ":param", path)
    # Replace numeric segments with :param
    path = re.sub(r"/\d+(?:/|$)", "/:param", path)
    # Replace UUID-like segments with :param
    path = re.sub(r"/[0-9a-f]{8,}(?:/|$)", "/:param", path)
    # Remove trailing slash
    path = path.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return path


def _extract_method_from_context(line: str) -> str:
    """Try to guess HTTP method from surrounding code context."""
    method_map = {
        ".get(": "GET",
        ".post(": "POST",
        ".put(": "PUT",
        ".patch(": "PATCH",
        ".delete(": "DELETE",
        ".head(": "HEAD",
        ".options(": "OPTIONS",
    }
    for key, method in method_map.items():
        if key in line:
            return method
    return "GET"


def _deduplicate_calls(calls: list[FrontendCall]) -> list[FrontendCall]:
    """Remove duplicate (url, file) calls, keeping first occurrence."""
    seen: set[tuple[str, str]] = set()
    result: list[FrontendCall] = []
    for c in calls:
        key = (c.url, c.file)
        if key not in seen:
            seen.add(key)
            result.append(c)
    return result


def scan_frontend_calls(root: Path) -> list[FrontendCall]:
    """Scan frontend source files for HTTP API calls."""
    calls: list[FrontendCall] = []
    for ext in _FRONTEND_EXTENSIONS:
        for file_path in safe_rglob(root, f"*{ext}"):
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8")
            except Exception as e:
                _log.warning("scan_frontend_calls failed: %s", e)
                continue

            rel_path = file_path.relative_to(root).as_posix()
            lines = content.splitlines()

            for line_num, line in enumerate(lines, 1):
                for pattern in _FRONTEND_PATTERNS:
                    for match in pattern.finditer(line):
                        url = match.group(1)
                        # Skip non-relative URLs and external URLs
                        if url.startswith("http://") or url.startswith("https://"):
                            continue
                        if url.startswith("//"):
                            continue
                        if url.startswith("data:") or url.startswith("blob:"):
                            continue
                        # Skip template literal with complex expressions
                        if "${" in url and "}" not in url:
                            continue
                        calls.append(
                            FrontendCall(
                                url=url.strip(),
                                file=rel_path,
                                line=line_num,
                                raw=line.strip(),
                            )
                        )
    return _deduplicate_calls(calls)


@dataclass
class OrphanedEndpointResult:
    """Result of orphaned endpoint analysis."""

    orphaned_routes: list[RouteInfo] = field(default_factory=list)
    dead_calls: list[FrontendCall] = field(default_factory=list)
    total_backend_routes: int = 0
    total_frontend_calls: int = 0


def find_orphaned_endpoints(root: Path) -> OrphanedEndpointResult:
    """
    Compare backend routes against frontend HTTP calls.
    Returns orphaned (backend-defined but never frontend-called) routes
    and dead calls (frontend calls matching no backend route).
    """
    # --- Backend routes ---
    stack = StackInfo.detect(root)
    scanner = FileScanner(root)
    file_infos = scanner.scan()
    mapper = RouteMapper(root, stack)
    backend_routes = mapper.extract(file_infos)

    # --- Frontend calls ---
    frontend_calls = scan_frontend_calls(root)

    # --- Normalize for comparison ---
    backend_patterns: set[tuple[str, str]] = set()
    for route in backend_routes:
        norm = _normalize_path(route.path)
        backend_patterns.add((route.method.upper(), norm))

    # Also add ANY method as wildcard match for any method
    any_method_patterns = {norm for (_, norm) in backend_patterns}

    frontend_norms: set[tuple[str, str]] = set()
    frontend_call_map: dict[tuple[str, str], list[FrontendCall]] = {}
    for call in frontend_calls:
        method = _extract_method_from_context(call.raw)
        norm = _normalize_path(call.url)
        key = (method, norm)
        frontend_norms.add(key)
        if key not in frontend_call_map:
            frontend_call_map[key] = []
        frontend_call_map[key].append(call)

    # --- Orphaned routes: backend endpoint never matched by any frontend call ---
    orphaned: list[RouteInfo] = []
    for route in backend_routes:
        norm = _normalize_path(route.path)
        method = route.method.upper()
        if (method, norm) not in frontend_norms and norm not in any_method_patterns:
            # Check if any frontend call matches with different method
            matched = False
            for _front_method, front_norm in frontend_norms:
                if front_norm == norm:
                    matched = True
                    break
            if not matched:
                orphaned.append(route)

    # --- Dead calls: frontend call matching no backend route ---
    dead: list[FrontendCall] = []
    for call in frontend_calls:
        method = _extract_method_from_context(call.raw)
        norm = _normalize_path(call.url)
        norm.lstrip("/")
        # Check against all backend route norms
        matched = False
        for back_method, back_norm in backend_patterns:
            if back_norm == norm:
                if back_method == method or back_method == "ANY":
                    matched = True
                    break
            # Also check wildcard
            if back_norm == norm:
                matched = True
                break
        if not matched:
            # Check any-method patterns
            if norm in any_method_patterns:
                matched = True
        if not matched:
            dead.append(call)

    return OrphanedEndpointResult(
        orphaned_routes=orphaned,
        dead_calls=dead,
        total_backend_routes=len(backend_routes),
        total_frontend_calls=len(frontend_calls),
    )


def findings_from_orphaned_endpoints(result: OrphanedEndpointResult) -> list[Finding]:
    """Convert orphaned endpoint analysis into findings."""
    findings: list[Finding] = []

    for route in result.orphaned_routes:
        findings.append(
            Finding(
                agent="OrphanedEndpointDetector",
                type="orphaned_backend_route",
                severity=Severity.MEDIUM,
                file=route.file,
                line=route.line or 1,
                message=f"Orphaned backend route: {route.method} {route.path}",
                detail=(
                    f"Route `{route.method} {route.path}` is defined in {route.file}:{route.line} "
                    f"but no frontend code calls it. Consider removing or documenting this endpoint."
                ),
                suggestion=f"Remove unused endpoint {route.method} {route.path} or add frontend integration",
                extra={
                    "endpoint_method": route.method,
                    "endpoint_path": route.path,
                    "endpoint_handler": route.handler,
                    "endpoint_framework": route.framework,
                },
            )
        )

    for call in result.dead_calls:
        findings.append(
            Finding(
                agent="OrphanedEndpointDetector",
                type="dead_frontend_call",
                severity=Severity.LOW,
                file=call.file,
                line=call.line,
                message=f"Dead frontend call: {call.url}",
                detail=(
                    f"Frontend call to `{call.url}` in {call.file}:{call.line} "
                    f"does not match any defined backend route."
                ),
                suggestion=f"Verify the API endpoint `{call.url}` exists or update the frontend call",
                extra={
                    "call_url": call.url,
                    "call_raw": call.raw,
                },
            )
        )

    return findings
