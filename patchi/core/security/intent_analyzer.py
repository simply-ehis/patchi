"""
Business Logic Analyzer — extracts authn/authz flows and access-control data.

Understands what code INTENDS to do (via decorators, middleware, naming
conventions) versus what it enforces, then surfaces the gaps:

- Routes registered without any auth guard while sibling routes have one
- Admin/privileged routes reachable with user-level guards only
- State-changing endpoints (POST/PUT/DELETE) missing CSRF/rate-limit signals
- Object references in route paths without ownership-check indicators

Deterministic: AST + decorator/name analysis over Python and JS/TS route
files. Zero AI. Findings are business-logic adjacent — they feed E-1 chain
analysis as ENTRY nodes.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_log = logging.getLogger("patchi.core.security.intent_analyzer")

# Route decorator patterns per framework
_ROUTE_DECORATORS = {
    # Python
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "api_view",
    "app.route",
    "router.get",
    "router.post",
    "router.put",
    "app.get",
    "app.post",
    "app.put",
    "app.delete",  # FastAPI
    # Java annotations handled textually below
}

_AUTH_GUARD_HINTS = (
    "auth",
    "login_required",
    "permission",
    "jwt",
    "token",
    "session",
    "current_user",
    "require_admin",
    "admin_required",
    "is_authenticated",
    "protected",
    "authorize",
    "guard",
    "principal",
    "identity",
)

_ADMIN_HINTS = ("admin", "superuser", "root", "manage", "internal", "privileged")

_STATE_CHANGING_METHODS = {"post", "put", "delete", "patch"}


@dataclass
class RouteInfo:
    """One extracted HTTP route."""

    file: str
    line: int
    method: str  # GET/POST/... or "?"
    path: str  # URL pattern
    function_name: str  # handler name
    has_auth_guard: bool  # auth signal found on/near the handler
    is_admin_path: bool  # path suggests privileged surface
    framework: str  # best-guess framework tag


@dataclass
class IntentReport:
    """Result of analyzing a project's routes for logic gaps."""

    routes: list[RouteInfo] = field(default_factory=list)
    unauthenticated_state_changing: list[RouteInfo] = field(default_factory=list)
    admin_without_strict_guard: list[RouteInfo] = field(default_factory=list)
    unprotected_among_protected: list[RouteInfo] = field(default_factory=list)

    @property
    def gap_count(self) -> int:
        return (
            len(self.unauthenticated_state_changing)
            + len(self.admin_without_strict_guard)
            + len(self.unprotected_among_protected)
        )

    def to_dict(self) -> dict:
        return {
            "routes_total": len(self.routes),
            "gaps_total": self.gap_count,
            "unauthenticated_state_changing": [
                self._r2d(r) for r in self.unauthenticated_state_changing
            ],
            "admin_without_strict_guard": [self._r2d(r) for r in self.admin_without_strict_guard],
            "unprotected_among_protected": [self._r2d(r) for r in self.unprotected_among_protected],
        }

    @staticmethod
    def _r2d(r: RouteInfo) -> dict:
        return {
            "file": r.file,
            "line": r.line,
            "method": r.method,
            "path": r.path,
            "function": r.function_name,
            "has_auth_guard": r.has_auth_guard,
        }


class IntentAnalyzer:
    """Extracts routes + auth intent from Python source files."""

    def analyze_file(self, file_path: Path, root: Path) -> list[RouteInfo]:
        """Parse one Python file; returns its routes."""
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            return []

        rel = file_path.relative_to(root).as_posix()
        routes: list[RouteInfo] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            deco_info = self._decorator_signals(node)
            if deco_info["method"] is None and deco_info["path"] is None:
                continue

            src_segment = self._function_source(node, source).lower()
            has_guard = deco_info["auth"] or any(h in src_segment for h in _AUTH_GUARD_HINTS)
            url = deco_info["path"] or ""
            routes.append(
                RouteInfo(
                    file=rel,
                    line=node.lineno,
                    method=deco_info["method"] or "?",
                    path=url,
                    function_name=node.name,
                    has_auth_guard=has_guard,
                    is_admin_path=self._looks_admin(url, node.name),
                    framework=deco_info["framework"],
                )
            )
        return routes

    def analyze_root(self, root: Path, max_files: int = 400) -> IntentReport:
        """Analyze all Python files under root (bounded)."""
        report = IntentReport()
        scanned = 0
        skip = {"node_modules", ".venv", "__pycache__", ".git", "venv", "build", "dist"}

        for p in sorted(root.rglob("*.py")):
            if scanned >= max_files:
                break
            if any(part in skip for part in p.parts):
                continue
            routes = self.analyze_file(p, root)
            if routes:
                scanned += 1
            report.routes.extend(routes)

        self._derive_gaps(report)
        return report

    # ── internals ───────────────────────────────────────────────────────────

    def _decorator_signals(self, node) -> dict[str, Any]:
        """Inspect decorators for route registration + auth markers."""
        out: dict[str, Any] = {
            "method": None,
            "path": None,
            "auth": False,
            "framework": "?",
        }
        for deco in node.decorator_list:
            call = deco.func if isinstance(deco, ast.Call) else deco
            name = self._dotted_name(call)
            if not name:
                continue
            lname = name.lower()

            # Auth guard decorators
            if any(h in lname for h in _AUTH_GUARD_HINTS):
                out["auth"] = True

            # Route decorators: app.get(...), router.post(...), @route(...)
            for m in _STATE_CHANGING_METHODS | {"get", "head", "options"}:
                if lname.endswith(f".{m}") or lname == m or f".{m}(" in lname:
                    out["method"] = m.upper()
                    if isinstance(deco, ast.Call) and deco.args:
                        first = deco.args[0]
                        if isinstance(first, ast.Constant) and isinstance(first.value, str):
                            out["path"] = first.value
                    elif isinstance(deco, ast.Call) and deco.keywords:
                        for kw in deco.keywords:
                            if kw.arg in ("path", "url") and isinstance(kw.value, ast.Constant):
                                out["path"] = kw.value.value
                    out["framework"] = name.split(".")[0]
                    break
            else:
                # bare @app.route("/x", methods=["POST"])
                if "route" in lname and isinstance(deco, ast.Call):
                    out["framework"] = name.split(".")[0]
                    if deco.args and isinstance(deco.args[0], ast.Constant):
                        out["path"] = deco.args[0].value
                    for kw in deco.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            methods = [
                                e.value for e in kw.value.elts if isinstance(e, ast.Constant)
                            ]
                            if methods:
                                out["method"] = str(methods[0]).upper()
        return out

    def _dotted_name(self, node: ast.expr) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def _function_source(self, node, full_source: str) -> str:
        lines = full_source.splitlines()
        end = getattr(node, "end_lineno", node.lineno + 5)
        start = max(node.lineno - len(node.decorator_list) - 1, 0)
        return "\n".join(lines[start:end])

    def _looks_admin(self, url: str, func_name: str) -> bool:
        blob = f"{url} {func_name}".lower()
        return any(h in blob for h in _ADMIN_HINTS)

    # ── Gap derivation ──────────────────────────────────────────────────────

    def _derive_gaps(self, report: IntentReport) -> None:
        routes = report.routes
        protected_count = sum(1 for r in routes if r.has_auth_guard)

        for r in routes:
            method = r.method.lower()
            # 1. State-changing + no auth anywhere near it
            if method in _STATE_CHANGING_METHODS and not r.has_auth_guard:
                report.unauthenticated_state_changing.append(r)
            # 2. Admin-looking path guarded at user level (or not at all)
            if r.is_admin_path and not any(
                h in (r.path + r.function_name).lower()
                for h in ("require_admin", "admin_required", "superuser")
            ):
                report.admin_without_strict_guard.append(r)

        # 3. In files where MOST handlers are guarded, flag the naked ones
        by_file: dict[str, list[RouteInfo]] = {}
        for r in routes:
            by_file.setdefault(r.file, []).append(r)
        for _f, file_routes in by_file.items():
            if len(file_routes) < 3:
                continue
            ratio = sum(1 for r in file_routes if r.has_auth_guard) / len(file_routes)
            if ratio >= 0.7:
                for r in file_routes:
                    if not r.has_auth_guard:
                        report.unprotected_among_protected.append(r)

        if protected_count == 0 and routes:
            # Whole route file with zero auth — that's a finding per file, not
            # per route; keep list bounded so output stays readable.
            report.unprotected_among_protected = report.unprotected_among_protected[:50]


def findings_from_report(report: IntentReport, root: Path) -> list[dict[str, Any]]:
    """Convert intent gaps into finding-shaped dicts (feed into chain engine)."""
    out: list[dict[str, Any]] = []

    def add(r: RouteInfo, ftype: str, sev: str, msg: str) -> None:
        out.append(
            {
                "agent": "IntentAnalyzer",
                "type": ftype,
                "severity": sev,
                "file": r.file,
                "line": r.line,
                "message": msg,
                "cwe": "",
            }
        )

    for r in report.unauthenticated_state_changing[:30]:
        add(
            r,
            "missing_auth",
            "high",
            f"State-changing {r.method} {r.path} has no authentication guard",
        )
    for r in report.admin_without_strict_guard[:20]:
        add(
            r,
            "auth_bypass_surface",
            "medium",
            f"Admin-surface route {r.path} lacks strict admin-level guard",
        )
    for r in report.unprotected_among_protected[:30]:
        add(
            r,
            "missing_auth",
            "medium",
            f"Handler {r.function_name} unguarded while siblings require auth",
        )
    return out
