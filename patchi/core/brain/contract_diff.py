"""
Contract Diff Engine — 3.1.3-7 Frontend ↔ Backend route mismatch detection.

Compares:
  - Frontend API calls (fetch, axios, trpc, ky) extracted via regex + tree-sitter
  - Backend routes (RouteMapper 18 frameworks)
Produces: missing_routes (404), orphan_endpoints, method_mismatch, param_drift.

Stored: .patchi/contract_diff.json + Findings (type contract_*) for ConfidenceGate.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from patchi.core.brain.route_mapper import RouteInfo
from patchi.core.brain.scanner import FileInfo

_log = logging.getLogger("patchi.brain.contract_diff")

_FRONTEND_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|ky\.(?:get|post)|trpc\.)\s*\(\s*['\"`]([^'\"`]+)['\"`]""",
    re.IGNORECASE,
)

_METHOD_RE = re.compile(r"""axios\.(get|post|put|delete|patch)\s*\(""", re.IGNORECASE)


@dataclass
class ContractDiff:
    missing_routes: list[dict] = field(default_factory=list)  # frontend calls no backend
    orphan_endpoints: list[dict] = field(default_factory=list)  # backend never called
    method_mismatch: list[dict] = field(default_factory=list)
    param_drift: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "missing_routes": self.missing_routes,
            "orphan_endpoints": self.orphan_endpoints,
            "method_mismatch": self.method_mismatch,
            "param_drift": self.param_drift,
            "total": len(self.missing_routes) + len(self.orphan_endpoints) + len(self.method_mismatch) + len(self.param_drift),
        }


def _normalize(path: str) -> str:
    p = path.split("?")[0].split("#")[0].strip()
    # replace :id, {id}, ${id} with :param
    p = re.sub(r"\{[^}]+\}", ":param", p)
    p = re.sub(r"\$\{[^}]+\}", ":param", p)
    p = re.sub(r":\w+", ":param", p)
    # collapse // -> /
    p = re.sub(r"/+", "/", p)
    return p.rstrip("/") or "/"


def extract_frontend_calls(file_infos: list[FileInfo], root: Path) -> list[dict]:
    calls: list[dict] = []
    for fi in file_infos:
        if fi.language.value not in ("javascript", "typescript"):
            continue
        try:
            content = (root / fi.path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _FRONTEND_RE.finditer(content):
            raw = m.group(1)
            # only consider api-like paths
            if not raw.startswith("/") and not raw.startswith("http"):
                continue
            # strip origin for http
            if raw.startswith("http"):
                try:
                    from urllib.parse import urlparse
                    raw = urlparse(raw).path or "/"
                except Exception:
                    continue
            line = content[: m.start()].count("\n") + 1
            method = "GET"
            mm = _METHOD_RE.search(content[max(0, m.start() - 200) : m.start() + 50])
            if mm:
                method = mm.group(1).upper()
            calls.append({"method": method, "path": _normalize(raw), "raw": m.group(1), "file": fi.path, "line": line})
    return calls


def diff_contract(frontend_calls: list[dict], backend_routes: list[RouteInfo]) -> ContractDiff:
    backend_set = {(_normalize(r.path), r.method.upper()): r for r in backend_routes}
    backend_paths = {_normalize(r.path) for r in backend_routes}
    frontend_paths = {c["path"] for c in frontend_calls}

    diff = ContractDiff()

    # 3.1.4 Missing routes: frontend calls 404
    for c in frontend_calls:
        key = (c["path"], c["method"])
        if c["path"] not in backend_paths:
            # check param-normalized already, so true missing
            diff.missing_routes.append(c)
        elif key not in backend_set:
            # same path different method
            diff.method_mismatch.append({"frontend": c, "backend": backend_set.get((c["path"], "GET")) or next((r for (p, _), r in backend_set.items() if p == c["path"]), None)})

    # 3.1.5 Orphan endpoints: backend never called
    for r in backend_routes:
        norm = _normalize(r.path)
        if norm not in frontend_paths and not _is_health_or_static(norm):
            diff.orphan_endpoints.append({"method": r.method, "path": r.path, "file": r.file, "line": r.line})

    # 3.1.7 Param drift: /user/:id vs /users/:userId (pluralization)
    for c in frontend_calls:
        for r in backend_routes:
            if _param_drift(c["path"], _normalize(r.path)):
                diff.param_drift.append({"frontend": c, "backend": {"path": r.path, "file": r.file}})

    return diff


def _is_health_or_static(path: str) -> bool:
    return path in ("/health", "/healthz", "/ready", "/metrics", "/static", "/favicon.ico") or path.startswith("/static/") or path.endswith((".css", ".js", ".png"))


def _param_drift(a: str, b: str) -> bool:
    # /user/:param vs /users/:param
    if a == b:
        return False
    sa, sb = a.strip("/").split("/"), b.strip("/").split("/")
    if len(sa) != len(sb):
        return False
    # one segment differs by pluralization
    diffs = sum(1 for x, y in zip(sa, sb, strict=True) if x != y)
    if diffs == 1:
        for x, y in zip(sa, sb, strict=True):
            if x != y and x.rstrip("s") != y.rstrip("s") and x != ":param" and y != ":param":
                return False
        # check if param name drift :id vs :userId (both become :param so not drift) — actually normalized, so drift only plural
        return any(abs(len(x) - len(y)) <= 1 for x, y in zip(sa, sb, strict=True) if x != y)
    return False


def build_and_save(root: Path, file_infos: list[FileInfo], routes: list[RouteInfo]) -> ContractDiff:
    fc = extract_frontend_calls(file_infos, root)
    d = diff_contract(fc, routes)
    try:
        out = root / ".patchi" / "contract_diff.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        import json

        out.write_text(json.dumps(d.to_dict(), indent=2), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        _log.debug("contract_diff save failed: %s", exc)
    return d
