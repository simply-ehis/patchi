"""Tier 2 knowledge documentation generator (code-derived, no AI).

Generates developer-facing knowledge docs from scan data:
  - API_SURFACE.md      — routes/methods/params from route_mapper
  - SECURITY_DOMAINS.md — findings grouped by agent, severity counts
  - MODULE_MAP.md       — scanned modules with purpose, size, deps
  - TEST_COVERAGE.md    — test file inventory, source ↔ test mapping

All output is pure Tier 1 rendering: no AI calls, just structured
enumeration from existing Brain data.

Usage::

    from patchi.core.brain.knowledge_doc_generator import generate_knowledge_docs

    docs = generate_knowledge_docs(project_root, scan_result)
    # docs == {"docs/API_SURFACE.md": "# API Surface\n...", ...}
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

_log = logging.getLogger(__name__)

_TODAY = time.strftime("%Y-%m-%d")


# ── Header helpers ────────────────────────────────────────────────────────────


def _greppable_header(
    purpose: str,
    owns: str,
    read_when: str,
    key_files: str,
    invariants: str,
    gotchas: str,
) -> list[str]:
    """Return the 7-line greppable header block (PURPOSE .. UPDATED)."""
    return [
        f"<!-- PURPOSE: {purpose} -->",
        f"<!-- OWNS: {owns} -->",
        f"<!-- READ-WHEN: {read_when} -->",
        f"<!-- KEY-FILES: {key_files} -->",
        f"<!-- INVARIANTS: {invariants} -->",
        f"<!-- GOTCHAS: {gotchas} -->",
        f"<!-- UPDATED: {_TODAY} -->",
        "",
    ]


# ── Public API ────────────────────────────────────────────────────────────────


def generate_knowledge_docs(
    project_root: Path,
    scan_result: dict[str, Any],
) -> dict[str, str]:
    """Generate Tier 2 knowledge docs from scan data.

    Parameters
    ----------
    project_root:
        Absolute path to the project root.
    scan_result:
        Dict produced by Brain.scan() (summary_dict) or a merged brain
        data dict.  Expected keys (all optional — missing keys produce
        empty sections):
          - ``routes``: list of RouteInfo or dicts
          - ``file_infos``: list of FileInfo or dicts
          - ``import_graph``: ImportGraph instance
          - ``security_findings``: list of Finding dicts (agent results)
          - ``scan_results``: dict of agent_name → result_dict (memory format)

    Returns
    -------
    dict[str, str]
        Mapping of relative file paths to Markdown content.  Keys are
        ``docs/API_SURFACE.md``, ``docs/SECURITY_DOMAINS.md``, etc.
    """
    docs: dict[str, str] = {}

    try:
        docs["docs/API_SURFACE.md"] = _build_api_surface(project_root, scan_result)
    except Exception as exc:
        _log.debug("API_SURFACE generation failed: %s", exc)
        docs["docs/API_SURFACE.md"] = _error_doc("API Surface", exc)

    try:
        docs["docs/SECURITY_DOMAINS.md"] = _build_security_domains(scan_result)
    except Exception as exc:
        _log.debug("SECURITY_DOMAINS generation failed: %s", exc)
        docs["docs/SECURITY_DOMAINS.md"] = _error_doc("Security Domains", exc)

    try:
        docs["docs/MODULE_MAP.md"] = _build_module_map(project_root, scan_result)
    except Exception as exc:
        _log.debug("MODULE_MAP generation failed: %s", exc)
        docs["docs/MODULE_MAP.md"] = _error_doc("Module Map", exc)

    try:
        docs["docs/TEST_COVERAGE.md"] = _build_test_coverage(project_root, scan_result)
    except Exception as exc:
        _log.debug("TEST_COVERAGE generation failed: %s", exc)
        docs["docs/TEST_COVERAGE.md"] = _error_doc("Test Coverage", exc)

    return docs


# ── API Surface ───────────────────────────────────────────────────────────────


def _build_api_surface(root: Path, data: dict) -> str:
    routes = _get_routes(data)
    header = _greppable_header(
        purpose="Complete API surface: all routes, methods, params, and handlers.",
        owns="docs/API_SURFACE.md",
        read_when="Adding endpoints, auditing auth coverage, writing integration tests.",
        key_files="docs/API_SURFACE.md",
        invariants="Every route from route_mapper appears exactly once. Auth column is Yes/No/?",
        gotchas="Routes detected by pattern matching — false positives possible on non-handler decorators.",
    )

    lines: list[str] = header
    lines.append("# API Surface")
    lines.append("")
    lines.append(f"_Generated {_TODAY} — {len(routes)} route(s) detected._")
    lines.append("")

    if not routes:
        lines.append("_No routes detected in this project._")
        lines.append("")
        return "\n".join(lines)

    # Group by method.
    by_method: dict[str, list[dict]] = defaultdict(list)
    for r in routes:
        method = _route_field(r, "method", "GET").upper()
        by_method[method].append(r)

    method_order = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

    # Summary table.
    lines.append("## Summary")
    lines.append("")
    lines.append("| Method | Count |")
    lines.append("|--------|-------|")
    for method in method_order:
        items = by_method.get(method, [])
        if items:
            lines.append(f"| {method} | {len(items)} |")
    lines.append("")

    # Detailed tables per method.
    lines.append("## Routes by Method")
    lines.append("")
    for method in method_order:
        items = by_method.get(method, [])
        if not items:
            continue
        lines.append(f"### {method}")
        lines.append("")
        lines.append("| Path | Handler | File | Auth | Framework |")
        lines.append("|------|---------|------|------|-----------|")
        for r in items:
            path = _route_field(r, "path", "/")
            handler = _route_field(r, "handler", "")
            file_ = _route_field(r, "file", "")
            auth_raw = _route_field(r, "auth_required", None)
            auth = "Yes" if auth_raw is True else ("No" if auth_raw is False else "?")
            fw = _route_field(r, "framework", "")
            lines.append(f"| `{path}` | `{handler}` | `{file_}` | {auth} | {fw} |")
        lines.append("")

    return "\n".join(lines)


# ── Security Domains ──────────────────────────────────────────────────────────


def _build_security_domains(data: dict) -> str:
    findings = _get_security_findings(data)
    header = _greppable_header(
        purpose="Security findings grouped by agent/domain with severity counts.",
        owns="docs/SECURITY_DOMAINS.md",
        read_when="Prioritizing security work, auditing agent coverage, reviewing severity distribution.",
        key_files="docs/SECURITY_DOMAINS.md",
        invariants="Severity counts are exact integers. First-10 findings per domain are literal.",
        gotchas="Findings reflect last scan only — run `p scan` to refresh.",
    )

    lines: list[str] = header
    lines.append("# Security Domains")
    lines.append("")
    lines.append(f"_Generated {_TODAY} — {len(findings)} finding(s) across agents._")
    lines.append("")

    if not findings:
        lines.append("_No security findings available. Run `p scan` to populate._")
        lines.append("")
        return "\n".join(lines)

    # Group by agent.
    by_agent: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        agent = f.get("agent", "unknown")
        by_agent[agent].append(f)

    # Global severity counts.
    severity_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        sev = f.get("severity", "medium")
        severity_counts[sev] += 1

    lines.append("## Severity Overview")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        if count:
            lines.append(f"| {sev} | {count} |")
    lines.append("")

    # Per-agent breakdown.
    lines.append("## Findings by Agent")
    lines.append("")
    lines.append("| Agent | Findings | Critical | High | Medium | Low | Info |")
    lines.append("|-------|----------|----------|------|--------|-----|------|")
    for agent in sorted(by_agent):
        agent_findings = by_agent[agent]
        counts = defaultdict(int)
        for f in agent_findings:
            counts[f.get("severity", "medium")] += 1
        lines.append(
            f"| {agent} | {len(agent_findings)} "
            f"| {counts.get('critical', 0)} | {counts.get('high', 0)} "
            f"| {counts.get('medium', 0)} | {counts.get('low', 0)} "
            f"| {counts.get('info', 0)} |"
        )
    lines.append("")

    # First-10 findings per agent.
    lines.append("## Detailed Findings (first 10 per agent)")
    lines.append("")
    for agent in sorted(by_agent):
        agent_findings = by_agent[agent]
        lines.append(f"### {agent}")
        lines.append("")
        lines.append("| Severity | Type | File | Line | Message |")
        lines.append("|----------|------|------|------|---------|")
        for f in agent_findings[:10]:
            sev = f.get("severity", "?")
            ftype = f.get("type", "")
            file_ = f.get("file", "")
            line = f.get("line", 0)
            msg = f.get("message", "")
            # Truncate long messages for table readability.
            if len(msg) > 100:
                msg = msg[:97] + "..."
            lines.append(f"| {sev} | `{ftype}` | `{file_}` | {line} | {msg} |")
        if len(agent_findings) > 10:
            lines.append(f"\n_{len(agent_findings) - 10} more finding(s) omitted._")
        lines.append("")

    return "\n".join(lines)


# ── Module Map ────────────────────────────────────────────────────────────────


def _build_module_map(root: Path, data: dict) -> str:
    file_infos = _get_file_infos(data)
    import_graph = data.get("import_graph")
    header = _greppable_header(
        purpose="All scanned modules with inferred purpose, file size, and dependency edges.",
        owns="docs/MODULE_MAP.md",
        read_when="Understanding module responsibilities, tracing import chains, finding orphan candidates.",
        key_files="docs/MODULE_MAP.md",
        invariants="Purpose comes from _infer_purpose (code-derived, not guessed). Sizes in bytes.",
        gotchas="Import edges are local-project-only — external packages not shown.",
    )

    lines: list[str] = header
    lines.append("# Module Map")
    lines.append("")
    lines.append(f"_Generated {_TODAY} — {len(file_infos)} module(s) scanned._")
    lines.append("")

    if not file_infos:
        lines.append("_No file info available. Run a brain scan first._")
        lines.append("")
        return "\n".join(lines)

    # Sort by path for stable output.
    sorted_fis = sorted(file_infos, key=lambda fi: _fi_field(fi, "path", ""))

    lines.append("## Modules")
    lines.append("")
    lines.append("| Module | Language | Size (bytes) | Lines | Purpose |")
    lines.append("|--------|----------|-------------|-------|---------|")
    for fi in sorted_fis:
        path = _fi_field(fi, "path", "")
        lang = _fi_field(fi, "language", "")
        size = _fi_field(fi, "size_bytes", 0)
        line_count = _fi_field(fi, "lines", 0)
        purpose = _fi_field(fi, "purpose", "")
        if len(purpose) > 80:
            purpose = purpose[:77] + "..."
        lines.append(f"| `{path}` | {lang} | {size} | {line_count} | {purpose} |")
    lines.append("")

    # Dependency edges from import graph.
    if import_graph is not None:
        edges = getattr(import_graph, "edges", {})
        if edges:
            lines.append("## Dependency Edges")
            lines.append("")
            lines.append("_Local project imports only (external packages excluded)._")
            lines.append("")
            lines.append("```")
            for src in sorted(edges):
                for tgt in sorted(edges[src]):
                    lines.append(f"{src} -> {tgt}")
            lines.append("```")
            lines.append("")

    return "\n".join(lines)


# ── Test Coverage ─────────────────────────────────────────────────────────────


def _build_test_coverage(root: Path, data: dict) -> str:
    file_infos = _get_file_infos(data)
    header = _greppable_header(
        purpose="Test file inventory: which source files have test counterparts, which don't.",
        owns="docs/TEST_COVERAGE.md",
        read_when="Prioritizing test authorship, auditing coverage gaps, onboarding new contributors.",
        key_files="docs/TEST_COVERAGE.md",
        invariants="Test detection uses path patterns + test-framework imports (not filename-only).",
        gotchas="Coverage is structural (file presence), not execution-based — a test file may be empty.",
    )

    lines: list[str] = header
    lines.append("# Test Coverage")
    lines.append("")
    lines.append(f"_Generated {_TODAY} — {len(file_infos)} file(s) scanned._")
    lines.append("")

    if not file_infos:
        lines.append("_No file info available. Run a brain scan first._")
        lines.append("")
        return "\n".join(lines)

    # Partition into test vs source files.
    test_files: list[str] = []
    source_files: list[str] = []
    for fi in file_infos:
        path = _fi_field(fi, "path", "")
        if _is_test_file(fi):
            test_files.append(path)
        else:
            source_files.append(path)

    test_stems = {PurePosixPath(p).stem for p in test_files}

    # Match source → test by stem similarity.
    covered: list[str] = []
    uncovered: list[str] = []
    for src in sorted(source_files):
        stem = PurePosixPath(src).stem
        # Check common test naming patterns.
        has_test = (
            stem in test_stems
            or f"test_{stem}" in test_stems
            or f"{stem}_test" in test_stems
            or f"{stem}.test" in test_stems
            or f"{stem}.spec" in test_stems
            or any(t.startswith(stem) for t in test_stems if stem)
        )
        if has_test:
            covered.append(src)
        else:
            uncovered.append(src)

    # Summary.
    total_source = len(source_files)
    total_test = len(test_files)
    coverage_ratio = len(covered) / total_source if total_source else 0.0

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Source files:** {total_source}")
    lines.append(f"- **Test files:** {total_test}")
    lines.append(f"- **Source files with test counterpart:** {len(covered)} ({coverage_ratio:.0%})")
    lines.append(f"- **Source files without test:** {len(uncovered)}")
    lines.append("")

    # Test files list.
    lines.append("## Test Files")
    lines.append("")
    if test_files:
        for tf in sorted(test_files):
            lines.append(f"- `{tf}`")
    else:
        lines.append("_No test files detected._")
    lines.append("")

    # Covered source files.
    lines.append("## Covered Source Files")
    lines.append("")
    if covered:
        for sf in sorted(covered):
            lines.append(f"- `{sf}`")
    else:
        lines.append("_No source files have test counterparts._")
    lines.append("")

    # Uncovered source files.
    lines.append("## Uncovered Source Files (no test detected)")
    lines.append("")
    if uncovered:
        for sf in sorted(uncovered):
            lines.append(f"- `{sf}`")
    else:
        lines.append("_All source files have test counterparts._")
    lines.append("")

    return "\n".join(lines)


# ── Data extraction helpers ───────────────────────────────────────────────────


def _get_routes(data: dict) -> list[Any]:
    """Extract route list from scan_result, handling dict and object forms."""
    raw = data.get("routes", [])
    if not raw:
        return []
    # If already a list of dicts, return as-is.
    if raw and isinstance(raw[0], dict):
        return raw
    # If list of RouteInfo objects, convert to dicts.
    return [r.to_dict() if hasattr(r, "to_dict") else r for r in raw]


def _get_file_infos(data: dict) -> list[dict]:
    """Extract file_infos from scan_result, normalizing to dicts."""
    raw = data.get("file_infos", [])
    if not raw:
        return []
    if raw and isinstance(raw[0], dict):
        return raw
    return [fi.to_dict() if hasattr(fi, "to_dict") else fi for fi in raw]


def _get_security_findings(data: dict) -> list[dict]:
    """Extract security findings from scan_result.

    Handles two formats:
      1. ``data["security_findings"]`` — flat list of Finding dicts
      2. ``data["scan_results"]`` — agent_name → {findings: [...]} mapping
    """
    # Direct list.
    direct = data.get("security_findings")
    if direct and isinstance(direct, list):
        return direct

    # Memory-style scan_results: {agent_name: {findings: [...]}}
    scan_results = data.get("scan_results", {})
    if scan_results and isinstance(scan_results, dict):
        findings: list[dict] = []
        for agent_name, agent_data in scan_results.items():
            if not isinstance(agent_data, dict):
                continue
            agent_findings = agent_data.get("findings", [])
            if agent_findings:
                for f in agent_findings:
                    if isinstance(f, dict):
                        f.setdefault("agent", agent_name)
                        findings.append(f)
        return findings

    return []


def _route_field(route: Any, field: str, default: Any = "") -> Any:
    """Get a field from a route (dict or object)."""
    if isinstance(route, dict):
        return route.get(field, default)
    return getattr(route, field, default)


def _fi_field(fi: Any, field: str, default: Any = "") -> Any:
    """Get a field from a FileInfo (dict or object)."""
    if isinstance(fi, dict):
        return fi.get(field, default)
    return getattr(fi, field, default)


def _is_test_file(fi: Any) -> bool:
    """Determine if a FileInfo represents a test file."""
    path = _fi_field(fi, "path", "")
    parts = path.replace("\\", "/").split("/")

    # Check path segments for test directories.
    test_dir_names = {"tests", "test", "__tests__", "spec", "specs", "testing"}
    if any(p.lower() in test_dir_names for p in parts):
        return True

    # Check filename patterns.
    stem = PurePosixPath(path).stem
    if stem.startswith("test_") or stem.endswith("_test"):
        return True
    if ".test" in stem or ".spec" in stem:
        return True

    # Check imports for test frameworks.
    imports = _fi_field(fi, "imports", [])
    python_test_imports = {"pytest", "unittest", "nose", "nose2", "mock"}
    js_test_imports = {"jest", "mocha", "vitest", "jasmine", "cypress", "playwright"}
    for imp in imports:
        if isinstance(imp, dict):
            src = (imp.get("source", "") or "").lower()
        else:
            src = (getattr(imp, "source", "") or "").lower()
        top = src.split(".")[0]
        if top in python_test_imports or top in js_test_imports:
            return True

    return False


def _error_doc(title: str, exc: Exception) -> str:
    """Produce a minimal error doc when generation fails."""
    return (
        f"<!-- PURPOSE: {title} documentation (generation failed) -->\n"
        f"<!-- UPDATED: {_TODAY} -->\n"
        f"\n"
        f"# {title}\n"
        f"\n"
        f"_Generation failed: {exc}_\n"
    )
