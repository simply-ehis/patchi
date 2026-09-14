"""`p docs` — Generate a project architecture document (Part 4 / Item 45).

Tier 1: pure rendering from Brain data, works with zero AI configured.
Tier 2: scoped AI narration (future, requires harness).

Output: a single Markdown file with table of contents, Mermaid diagrams,
tables, and cited evidence — designed to be portable context for new AI
conversations about the codebase.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

_SOURCE_EXTS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
    ".rb", ".php", ".cs", ".swift", ".kt", ".scala", ".ex", ".exs",
    ".c", ".cpp", ".h", ".hpp",
})


@dataclass
class FreshnessReport:
    """Result of comparing doc mtime vs newest source file mtime."""
    stale_files: list[str]
    fresh: bool
    newest_source_mtime: float
    newest_doc_mtime: float


def _check_docs_freshness(docs_dir: Path, project_root: Path) -> FreshnessReport:
    """Compare the mtime of the newest source file against the architecture doc.

    Returns a ``FreshnessReport`` with ``fresh=False`` when the doc is older
    than the newest source file (or when no doc exists yet).
    """
    # Find the doc file.
    doc_path = docs_dir / "ARCHITECTURE.md"
    newest_doc_mtime = 0.0
    if doc_path.exists():
        try:
            newest_doc_mtime = doc_path.stat().st_mtime
        except OSError:
            pass

    # Walk the project for the newest source file mtime.
    newest_source_mtime = 0.0
    stale_files: list[str] = []

    ignore_dirs = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "dist", "build", ".mypy_cache", ".pytest_cache", ".tox",
        "patchi",  # don't count patchi's own source as "project source"
    }

    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() not in _SOURCE_EXTS:
                continue
            try:
                mtime = fpath.stat().st_mtime
            except OSError:
                continue
            if mtime > newest_source_mtime:
                newest_source_mtime = mtime
            # Track source files that are newer than the doc.
            if mtime > newest_doc_mtime:
                try:
                    stale_files.append(fpath.relative_to(project_root).as_posix())
                except ValueError:
                    stale_files.append(str(fpath))

    fresh = newest_doc_mtime >= newest_source_mtime if newest_doc_mtime > 0 else False
    return FreshnessReport(
        stale_files=stale_files,
        fresh=fresh,
        newest_source_mtime=newest_source_mtime,
        newest_doc_mtime=newest_doc_mtime,
    )


def generate_sections(
    root: Path,
    *,
    brain_data: dict[str, Any] | None = None,
    ai_available: bool = False,
) -> list[tuple[int, str, list[str]]]:
    """Build the architecture document as structured sections.

    Returns a list of ``(heading_level, heading_text, content_lines)``
    tuples suitable for :func:`patchi.cli.markdown_writer.write_markdown`.
    """
    brain = brain_data or {}
    sections: list[tuple[int, str, list[str]]] = []

    toc_items = [
        "1. [Project Overview](#project-overview)",
        "2. [Project Tree](#project-tree)",
        "3. [Routes](#routes)",
        "4. [Key Abstractions](#key-abstractions)",
        "5. [Dependency Graph](#dependency-graph)",
        "6. [Capabilities](#capabilities)",
        "7. [Functionality Checks](#functionality-checks)",
        "8. [AI Narration](#ai-narration)",
    ]
    sections.append((2, "Table of Contents", [f"- {item}" for item in toc_items]))
    sections.append((2, "Project Overview", _render_overview(root, brain).splitlines()))
    sections.append((2, "Project Tree", _render_tree(root, brain).splitlines()))
    sections.append((2, "Routes", _render_routes(brain).splitlines()))
    sections.append((2, "Key Abstractions", _render_abstractions(brain).splitlines()))
    sections.append((2, "Dependency Graph", _render_dependency_diagram(brain).splitlines()))
    sections.append((2, "Capabilities", _render_capabilities(root, brain).splitlines()))
    sections.append((2, "Functionality Checks", _render_functionality_checks(brain).splitlines()))

    if ai_available:
        ai_lines = ["_Tier 2 narration would appear here with AI configured._"]
    else:
        ai_lines = [
            "_Unavailable — AI not configured. Configure an AI provider "
            "with `p key add` to enable scoped narration for abstractions "
            "and user flows._",
        ]
    sections.append((2, "AI Narration", ai_lines))

    return sections


def _build_doc_metadata(project_root: Path, brain_data: dict[str, Any]) -> dict:
    """Build metadata dict for docs/.patchi-meta.json."""
    from patchi import __version__ as patchi_version

    # Count source files scanned.
    file_infos = brain_data.get("file_infos", [])
    source_file_count = len(file_infos) if isinstance(file_infos, list) else 0

    # Count findings.
    findings = brain_data.get("security_findings", [])
    finding_count = len(findings) if isinstance(findings, list) else 0

    # Current git commit (graceful failure).
    git_commit = None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            git_commit = result.stdout.strip()
    except Exception:
        pass

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "patchi_version": patchi_version,
        "git_commit": git_commit,
        "source_file_count": source_file_count,
        "finding_count": finding_count,
    }


def generate_docs(
    root: Path,
    *,
    brain_data: dict[str, Any] | None = None,
    ai_available: bool = False,
) -> str:
    """Generate a Markdown architecture document for the project.

    Tier 1 sections are always rendered.  Tier 2 sections are either
    rendered (if *ai_available*) or marked "unavailable — AI not configured".

    Returns the full Markdown string.
    """
    project_name_str = project_name(root, brain_data or {})
    header_lines = [
        f"_Generated by Patchi on {time.strftime('%Y-%m-%d')}_",
        "",
    ]

    lines: list[str] = [f"# {project_name_str} — Architecture", ""]
    lines.extend(header_lines)

    for level, heading, content in generate_sections(
        root, brain_data=brain_data, ai_available=ai_available,
    ):
        lines.append(f"{'#' * level} {heading}")
        lines.append("")
        if content:
            lines.extend(content)
            lines.append("")

    return "\n".join(lines)


# ── Section renderers ────────────────────────────────────────────────────────


def project_name(root: Path, brain: dict) -> str:
    """Derive project name from manifest or directory name."""
    purpose = brain.get("project_purpose", "")
    if purpose and "—" in purpose:
        return purpose.split("—")[0].strip()
    if purpose and ":" in purpose:
        return purpose.split(":")[0].strip()
    return root.name


def _render_overview(root: Path, brain: dict) -> str:
    lines: list[str] = []
    purpose = brain.get("project_purpose", "Project purpose not yet determined.")
    lines.append(f"**Purpose:** {purpose}\n")

    stats = brain.get("stats", {})
    if stats:
        parts = []
        if stats.get("file_count"):
            parts.append(f"{stats['file_count']} files")
        if stats.get("route_count"):
            parts.append(f"{stats['route_count']} routes")
        if stats.get("function_count"):
            parts.append(f"{stats['function_count']} functions")
        if stats.get("class_count"):
            parts.append(f"{stats['class_count']} classes")
        if parts:
            lines.append(f"**Size:** {', '.join(parts)}\n")

    stack = brain.get("stack", {})
    if stack:
        langs = stack.get("languages", [])
        fws = stack.get("frameworks", [])
        if langs:
            lines.append(f"**Languages:** {', '.join(langs)}\n")
        if fws:
            lines.append(f"**Frameworks:** {', '.join(fws)}\n")

    return "\n".join(lines)


def _render_tree(root: Path, brain: dict) -> str:
    """Render a simplified project tree from file discovery data."""
    file_infos = brain.get("file_infos", [])
    if not file_infos:
        return "_No file discovery data available._\n"

    # Group by top-level directory.
    from collections import defaultdict

    dirs: dict[str, list[str]] = defaultdict(list)
    for fi in file_infos:
        path = getattr(fi, "path", str(fi))
        parts = Path(path).parts
        if len(parts) > 1:
            dirs[parts[0]].append(path)
        else:
            dirs["."].append(path)

    lines = ["```"]
    for d in sorted(dirs.keys()):
        files = sorted(dirs[d])
        lines.append(f"{d}/")
        for f in files[:20]:  # Cap per dir.
            lines.append(f"  {Path(f).name}")
        if len(files) > 20:
            lines.append(f"  ... and {len(files) - 20} more")
    lines.append("```")
    return "\n".join(lines)


def _render_routes(brain: dict) -> str:
    routes = brain.get("routes", [])
    if not routes:
        return "_No routes detected._\n"

    lines = ["| Method | Path | Handler | Auth |"]
    lines.append("|--------|------|---------|------|")
    for r in routes[:50]:
        method = getattr(r, "method", "") if hasattr(r, "method") else r.get("method", "")
        path = getattr(r, "path", "") if hasattr(r, "path") else r.get("path", "")
        handler = getattr(r, "handler", "") if hasattr(r, "handler") else r.get("handler", "")
        auth = getattr(r, "auth_required", None) if hasattr(r, "auth_required") else r.get("auth_required")
        auth_str = "Yes" if auth else ("No" if auth is not None else "?")
        lines.append(f"| {method} | `{path}` | `{handler}` | {auth_str} |")

    if len(routes) > 50:
        lines.append(f"\n_Showing 50 of {len(routes)} routes._")

    return "\n".join(lines)


def _render_abstractions(brain: dict) -> str:
    """Render key abstractions — highest fan-in/fan-out from symbol graph."""
    symbols = brain.get("symbols", [])
    if not symbols:
        return "_No symbol graph data available._\n"

    # Compute fan-in from edges.
    edges = brain.get("symbol_edges", [])
    fan_in: dict[int, int] = {}
    for e in edges:
        target = e.get("target", 0) if isinstance(e, dict) else getattr(e, "target_id", 0)
        fan_in[target] = fan_in.get(target, 0) + 1

    # Rank by fan-in.
    def _sym_id(s: object) -> int:
        if isinstance(s, dict):
            return int(s.get("id", 0) or 0)
        return int(getattr(s, "id", 0) or 0)

    ranked = sorted(symbols, key=lambda s: fan_in.get(_sym_id(s), 0), reverse=True)

    lines = ["| Symbol | Kind | File | Fan-in |"]
    lines.append("|--------|------|------|--------|")
    for s in ranked[:20]:
        name = s.get("name", "") if isinstance(s, dict) else getattr(s, "name", "")
        kind = s.get("kind", "") if isinstance(s, dict) else getattr(s, "kind", "")
        f = s.get("file", "") if isinstance(s, dict) else getattr(s, "file", "")
        sid = s.get("id", 0) if isinstance(s, dict) else getattr(s, "id", 0)
        fi = fan_in.get(sid, 0)
        lines.append(f"| `{name}` | {kind} | `{f}` | {fi} |")

    return "\n".join(lines)


def _render_dependency_diagram(brain: dict) -> str:
    """Render a Mermaid dependency diagram from import graph data."""
    import_graph = brain.get("import_graph")
    if not import_graph:
        return "_No import graph data available._\n"

    try:
        from patchi.core.brain.mermaid import dependency_diagram

        return f"```mermaid\n{dependency_diagram(import_graph)}\n```"
    except Exception as e:
        _log.debug("Mermaid generation failed: %s", e)
        return "_Diagram generation unavailable._\n"


def _render_capabilities(root: Path, brain: dict) -> str:
    """Render the code-derived capability inventory."""
    try:
        from patchi.core.brain.capability_inventory import build_inventory

        inv = build_inventory(
            root,
            file_infos=brain.get("file_infos"),
            routes=brain.get("routes"),
        )
        if inv.total == 0:
            return "_No capabilities discovered from code._\n"

        lines = [f"_{inv.summary()}_\n"]

        # Route capabilities.
        if inv.routes:
            lines.append("### Routes\n")
            for e in inv.routes[:30]:
                lines.append(f"- `{e.name}` — {e.description}")
            lines.append("")

        # Agent capabilities.
        if inv.agents:
            lines.append("### Agents\n")
            by_group: dict[str, list] = {}
            for e in inv.agents:
                g = e.meta.get("group", "other")
                by_group.setdefault(g, []).append(e)
            for group, agents in sorted(by_group.items()):
                lines.append(f"**{group}:** {', '.join(a.name for a in agents[:10])}")
                if len(agents) > 10:
                    lines.append(f"  _...and {len(agents) - 10} more_")
            lines.append("")

        return "\n".join(lines)
    except Exception as e:
        _log.debug("Capability inventory failed: %s", e)
        return "_Capability inventory unavailable._\n"


def _render_functionality_checks(brain: dict) -> str:
    """Render critical flows from the contract."""
    contract = brain.get("contract", {})
    flows = contract.get("flows", [])
    if not flows:
        return "_No contract flows detected._\n"

    critical = [f for f in flows if f.get("critical", False)]
    if not critical:
        return f"_{len(flows)} flows detected, none marked critical._\n"

    lines = [f"_{len(critical)} critical flows:_\n"]
    for f in critical[:20]:
        name = f.get("name", "?")
        desc = f.get("description", "")
        routes = f.get("routes", [])
        route_str = ", ".join(f"`{r}`" for r in routes[:3]) if routes else "no routes"
        lines.append(f"- **{name}**: {desc} ({route_str})")

    return "\n".join(lines)
