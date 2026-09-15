"""
`p why` / `p impact` — Reasoning Engine views (restored).

  p why src/auth/login.py                   — why a file matters (dependents)
  p why src/auth/login.py --mermaid         — the same answer as Mermaid diagrams
  p impact src/api/routes.py                — change-impact / blast radius report
  p impact --all                            — blast-radius map for every file

Restoration note (Part 3 §1): these handlers were deleted in ef77be5 ("Remove
14 dead command files") while the registry kept pointing at them — `p why`,
`p impact`, `p blast` all crashed on import, and `p watch`'s Phase 4b impact
step silently degraded. The ReasoningEngine itself never went away; only this
CLI shim did. The former `p blast` helpers (`_build_graph`,
`_show_all_blast_radii`) are inlined here rather than re-imported from the
deleted blast_cmd module.

All views read the cached Layered Brain / import graph (built by `p scan`);
they never re-read raw source for the reasoning paths, so they're instant and
offline-safe.
"""

from __future__ import annotations

import ast
import logging
import os
from collections import deque
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con, print_json
from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS
from patchi.core.brain.reasoning import ReasoningEngine
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.commands.reason_cmd")


def run_why(path: str, root: Path | None = None, mermaid: bool = False) -> None:
    """p why <file> — why a file matters."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # --mermaid needs only the import graph, not the layered brain, so it
    # stays useful even when layers are stale or absent.
    if mermaid:
        _emit_mermaid(r, path)
        return

    engine = ReasoningEngine(r)
    info = engine.why(path)
    if "error" in info:
        con.print(f"[yellow]{info['error']}[/yellow]")
        return

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_row("[bold #F2EDD6]File[/bold #F2EDD6]", info["file"])
    table.add_row("[bold #F2EDD6]Layer[/bold #F2EDD6]", info["layer"])
    table.add_row("[bold #F2EDD6]Importance[/bold #F2EDD6]", info["importance"])
    table.add_row("[bold #F2EDD6]Purpose[/bold #F2EDD6]", info["purpose"] or "—")
    table.add_row(
        "[bold #F2EDD6]Depended on by[/bold #F2EDD6]",
        ", ".join(info["depended_on_by"]) or "nothing (no internal dependents)",
    )
    table.add_row("[bold #F2EDD6]Files in layer[/bold #F2EDD6]", str(info["files_in_layer"]))
    con.print()
    con.print(
        Panel(
            table,
            title="[bold #C8621A]Why this file matters[/bold #C8621A]",
            border_style="#2A3D28",
        )
    )
    con.print()


def _cached_graph(root: Path):
    """ImportGraph from cached brain memory (no raw-source reads — `p why`
    stays instant and offline-safe). Returns None when no scan data exists."""
    from patchi.core import memory as mem
    from patchi.core.brain.import_graph import ImportGraph

    data = (mem.get_brain(root) or {}).get("import_graph") or {}
    if not data.get("nodes"):
        return None
    graph = ImportGraph()
    for n in data["nodes"]:
        graph.nodes.add(n)
    for src, targets in (data.get("edges") or {}).items():
        for tgt in targets:
            graph.add_edge(src, tgt)
    return graph


def _emit_mermaid(root: Path, path: str) -> None:
    """--mermaid: the explanation path as Mermaid sequence diagrams.

    Two walks over the cached import graph, reusing brain/mermaid.py:
      1. dependents — who calls this file (why it matters)
      2. call flow  — what this file leans on (what changes drag in)
    The target is synthesized as a pseudo-route so sequence_diagram's
    handler walk starts at the file itself.
    """
    from patchi.core.brain.mermaid import sequence_diagram
    from patchi.core.brain.route_mapper import RouteInfo

    graph = _cached_graph(root)
    if graph is None:
        con.print("[yellow]No import graph data. Run `p scan` first, then re-run with --mermaid.[/yellow]")
        return

    route = RouteInfo(method="USE", path=path, handler=Path(path).stem, file=path, line=1)

    reversed_graph = type(graph)()
    for n in graph.nodes:
        reversed_graph.nodes.add(n)
    for src, targets in graph.edges.items():
        for tgt in targets:
            reversed_graph.add_edge(tgt, src)  # dependents become the walk

    blocks = [
        ("Dependents — who calls this file", reversed_graph),
        ("Call flow — what this file leans on", graph),
    ]
    con.print()
    for title, g in blocks:
        con.print(f"[bold]{title}[/bold]")
        con.print("```mermaid")
        con.print(sequence_diagram([route], g, entry=path, title=f"p why — {path}"))
        con.print("```")
        con.print()


def run_impact(
    files: list[str] | None = None,
    show_all: bool = False,
    json_output: bool = False,
    root: Path | None = None,
) -> None:
    """p impact <file> [<file> ...] --json — machine-pure blast-radius report.

    Canonical home of blast-radius analysis (absorbs the former
    `p blast` command: --all lists every file's radius).

    With ``--json``: one pure-JSON stdout document (no human UI before it,
    no Rich soft-wrapping) — {files, summary, affected_layers,
    impacted_layers, blast_radii?}. Safe for CI to ``json.load`` directly.
    """
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        if json_output:
            print_json({"error": str(e)})
            return
        con.print(f"[red]{e}[/red]")
        return

    if show_all:
        graph = _build_graph(r)
        if not graph.nodes:
            if json_output:
                print_json({"error": "no import graph data — run p scan first"})
            else:
                con.print("[yellow]No import graph data. Run `p scan` first.[/yellow]")
            return
        _show_all_blast_radii(graph, r, json_output=json_output)
        return

    if not files:
        if json_output:
            print_json(
                {"error": "provide at least one changed file, e.g. p impact <file> (or p impact --all)"}
            )
            return
        con.print(
            "[red]Provide at least one changed file, e.g.[/red] "
            "[bold]p impact src/api/routes.py[/bold] "
            "[dim](or p impact --all)[/dim]"
        )
        return

    engine = ReasoningEngine(r)
    analysis = engine.impact_analysis(files)

    if json_output:
        print_json(
            {
                "files": list(files),
                "summary": analysis.summary,
                "affected_layers": list(analysis.affected_layers),
                "impacted_layers": list(analysis.impacted_layers),
            }
        )
        return

    con.print()
    con.print(f"[dim]{analysis.summary}[/dim]")
    con.print()

    if analysis.affected_layers:
        con.print("[bold #F2EDD6]Directly affected layers:[/bold #F2EDD6]")
        for name in analysis.affected_layers:
            con.print(f"  • {name}")
    if analysis.impacted_layers:
        con.print()
        con.print("[bold #FF8C42]Blast radius (downstream dependents):[/bold #FF8C42]")
        for name in analysis.impacted_layers:
            con.print(f"  • {name}")
    elif analysis.affected_layers:
        con.print()
        con.print("[dim]No downstream layers depend on the changed code.[/dim]")
    con.print()


# ── Former p blast helpers (inlined from the deleted blast_cmd) ─────────────


def _build_graph(root: Path):
    """Build import graph from project source files."""
    from patchi.core.brain.import_graph import ImportGraph

    graph = ImportGraph()
    skip = DEFAULT_IGNORE_DIRS

    for py_file in _safe_rglob(root, "*.py", skip):
        rel = py_file.relative_to(root).as_posix()
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content, filename=rel)
        except Exception as e:
            _log.warning("_build_graph failed: %s", e)
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported = _resolve_import(alias.name, root, py_file)
                    if imported:
                        graph.add_edge(rel, imported)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported = _resolve_import(node.module, root, py_file)
                    if imported:
                        graph.add_edge(rel, imported)

    return graph


def _resolve_import(module_name: str, root: Path, from_file: Path) -> str | None:
    """Resolve a module name to a relative file path."""
    parts = module_name.split(".")
    # Try as direct file (.py extension)
    candidate = root / "/".join(parts)
    if candidate.is_file():
        return candidate.relative_to(root).as_posix()
    candidate = root / ("/".join(parts) + ".py")
    if candidate.is_file():
        return candidate.relative_to(root).as_posix()
    candidate = root / "/".join(parts) / "__init__.py"
    if candidate.is_file():
        return candidate.relative_to(root).as_posix()
    # Try relative to the importing file
    parent = from_file.parent
    candidate = parent / "/".join(parts)
    if candidate.is_file():
        return candidate.relative_to(root).as_posix()
    candidate = parent / ("/".join(parts) + ".py")
    if candidate.is_file():
        return candidate.relative_to(root).as_posix()
    candidate = parent / "/".join(parts) / "__init__.py"
    if candidate.is_file():
        return candidate.relative_to(root).as_posix()
    return None


def _show_all_blast_radii(graph, root: Path, json_output: bool = False) -> None:
    """Show blast radius summary for all files.

    With ``json_output`` the document is emitted via :func:`print_json`
    (byte-pure); the human table path is unchanged.
    """
    radii = []
    for node in graph.nodes:
        direct = graph.reverse.get(node, set())
        all_affected: set[str] = set()
        queue: deque[str] = deque(direct)
        while queue:
            n = queue.popleft()
            if n == node or n in all_affected:
                continue
            all_affected.add(n)
            for parent in graph.reverse.get(n, set()):
                if parent not in all_affected:
                    queue.append(parent)
        radii.append((node, len(direct), len(all_affected)))

    # Sort by total affected (highest first)
    radii.sort(key=lambda x: -x[2])

    if json_output:
        print_json({"blast_radii": [{"file": node, "direct": d, "total_affected": t} for node, d, t in radii]})
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("File", style="bold #F2EDD6", width=40)
    table.add_column("Direct", justify="right", width=8)
    table.add_column("Total", justify="right", width=8)
    table.add_column("Risk", width=10)

    for file_rel, direct_count, total_count in radii[:30]:
        if total_count == 0:
            risk = Text("LOW", style="#4ADE80")
        elif total_count <= 3:
            risk = Text("MED", style="#FACC15")
        else:
            risk = Text("HIGH", style="#FF4D6D")

        table.add_row(
            file_rel[:40],
            str(direct_count) if direct_count else "—",
            str(total_count) if total_count else "—",
            risk,
        )

    con.print()
    con.print(Panel(table, title="💥 Blast Radius Map — All Files", border_style="#C8621A"))
    con.print()


def _safe_rglob(root: Path, pattern: str, skip: set):
    """Directory-walking with pruning."""
    suffix = pattern.replace("*.", ".")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            if fn.endswith(suffix):
                yield Path(dirpath) / fn
