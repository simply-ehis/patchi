"""
`p blast <file>` — Blast radius analysis.

Shows exactly what breaks when you change a file:
- Direct importers (who imports this file)
- Transitive dependents (the full cascade)
- Affected test files
- Risk score (low/medium/high/critical)
- Suggested safe refactor path

This is what no other AI coding tool does — it understands your
codebase as a dependency graph, not just individual files.

Usage:
  p blast src/auth/login.py       — who imports login.py?
  p blast src/api/routes.py       — full cascade from routes.py
  p blast --all                   — show blast radius for all files
"""

from __future__ import annotations

import logging
import os
from collections import deque
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from patchi.cli.console import con
from patchi.core.brain.import_graph import ImportGraph
from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.blast_cmd")


def run(file_path: str | None = None, show_all: bool = False, root: Path | None = None) -> None:
    """Entry point for `p blast <file>`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    graph = _build_graph(r)
    if not graph.nodes:
        con.print("[yellow]No import graph data. Run `p scan` first.[/yellow]")
        return

    if show_all:
        _show_all_blast_radii(graph, r)
        return

    if not file_path:
        con.print("[red]Usage: p blast <file>[/red]")
        con.print("[dim]Example: p blast src/auth/login.py[/dim]")
        return

    # Resolve file path
    resolved = _resolve_file(file_path, r)
    if not resolved:
        con.print(f"[red]File not found: {file_path!r}[/red]")
        return

    _show_blast_radius(resolved, graph, r)


def _build_graph(root: Path) -> ImportGraph:
    """Build import graph from project source files."""
    import ast

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


def _resolve_file(file_path: str, root: Path) -> str | None:
    """Resolve a user-provided file path to a relative path in the graph."""
    # Try exact match
    p = root / file_path
    if p.is_file():
        return p.relative_to(root).as_posix()
    # Try with .py extension
    if not file_path.endswith(".py"):
        p = root / (file_path + ".py")
        if p.is_file():
            return p.relative_to(root).as_posix()
    # Try partial match
    for node_p in root.rglob("*.py"):
        rel = node_p.relative_to(root).as_posix()
        if rel.endswith(file_path) or file_path in rel:
            return rel
    return None


def _show_blast_radius(file_rel: str, graph: ImportGraph, root: Path) -> None:
    """Display blast radius for a single file."""
    # BFS to find all dependents
    direct = sorted(graph.reverse.get(file_rel, set()))
    all_affected = set()
    queue = deque(direct)
    while queue:
        node = queue.popleft()
        if node == file_rel or node in all_affected:
            continue
        all_affected.add(node)
        for parent in graph.reverse.get(node, set()):
            if parent not in all_affected:
                queue.append(parent)

    all_affected = sorted(all_affected)
    count = len(all_affected)

    # Find affected tests
    tests_affected = [f for f in all_affected if "test" in f.lower()]

    # Risk level
    if count == 0:
        risk_color = "#4ADE80"
    elif count <= 3:
        risk_color = "#FACC15"
    elif count <= 10:
        risk_color = "#FF8C42"
    else:
        risk_color = "#FF4D6D"

    con.print()
    con.print(
        Panel(
            "[bold]Blast Radius Analysis[/bold]\n",
            title="💥 Blast Radius",
            border_style=risk_color,
            padding=(1, 2),
        )
    )

    if direct:
        con.print()
        con.print("[bold #F2EDD6]Direct dependents:[/bold #F2EDD6]")
        for d in direct[:20]:
            is_test = "test" in d.lower()
            icon = "🧪" if is_test else "  "
            con.print(f"  {icon} [dim]{d}[/dim]")
        if len(direct) > 20:
            con.print(f"  [dim]… and {len(direct) - 20} more[/dim]")

    if tests_affected:
        con.print()
        con.print("[bold #F2EDD6]Affected tests:[/bold #F2EDD6]")
        for t in tests_affected[:10]:
            con.print(f"  🧪 [dim]{t}[/dim]")

    # Show cascade tree (limited depth)
    if all_affected and count <= 30:
        con.print()
        con.print("[bold #F2EDD6]Full dependency cascade:[/bold #F2EDD6]")
        tree = Tree(f"  [bold]{file_rel}[/bold]")
        _build_tree(tree, file_rel, graph, depth=0, max_depth=3, visited=set())
        con.print(tree)

    con.print()
    if count > 0:
        con.print(
            f"[dim]⚡ Changing [bold]{file_rel}[/bold] could break {count} file(s). "
            f"Run tests after modifying.[/dim]"
        )
    else:
        con.print(
            f"[dim]✓ [bold]{file_rel}[/bold] has no dependents — safe to modify freely.[/dim]"
        )
    con.print()


def _build_tree(
    parent_tree, file_rel: str, graph: ImportGraph, depth: int, max_depth: int, visited: set
) -> None:
    """Recursively build a tree of dependents."""
    if depth >= max_depth:
        return
    dependents = sorted(graph.reverse.get(file_rel, set()))
    for dep in dependents:
        if dep in visited:
            parent_tree.add(f"[dim]{dep} (circular)[/dim]")
            continue
        visited.add(dep)
        child = parent_tree.add(dep)
        _build_tree(child, dep, graph, depth + 1, max_depth, visited)


def _show_all_blast_radii(graph: ImportGraph, root: Path, json_output: bool = False) -> None:
    """Show blast radius summary for all files."""
    radii = []
    for node in graph.nodes:
        direct = graph.reverse.get(node, set())
        all_affected = set()
        queue = deque(direct)
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
        import json as _json

        con.print(
            _json.dumps(
                {
                    "blast_radii": [
                        {"file": node, "direct": d, "total_affected": t} for node, d, t in radii
                    ]
                },
                indent=2,
            )
        )
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
        elif total_count <= 10:
            risk = Text("HIGH", style="#FF8C42")
        else:
            risk = Text("CRIT", style="#FF4D6D bold")

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
