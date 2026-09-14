"""`p docs` — Generate a project architecture document.

Tier 1: pure rendering from Brain data, works with zero AI configured.
Tier 2: scoped AI narration (future, requires harness).

Usage:
    p docs                  # Generate docs to docs/ARCHITECTURE.md
    p docs --output FILE    # Write to a specific file
    p docs --stdout         # Print to stdout instead of file
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from patchi.cli.framework import Arg

_log = logging.getLogger(__name__)

ARGS = (
    Arg("--output", "-o", help="Output file path", default=None),
    Arg("--stdout", help="Print to stdout instead of writing a file", action="store_true"),
)


def run(args: object) -> None:
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    root = Path(getattr(args, "project_root", "."))
    output_path = getattr(args, "output", None)
    to_stdout = getattr(args, "stdout", False)

    console.print(Panel("[bold]Patchi — Project Architecture Doc[/bold]", style="blue"))

    # Build brain data from a lightweight scan.
    brain_data = _build_brain_data(root, console)

    # Check if AI is available.
    ai_available = _check_ai()

    # Generate the doc.
    from patchi.core.brain.docs_generator import generate_docs

    doc = generate_docs(root, brain_data=brain_data, ai_available=ai_available)

    # Output.
    if to_stdout:
        sys.stdout.write(doc)
        return

    if not output_path:
        # Default: docs/ARCHITECTURE.md in the project root.
        docs_dir = root / "docs"
        docs_dir.mkdir(exist_ok=True)
        output_path = str(docs_dir / "ARCHITECTURE.md")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8")
    console.print(f"\n[green]✓[/green] Architecture doc written to [bold]{out}[/bold]")
    console.print("  Sections: overview, tree, routes, abstractions, dependencies, capabilities, functionality")


def _build_brain_data(root: Path, console: object) -> dict:
    """Build brain data from a lightweight scan pass."""
    brain: dict = {}

    try:
        from patchi.core.brain.scanner import run_scanners

        console.print("  [dim]Scanning project structure...[/dim]")
        scan_result = run_scanners(root)
        brain.update(scan_result)
    except Exception as e:
        _log.debug("Scan pass failed: %s", e)
        console.print(f"  [yellow]⚠ Scan pass failed: {e}[/yellow]")

    # Import graph for Mermaid diagrams.
    try:
        from patchi.core.brain.import_graph import build_import_graph

        console.print("  [dim]Building import graph...[/dim]")
        graph = build_import_graph(root)
        brain["import_graph"] = graph
    except Exception as e:
        _log.debug("Import graph build failed: %s", e)

    # Symbol graph for abstractions.
    try:
        from patchi.core.brain.symbol_graph import SymbolGraph

        sg = SymbolGraph(root)
        count = sg.ensure_built()
        if count > 0:
            brain["symbols"] = [s.to_dict() for s in sg.get_all_symbols()]
            brain["symbol_edges"] = sg.export_json().get("edges", [])
        sg.close()
    except Exception as e:
        _log.debug("Symbol graph build failed: %s", e)

    return brain


def _check_ai() -> bool:
    """Check if an AI provider is configured."""
    try:
        from patchi.core.config import load_config

        config = load_config()
        ai = config.get("ai", {})
        return bool(ai.get("provider") and ai.get("api_key"))
    except Exception:
        return False
