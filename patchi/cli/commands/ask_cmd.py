"""
CLI command for the Reasoning Engine.

Usage:
    p ask "what changed?"
    p ask "what does auth do?"
    p ask "what imports secrets?"
    p ask "security hotspots"
    p ask --json "what layers exist?"
"""

from __future__ import annotations

import sys


def run(question: list[str] | str | None = None, json_output: bool = False) -> None:
    """Entry point for ``p ask``."""
    # Handle question — could be a list of words, a string, or None
    if question is None:
        sys.exit(1)

    if isinstance(question, list):
        question = " ".join(question)

    if not question.strip():
        sys.exit(1)

    from patchi.core.config import require_project_root

    try:
        root = require_project_root()
    except Exception:
        sys.exit(1)

    from patchi.core.security.reasoning import answer_question

    result = answer_question(question, root)

    if json_output:
        return

    # Rich terminal output
    _print_result(result)


def _print_result(result) -> None:
    """Print reasoning result with rich formatting."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()

    # Header
    console.print()
    console.print(
        Panel(
            Text(f'"{result.question}"', style="bold cyan"),
            title="[bold]Reasoning Engine[/bold]",
            border_style="cyan",
        )
    )
    console.print()

    # Answer
    console.print("[bold]Answer:[/bold]")
    for line in result.answer.split("\n"):
        if line.startswith("==="):
            console.print(f"  [bold yellow]{line}[/bold yellow]")
        elif line.startswith("  "):
            console.print(f"  [dim]{line.strip()}[/dim]")
        elif line.startswith("-"):
            console.print(f"  {line}")
        elif ":" in line:
            parts = line.split(":", 1)
            console.print(f"  [bold]{parts[0]}:[/bold]{parts[1]}")
        else:
            console.print(f"  {line}")
    console.print()

    # Layers table (if any)
    if result.layers:
        table = Table(title="Affected Layers", box=None, show_lines=False)
        table.add_column("Layer", style="cyan")
        table.add_column("Files", style="dim")
        for layer_name in sorted(result.layers)[:10]:
            layer_files = [f for f in result.files if layer_name in f]
            table.add_row(layer_name, str(len(layer_files)) if layer_files else "-")
        console.print(table)
        if len(result.layers) > 10:
            console.print(f"  [dim]... and {len(result.layers) - 10} more layers[/dim]")
        console.print()

    # Structured details
    if result.details:
        if "hotspots" in result.details:
            table = Table(title="Security Hotspots", box=None, show_lines=False)
            table.add_column("Score", style="red")
            table.add_column("Layer", style="cyan")
            table.add_column("Reasons", style="yellow")
            for h in result.details["hotspots"][:10]:
                table.add_row(
                    str(h["risk_score"]),
                    h["name"],
                    ", ".join(h["reasons"][:3]),
                )
            console.print(table)
            console.print()

        if "layer_files" in result.details:
            console.print("[bold]Files by Layer:[/bold]")
            for layer, files in result.details["layer_files"].items():
                console.print(f"  [cyan]{layer}:[/cyan]")
                for f in files[:5]:
                    console.print(f"    - {f}")
                if len(files) > 5:
                    console.print(f"    ... and {len(files) - 5} more")
            console.print()

        if "api" in result.details and result.details["api"]:
            api = result.details["api"][:20]
            console.print(f"[bold]Public API ({len(api)} symbols):[/bold]")
            for sym in api:
                console.print(f"  - {sym}")
            console.print()

        if "depends" in result.details and result.details["depends"]:
            deps = result.details["depends"]
            console.print(f"[bold]Dependencies:[/bold] {', '.join(deps)}")
            console.print()

        if "dependents" in result.details and result.details["dependents"]:
            deps = result.details["dependents"]
            console.print(f"[bold]Dependents:[/bold] {', '.join(deps)}")
            console.print()

        if "importers" in result.details:
            importers = result.details["importers"]
            console.print(f"[bold]Imported by ({len(importers)}):[/bold]")
            for imp in importers:
                console.print(f"  - {imp}")
            console.print()
