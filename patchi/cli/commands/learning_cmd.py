"""
`p learning` — Show learning brain state from the last scan.

Usage:
  p learning              — show accept/reject patterns and agent trust
  p learning --json       — machine-readable output
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.learning_cmd")


def run(
    json_output: bool = False,
    root: Path | None = None,
) -> None:
    """Entry point for `p learning`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    try:
        from patchi.core.brain.learning import get_summary
    except ImportError as e:
        con.print(f"[red]Learning module not available: {e}[/red]")
        return

    summary = get_summary(r)

    if json_output:
        con.print(json.dumps(summary, indent=2))
        return

    con.print()
    con.print("[bold #C8621A]── Learning Brain State ──[/bold #C8621A]")
    con.print()

    # Acceptances
    acceptances = summary.get("acceptances", {})
    if acceptances:
        con.print("[bold green]✅ Accepted Findings[/bold green]")
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Finding Type")
        table.add_column("Count", justify="right")
        for ftype, count in sorted(acceptances.items(), key=lambda x: -x[1]):
            table.add_row(ftype, str(count))
        con.print(table)
        con.print()
    else:
        con.print("[dim]No acceptance data yet.[/dim]")
        con.print()

    # Rejections
    rejections = summary.get("rejections", {})
    if rejections:
        con.print("[bold red]❌ Rejected Findings[/bold red]")
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Finding Type")
        table.add_column("Count", justify="right")
        for ftype, count in sorted(rejections.items(), key=lambda x: -x[1]):
            table.add_row(ftype, str(count))
        con.print(table)
        con.print()
    else:
        con.print("[dim]No rejection data yet.[/dim]")
        con.print()

    # Agent trust
    trust = summary.get("agent_trust", {})
    if trust:
        con.print("[bold]🤝 Agent Trust Scores[/bold]")
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Agent")
        table.add_column("Trust", justify="right")
        table.add_column("Bar")
        for agent, score in sorted(trust.items(), key=lambda x: -x[1]):
            bar_len = int(score * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            color = "green" if score >= 0.7 else "yellow" if score >= 0.4 else "red"
            table.add_row(
                agent, f"[{color}]{score * 100:.0f}%[/{color}]", f"[{color}]{bar}[/{color}]"
            )
        con.print(table)
        con.print()
    else:
        con.print("[dim]No agent trust data yet.[/dim]")
        con.print()

    # Skip types
    skip = summary.get("skip_types", [])
    if skip:
        con.print("[bold yellow]🚫 Auto-Skipped Types[/bold yellow]")
        for ftype in skip:
            con.print(f"  [yellow]• {ftype}[/yellow]")
        con.print()
