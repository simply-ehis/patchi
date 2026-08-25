"""
`p chains` — Show exploit chains and intent gaps from the last scan.

Usage:
  p chains                — show all chains + intent gaps
  p chains --json         — machine-readable output
  p chains --min-score 50 — filter chains by minimum score
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.chains_cmd")


def run(
    min_score: float = 0,
    json_output: bool = False,
    root: Path | None = None,
) -> None:
    """Entry point for `p chains`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    ci_path = r / ".patchi" / "chain_intent.json"
    if not ci_path.is_file():
        con.print("[yellow]No chain/intent data found.[/yellow]")
        con.print("[dim]Run [bold]p scan[/bold] first to generate exploit chains and intent analysis.[/dim]")
        return

    try:
        data = json.loads(ci_path.read_text(encoding="utf-8"))
    except Exception as e:
        con.print(f"[red]Failed to load chain data: {e}[/red]")
        return

    chains = data.get("chains", [])
    intent = data.get("intent_report")

    if not chains and not intent:
        con.print("[dim]No exploit chains or intent gaps found in last scan.[/dim]")
        return

    # Filter by min score
    if min_score > 0:
        chains = [c for c in chains if c.get("score", 0) >= min_score]

    if json_output:
        _print_json(chains, intent)
        return

    # ── Rich output ───────────────────────────────────────────────────────
    con.print()
    con.print("[bold #C8621A]── Exploit Chains & Intent Gaps ──[/bold #C8621A]")
    con.print()

    # Chains table
    if chains:
        con.print(f"[bold]Exploit Chains[/bold] ({len(chains)})")
        con.print()

        table = Table(show_header=True, header_style="bold #C8621A", box=None)
        table.add_column("#", style="dim", width=3)
        table.add_column("Severity", width=10)
        table.add_column("Score", justify="right", width=6)
        table.add_column("Steps", justify="right", width=5)
        table.add_column("Narrative")

        for i, chain in enumerate(chains, 1):
            sev = chain.get("severity", "info")
            score = chain.get("score", 0)
            length = chain.get("length", 0)
            narrative = chain.get("narrative", "")

            sev_color = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(sev, "dim")

            table.add_row(
                str(i),
                f"[{sev_color}]{sev}[/{sev_color}]",
                f"{score:.0f}",
                str(length),
                narrative[:90],
            )

        con.print(table)
        con.print()

        # Show step details for top chains
        for i, chain in enumerate(chains[:3], 1):
            steps = chain.get("steps", [])
            if steps:
                con.print(f"  [dim]Chain #{i} steps:[/dim]")
                for step in steps:
                    role = step.get("role", "?")
                    ftype = step.get("type", "?")
                    file_ = step.get("file", "?")
                    line = step.get("line", "?")
                    sev = step.get("severity", "info")
                    con.print(f"    [{sev}] [{role}] {ftype} @ {file_}:{line}")
                con.print()
    else:
        con.print("[dim]No exploit chains found.[/dim]")
        con.print()

    # Intent gaps
    if intent and intent.get("gaps_total", 0) > 0:
        con.print(f"[bold]Intent Gaps[/bold] ({intent['gaps_total']} across {intent.get('routes_total', '?')} routes)")
        con.print()

        for category, label, color in [
            ("unauthenticated_state_changing", "Unauthenticated state-changing routes", "red"),
            ("admin_without_strict_guard", "Admin routes without strict guard", "yellow"),
            ("unprotected_among_protected", "Unprotected routes among protected peers", "yellow"),
        ]:
            routes = intent.get(category, [])
            if routes:
                con.print(f"  [{color}]● {label} ({len(routes)})[/{color}]")
                for r in routes[:5]:
                    method = r.get("method", "?")
                    path = r.get("path", "?")
                    file_ = r.get("file", "?")
                    line = r.get("line", "?")
                    has_guard = r.get("has_auth_guard", False)
                    guard = "✓" if has_guard else "✗"
                    con.print(f"    {method} {path} @ {file_}:{line} [dim]({guard})[/dim]")
                if len(routes) > 5:
                    con.print(f"    [dim]… and {len(routes) - 5} more[/dim]")
                con.print()

    if not chains and (not intent or intent.get("gaps_total", 0) == 0):
        con.print("[dim]No issues found. The codebase is clean.[/dim]")
    con.print()


def _print_json(chains: list, intent: dict | None) -> None:
    """Print JSON output."""
    output = {
        "chains": chains,
        "intent_report": intent,
        "summary": {
            "total_chains": len(chains),
            "critical": sum(1 for c in chains if c.get("severity") == "critical"),
            "high": sum(1 for c in chains if c.get("severity") == "high"),
            "intent_gaps": intent.get("gaps_total", 0) if intent else 0,
        },
    }
    con.print(json.dumps(output, indent=2))
