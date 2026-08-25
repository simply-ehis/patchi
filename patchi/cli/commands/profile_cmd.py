"""
`p profile` — Show agent profiler stats from the last scan.

Usage:
  p profile              — show all agent profiles
  p profile auth_agent   — show details for one agent
  p profile --json       — machine-readable output
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.profile_cmd")


def run(
    agent_name: str | None = None,
    json_output: bool = False,
    root: Path | None = None,
) -> None:
    """Entry point for `p profile`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    try:
        from patchi.core.ai.agent_profiler import (
            get_all_profiles,
            get_profile_summary,
        )
    except ImportError as e:
        con.print(f"[red]Agent profiler not available: {e}[/red]")
        return

    if agent_name:
        _show_agent_detail(r, agent_name)
        return

    summary = get_profile_summary(r)
    profiles = get_all_profiles(r)

    if not profiles:
        con.print("[dim]No agent profiles yet. Run a scan to start collecting data.[/dim]")
        return

    if json_output:
        con.print(json.dumps({
            "summary": summary,
            "agents": {k: v.to_dict() for k, v in profiles.items()},
        }, indent=2))
        return

    con.print()
    con.print("[bold #C8621A]── Agent Profiles ──[/bold #C8621A]")
    con.print()

    # Summary line
    con.print(
        f"  [bold]{summary['agents']}[/bold] agents · "
        f"[bold]{summary['total_runs']}[/bold] total runs · "
        f"[bold]${summary['total_cost']:.4f}[/bold] total cost · "
        f"[bold]{summary['total_findings']}[/bold] findings · "
        f"accuracy [bold]{summary['avg_accuracy'] * 100:.1f}%[/bold]"
    )
    con.print()

    # Table
    table = Table(show_header=True, header_style="bold #C8621A", box=None)
    table.add_column("Agent", style="bold")
    table.add_column("Runs", justify="right")
    table.add_column("P50", justify="right")
    table.add_column("P95", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Accuracy", justify="right")
    table.add_column("Cost", justify="right")
    table.add_column("Model")

    for name, p in sorted(profiles.items(), key=lambda x: -x[1].run_count):
        acc_str = f"{p.accuracy * 100:.0f}%" if p.run_count >= 3 else "n/a"
        acc_color = (
            "green" if p.accuracy >= 0.8
            else "yellow" if p.accuracy >= 0.5
            else "red"
        ) if p.run_count >= 3 else "dim"

        p95_str = f"{p.p95_wall_ms:.0f}ms"
        p95_color = (
            "red" if p.p95_wall_ms > 5000
            else "yellow" if p.p95_wall_ms > 2000
            else ""
        )

        table.add_row(
            name,
            str(p.run_count),
            f"{p.p50_wall_ms:.0f}ms",
            f"[{p95_color}]{p95_str}[/{p95_color}]" if p95_color else p95_str,
            str(p.total_findings),
            f"[{acc_color}]{acc_str}[/{acc_color}]",
            f"${p.total_cost_usd:.4f}",
            p.most_used_model or "—",
        )

    con.print(table)

    # Slowest agents
    slowest = summary.get("slowest", [])
    if slowest:
        con.print()
        con.print("  [bold]Slowest agents (P95):[/bold]")
        for s in slowest[:5]:
            con.print(f"    {s['agent']}: [dim]{s['p95_ms']}ms[/dim]")
    con.print()


def _show_agent_detail(root: Path, agent_name: str) -> None:
    """Show detailed profile for one agent."""
    from patchi.core.ai.agent_profiler import get_profile

    profile = get_profile(root, agent_name)
    if profile.run_count == 0:
        con.print(f"[dim]No data for agent '{agent_name}'.[/dim]")
        return

    con.print()
    con.print(f"[bold #C8621A]── Agent Profile: {agent_name} ──[/bold #C8621A]")
    con.print()
    con.print(f"  Runs:        [bold]{profile.run_count}[/bold]")
    con.print(f"  P50 latency: [bold]{profile.p50_wall_ms:.0f}ms[/bold]")
    con.print(f"  P95 latency: [bold]{profile.p95_wall_ms:.0f}ms[/bold]")
    con.print(f"  Total wall:  {profile.total_wall_ms / 1000:.1f}s")
    con.print(f"  Findings:    [bold]{profile.total_findings}[/bold]")
    con.print(f"  Accepted:    [green]{profile.total_accepted}[/green]")
    con.print(f"  Rejected:    [red]{profile.total_rejected}[/red]")
    if profile.run_count >= 3:
        con.print(f"  Accuracy:    [bold]{profile.accuracy * 100:.1f}%[/bold]")
    con.print(f"  Avg/run:     {profile.avg_findings_per_run:.1f} findings")
    con.print(f"  Total cost:  [bold]${profile.total_cost_usd:.4f}[/bold]")
    con.print(f"  Model:       {profile.most_used_model or '—'}")
    con.print()
