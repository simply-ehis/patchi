"""
`p agent-stats` — Unified agent profiling and learning brain state.

Combines the original `p profile` (agent profiler stats) and `p learning`
(learning brain accept/reject patterns) into a single command.

Usage:
  p agent-stats              — show all agent profiles + learning state
  p agent-stats auth_agent   — show details for one agent
  p agent-stats --json       — machine-readable output
  p agent-stats --profile    — show only agent profiler stats
  p agent-stats --learning   — show only learning brain state
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.agent_stats_cmd")


def run(
    agent_name: str | None = None,
    json_output: bool = False,
    root: Path | None = None,
    profile: bool = False,
    learning: bool = False,
) -> None:
    """Entry point for `p agent-stats`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # Specific agent detail
    if agent_name:
        _show_agent_detail(r, agent_name)
        return

    # Collect data from both sources
    profile_data = _get_profile_data(r)
    learning_data = _get_learning_data(r)

    if json_output:
        payload = {
            "profile": profile_data,
            "learning": learning_data,
        }
        con.print(json.dumps(payload, indent=2, default=str))
        return

    con.print()
    con.print("[bold #C8621A]── Agent Stats ──[/bold #C8621A]")
    con.print()

    # Show profiler stats (unless --learning only)
    if not learning:
        _show_profile_section(profile_data)

    # Show learning state (unless --profile only)
    if not profile:
        _show_learning_section(learning_data)

    con.print()


def _get_profile_data(root: Path) -> dict:
    """Get agent profiler data."""
    try:
        from patchi.core.ai.agent_profiler import get_all_profiles, get_profile_summary

        profiles = get_all_profiles(root)
        summary = get_profile_summary(root)
        return {
            "summary": summary,
            "profiles": {k: v.to_dict() for k, v in profiles.items()},
        }
    except ImportError:
        return {"summary": {}, "profiles": {}}


def _get_learning_data(root: Path) -> dict:
    """Get learning brain data."""
    try:
        from patchi.core.brain.learning import get_summary

        return get_summary(root)
    except ImportError:
        return {}


def _show_profile_section(data: dict) -> None:
    """Show the agent profiler section."""
    summary = data.get("summary", {})
    profiles = data.get("profiles", {})

    if not profiles:
        con.print("[dim]No agent profiles yet. Run a scan to start collecting data.[/dim]")
        con.print()
        return

    con.print("[bold]Agent Profiler[/bold]")
    con.print()

    # Summary line
    con.print(
        f"  [bold]{summary.get('agents', 0)}[/bold] agents · "
        f"[bold]{summary.get('total_runs', 0)}[/bold] total runs · "
        f"[bold]${summary.get('total_cost', 0):.4f}[/bold] total cost · "
        f"[bold]{summary.get('total_findings', 0)}[/bold] findings · "
        f"accuracy [bold]{summary.get('avg_accuracy', 0) * 100:.1f}%[/bold]"
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

    for name, p in sorted(profiles.items(), key=lambda x: -x[1].get("run_count", 0)):
        run_count = p.get("run_count", 0)
        p50 = p.get("p50_wall_ms", 0)
        p95 = p.get("p95_wall_ms", 0)
        findings = p.get("total_findings", 0)
        accuracy = p.get("accuracy", 0)
        cost = p.get("total_cost_usd", 0)
        model = p.get("most_used_model", "—")

        acc_str = f"{accuracy * 100:.0f}%" if run_count >= 3 else "n/a"
        acc_color = (
            ("green" if accuracy >= 0.8 else "yellow" if accuracy >= 0.5 else "red")
            if run_count >= 3
            else "dim"
        )

        p95_str = f"{p95:.0f}ms"
        p95_color = "red" if p95 > 5000 else "yellow" if p95 > 2000 else ""

        table.add_row(
            name,
            str(run_count),
            f"{p50:.0f}ms",
            f"[{p95_color}]{p95_str}[/{p95_color}]" if p95_color else p95_str,
            str(findings),
            f"[{acc_color}]{acc_str}[/{acc_color}]",
            f"${cost:.4f}",
            model or "—",
        )

    con.print(table)

    # Slowest agents
    slowest = summary.get("slowest", [])
    if slowest:
        con.print()
        con.print("  [bold]Slowest agents (P95):[/bold]")
        for s in slowest[:5]:
            con.print(f"    {s.get('agent', '?')}: [dim]{s.get('p95_ms', 0)}ms[/dim]")
    con.print()


def _show_learning_section(data: dict) -> None:
    """Show the learning brain section."""
    if not data:
        con.print("[dim]No learning data yet. Run scans and accept/reject findings to build patterns.[/dim]")
        con.print()
        return

    con.print("[bold]Learning Brain[/bold]")
    con.print()

    # Acceptances
    acceptances = data.get("acceptances", {})
    if acceptances:
        con.print("[bold green]Accepted Findings[/bold green]")
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
    rejections = data.get("rejections", {})
    if rejections:
        con.print("[bold red]Rejected Findings[/bold red]")
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
    trust = data.get("agent_trust", {})
    if trust:
        con.print("[bold]Agent Trust Scores[/bold]")
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Agent")
        table.add_column("Trust", justify="right")
        table.add_column("Bar")
        for agent, score in sorted(trust.items(), key=lambda x: -x[1]):
            bar_len = int(score * 20)
            bar = "#" * bar_len + "." * (20 - bar_len)
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
    skip = data.get("skip_types", [])
    if skip:
        con.print("[bold yellow]Auto-Skipped Types[/bold yellow]")
        for ftype in skip:
            con.print(f"  [yellow]* {ftype}[/yellow]")
        con.print()


def _show_agent_detail(root: Path, agent_name: str) -> None:
    """Show detailed profile for one agent."""
    try:
        from patchi.core.ai.agent_profiler import get_profile
    except ImportError:
        con.print("[red]Agent profiler not available.[/red]")
        return

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
    con.print()
