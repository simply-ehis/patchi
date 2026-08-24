"""
`p learn` — Learning Brain (Phase 5).

Shows what Patchi has learned from your accept/reject patterns and the reusable
fix patterns it has captured, lets you re-derive conventions from a fresh scan,
and lets you reset that learning.

  p learn              — show learned accept/reject patterns + which fix types are skipped
  p learn patterns     — show captured fix patterns
  p learn --force      — re-derive conventions/patterns from the current project
  p learn --reset      — forget all learned patterns for this project
"""

from __future__ import annotations

from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.core.brain import learning
from patchi.core.config import require_project_root


import logging
_log = logging.getLogger("patchi.cli.learn_cmd")

def run(
    force: bool = False,
    sub: str | None = None,
    reset: bool = False,
    root: Path | None = None,
) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if reset:
        path = r / ".patchi" / "learning.json"
        if path.exists():
            try:
                path.unlink()
                con.print("[#4ADE80]✓[/#4ADE80] Learning data reset for this project.")
            except Exception as e:
                _log.warning("run failed: %s", e)
                con.print("[red]Could not reset learning data.[/red]")
        else:
            con.print("[dim]Nothing to reset.[/dim]")
        con.print()
        return

    if sub == "patterns":
        _show_patterns(r)
        return

    if force:
        _relearn(r)

    summary = learning.get_summary(r)
    has_data = summary["acceptances"] or summary["rejections"] or summary.get("agent_trust")
    if not has_data:
        con.print()
        con.print("[dim]No learning data yet. Patchi learns from the fixes you accept or reject "
                  "(e.g. [bold]p auto <files> --reject <type>[/bold]).[/dim]")
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Fix type", width=20)
    table.add_column("Accepted", width=10)
    table.add_column("Rejected", width=10)
    table.add_column("Status", width=14)
    types = list(summary["acceptances"].keys()) + list(summary["rejections"].keys())
    for t in sorted(set(types)):
        acc = summary["acceptances"].get(t, 0)
        rej = summary["rejections"].get(t, 0)
        status = "[yellow]skipped[/yellow]" if t in summary["skip_types"] else "[dim]active[/dim]"
        table.add_row(t, str(acc), str(rej), status)

    con.print()
    con.print(table)
    if summary.get("agent_trust"):
        con.print()
        con.print("[dim]Agent trust:[/dim]")
        for agent, score in summary["agent_trust"].items():
            con.print(f"  {agent}: {score}")
    con.print()
    con.print("[dim]Run [bold]p learn patterns[/bold] to see captured fix strategies, "
              "[bold]p learn --reset[/bold] to forget.[/dim]")
    con.print()


def _show_patterns(r: Path) -> None:
    patterns = learning.list_fix_patterns(r)
    if not patterns:
        con.print()
        con.print("[dim]No fix patterns captured yet.[/dim]")
        con.print()
        return
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Type", width=18)
    table.add_column("File", width=30)
    table.add_column("Strategy", width=22)
    table.add_column("Summary", width=34)
    for p in patterns:
        table.add_row(
            p.get("finding_type", ""),
            p.get("file_pattern", ""),
            p.get("fix_strategy", ""),
            p.get("fix_summary", ""),
        )
    con.print()
    con.print(table)
    con.print()


def _relearn(r: Path) -> None:
    """Re-derive conventions/patterns from a fresh proactive scan of the project."""
    try:
        from patchi.core.brain.proactive import ProactiveAgent
        from patchi.core.brain.scanner import FileScanner

        scanner = FileScanner(r)
        file_infos = scanner.scan()
        agent = ProactiveAgent(r)
        captured = 0
        for fi in file_infos:
            fixes = agent.analyze_change([fi.path], file_infos, None, None, include_format=False)
            for f in fixes:
                learning.record_fix_pattern(
                    f.fix_type, f.file, "auto", f.description, r
                )
                captured += 1
        con.print(f"[dim]Re-learned {captured} fix pattern(s) from the current project.[/dim]")
    except Exception as e:
        con.print(f"[dim]Re-learn skipped: {e}[/dim]")
