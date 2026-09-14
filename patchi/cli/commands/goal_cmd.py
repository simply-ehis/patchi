"""
`p goal` — loop until a health target is reached (restored).

  p goal                     — iterate scan→fix until health 100 (max 5 rounds)
  p goal --target 85         — stop at 85 instead
  p goal --max-loops 3       — cap iterations
  p goal --dry-run           — report current health and the plan, change nothing

Restoration note (Part 3 §1): registered in COMMANDS.md §10 and the CLI
registry but the handler module was deleted in ef77be5 while the registry
entry survived — every invocation crashed on import. Rebuilt on the honest
measurement chain (`p doctor` health probe + `p fix`), NOT on a health score
that can silently report 100: the loop re-checks real health each round and
stops when the target is genuinely met, the loop budget is exhausted, or a
round makes no progress — whichever comes first.
"""

from __future__ import annotations

import time
from pathlib import Path

from rich.panel import Panel

from patchi.cli.console import con
from patchi.core.config import require_project_root


def _health_now(root: Path) -> int | None:
    """Best-effort real health number; None when it cannot be computed."""
    try:
        from patchi.core.health import compute as compute_health

        return int(compute_health(root).total)
    except Exception as e:
        con.print(f"  [dim]health unavailable: {e}[/dim]")
        return None


def _run_fix_round(root: Path, dry_run: bool) -> bool:
    """One safe-fix round via the existing `p fix` machinery. True = ran."""
    try:
        from patchi.cli.commands import fix_cmd

        fix_cmd.run(area=None, dry_run=dry_run, preview=False, safe_all=True, root=root)
        return True
    except Exception as e:
        con.print(f"  [yellow]fix round failed: {e}[/yellow]")
        return False


def run(
    max_loops: int = 5,
    target: int = 100,
    dry_run: bool = False,
    root: Path | None = None,
) -> int:
    """Entry point for `p goal`. Returns a process exit code."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return 2

    target = max(0, min(100, target))
    con.print()
    con.print(
        Panel(
            f"[bold #F2EDD6]Goal:[/bold #F2EDD6] health ≥ [bold]{target}[/bold]  "
            f"[dim]· max {max_loops} round(s) · {'DRY RUN' if dry_run else 'applying safe fixes'}[/dim]",
            title="[bold #C8621A]p goal[/bold #C8621A]",
            border_style="#C8621A",
            padding=(0, 1),
        )
    )

    current = _health_now(r)
    if current is None:
        con.print("[red]Cannot measure health — run `p scan` first, then retry.[/red]")
        return 2

    con.print(f"  Current health: [bold]{current}/100[/bold]")
    if current >= target:
        con.print("[#4ADE80]✓[/#4ADE80] Target already met. Nothing to do.")
        con.print()
        return 0

    if dry_run:
        con.print(
            f"  [dim]Would run up to {max_loops} safe-fix round(s) "
            f"(scan → fix → reassess) to close the {target - current}-point gap.[/dim]"
        )
        con.print()
        return 0

    start = time.monotonic()
    for round_no in range(1, max_loops + 1):
        con.print(f"\n[bold #C8621A]Round {round_no}/{max_loops}[/bold #C8621A]")
        before = _health_now(r) or current

        if not _run_fix_round(r, dry_run=False):
            con.print("  [yellow]Round aborted — fix step unavailable.[/yellow]")
            break

        after = _health_now(r)
        if after is None:
            con.print("  [yellow]Health unavailable after round — stopping.[/yellow]")
            break

        delta = after - before
        arrow = "↑" if delta > 0 else ("→" if delta == 0 else "↓")
        con.print(f"  {arrow} health {before} → [bold]{after}[/bold] ({delta:+d})")

        if after >= target:
            con.print(f"\n[#4ADE80]✓ Target met: {after}/100 ≥ {target}.[/#4ADE80]")
            con.print(f"[dim]Done in {time.monotonic() - start:.0f}s.[/dim]")
            con.print()
            return 0

        if delta <= 0:
            con.print("  [dim]No progress this round — stopping rather than churning the codebase for a number.[/dim]")
            break
        current = after

    con.print(
        f"\n[#FACC15]⚠[/#FACC15] Stopped at [bold]{current}/100[/bold] "
        f"(target {target}). Run `p doctor` to see what's holding it back."
    )
    con.print()
    return 1
