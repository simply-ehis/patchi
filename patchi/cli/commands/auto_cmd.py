"""
`p auto` — Proactive Agent (Phase 4).

Given changed file(s), propose (and with `--apply`, perform) safe fixes:
missing imports, unused imports, dead code, formatting, signature-change caller
updates, and charter violations introduced by the change.

Usage:
  p auto src/api/routes.py                — list proposed fixes
  p auto src/api/routes.py --apply        — apply safe fixes automatically
  p auto src/api/routes.py --apply --unsafe — apply all proposed fixes
"""

from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from patchi.cli.console import con
from patchi.core.brain import learning
from patchi.core.brain.proactive import run_proactive
from patchi.core.config import require_project_root


def run(
    files: list[str],
    apply: bool = False,
    unsafe: bool = False,
    reject: str | None = None,
    root: Path | None = None,
) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # Explicit teaching signal: record that the user rejects a fix type, then exit.
    if reject:
        learning.record_rejection(reject, "ProactiveAgent", r)
        count = learning.get_summary(r)["rejections"].get(reject, 0)
        con.print()
        con.print(
            f"[#FACC15]✗[/#FACC15] Recorded rejection of [bold]{reject}[/bold] "
            f"(now rejected {count}×)."
        )
        if not learning.should_suggest(reject, r):
            con.print("[dim]Patchi will no longer propose this fix type for this project.[/dim]")
        con.print()
        return

    if not files:
        con.print(
            "[red]Provide at least one changed file, e.g.[/red] "
            "[bold]p auto src/api/routes.py[/bold]"
        )
        return

    con.print()
    con.print("[dim]Scanning project to build context…[/dim]")
    result = run_proactive(r, files, apply=apply, unsafe=unsafe)

    fixes = result["fixes"]
    if not fixes and not result["suppressed"]:
        con.print("[#4ADE80]✓[/#4ADE80] No proactive fixes proposed for the changed file(s).")
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Safe", width=6)
    table.add_column("Type", width=18)
    table.add_column("File", width=34)
    table.add_column("Fix")
    for f in fixes:
        safe = "[#4ADE80]yes[/#4ADE80]" if f.safe else "[#FACC15]no[/#FACC15]"
        table.add_row(safe, f.fix_type, f.file, f.description)

    title = "[bold #C8621A]Proactive Fixes[/bold #C8621A]"
    con.print(Panel(table, title=title, border_style="#2A3D28"))
    con.print()

    for f in result["escalated"]:
        con.print(
            f"[#FACC15]⚠[/#FACC15] [yellow]Needs review:[/yellow] "
            f"{f.fix_type} → {f.file}" + (f" ({f.name})" if f.name else "")
        )
        con.print(f"  [dim]{f.description}[/dim]")
    if result["escalated"]:
        con.print()

    for f in result["suppressed"]:
        con.print(
            f"[dim]↷ suppressed (you rejected this type before): {f.fix_type} → {f.file}[/dim]"
        )
    if result["suppressed"]:
        con.print()

    if not apply:
        con.print(
            "[dim]Run with [bold]--apply[/bold] to perform safe fixes, "
            "or [bold]--apply --unsafe[/bold] for all.[/dim]"
        )
        con.print()
        return

    con.print(
        f"[#4ADE80]✓[/#4ADE80] [dim]{len(result['applied'])} applied, "
        f"{len(result['skipped'])} skipped.[/dim]"
    )
    con.print()
