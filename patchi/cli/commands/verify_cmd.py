"""
`p verify` — Self-Report Verifier (Dream Assistant spec, priority #1).

Independently re-runs the project's real tests (+ scan) and reports the truth
instead of trusting a "tests pass" claim. Flags regressions vs the last baseline.

  p verify                       — re-run tests + scan, diff vs baseline, report
  p verify --no-scan             — only re-run tests
  p verify --claim "tests pass"  — assert a specific claim against actual truth
"""

from __future__ import annotations

from pathlib import Path

from rich.panel import Panel

from patchi.cli.console import con
from patchi.core.brain.verify import claim_holds, verify_project
from patchi.core.config import require_project_root


def run(
    no_scan: bool = False,
    claim: str | None = None,
    root: Path | None = None,
) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    con.print()
    con.print("[dim]Independently re-running tests (ignoring any self-report)…[/dim]")
    report = verify_project(r, run_scan=not no_scan)

    title = "[bold #C8621A]Verification[/bold #C8621A]"
    con.print(Panel(report.summary, title=title, border_style="#2A3D28"))

    if report.regression and report.regression.get("has_baseline"):
        res = report.regression.get("resolved_failures")
        if res:
            con.print(f"[dim]{len(res)} previously-failing test(s) now pass.[/dim]")

    if claim is not None:
        ok = claim_holds(claim, report)
        verdict = "[#4ADE80]TRUE[/#4ADE80]" if ok else "[#FACC15]FALSE[/#FACC15]"
        con.print()
        con.print(f'[bold]Claim:[/bold] "{claim}"  →  holds: {verdict}')
        if not ok:
            con.print("[dim]Do not report this as done. Fix and re-run [bold]p verify[/bold].[/dim]")

    con.print()
