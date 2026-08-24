"""
`p intent` — Business-logic / access-control analysis.

Extracts HTTP routes + auth guards, then reports the gaps:
  - state-changing endpoints with no auth
  - admin-surface routes without strict admin guards
  - unguarded handlers among guarded siblings

Usage:
    p intent               — analyze and show gaps
    p intent --json        — machine-readable

Exit codes: 0 clean · 1 gaps found · 2 nothing analyzed
"""

from __future__ import annotations

import json
import sys

from rich.table import Table

from patchi.cli.console import con
from patchi.core.config import require_project_root


def run(json_output: bool = False) -> int:
    """Entry point for `p intent`."""
    try:
        r = require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return 2

    from patchi.core.security.intent_analyzer import IntentAnalyzer, findings_from_report

    con.print()
    con.print("[bold #C8621A]Business Logic Analysis[/bold #C8621A]  [dim]routes + auth intent[/dim]")
    con.print()

    analyzer = IntentAnalyzer()
    report = analyzer.analyze_root(r)

    if not report.routes:
        con.print("[yellow]No routes detected — nothing to analyze.[/yellow]")
        con.print("[dim]Supported: Python route decorators (Flask/FastAPI/Django-style).[/dim]")
        return 2

    if json_output:
        sys.stdout.write(json.dumps(report.to_dict(), indent=2) + "\n")
        return 1 if report.gap_count else 0

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Method", width=7)
    table.add_column("Path", width=34)
    table.add_column("Handler", width=26)
    table.add_column("Auth", width=6)
    table.add_column("Flag", style="dim")

    def _flag(r) -> str:
        if r in report.unauthenticated_state_changing:
            return "[#FF4D6D]no-auth on write[/#FF4D6D]"
        if r in report.admin_without_strict_guard:
            return "[#FF8C42]admin surface[/#FF8C42]"
        if r in report.unprotected_among_protected:
            return "[#FACC15]unguarded sibling[/#FACC15]"
        return ""

    for rt in report.routes[:60]:
        table.add_row(
            rt.method,
            (rt.path or "?")[:34],
            rt.function_name[:26],
            "[#4ADE80]yes[/#4ADE80]" if rt.has_auth_guard else "[#FF4D6D]NO[/#FF4D6D]",
            _flag(rt),
        )
    con.print(table)
    shown = min(len(report.routes), 60)
    if len(report.routes) > shown:
        con.print(f"[dim]… and {len(report.routes) - shown} more[/dim]")

    con.print()
    con.print(
        f"[bold]{report.gap_count} gap(s)[/bold] across "
        f"{len(report.routes)} route(s). "
        f"[dim]Findings feed `p chain` as entry nodes.[/dim]"
    )
    con.print()

    findings = findings_from_report(report, r)
    if findings and not json_output:
        con.print(f"[dim]Chain-ready findings generated: {len(findings)}[/dim]")
        con.print()

    return 1 if report.gap_count else 0
