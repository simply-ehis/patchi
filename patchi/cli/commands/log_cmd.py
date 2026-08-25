"""
`p log` — Git changelog.

Usage:
  p log [--since HEAD~N]      — show recent commits with changed files
  p log --since HEAD~5        — show last 5 commits
  p log --since 2026-01-01    — show commits since a date
"""

from __future__ import annotations

from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.core.brain.git_aware import changelog
from patchi.core.config import require_project_root


def run(since: str = "HEAD~10", root: Path | None = None) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    entries = changelog(r, since)

    if not entries:
        con.print("[dim]No git history found or not a git repository.[/dim]")
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Hash", style="bold #F2EDD6", width=10)
    table.add_column("Date", width=12)
    table.add_column("Author", width=18)
    table.add_column("Message", style="dim", width=50)
    table.add_column("Files", style="dim", width=20)

    for entry in entries:
        files_str = ", ".join(entry.get("files", [])[:3])
        if len(entry.get("files", [])) > 3:
            files_str += f" +{len(entry['files']) - 3} more"
        table.add_row(
            entry.get("hash", "?"),
            entry.get("date", ""),
            entry.get("author", "")[:18],
            entry.get("summary", "")[:50],
            files_str,
        )

    con.print()
    con.print(table)
    con.print()
    con.print(f"[dim]Total: {len(entries)} entries (since {since})[/dim]")
    con.print()
