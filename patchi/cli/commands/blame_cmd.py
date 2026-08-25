"""
`p blame` — Git blame for a specific file and line.

Usage:
  p blame <file> [line]       — show who last touched the given line
  p blame <file>              — show blame for all lines
"""

from __future__ import annotations

import logging
from pathlib import Path

from patchi.cli.console import con
from patchi.core.brain.git_aware import blame_line
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.blame_cmd")

def run(file_path: str, line: int | None = None, root: Path | None = None) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if line is not None:
        result = blame_line(file_path, line, r)
        if result:
            con.print()
            con.print(f"[bold #C8621A]Line {line} of {file_path}[/bold #C8621A]")
            con.print(f"  Commit: [bold]{result.get('commit', '?')[:12]}[/bold]")
            con.print(f"  Author: {result.get('author', '?')}")
            con.print(f"  Date:   {result.get('date', '?')}")
            if result.get("summary"):
                con.print(f"  Message: {result['summary']}")
            con.print()
        else:
            con.print(f"[yellow]No blame info for line {line} in {file_path}[/yellow]")
    else:
        con.print(f"[dim]Showing full blame for {file_path}[/dim]")
        try:
            import subprocess

            resolved = (r / file_path).resolve()
            if not str(resolved).startswith(str(r.resolve())):
                con.print("[red]File path is outside the project root[/red]")
                return
            subprocess.run(["git", "blame", str(resolved)], cwd=str(r))
        except Exception as e:
            _log.warning("run failed: %s", e)
            con.print("[red]Could not run git blame[/red]")
