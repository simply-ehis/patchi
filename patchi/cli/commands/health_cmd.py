"""
`p health` — Redirect to `p status --deep`.

This command is deprecated. Use `p status --deep` instead.
"""

from __future__ import annotations

from pathlib import Path

from patchi.cli.console import con


def run(root: Path | None = None, json_output: bool = False) -> None:
    """Redirect to p status --deep."""
    from patchi.cli.commands.status_cmd import run as status_run

    con.print("[dim]Note: 'p health' is deprecated. Use 'p status --deep' instead.[/dim]")
    status_run(root=root, json_output=json_output, deep=True)
