"""
`p web` command — archived.

The Web UI has been archived to `.patchi/web_archive/` for focused CLI
development. The code is preserved but no longer actively maintained.

To run it manually:
    pip install fastapi uvicorn
    python -m uvicorn patchi.web.app:create_app --host 127.0.0.1 --port 1612
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

console = Console()


def run(root: Path | None = None) -> None:
    console.print("[bold yellow]Web UI Archived[/bold yellow]")
    console.print()
    console.print(
        "The Patchi Web UI has been [bold]archived[/bold] to focus on CLI development."
    )
    console.print("Source code preserved at: [dim].patchi/web_archive/[/dim]")
    console.print()
    console.print("Use the CLI instead:")
    console.print("  [cyan]p scan[/cyan]        — scan your project")
    console.print("  [cyan]p security[/cyan]    — run security agents")
    console.print("  [cyan]p fix[/cyan]         — apply fixes")
    console.print("  [cyan]p status[/cyan]      — show health and state")
    console.print("  [cyan]p chat[/cyan]        — ask questions about your project")
