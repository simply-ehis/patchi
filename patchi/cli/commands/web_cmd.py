"""
`p web` command — launch the unified Patchi web UI.

One server, one UI:
  - Mission Control dashboard (/)          — health, live agent feed, tools
  - Brain map / Council / Attacks / Tests  — intelligence views
  - Findings / Review / Chat               — workflow pages
  - Hosted control plane   (/hosted)       — overview, compliance, webhooks

Usage:
    p web                 # serve on 127.0.0.1:1612
    p web --port 8000     # custom port
    p web --open          # also open the browser

Requires the `web` extra:  pip install patchi[web]
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

console = Console()

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1612


def run(root: Path | None = None, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, open_browser: bool = False) -> None:
    """Start the unified Patchi web server (blocking)."""
    from patchi.core.config import find_project_root

    project_root = root or find_project_root()
    if project_root is None:
        console.print("[red]No .patchi project found.[/red] Run [bold]p init[/bold] first.")
        raise SystemExit(1)

    try:
        import uvicorn  # noqa: F401
    except ImportError:
        console.print("[red]Missing dependencies.[/red] Install with: [bold]pip install patchi[web][/bold]")
        raise SystemExit(1)

    from patchi.web.app import create_app

    url = f"http://{host}:{port}"
    console.print()
    console.print(f"[bold #C8621A]Patchi Web UI[/bold #C8621A] -> [link={url}]{url}[/link]")
    console.print("[dim]Mission Control · Council · Red Team · Live Tests · Hosted[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")
    console.print()

    app = create_app(project_root)

    if open_browser:
        import threading
        import webbrowser

        threading.Timer(1.5, webbrowser.open, args=(url,)).start()

    uvicorn.run(app, host=host, port=port, log_level="warning")
