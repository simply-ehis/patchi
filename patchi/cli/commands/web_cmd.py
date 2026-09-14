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


def _resolve_project(explicit: str | None) -> Path:
    """Pick the project to serve — EXACTLY like every other p <command>.

    1:1 rule: the web UI opens the project the terminal is standing in.
    Resolution is the same find_project_root() walk-up every other command
    uses (nearest .patchi at or above cwd). The only extra is an explicit
    --project override. Anything else refuses, same message, same exit.

    The multi-project story lives IN the web UI (header switcher), not in
    magic cwd guessing here.
    """
    from patchi.core.config import find_project_root

    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not (p / ".patchi").is_dir():
            console.print(f"[red]{p} has no .patchi directory.[/red] Run [bold]p init[/bold] there first.")
            raise SystemExit(1)
        return p

    found = find_project_root()
    if found:
        if found.resolve() == Path.home().resolve():
            console.print(
                "[yellow]Note:[/yellow] resolved to your HOME directory "
                f"({found}) because it contains a .patchi folder. "
                "If that's not intentional, cd into your real project or use "
                "[bold]--project <path>[/bold]."
            )
        return found

    # Same contract as require_project_root(); candidates listed as FYI only
    from patchi.core.tenant import TenantManager

    console.print("[red]No .patchi directory found.[/red] Run [bold]p init[/bold] in your project folder first.")
    nearby = TenantManager().discover_projects(near=Path.cwd())
    if nearby:
        console.print("[dim]Patchi projects near here:[/dim]")
        for c in nearby[:5]:
            console.print(f'[dim]  - {c}  ->  p web --project "{c}"[/dim]')
        if len(nearby) > 5:
            console.print(f"[dim]  … and {len(nearby) - 5} more[/dim]")
    raise SystemExit(1)


def run(
    root: Path | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    open_browser: bool = False,
    project: str | None = None,
) -> None:
    """Start the unified Patchi web server (blocking)."""
    try:
        import uvicorn  # noqa: F401
    except ImportError as e:
        console.print("[red]Missing dependencies.[/red] Install with: [bold]pip install patchi[web][/bold]")
        raise SystemExit(1) from e

    project_root = root or _resolve_project(project)

    url = f"http://{host}:{port}"
    console.print()
    console.print(f"[bold #C8621A]Patchi Web UI[/bold #C8621A] -> [link={url}]{url}[/link]")
    console.print("[dim]Mission Control · Council · Red Team · Live Tests · Hosted[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")
    console.print()

    from patchi.web.app import create_app

    app = create_app(project_root)

    if open_browser:
        import threading
        import webbrowser

        threading.Timer(1.5, webbrowser.open, args=(url,)).start()

    uvicorn.run(app, host=host, port=port, log_level="warning")
