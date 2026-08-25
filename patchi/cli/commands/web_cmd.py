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
    """Pick the project to serve.

    Order:
      1. --project PATH (must contain .patchi)
      2. nearest ancestor of cwd containing .patchi  (inside a repo)
      3. single child of cwd containing .patchi       (workspace folder pattern)
      4. otherwise: error listing discovered candidates so the user can choose
    """
    from patchi.core.config import find_project_root
    from patchi.core.tenant import TenantManager

    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not (p / ".patchi").is_dir():
            console.print(f"[red]{p} has no .patchi directory.[/red] Run [bold]p init[/bold] there first.")
            raise SystemExit(1)
        return p

    up = find_project_root()
    if up:
        return up

    # Workspace pattern: cwd holds several checkouts
    mgr = TenantManager()
    candidates = mgr.discover_projects(near=Path.cwd())
    if len(candidates) == 1:
        return candidates[0]
    if candidates:
        console.print("[yellow]Multiple Patchi projects found here:[/yellow]")
        for c in candidates:
            console.print(f"  - {c}")
        console.print("Start one explicitly: [bold]p web --project <path>[/bold]")
        raise SystemExit(1)

    console.print("[red]No .patchi project found.[/red] Run [bold]p init[/bold] or pass [bold]--project <path>[/bold].")
    raise SystemExit(1)


def run(root: Path | None = None, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, open_browser: bool = False, project: str | None = None) -> None:
    """Start the unified Patchi web server (blocking)."""
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        console.print("[red]Missing dependencies.[/red] Install with: [bold]pip install patchi[web][/bold]")
        raise SystemExit(1)

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
