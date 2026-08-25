"""
Cross-repo CLI command.

Runs cross-repository intelligence analysis to find
Routes, Channels, and HTTP calls across multiple indexed projects.
"""

from __future__ import annotations


def run(args):
    """Entry point for the cross-repo command."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()

    # Accept either the main.py subparser shape (action / --target) or the
    # module's own register() shape (projects / --all / --mode).
    target_projects = list(getattr(args, "projects", None) or [])
    if getattr(args, "target", None):
        target_projects = [args.target]
    mode = getattr(args, "mode", None) or "cross-repo-intelligence"
    action = getattr(args, "action", None)
    if action == "health":
        mode = "health"
    elif action == "fix":
        mode = "fix"
    all_flag = getattr(args, "all", False)

    if not target_projects:
        console.print("[yellow]No target projects specified.[/yellow]")
        console.print("Usage: p cross-repo project1 project2 [project3 ...]")
        console.print("Or: p cross-repo --all  (analyze all indexed projects)")
        return

    console.print(
        Panel(
            f"[bold]Cross-Repository Intelligence[/bold]\n"
            f"Mode: {mode}\n"
            f"Targets: {', '.join(target_projects)}",
            border_style="blue",
        )
    )

    try:
        from patchi.codebase_memory import index_repository, list_projects

        if all_flag:
            all_projects = list_projects()
            target_projects = [p["name"] for p in all_projects if p.get("name")]
            console.print(f"[dim]Found {len(target_projects)} indexed projects[/dim]")

        if len(target_projects) < 2:
            console.print("[red]Need at least 2 projects for cross-repo analysis.[/red]")
            return

        console.print(
            f"\n[bold]Running cross-repo intelligence on {len(target_projects)} projects...[/bold]\n"
        )

        results = index_repository(
            repo_path=".",
            mode="cross-repo-intelligence",
            target_projects=target_projects,
        )

        if not results:
            console.print("[yellow]No cross-repo links found.[/yellow]")
            return

        table = Table(title="Cross-Repository Links", border_style="green")
        table.add_column("Source", style="cyan")
        table.add_column("Target", style="magenta")
        table.add_column("Type", style="yellow")
        table.add_column("Detail", style="white")

        for link in results if isinstance(results, list) else []:
            source = str(link.get("source", link.get("from", "")))
            target = str(link.get("target", link.get("to", "")))
            link_type = str(link.get("type", link.get("edge_type", "")))
            detail = str(link.get("detail", link.get("label", "")))[:80]
            table.add_row(source, target, link_type, detail)

        console.print(table)
        console.print(
            f"\n[green]Found {len(results) if isinstance(results, list) else 0} cross-repo links.[/green]"
        )

    except ImportError:
        console.print("[red]codebase-memory module not available.[/red]")
        console.print("Install it with: pip install codebase-memory")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def register(subparsers):
    """Register the cross-repo subcommand."""
    parser = subparsers.add_parser(
        "cross-repo",
        help="Cross-repository intelligence analysis",
        description="Find Routes, Channels, and HTTP calls across multiple indexed projects.",
    )
    parser.add_argument("projects", nargs="*", help="Target project names to analyze")
    parser.add_argument("--all", action="store_true", help="Analyze all indexed projects")
    parser.add_argument(
        "--mode",
        default="cross-repo-intelligence",
        help="Analysis mode (default: cross-repo-intelligence)",
    )
    parser.set_defaults(func=run)
    return parser
