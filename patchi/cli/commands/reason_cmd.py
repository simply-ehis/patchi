from patchi.cli.console import con
"""
`p ask` / `p why` / `p impact` — the Reasoning Engine (Pillar 3).

  p ask "what does the auth subsystem do?"  — NL answer from the layered brain
  p why src/auth/login.py                   — why a file matters (dependents)
  p impact src/api/routes.py                — change-impact / blast radius report

All three read the cached Layered Brain (built by `p scan`); they never re-read
raw source, so they're instant and offline-safe.
"""

from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from patchi.core.brain.reasoning import ReasoningEngine
from patchi.core.config import require_project_root


def run_ask(question: str, root: Path | None = None) -> None:
    """p ask "<question>" — answer from the layered brain."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if not question or not question.strip():
        con.print("[red]Provide a question, e.g.[/red] "
                  "[bold]p ask \"what does the auth subsystem do?\"[/bold]")
        return

    engine = ReasoningEngine(r)
    answer = engine.ask(question)
    con.print()
    con.print(Panel(answer, title="[bold #C8621A]Patchi · Reasoning[/bold #C8621A]",
                    border_style="#2A3D28"))
    con.print()


def run_why(path: str, root: Path | None = None) -> None:
    """p why <file> — why a file matters."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    engine = ReasoningEngine(r)
    info = engine.why(path)
    if "error" in info:
        con.print(f"[yellow]{info['error']}[/yellow]")
        return

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_row("[bold #F2EDD6]File[/bold #F2EDD6]", info["file"])
    table.add_row("[bold #F2EDD6]Layer[/bold #F2EDD6]", info["layer"])
    table.add_row("[bold #F2EDD6]Importance[/bold #F2EDD6]", info["importance"])
    table.add_row("[bold #F2EDD6]Purpose[/bold #F2EDD6]", info["purpose"] or "—")
    table.add_row(
        "[bold #F2EDD6]Depended on by[/bold #F2EDD6]",
        ", ".join(info["depended_on_by"]) or "nothing (no internal dependents)",
    )
    table.add_row(
        "[bold #F2EDD6]Files in layer[/bold #F2EDD6]", str(info["files_in_layer"])
    )
    con.print()
    con.print(Panel(table, title="[bold #C8621A]Why this file matters[/bold #C8621A]",
                    border_style="#2A3D28"))
    con.print()


def run_impact(files: list[str], root: Path | None = None) -> None:
    """p impact <file> [<file> ...] — change-impact / blast-radius report."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if not files:
        con.print("[red]Provide at least one changed file, e.g.[/red] "
                  "[bold]p impact src/api/routes.py[/bold]")
        return

    engine = ReasoningEngine(r)
    analysis = engine.impact_analysis(files)

    con.print()
    con.print(f"[dim]{analysis.summary}[/dim]")
    con.print()

    if analysis.affected_layers:
        con.print("[bold #F2EDD6]Directly affected layers:[/bold #F2EDD6]")
        for name in analysis.affected_layers:
            con.print(f"  • {name}")
    if analysis.impacted_layers:
        con.print()
        con.print("[bold #FF8C42]Blast radius (downstream dependents):[/bold #FF8C42]")
        for name in analysis.impacted_layers:
            con.print(f"  • {name}")
    elif analysis.affected_layers:
        con.print()
        con.print("[dim]No downstream layers depend on the changed code.[/dim]")
    con.print()
