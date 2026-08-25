from patchi.cli.console import con

"""
`p queue` — view and control the task queue.

Subcommands:
  p queue               — show queue overview
  p queue pause         — pause execution
  p queue resume        — resume
  p queue skip          — skip current active item
  p queue clear         — remove all waiting items
  p queue mode single   — set single queue mode
  p queue mode multi    — set multi queue mode
  p queue mode off      — disable queue
"""

from pathlib import Path

from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from patchi.core import config as cfg
from patchi.core import queue as q
from patchi.core.constants import QueueMode


def _root(root: Path | None) -> Path | None:
    return root


def run_show(root: Path | None = None) -> None:
    """p queue — show current queue."""
    try:
        data = q.list_all(root)
        s = q.stats(root)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    items = data["items"]
    paused = data.get("paused", False)
    current_mode = cfg.get_queue_mode(root)

    con.print()
    # Status line
    status = "[yellow]PAUSED[/yellow]" if paused else "[#4ADE80]RUNNING[/#4ADE80]"
    con.print(
        f"[bold #F2EDD6]Queue[/bold #F2EDD6]  "
        f"{status}  [dim]mode: {current_mode.value}[/dim]  "
        f"[dim]{s['waiting']} waiting · {s['active']} active · {s['done']} done[/dim]"
    )
    con.print()

    if not items:
        con.print("[dim]Nothing in the queue. Patchi is resting.[/dim]")
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("ID", style="dim", width=10)
    table.add_column("Type", style="#F2EDD6", width=12)
    table.add_column("Target", style="#B8A898", width=20)
    table.add_column("State", style="bold", width=10)
    table.add_column("Agent", style="dim", width=16)

    state_colors = {
        "waiting": "#B8A898",
        "active": "#C8621A",
        "done": "#4ADE80",
        "failed": "#FF4D6D",
        "skipped": "dim",
    }

    for item in sorted(items, key=lambda i: i.get("created", ""), reverse=True):
        state = item["state"]
        color = state_colors.get(state, "white")
        table.add_row(
            item["id"],
            item.get("type", "—"),
            item.get("target", "—"),
            Text(state, style=color),
            item.get("agent") or "—",
        )

    con.print(table)
    con.print()
    con.print("[dim]p queue pause  ·  p queue resume  ·  p queue skip  ·  p queue clear[/dim]")
    con.print()


def run_pause(root: Path | None = None) -> None:
    try:
        q.pause(root)
        con.print("[yellow]Queue paused.[/yellow] Use [bold]p queue resume[/bold] to continue.")
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")


def run_resume(root: Path | None = None) -> None:
    try:
        q.resume(root)
        con.print("[#4ADE80]Queue resumed.[/#4ADE80]")
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")


def run_skip(root: Path | None = None) -> None:
    try:
        skipped_id = q.skip_active(root)
        if skipped_id:
            con.print(f"[dim]Skipped item [bold]{skipped_id}[/bold].[/dim]")
        else:
            con.print("[dim]Nothing active to skip.[/dim]")
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")


def run_clear(root: Path | None = None) -> None:
    try:
        s = q.stats(root)
        waiting = s["waiting"]
        if waiting == 0:
            con.print("[dim]Queue is already empty.[/dim]")
            return

        con.print(f"[yellow]This will remove {waiting} waiting item(s).[/yellow]")
        confirmed = Confirm.ask("Clear the queue?", default=False)
        if confirmed:
            removed = q.clear(root)
            con.print(f"[#4ADE80]✓[/#4ADE80] Removed {removed} waiting item(s).")
        else:
            con.print("[dim]Cancelled.[/dim]")
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")


def run_set_mode(mode_str: str, root: Path | None = None) -> None:
    """p queue mode <single|multi|off>"""
    try:
        mode = QueueMode(mode_str.lower())
    except ValueError:
        con.print(f"[red]Unknown mode: {mode_str!r}[/red]\n[dim]Valid: single · multi · off[/dim]")
        return

    try:
        cfg.set_queue_mode(mode, root)
        con.print(
            f"[#4ADE80]✓[/#4ADE80] Queue mode set to [bold]{mode.value}[/bold].\n"
            f"[dim]{mode.description()}[/dim]"
        )
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
