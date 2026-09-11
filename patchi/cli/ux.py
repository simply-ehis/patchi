"""
CLI UX — Shared UI components for consistent user experience.

Provides spinners, progress bars, status indicators, and formatting helpers
for a polished CLI experience.

Usage:
    from patchi.cli.ux import (
        spinner, progress_bar, status_icon, format_header,
        format_error, format_success, format_warning, format_step,
        live_status, CountdownTimer,
    )
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Callable, Generator

from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con


# ── Status Icons ──────────────────────────────────────────────────────────────

def status_icon(status: str) -> str:
    """Get a status icon for the given status."""
    icons = {
        "done": "✓",
        "passed": "✓",
        "success": "✓",
        "running": "⟳",
        "pending": "–",
        "skipped": "–",
        "failed": "✗",
        "error": "✗",
        "warning": "⚠",
    }
    return icons.get(status.lower(), "·")


def status_style(status: str) -> str:
    """Get Rich style for status."""
    styles = {
        "done": "green",
        "passed": "green",
        "success": "green",
        "running": "cyan",
        "pending": "dim",
        "skipped": "yellow",
        "failed": "red",
        "error": "red",
        "warning": "yellow",
    }
    return styles.get(status.lower(), "white")


def colored_status(status: str) -> str:
    """Get colored status string."""
    icon = status_icon(status)
    style = status_style(status)
    return f"[{style}]{icon} {status}[/{style}]"


# ── Formatting Helpers ────────────────────────────────────────────────────────

def format_header(title: str, subtitle: str | None = None) -> Panel:
    """Format a section header."""
    if subtitle:
        return Panel(
            f"[bold]{title}[/bold]\n[dim]{subtitle}[/dim]",
            border_style="blue",
            padding=(0, 1),
        )
    return Panel(f"[bold]{title}[/bold]", border_style="blue", padding=(0, 1))


def format_step(step: int, total: int, description: str) -> Text:
    """Format a step indicator."""
    return Text.from_markup(f"  [{step}/{total}] {description}", style="cyan")


def format_success(message: str) -> Panel:
    """Format a success message."""
    return Panel(f"[green]✓ {message}[/green]", border_style="green", padding=(0, 1))


def format_error(message: str, details: str | None = None) -> Panel:
    """Format an error message."""
    content = f"[red]✗ {message}[/red]"
    if details:
        content += f"\n\n[dim]{details}[/dim]"
    return Panel(content, border_style="red", padding=(0, 1))


def format_warning(message: str) -> Panel:
    """Format a warning message."""
    return Panel(f"[yellow]⚠ {message}[/yellow]", border_style="yellow", padding=(0, 1))


def format_info(message: str) -> Panel:
    """Format an info message."""
    return Panel(f"[blue]ℹ {message}[/blue]", border_style="blue", padding=(0, 1))


# ── Progress Bar ──────────────────────────────────────────────────────────────

def create_progress() -> Progress:
    """Create a standard progress bar."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        con=con,
    )


def progress_bar(
    items: list[Any],
    description: str = "Processing",
    process_fn: Callable[[Any], Any] | None = None,
) -> list[Any]:
    """Run items through a progress bar."""
    results = []
    with create_progress() as progress:
        task = progress.add_task(description, total=len(items))
        for item in items:
            if process_fn:
                result = process_fn(item)
                results.append(result)
            else:
                results.append(item)
            progress.advance(task)
    return results


# ── Spinner Context Manager ───────────────────────────────────────────────────

@contextmanager
def spinner(
    message: str,
    success_message: str | None = None,
    error_message: str | None = None,
) -> Generator[Callable[[str], None], None, None]:
    """Context manager that shows a spinner while working.

    Usage:
        with spinner("Scanning...", "Done!", "Failed!") as update:
            # do work
            update("Processing files...")
            # more work
    """
    from rich.status import Status

    status = Status(message, console=con, spinner="dots")

    def update_fn(msg):
        status.update(msg)

    try:
        status.start()
        yield update_fn
        status.stop()
        if success_message:
            con.print(f"[green]✓ {success_message}[/green]")
    except Exception as e:
        status.stop()
        if error_message:
            con.print(f"[red]✗ {error_message}: {e}[/red]")
        raise


# ── Live Status Display ───────────────────────────────────────────────────────

class LiveStatus:
    """Live status display for multi-step operations."""

    def __init__(self, title: str):
        self.title = title
        self.steps: list[dict] = []
        self.current_step = 0
        self._live: Live | None = None

    def add_step(self, name: str, description: str) -> int:
        """Add a step and return its index."""
        self.steps.append({
            "name": name,
            "description": description,
            "status": "pending",
            "result": None,
        })
        return len(self.steps) - 1

    def start_step(self, index: int) -> None:
        """Mark a step as running."""
        if 0 <= index < len(self.steps):
            self.steps[index]["status"] = "running"
            self.current_step = index
            self._render()

    def complete_step(self, index: int, status: str = "done", result: str | None = None) -> None:
        """Mark a step as complete."""
        if 0 <= index < len(self.steps):
            self.steps[index]["status"] = status
            self.steps[index]["result"] = result
            self._render()

    def _render(self) -> None:
        """Render the current state."""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Status", width=3)
        table.add_column("Step", ratio=3)
        table.add_column("Result", ratio=2)

        for step in self.steps:
            icon = status_icon(step["status"])
            style = status_style(step["status"])
            result = step["result"] or ""
            table.add_row(
                f"[{style}]{icon}[/{style}]",
                step["description"],
                f"[dim]{result}[/dim]" if result else "",
            )

        if self._live:
            self._live.update(table)

    def __enter__(self) -> "LiveStatus":
        self._live = Live(table=None, console=con, refresh_per_second=4)
        self._live.start()
        return self

    def __exit__(self, *args) -> None:
        if self._live:
            self._live.stop()


# ── Confirmation Prompt ────────────────────────────────────────────────────────

def confirm(message: str, default: bool = False) -> bool:
    """Prompt for confirmation with rich styling.

    Args:
        message: The confirmation message
        default: Default answer if user just presses Enter

    Returns:
        True if confirmed, False otherwise
    """
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            choice = input(f"{message} {suffix}: ").strip().lower()
            if not choice:
                return default
            if choice in ("y", "yes"):
                return True
            if choice in ("n", "no"):
                return False
            con.print("[dim]Please enter y or n[/dim]")
        except (EOFError, KeyboardInterrupt):
            return default


def select(
    message: str,
    options: list[str],
    default: int = 0,
) -> int:
    """Prompt user to select from a list.

    Args:
        message: The prompt message
        options: List of options to choose from
        default: Default selection index

    Returns:
        Selected index
    """
    con.print(f"[bold]{message}[/bold]")
    con.print()

    for i, option in enumerate(options):
        marker = "→" if i == default else " "
        style = "cyan" if i == default else ""
        con.print(f"  {marker} [{style}]{i + 1}[/{style}]. {option}")

    con.print()

    while True:
        try:
            choice = input(f"Select (1-{len(options)}) [{default + 1}]: ").strip()
            if not choice:
                return default
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
            con.print(f"[dim]Please enter a number between 1 and {len(options)}[/dim]")
        except (ValueError, EOFError, KeyboardInterrupt):
            return default


# ── Summary Panel ──────────────────────────────────────────────────────────────

def summary_panel(
    title: str,
    items: dict[str, bool],
    elapsed: float | None = None,
) -> Panel:
    """Create a summary panel showing pass/fail status.

    Args:
        title: Panel title
        items: Dict of item_name -> passed (bool)
        elapsed: Optional elapsed time in seconds
    """
    lines = []
    passed = sum(1 for v in items.values() if v)
    total = len(items)

    for name, success in items.items():
        icon = "✓" if success else "✗"
        style = "green" if success else "red"
        lines.append(f"[{style}]{icon} {name}[/{style}]")

    content = "\n".join(lines)

    if elapsed is not None:
        content += f"\n\n[dim]Completed in {elapsed:.1f}s[/dim]"

    border = "green" if passed == total else "yellow" if passed > 0 else "red"

    return Panel(
        f"[bold]{title}[/bold]\n\n{content}\n\n"
        f"[dim]{passed}/{total} passed[/dim]",
        border_style=border,
        padding=(0, 1),
    )


# ── Result Table ──────────────────────────────────────────────────────────────

def result_table(
    title: str,
    rows: list[dict],
    columns: list[str] | None = None,
) -> Table:
    """Create a formatted result table."""
    if columns is None:
        columns = ["Check", "Status", "Findings", "Details"]

    table = Table(title=title, show_header=True, header_style="bold")
    for col in columns:
        table.add_column(col)

    for row in rows:
        values = []
        for col in columns:
            key = col.lower()
            if key in row:
                val = row[key]
                if key == "status":
                    values.append(colored_status(str(val)))
                elif key == "findings":
                    count = int(val) if val else 0
                    if count > 0:
                        values.append(f"[red]{count}[/red]")
                    else:
                        values.append("[green]0[/green]")
                else:
                    values.append(str(val))
            else:
                values.append("")
        table.add_row(*values)

    return table


# ── Countdown Timer ───────────────────────────────────────────────────────────

class CountdownTimer:
    """Visual countdown timer for timed operations."""

    def __init__(self, seconds: int, description: str = "Time remaining"):
        self.seconds = seconds
        self.description = description
        self._start = 0.0

    def __enter__(self) -> "CountdownTimer":
        self._start = time.monotonic()
        return self

    def __exit__(self, *args) -> None:
        pass

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    @property
    def remaining(self) -> float:
        return max(0, self.seconds - self.elapsed)

    @property
    def is_complete(self) -> bool:
        return self.elapsed >= self.seconds

    def format_remaining(self) -> str:
        """Format remaining time as MM:SS."""
        r = int(self.remaining)
        mins, secs = divmod(r, 60)
        return f"{mins:02d}:{secs:02d}"
