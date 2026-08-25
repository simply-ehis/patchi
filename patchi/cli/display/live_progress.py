"""
Lightweight live progress display for single-command streaming.

Shows an inline updating panel with:
- Title header
- Live log lines (ring buffer, last 20 shown)
- Optional step-based progress bar
- Auto-collapse to one-line summary when stopped

Thread-safe — call from any thread.
No screen/alt-screen mode — works inline in the terminal.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.text import Text

_log = logging.getLogger("patchi.cli.live_progress")

@dataclass
class _ProgressState:
    log_lines: list[tuple[str, str]] = field(default_factory=list)
    total_steps: int = 0
    current_step: int = 0
    sub_label: str = ""
    findings: int = 0
    status_text: str = "running…"
    done: bool = False
    failed: bool = False


class LiveProgress:
    """
    Inline live progress display for a single command.

    Usage:
        lp = LiveProgress(console, title="p security")
        lp.start()
        lp.log("Scanning foo.py")
        lp.set_progress(5, 10, "TaintAnalyzer")
        lp.update()
        lp.stop(summary="3 findings in 1.2s")
    """

    def __init__(self, console: Console | None = None, title: str = "progress"):
        self.con = console or Console()
        self._title = title
        self._lock = threading.RLock()
        self._state = _ProgressState()
        self._live: Live | None = None
        self._start_time: float = 0.0

    def start(self):
        self._start_time = time.monotonic()
        self._live = Live(
            self._render(),
            console=self.con,
            refresh_per_second=8,
            transient=False,
            screen=False,
        )
        self._live.__enter__()

    def stop(self, summary: str = ""):
        if self._live:
            with self._lock:
                self._state.done = True
            self._live.update(self._render())
            try:
                self._live.__exit__(None, None, None)
            except Exception as e:
                _log.warning("LiveProgress.stop failed: %s", e)
            self._live = None

        elapsed = int((time.monotonic() - self._start_time) * 1000)
        if summary:
            self.con.print(f"  [bold #A78BFA]{self._title}:[/bold #A78BFA] {summary} [dim]({elapsed}ms)[/dim]")

    def update(self):
        if self._live:
            try:
                self._live.update(self._render())
            except Exception as e:
                _log.warning("LiveProgress.update failed: %s", e)

    def log(self, message: str, style: str = ""):
        with self._lock:
            self._state.log_lines.append((style, message))
            if len(self._state.log_lines) > 50:
                self._state.log_lines = self._state.log_lines[-50:]

    def set_progress(self, current: int, total: int, label: str = ""):
        with self._lock:
            self._state.total_steps = total
            self._state.current_step = current
            if label:
                self._state.sub_label = label

    def set_findings(self, count: int):
        with self._lock:
            self._state.findings = count

    def set_status(self, text: str):
        with self._lock:
            self._state.status_text = text

    def _render(self) -> RenderableType:
        with self._lock:
            lines = []
            for style, text in self._state.log_lines[-20:]:
                if style:
                    lines.append(Text(text, style=style))
                else:
                    lines.append(Text(text))

            # Progress bar
            if self._state.total_steps > 0 and not self._state.done:
                progress = Progress(
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    console=self.con,
                )
                task_id = progress.add_task(
                    self._state.sub_label or "",
                    total=self._state.total_steps,
                    completed=self._state.current_step,
                )
                progress.update(task_id, completed=self._state.current_step)
                lines.append(Text(""))
                lines.append(progress)

            # Findings counter
            if self._state.findings:
                lines.append(Text(f"  ! {self._state.findings} finding(s)", style="yellow"))

            elapsed = int((time.monotonic() - self._start_time) * 1000) if self._start_time else 0
            footer = Text(
                f" {self._state.status_text}  - {elapsed}ms",
                style="dim",
            )

            grid = Group(*lines, Text(""), footer)
            icon = "[#4ADE80]v[/#4ADE80]" if self._state.done and not self._state.failed else \
                   "[red]x[/red]" if self._state.failed else \
                   "[yellow]~[/yellow]"
            return Panel(
                grid,
                title=f"{icon} [bold #A78BFA]{self._title}[/bold #A78BFA]",
                border_style="dim",
                padding=(0, 1),
            )
