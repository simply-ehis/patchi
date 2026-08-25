"""
Live audit display — rich.Live-powered dashboard with collapsible phase panels.

Layout:
┌─ p audit ──────────────────────────────────────────────────────┐
│ ◉ Scan        → 47 files · 12 routes · 6 domains · 1.2s      │
│ ┌──────────────────────────────────────────────────────────────┐│
│ │  ● Discovering files...                                     ││
│ │  ● Parsing src/main.py                                      ││
│ │  ● FastAPI v0.115.0 detected                                ││
│ │  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   ││
│ └────────────────────────────────────────────────────────────┘│
│ ◉ Security    → TaintAnalyzer running (3 findings so far)...   │
│ ┌────────────────────────────────────────────────────────────┐│
│ │  ● TaintAnalyzer — scanning src/routes.py                  ││
│ │  ●   ⚑ Finding #3: Unsafe string concat in query builder  ││
│ │  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ││
│ └────────────────────────────────────────────────────────────┘│
│ ○ Tests       → pending                                       │
│ ○ Health      → pending                                       │
└────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.text import Text

_log = logging.getLogger("patchi.cli.live_audit")


class PhaseStatus(Enum):
    PENDING = "○"
    RUNNING = "◉"
    DONE = "✓"
    FAILED = "✗"
    SKIPPED = "⊘"


_PHASE_COLORS = {
    "scan": "#C8621A",
    "security": "#4ADE80",
    "tests": "#60A5FA",
    "health": "#A78BFA",
}


@dataclass
class PhaseState:
    """Mutable state of a single phase. Updated by the audit runner threads."""

    name: str
    status: PhaseStatus = PhaseStatus.PENDING
    summary: str = ""
    duration_ms: int = 0
    log_lines: list[tuple[str, str]] = field(default_factory=list)  # (style, text)
    findings: int = 0
    files_scanned: int = 0
    total_steps: int = 0
    current_step: int = 0
    sub_label: str = ""


class LiveAuditDisplay:
    """
    Manages a rich.live.Live renderable with collapsible phase panels.

    Thread-safe — call from any thread. The display auto-refreshes.
    """

    def __init__(self, console: Console | None = None):
        self.con = console or Console()
        self._lock = threading.RLock()
        self._phases: dict[str, PhaseState] = {}
        self._expanded_phase: str | None = None  # None = auto (latest running)
        self._live: Live | None = None
        self._start_time: float = 0.0

    def start(self, title: str = "p audit"):
        """Start the live display. Must be called from main thread."""
        self._start_time = time.monotonic()
        self._live = Live(
            self._render(),
            console=self.con,
            refresh_per_second=8,
            transient=False,
            screen=False,
        )
        self._live.__enter__()

    def stop(self):
        """Stop the live display and restore normal terminal."""
        if self._live:
            try:
                self._live.__exit__(None, None, None)
            except Exception as e:
                _log.warning("LiveAuditDisplay.stop failed: %s", e)
            self._live = None
        self.con.print()

    def phase(self, name: str) -> PhaseState:
        """Get or create a phase by name."""
        with self._lock:
            if name not in self._phases:
                self._phases[name] = PhaseState(name=name)
            return self._phases[name]

    def update(self):
        """Trigger a refresh. Call after modifying any phase state."""
        if self._live:
            try:
                self._live.update(self._render())
            except Exception as e:
                _log.warning("LiveAuditDisplay.update failed: %s", e)

    def _render(self) -> RenderableType:
        """Build the full renderable from current phase states."""
        with self._lock:
            elapsed = int((time.monotonic() - self._start_time) * 1000)
            rows = []
            color = _PHASE_COLORS

            # Auto-expand the currently running phase
            running = [p for p in self._phases.values() if p.status == PhaseStatus.RUNNING]
            expanded = running[0].name if running else None

            for phase_name in ("scan", "security", "tests", "health"):
                phase = self._phases.get(phase_name)
                if phase is None:
                    rows.append(self._render_header_line(phase_name, PhaseStatus.PENDING, "", 0))
                    continue

                # Header line
                header = self._render_header_line(
                    phase_name, phase.status, phase.summary, phase.duration_ms
                )

                # Expanded body if this phase is running AND the running phase
                is_expanded = phase_name == expanded
                if is_expanded and phase.log_lines:
                    body = self._render_expanded_body(phase)
                    rows.append(Group(header, body))
                else:
                    rows.append(header)

            total_findings = sum(p.findings for p in self._phases.values())
            total_files = sum(p.files_scanned for p in self._phases.values())
            footer = Text(
                f" Total: {total_files} files · {total_findings} findings · {elapsed}ms",
                style="dim",
            )
            grid = Group(*rows, Text(""), footer)
            return Panel(
                grid, title=f"[bold]{color.get('audit', '#C8621A')}audit[/bold]", border_style="dim"
            )

    def _render_header_line(
        self, name: str, status: PhaseStatus, summary: str, duration_ms: int
    ) -> RenderableType:
        """A single-line phase header: ◉ Scan → 47 files · 1.2s"""
        color = _PHASE_COLORS.get(name, "white")
        status_icon = status.value
        status_color = {
            PhaseStatus.DONE: "green",
            PhaseStatus.FAILED: "red",
            PhaseStatus.RUNNING: "yellow",
            PhaseStatus.PENDING: "dim",
            PhaseStatus.SKIPPED: "dim",
        }.get(status, "dim")

        label = name.capitalize()
        dur = f"· {duration_ms}ms" if duration_ms else ""
        summary_part = f" → {summary}" if summary else ""

        parts = [
            f"[{status_color}]{status_icon}[/{status_color}] ",
            f"[bold {color}]{label:<10}[/bold {color}]",
        ]
        if summary_part:
            parts.append(f"[dim]{summary_part}[/dim]")
        if duration_ms:
            parts.append(f"[dim]{dur}[/dim]")
        return Text.assemble(*parts)

    def _render_expanded_body(self, phase: PhaseState) -> RenderableType:
        """Expanded panel showing live log lines + progress bar."""
        lines = []
        for style, text in phase.log_lines:
            if style:
                lines.append(Text(text, style=style))
            else:
                lines.append(Text(text))

        # Progress bar if there are sub-steps
        if phase.total_steps > 0:
            progress = Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=self.con,
            )
            task_id = progress.add_task(
                phase.sub_label or "",
                total=phase.total_steps,
                completed=phase.current_step,
            )
            progress.update(task_id, completed=phase.current_step)
            lines.append(Text(""))
            lines.append(progress)

        # If findings found during live phase, show count
        if phase.findings:
            lines.append(Text(f"\n  ⚑ {phase.findings} finding(s) so far", style="yellow"))

        panel = Panel(
            Group(*lines),
            border_style="dim",
            padding=(0, 1),
            width=None,
        )
        return panel

    def log(self, phase_name: str, message: str, style: str = ""):
        """Append a log line to a phase."""
        with self._lock:
            phase = self.phase(phase_name)
            # Keep last 50 lines
            phase.log_lines.append((style, message))
            if len(phase.log_lines) > 50:
                phase.log_lines = phase.log_lines[-50:]

    def set_phase_status(
        self,
        name: str,
        status: PhaseStatus,
        summary: str = "",
        duration_ms: int = 0,
        findings: int = 0,
        files_scanned: int = 0,
    ):
        with self._lock:
            phase = self.phase(name)
            phase.status = status
            if summary:
                phase.summary = summary
            if duration_ms:
                phase.duration_ms = duration_ms
            if findings:
                phase.findings = findings
            if files_scanned:
                phase.files_scanned = files_scanned

    def set_phase_progress(self, name: str, current: int, total: int, label: str = ""):
        with self._lock:
            phase = self.phase(name)
            phase.total_steps = total
            phase.current_step = current
            if label:
                phase.sub_label = label
