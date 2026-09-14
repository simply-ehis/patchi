"""
`p settings mode` — view and change Patchi's operating mode.

Usage:
  p settings mode            — show current mode
  p settings mode confirm    — require approval for every action
  p settings mode auto       — auto-apply safe fixes, ask for risky ones
  p settings mode autopilot  — full trust, Patchi decides everything
"""

from __future__ import annotations

from pathlib import Path

from rich.panel import Panel

from patchi.cli.console import con
from patchi.core import config as cfg
from patchi.core.constants import Mode

_DESCRIPTIONS = {
    Mode.CONFIRM: "Every action requires your approval before it applies.",
    Mode.AUTO: "Low-risk fixes apply automatically (risk score 0–30).",
    Mode.AUTOPILOT: "Full trust. Patchi applies whatever it decides is correct.",
}

_CHANGE_HINT = (
    "[dim]Change mode: [bold]p settings mode confirm[/bold]  ·  "
    "[bold]p settings mode auto[/bold]  ·  [bold]p settings mode autopilot[/bold][/dim]"
)


def run(mode_str: str | None = None, root: Path | None = None) -> None:
    """
    Unified entry point for the registry (§3 Command Unification) --
    `p mode` alone shows the current mode, `p mode <name>` sets it.
    """
    if mode_str:
        run_set(mode_str, root)
    else:
        run_show(root)


def run_show(root: Path | None = None) -> None:
    """p mode — show current mode with description."""
    try:
        mode = cfg.get_mode(root)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    con.print()
    con.print(
        Panel.fit(
            f"[bold {mode.color()}]{mode.label()}[/bold {mode.color()}]\n",
            title="[bold #C8621A]Current Mode[/bold #C8621A]",
            border_style="#2A3D28",
        )
    )
    con.print()
    con.print(_CHANGE_HINT)
    con.print()


def run_set(mode_str: str, root: Path | None = None) -> None:
    """p mode <confirm|auto|autopilot>"""
    try:
        mode = Mode(mode_str.lower())
    except ValueError:
        con.print(
            f"[red]Unknown mode: {mode_str!r}[/red]\n[dim]Valid: confirm · auto · autopilot[/dim]"
        )
        return

    try:
        cfg.set_mode(mode, root)
        con.print(
            f"[#4ADE80]✓[/#4ADE80] Mode set to [bold {mode.color()}]{mode.label()}[/bold {mode.color()}].\n"
            f"[dim]{_DESCRIPTIONS[mode]}[/dim]"
        )
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
