from patchi.cli.console import con

"""
`p status` — quick overview of Patchi's current state.

Shows: Brain health · Current mode · Queue depth · AI key status
"""

from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core import queue as q


def _health_bar(score: int, width: int = 20) -> str:
    """Build a visual health bar: [████████░░░░░░░░░░░░] 80/100."""
    filled = int(score / 100 * width)
    empty = width - filled
    if score >= 80:
        color = "#4ADE80"
    elif score >= 50:
        color = "#FACC15"
    elif score >= 25:
        color = "#FF8C42"
    else:
        color = "#FF4D6D"
    bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"
    return f"{bar} {score}/100"


def run(root: Path | None = None, json_output: bool = False) -> None:
    """p status"""
    try:
        config = cfg.load(root)
        brain = mem.get_brain(root)
        qstats = q.stats(root)
        mode = cfg.get_mode(root)
        qmode = cfg.get_queue_mode(root)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if json_output:
        import json as _json

        health_score = brain.get("health_score", {}) if brain else {}
        stack = (brain or {}).get("stack", {}) or {}
        con.print(
            _json.dumps(
                {
                    "mode": mode,
                    "queue_mode": qmode,
                    "queue": qstats,
                    "health_score": health_score,
                    "brain": {
                        "ready": bool(brain and not brain.get("stale") and not brain.get("error")),
                        "stale": bool((brain or {}).get("stale")),
                        "file_count": (brain or {}).get("file_count", 0),
                        "route_count": (brain or {}).get("route_count", 0),
                        "frameworks": [f.get("name", "") for f in stack.get("frameworks", [])[:3]],
                    },
                },
                indent=2,
                default=str,
            )
        )
        return

    con.print()

    # ── Build info sections ────────────────────────────────────────────────────

    # Health score
    health_score = brain.get("health_score", {})
    health_total = health_score.get("total")
    health_grade = health_score.get("grade", "")

    if health_total is not None:
        health_bar = _health_bar(health_total)
        comps = health_score.get("components", {})
        health_detail = (
            f"security {comps.get('security', 0):.0f}  "
            f"tests {comps.get('test_coverage', 0):.0f}  "
            f"dead {comps.get('dead_code', 0):.0f}  "
            f"deps {comps.get('dependency', 0):.0f}  "
            f"contract {comps.get('contract', 0):.0f}"
        )
    else:
        health_bar = "[dim]No scan yet[/dim]"
        health_detail = "Run [bold]p scan[/bold] to compute"

    # Brain
    if not brain:
        brain_line = "[dim]No scan yet — run [bold]p scan[/bold][/dim]"
    elif brain.get("stale"):
        reason = brain.get("stale_reason", "Files changed since last scan")
        brain_line = f"[yellow]Stale[/yellow] — {reason}"
    elif brain.get("error"):
        brain_line = f"[red]Error:[/red] {brain.get('error', '')}"
    else:
        fc = brain.get("file_count", 0)
        rc = brain.get("route_count", 0)
        fw = ""
        stack = brain.get("stack", {})
        if stack and stack.get("frameworks"):
            fw_names = [f.get("name", "") for f in stack["frameworks"][:3]]
            fw = f"  ·  {', '.join(fw_names)}"
        brain_line = f"[#4ADE80]Ready[/#4ADE80] — {fc} files · {rc} routes{fw}"

    # Mode
    mode_colors = {"confirm": "#60A5FA", "auto": "#FACC15", "autopilot": "#4ADE80"}
    mode_icons = {"confirm": "🔒", "auto": "⚡", "autopilot": "🤖"}
    mc = mode_colors.get(mode.value, "dim")
    mi = mode_icons.get(mode.value, "")
    mode_line = f"[bold {mc}]{mi} {mode.label()}[/bold {mc}]"
    mode_desc = {
        "confirm": "Every fix requires your approval",
        "auto": "Low-risk auto-applied, risky ones ask",
        "autopilot": "Full trust — Patchi decides",
    }.get(mode.value, "")

    # Queue
    queue_paused = qstats.get("paused", False)
    queue_waiting = qstats.get("waiting", 0)
    queue_active = qstats.get("active", 0)

    if queue_paused:
        queue_line = "[yellow]Paused[/yellow]"
    elif queue_active:
        queue_line = f"[#C8621A]{queue_active} active[/#C8621A]"
    elif queue_waiting:
        queue_line = f"{queue_waiting} waiting"
    else:
        queue_line = "[dim]Empty[/dim]"
    queue_detail = f"mode: {qmode.value}"

    # AI
    ai_config = config.get("ai", {})
    local_model = ai_config.get("local_model_name")
    keys = ai_config.get("keys", [])
    horde_fallback = ai_config.get("horde_fallback", False)

    if local_model:
        ai_line = f"[#4ADE80]Local:[/#4ADE80] {local_model}"
        ai_detail = "Offline · zero cost"
    elif keys:
        working = [k for k in keys if k.get("status") != "error"]
        if working:
            ai_line = f"[#4ADE80]{len(working)}/{len(keys)} keys active[/#4ADE80]"
        else:
            ai_line = f"[red]0/{len(keys)} keys active[/red]"
        ai_detail = "  ".join(k.get("nickname", "?") for k in keys[:4])
        if len(keys) > 4:
            ai_detail += f" +{len(keys) - 4} more"
    elif horde_fallback:
        ai_line = "[yellow]Community fallback[/yellow]"
        ai_detail = "AI Horde · slower but always works"
    else:
        ai_line = "[yellow]Not configured[/yellow]"
        ai_detail = "Run [bold]p key add[/bold] or [bold]p init[/bold]"

    # ── Render ─────────────────────────────────────────────────────────────────

    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 2))
    table.add_column("Key", style="bold #F2EDD6", width=14)
    table.add_column("Value", min_width=30)
    table.add_column("Detail", style="dim")

    table.add_row("Health", Text.from_markup(health_bar), health_detail)
    table.add_row("Brain", Text.from_markup(brain_line), "")
    table.add_row("Mode", Text.from_markup(mode_line), mode_desc)
    table.add_row("Queue", Text.from_markup(queue_line), queue_detail)
    table.add_row("AI", Text.from_markup(ai_line), ai_detail)

    panel_title = "[bold #C8621A]Patchi Status[/bold #C8621A]"
    if health_grade:
        panel_title += f"  [dim]{health_grade}[/dim]"

    con.print(
        Panel(
            table,
            title=panel_title,
            border_style="#2A3D28",
            padding=(0, 1),
        )
    )
    con.print()
