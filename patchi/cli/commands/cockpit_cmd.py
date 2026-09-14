"""
`p cockpit` — the live cockpit (a single glanceable dashboard for a coding session).

    p cockpit                 live dashboard, refreshes as you save files
    p cockpit --area src/api  scope the fix list to a subtree
    p cockpit --once          render one frame and exit (CI / smoke test)
    p cockpit --interval 30   seconds between full health/drift refreshes

It is a *view layer only*: every number comes from signals Patchi already
computes (health score, Plan-vs-Built drift, Prioritized Fix List, blast radius,
secrets sweep). No new analysis lives here.
"""

from __future__ import annotations

import time
from pathlib import Path

from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core.brain import cockpit as ck
from patchi.core.config import require_project_root

_FIX_LABEL = {
    "charter_violation": ("Charter", "#FF4D6D"),
    "signature_callers": ("Breaking", "#FF8C42"),
    "missing_import": ("Missing import", "#FACC15"),
    "dead_code": ("Dead code", "#9AA0A6"),
    "unused_import": ("Unused import", "#9AA0A6"),
    "format": ("Format", "#86EFAC"),
}
_LEVEL_STYLE = {"info": "#86EFAC", "warn": "#FACC15", "crit": "#FF4D6D"}


# ── Panels ───────────────────────────────────────────────────────────────────────


def _header(state: ck.CockpitState) -> Panel:
    t = Table.grid(expand=True)
    t.add_column(justify="left")
    t.add_column(justify="right")

    if state.health_total is None:
        health = Text("Health  —  (run `p scan`)", style="#9AA0A6")
    else:
        health = Text.assemble(
            ("Health  ", "#F2EDD6"),
            (f"{state.health_total}", f"bold {state.health_color}"),
            (f"  {state.health_grade}", state.health_color),
        )

    drift = state.drift or {}
    if not drift.get("has_plan"):
        plan = Text("Plan  no baseline (`p audit save`)", style="#9AA0A6")
    elif drift.get("clean"):
        plan = Text("Plan  ✓ ON PLAN", style="bold #86EFAC")
    else:
        sd = drift.get("scope_diff", {}) or {}
        delta = sd.get("added_count", 0) + sd.get("removed_count", 0) + sd.get("modified_count", 0)
        nf = drift.get("new_findings", 0)
        plan = Text.assemble(
            ("Plan  ⚠ DRIFT", "bold #FF4D6D"),
            (f"  ({delta} file Δ, +{nf} findings)", "#FF8C42"),
        )

    t.add_row(health, plan)
    return Panel(t, border_style="#2A3D28", padding=(0, 1))


def _fix_panel(state: ck.CockpitState) -> Panel:
    if not state.fixes:
        if state.fixes_computing or state.fixes_at == 0:
            body = Text("Computing fix list…", style="#FACC15")
        else:
            body = Text("No fixes proposed — clean, or run `p scan` first.", style="#9AA0A6")
        return Panel(body, title="[bold #C8621A]Prioritized Fix List[/bold #C8621A]", border_style="#2A3D28")

    tbl = Table(show_header=True, header_style="dim", box=None, expand=True, pad_edge=False)
    tbl.add_column("#", justify="right", width=2, style="dim")
    tbl.add_column("Type", width=14)
    tbl.add_column("Where", overflow="ellipsis", no_wrap=True)
    tbl.add_column("", justify="right", width=6)

    for i, f in enumerate(state.fixes[:12], 1):
        label, color = _FIX_LABEL.get(f["fix_type"], (f["fix_type"], "#F2EDD6"))
        where = f["file"] + (f" · {f['name']}" if f["name"] else "")
        tag = Text("safe", style="#86EFAC") if f["safe"] else Text("review", style="#FF8C42")
        tbl.add_row(str(i), Text(label, style=color), where, tag)

    extra = len(state.fixes) - 12
    title = f"[bold #C8621A]Prioritized Fix List[/bold #C8621A] [dim]({len(state.fixes)})[/dim]"
    grp = Group(tbl, Text(f"  +{extra} more…", style="dim")) if extra > 0 else tbl
    return Panel(grp, title=title, border_style="#2A3D28")


def _blast_panel(state: ck.CockpitState) -> Panel:
    if not state.last_file:
        body = Text("Save a file to see its blast radius.", style="#9AA0A6")
        return Panel(body, title="[bold #C8621A]Blast Radius[/bold #C8621A]", border_style="#2A3D28")

    lines: list = [Text(state.blast_summary or "", style="#F2EDD6"), Text("")]
    if state.blast_affected:
        lines.append(Text("Directly affected:", style="bold #F2EDD6"))
        lines += [Text(f"  • {n}", style="#F2EDD6") for n in state.blast_affected]
    if state.blast_impacted:
        lines.append(Text("Downstream (blast):", style="bold #FF8C42"))
        lines += [Text(f"  • {n}", style="#FF8C42") for n in state.blast_impacted]
    elif state.blast_affected:
        lines.append(Text("No downstream dependents.", style="dim"))

    title = f"[bold #C8621A]Blast Radius[/bold #C8621A] [dim]{state.last_file}[/dim]"
    return Panel(Group(*lines), title=title, border_style="#2A3D28")


def _events_panel(state: ck.CockpitState) -> Panel:
    if not state.events:
        body = Text("Watching…", style="#9AA0A6")
    else:
        rows = []
        for ev in list(state.events)[-8:]:
            style = _LEVEL_STYLE.get(ev.level, "#F2EDD6")
            mark = {"info": "·", "warn": "▲", "crit": "✖"}.get(ev.level, "·")
            rows.append(
                Text.assemble(
                    (f"{ev.stamp()} ", "dim"),
                    (f"{mark} ", style),
                    (ev.text, style),
                )
            )
        body = Group(*rows)
    sec = f" · [#FF4D6D]{len(state.secrets)} secret(s)[/#FF4D6D]" if state.secrets else ""
    return Panel(body, title=f"[bold #C8621A]Events[/bold #C8621A]{sec}", border_style="#2A3D28")


# ── Layout ─────────────────────────────────────────────────────────────────────


def _build_layout() -> Layout:
    root = Layout()
    root.split_column(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="events", size=10),
    )
    root["body"].split_row(Layout(name="fixes"), Layout(name="blast"))
    return root


def _render(layout: Layout, state: ck.CockpitState) -> None:
    layout["header"].update(_header(state))
    layout["fixes"].update(_fix_panel(state))
    layout["blast"].update(_blast_panel(state))
    layout["events"].update(_events_panel(state))


# ── Entry point ────────────────────────────────────────────────────────────────


def run(
    root: Path | None = None,
    interval: float = 15.0,
    area: str | None = None,
    once: bool = False,
    poll: float = 1.0,
    scan_secrets: bool = False,
) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    state = ck.gather_full(r, area=area, scan_secrets=scan_secrets, fixes_sync=once)
    layout = _build_layout()
    _render(layout, state)

    if once:
        con.print(layout)
        return

    watcher = ck.SourceWatcher(r)
    con.print("[dim]Cockpit live — press Ctrl+C to exit.[/dim]")
    try:
        with Live(layout, console=con, refresh_per_second=4, screen=True):
            last_full = time.time()
            while True:
                changed = watcher.poll()
                if changed:
                    ck.refresh_on_change(state, changed)
                    ck.refresh_fixes_async(state)
                if time.time() - last_full >= interval:
                    ck.update_metrics(state)
                    ck.refresh_fixes_async(state)
                    last_full = time.time()
                _render(layout, state)
                time.sleep(poll)
    except KeyboardInterrupt:
        con.print("[dim]Cockpit closed.[/dim]")
