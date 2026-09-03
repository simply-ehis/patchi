from pathlib import Path

from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core import config as cfg
from patchi.core.constants import RestrictionType

"""
`p restrict` — manage no-touch zones, scan-only paths, and sensitive files.

Subcommands:
  p restrict add <path>           — add as no-touch zone
  p restrict scan-only <path>     — add as scan-only zone
  p restrict sensitive <path>     — mark as sensitive file
  p restrict list                 — list all constraints
  p restrict remove <path>        — remove a constraint
  p restrict disable <path>       — temporarily disable
  p restrict enable <path>        — re-enable
"""


_TYPE_COLORS = {
    RestrictionType.NO_TOUCH.value: "red",
    RestrictionType.SCAN_ONLY.value: "yellow",
    RestrictionType.SENSITIVE.value: "#C8621A",
}

_TYPE_LABELS = {
    RestrictionType.NO_TOUCH.value: "no-touch",
    RestrictionType.SCAN_ONLY.value: "scan-only",
    RestrictionType.SENSITIVE.value: "sensitive",
}


def run_add(path: str, rtype: RestrictionType, reason: str = "", root: Path | None = None) -> None:
    try:
        cfg.add_restriction(path, rtype, reason, root)
        label = _TYPE_LABELS[rtype.value]
        con.print(f"[#4ADE80]✓[/#4ADE80] Added [bold]{path}[/bold] as [bold]{label}[/bold].")
        _show_type_note(rtype)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")


def run_list(root: Path | None = None) -> None:
    try:
        restrictions = cfg.get_restrictions(root)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    con.print()
    if not restrictions:
        con.print("[dim]No restrictions configured. All files are accessible.[/dim]")
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Path", style="bold #F2EDD6")
    table.add_column("Type", width=12)
    table.add_column("Status", width=10)
    table.add_column("Reason", style="dim")

    for r in restrictions:
        rtype = r.get("type", "no_touch")
        color = _TYPE_COLORS.get(rtype, "white")
        label = _TYPE_LABELS.get(rtype, rtype)
        status = (
            Text("active", style="#4ADE80")
            if r.get("enabled", True)
            else Text("disabled", style="dim")
        )

        table.add_row(
            r["path"],
            Text(label, style=color),
            status,
            r.get("reason", ""),
        )

    con.print(table)
    con.print()


def run_remove(path: str, root: Path | None = None) -> None:
    try:
        removed = cfg.remove_restriction(path, root)
        if removed:
            con.print(f"[#4ADE80]✓[/#4ADE80] Removed restriction for [bold]{path}[/bold].")
            con.print("[dim]Patchi will rescan this area on the next run.[/dim]")
        else:
            con.print(f"[yellow]No restriction found for {path!r}.[/yellow]")
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")


def run_disable(path: str, root: Path | None = None) -> None:
    try:
        ok = cfg.toggle_restriction(path, enabled=False, root=root)
        if ok:
            con.print(f"[dim]Restriction for [bold]{path}[/bold] disabled (not removed).[/dim]")
        else:
            con.print(f"[yellow]No restriction found for {path!r}.[/yellow]")
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")


def run_enable(path: str, root: Path | None = None) -> None:
    try:
        ok = cfg.toggle_restriction(path, enabled=True, root=root)
        if ok:
            con.print(f"[#4ADE80]✓[/#4ADE80] Restriction for [bold]{path}[/bold] re-enabled.")
        else:
            con.print(f"[yellow]No restriction found for {path!r}.[/yellow]")
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")


def _show_type_note(rtype: RestrictionType) -> None:
    notes = {
        RestrictionType.NO_TOUCH: "Patchi will never read, scan, or modify this path.",
        RestrictionType.SCAN_ONLY: "Patchi will scan and report but never propose fixes here.",
        RestrictionType.SENSITIVE: "Patchi acknowledges this file exists but never reads its contents.",
    }
    con.print(f"[dim]{notes[rtype]}[/dim]")
