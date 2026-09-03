from pathlib import Path

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core import memory as mem
from patchi.core.config import require_project_root
from patchi.core.constants import MemoryCategory

"""
`p memory` — view and manage Patchi's memory.

Subcommands:
  p memory                  — show all categories with counts
  p memory show <category>  — show full data for a category
  p memory delete <category>— clear a category (with warning)
  p memory delete all       — full reset (requires CONFIRM)
"""


def run_show_all(root: Path | None = None) -> None:
    """p memory — show all categories."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    data = mem.summary(r)

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Category", style="bold #F2EDD6", width=16)
    table.add_column("Items", style="#B8A898")
    table.add_column("Description", style="dim")

    descriptions = {
        "brain": "Brain's understanding of your app",
        "patches": "Applied fix history with diffs",
        "failed": "Patches that failed and were rolled back",
        "scans": "Last results from every scanner agent",
        "issues": "Known unfixed issues",
        "restrictions": "No-touch zones and scan-only paths",
        "tokens": "Dev access token names (values never stored)",
        "layers": "Layered brain (Pillar 1) — module/subsytem/project map",
        "charter": "Project guard-rail charter (Pillar 2)",
    }

    for category, info in data.items():
        if "count" in info:
            count_str = str(info["count"])
        elif "keys" in info:
            count_str = f"{len(info['keys'])} sections"
        else:
            count_str = "—"

        table.add_row(category, count_str, descriptions.get(category, ""))

    con.print()
    con.print(
        Panel(table, title="[bold #C8621A]Patchi Memory[/bold #C8621A]", border_style="#2A3D28")
    )
    con.print()
    con.print(
        "[dim]Commands: [bold]p memory show <category>[/bold]  ·  [bold]p memory delete <category>[/bold][/dim]"
    )
    con.print()


def run_show(category_str: str, root: Path | None = None) -> None:
    """p memory show <category>"""
    import json

    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # Special-case: 'scans' gets a formatted view instead of raw JSON
    if category_str.lower() in ("scans", "scan"):
        _show_scans(r)
        return

    try:
        category = _parse_category(category_str)
    except ValueError as e:
        con.print(f"[red]{e}[/red]")
        return

    data = mem.read(category, r)
    con.print()
    con.print(f"[bold #F2EDD6]Memory: {category.value}[/bold #F2EDD6]")
    con.print()
    con.print_json(json.dumps(data, indent=2, default=str))
    con.print()


def _show_scans(root: Path) -> None:
    """Structured view of scan results — one row per agent."""
    from rich.table import Table

    scans = mem.get_scan_results(root)
    if not scans:
        con.print("[dim]No scan results yet. Run [bold]p scan[/bold] first.[/dim]")
        return

    con.print()
    con.print("[bold #F2EDD6]Last Scan Results by Agent[/bold #F2EDD6]")
    con.print()

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Agent", style="bold #F2EDD6", width=26)
    table.add_column("Status", width=10)
    table.add_column("Findings", justify="right", width=10)
    table.add_column("Files", justify="right", width=8)
    table.add_column("Duration", justify="right", width=10)

    colors = {"done": "#4ADE80", "failed": "#FF4D6D", "skipped": "dim"}
    for agent_name, data in sorted(scans.items()):
        status = data.get("status", "?")
        table.add_row(
            agent_name,
            Text(status, style=colors.get(status, "white")),
            str(data.get("finding_count", 0)),
            str(data.get("files_scanned", 0)),
            f"{data.get('duration_ms', 0)}ms",
        )

    con.print(table)
    con.print()


def run_delete(category_str: str, root: Path | None = None) -> None:
    """p memory delete <category> — with warning"""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if category_str.lower() == "all":
        _delete_all(r)
        return

    try:
        category = _parse_category(category_str)
    except ValueError as e:
        con.print(f"[red]{e}[/red]")
        return

    consequence = _delete_consequence(category)
    con.print()
    con.print(f"[yellow]Warning:[/yellow] {consequence}")
    con.print()

    confirmed = Confirm.ask(f"Delete [bold]{category.value}[/bold] memory?", default=False)
    if confirmed:
        mem.delete(category, r)
        con.print(f"[#4ADE80]✓[/#4ADE80] [bold]{category.value}[/bold] memory cleared.")
    else:
        con.print("[dim]Cancelled.[/dim]")
    con.print()


def _delete_all(root: Path) -> None:
    """Full memory reset — requires typing CONFIRM."""
    con.print()
    con.print("[red bold]Full memory reset.[/red bold]\n")
    con.print()
    typed = Prompt.ask("[bold]Type CONFIRM to proceed[/bold]")
    if typed.strip() == "CONFIRM":
        mem.delete_all(root)
        con.print("[#4ADE80]✓[/#4ADE80] All memory cleared. Patchi starts fresh on the next run.")
    else:
        con.print("[dim]Cancelled.[/dim]")
    con.print()


# ── Helpers ────────────────────────────────────────────────────────────────────


def _parse_category(s: str) -> MemoryCategory:
    valid = {c.value: c for c in MemoryCategory}
    # Allow shorthand aliases
    aliases = {
        "patch": MemoryCategory.PATCHES,
        "fail": MemoryCategory.FAILED,
        "scan": MemoryCategory.SCANS,
        "issue": MemoryCategory.ISSUES,
        "restrict": MemoryCategory.RESTRICTIONS,
        "token": MemoryCategory.TOKENS,
    }
    cleaned = s.lower().strip()
    if cleaned in valid:
        return valid[cleaned]
    if cleaned in aliases:
        return aliases[cleaned]
    raise ValueError(f"Unknown category: {s!r}\nValid: {', '.join(valid.keys())}")


def _delete_consequence(category: MemoryCategory) -> str:
    consequences = {
        MemoryCategory.BRAIN: "Deleting Brain state means Patchi will re-learn your entire app before the next action.",
        MemoryCategory.PATCHES: "Deleting patch history means you can no longer undo or review past fixes.",
        MemoryCategory.FAILED: "Deleting failed patch history clears all recorded failure reasons.",
        MemoryCategory.SCANS: "Deleting scan results means Patchi will re-scan before the next action.",
        MemoryCategory.ISSUES: "Deleting known issues clears all recorded unfixed findings.",
        MemoryCategory.RESTRICTIONS: "Deleting restrictions removes all no-touch and scan-only zones. "
        "Patchi will have access to all files on next run.",
        MemoryCategory.TOKENS: "Deleting dev tokens removes all stored access token references.",
    }
    return consequences.get(category, "This area will be cleared and rescanned on next run.")
