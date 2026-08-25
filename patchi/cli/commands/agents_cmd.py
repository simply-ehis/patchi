"""
`p agents` — Inspect and monitor Patchi agents.

Subcommands:
  p agents              — list all agents grouped by type
  p agents list         — same as above
  p agents list scanner — list only scanner agents
  p agents list fix     — list only fix agents p agents status       — show which agents ran in the last scan and their results
"""

from __future__ import annotations

from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Import scanners to trigger @register decorators
import patchi.core.agents.scanners  # noqa: F401

# Security agents register lazily inside security_agents; import it so the
# whole SECURITY group appears in `p agents list` (previously showed 0).
import patchi.core.security.security_agents  # noqa: F401
from patchi.cli.console import con
from patchi.core import memory as mem
from patchi.core.agents.base import AgentGroup, list_agents
from patchi.core.agents.coordinator import Coordinator
from patchi.core.config import require_project_root

_GROUP_ORDER = [
    AgentGroup.SCANNER,
    AgentGroup.FIX,
    AgentGroup.TEST,
    AgentGroup.SECURITY,
    AgentGroup.GUARD,
]

def run_list(group_name: str | None = None, root: Path | None = None) -> None:
    """p agents [list] [group]"""
    # Parse group filter
    target_group: AgentGroup | None = None
    if group_name:
        try:
            target_group = AgentGroup(group_name.lower())
        except ValueError:
            con.print(f"[red]Unknown group: {group_name!r}[/red]")
            con.print(f"[dim]Valid groups: {', '.join(g.value for g in AgentGroup)}[/dim]")
            return

    # Load last scan results for status indicators
    scan_results: dict = {}
    try:
        r = root or require_project_root()
        scan_results = mem.get_scan_results(r)
    except RuntimeError:
        pass  # no project — still show the agent list

    con.print()

    groups_to_show = [target_group] if target_group else _GROUP_ORDER
    for group in groups_to_show:
        agents = list_agents(group)
        _render_group(group, agents, scan_results)

    if not target_group:
        con.print(
            "[dim]Filter: [bold]p agents list scanner[/bold]  ·  "
            "[bold]p agents list security[/bold]  …[/dim]"
        )
    con.print()

def _render_group(
    group: AgentGroup,
    agents: list,
    scan_results: dict,
) -> None:
    ant_type = group.ant_type()
    title = f"[bold #C8621A]{group.label()}[/bold #C8621A] [dim]({ant_type})[/dim]"

    table = Table(show_header=True, header_style="dim", box=None, pad_edge=False, padding=(0, 2))
    table.add_column("Agent", style="bold #F2EDD6", width=26)
    table.add_column("Last Status", width=12)
    table.add_column("Findings", width=10)
    table.add_column("Duration", width=10)

    for agent_cls in agents:
        last = scan_results.get(agent_cls.name, {})
        status_val = last.get("status", "idle")
        duration_ms = last.get("duration_ms", 0)
        findings = last.get("finding_count", 0)

        status_text = _status_text(status_val)
        dur_str = f"{duration_ms}ms" if duration_ms else "—"
        find_str = str(findings) if findings else "—"

        table.add_row(
            agent_cls.name,
            status_text,
            find_str,
            dur_str,
            "",
        )

    con.print(Panel(table, title=title, border_style="#2A3D28", padding=(0, 1)))
    con.print()

def run_status(root: Path | None = None) -> None:
    """p agents status — detailed last-run status for all agents."""
    try:
        r = root or require_project_root()
        scan_results = mem.get_scan_results(r)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if not scan_results:
        con.print("[dim]No agents have run yet. Run [bold]p scan[/bold] to start.[/dim]")
        return

    con.print()
    con.print("[bold #F2EDD6]Last Agent Run Summary[/bold #F2EDD6]")
    con.print()

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Agent", style="bold #F2EDD6", width=26)
    table.add_column("Status", width=10)
    table.add_column("Findings", justify="right", width=10)
    table.add_column("Files", justify="right", width=8)
    table.add_column("Duration", justify="right", width=10)
    table.add_column("Errors", style="dim", width=6)

    for agent_name, data in sorted(scan_results.items()):
        if agent_name == "Brain":
            continue  # Brain is not an agent
        status_text = _status_text(data.get("status", "idle"))
        dur = data.get("duration_ms", 0)
        table.add_row(
            agent_name,
            status_text,
            str(data.get("finding_count", 0)),
            str(data.get("files_scanned", 0)),
            f"{dur}ms",
            str(len(data.get("errors", []))),
        )

    con.print(table)
    con.print()

def run_reset(agent_name: str | None = None, root: Path | None = None) -> None:
    """p agents reset [name] — reset circuit breaker for one or all agents."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    coord = Coordinator(r)
    reset = coord.reset_circuit_breaker(agent_name)
    if reset:
        con.print()
        con.print(
            f"[#4ADE80]✓[/#4ADE80] Circuit breaker reset for [bold]{len(reset)}[/bold] agent(s):"
        )
        for name in reset[:10]:
            con.print(f"  [dim]  {name}[/dim]")
        if len(reset) > 10:
            con.print(f"  [dim]  ... and {len(reset) - 10} more[/dim]")
        con.print()
    else:
        con.print("[dim]No circuit-broken agents to reset.[/dim]")

def _status_text(status: str) -> Text:
    colors = {
        "done": "#4ADE80",
        "failed": "#FF4D6D",
        "skipped": "dim",
        "running": "#C8621A",
        "idle": "dim",
    }
    label = str(status) if status is not None else "unknown"
    return Text(label, style=colors.get(status, "white"))
