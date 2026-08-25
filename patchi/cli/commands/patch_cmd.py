"""
`p patch` — Manage individual patches by ID.

Subcommands:
  p patch list          — list all patches (all states)
  p patch show <id>     — show full diff + metadata for one patch
  p patch apply <id>    — apply a pending patch
  p patch reject <id>   — reject a pending patch
"""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core import memory as mem
from patchi.core.config import require_project_root
from patchi.core.fix.patch import Patch, PatchState

_STATE_COLORS = {
    "proposed": "#B8A898",
    "pending": "#FACC15",
    "auto_applied": "#4ADE80",
    "applying": "#C8621A",
    "applied": "#4ADE80",
    "failed": "#FF4D6D",
    "rolled_back": "#FF8C42",
    "rejected": "dim",
    "undone": "dim",
}


def run_list(root: Path | None = None, json_output: bool = False) -> None:
    """p patch list"""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    patches_raw = mem.list_patches(r)
    if json_output:
        import json as _json

        con.print(_json.dumps({"patches": patches_raw or []}, indent=2, default=str))
        return

    if not patches_raw:
        con.print("[dim]No patches yet. Run [bold]p fix[/bold] to generate some.[/dim]")
        return

    con.print()
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("ID", style="bold #F2EDD6", width=10)
    table.add_column("State", width=12)
    table.add_column("Agent", style="dim", width=18)
    table.add_column("Risk", width=8)
    table.add_column("Files", justify="right", width=6)
    table.add_column("Description", width=44)

    risk_colors = {"low": "#4ADE80", "medium": "#FACC15", "high": "#FF4D6D"}

    for p in reversed(patches_raw):  # newest first
        risk_score = p.get("risk_score", 0)
        risk_level = p.get("risk_level", "low")
        state = p.get("state", "proposed")
        table.add_row(
            p.get("id", "?"),
            Text(state, style=_STATE_COLORS.get(state, "white")),
            p.get("agent", "?"),
            Text(f"{risk_score}", style=risk_colors.get(risk_level, "white")),
            str(p.get("file_count", 0)),
            p.get("description", "?")[:44],
        )

    con.print(table)
    con.print()
    con.print("[dim]p patch show <id>  ·  p patch apply <id>  ·  p patch reject <id>[/dim]")
    con.print()


def run_show(patch_id: str, root: Path | None = None, json_output: bool = False) -> None:
    """p patch show <id>"""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    patch_dict = mem.get_patch(patch_id, r)
    if not patch_dict:
        if json_output:
            import json as _json

            con.print(_json.dumps({"error": f"Patch {patch_id!r} not found"}, indent=2))
        else:
            con.print(f"[red]Patch {patch_id!r} not found.[/red]")
        return

    if json_output:
        import json as _json

        con.print(_json.dumps(patch_dict, indent=2, default=str))
        return

    patch = Patch.from_dict(patch_dict)
    state = patch.state.value
    state_color = _STATE_COLORS.get(state, "white")
    risk_colors = {"low": "#4ADE80", "medium": "#FACC15", "high": "#FF4D6D"}
    risk_color = risk_colors.get(patch.risk_level, "white")

    con.print()
    con.print(
        f"[bold #F2EDD6]Patch {patch.id}[/bold #F2EDD6]  [{state_color}]{state}[/{state_color}]"
    )
    con.print(
        f"[dim]Agent: {patch.agent}  ·  Type: {patch.patch_type.value}  ·  "
        f"Proposed: {patch.proposed_at[:19]}[/dim]"
    )
    con.print()
    con.print(f"  {patch.description}")
    if patch.ai_explanation:
        con.print(f"  [dim italic]{patch.ai_explanation[:120]}[/dim italic]")
    con.print()
    con.print(
        f"  [bold {risk_color}]Risk: {patch.risk_score}/100 ({patch.risk_level})[/bold {risk_color}]"
        f"   [dim]Confidence: {patch.confidence}%"
        f"   Blast radius: {patch.blast_radius}[/dim]"
    )
    con.print()

    for change in patch.changes:
        if not change.diff.strip():
            continue
        con.print(
            f"[bold #B8A898]{change.path}[/bold #B8A898]  "
            f"[dim]+{change.lines_added} -{change.lines_removed}[/dim]"
        )
        con.print(Syntax(change.diff, "diff", theme="monokai", padding=1))

    if patch.test_result:
        passed = patch.test_result.get("passed")
        if passed is True:
            con.print("[#4ADE80]Tests passed.[/#4ADE80]")
        elif passed is False:
            con.print("[red]Tests failed — patch rolled back.[/red]")
            out = patch.test_result.get("output", "")
            if out:
                con.print(f"[dim]{out[:500]}[/dim]")

    con.print()


def run_apply(patch_id: str, root: Path | None = None) -> None:
    """p patch apply <id>"""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    patch_dict = mem.get_patch(patch_id, r)
    if not patch_dict:
        con.print(f"[red]Patch {patch_id!r} not found.[/red]")
        return

    if patch_dict.get("state") not in ("pending", "proposed"):
        con.print(f"[yellow]Patch {patch_id} is already {patch_dict['state']}.[/yellow]")
        return

    from patchi.core.fix.applier import PatchApplier
    from patchi.core.fix.risk_gate import RiskGate

    patch = Patch.from_dict(patch_dict)
    gate = RiskGate(r)
    gate_result = gate.evaluate(patch)

    if gate_result.is_blocked:
        con.print(f"[red]Blocked:[/red] {gate_result.blocks[0]}")
        return

    con.print(f"Applying patch [bold]{patch_id}[/bold]…")
    result = PatchApplier(r).apply(patch)

    if result.success:
        con.print(
            f"[#4ADE80]✓ Applied.[/#4ADE80]  "
            f"[dim]Tests: {'passed' if result.test_passed else 'skipped'}  "
            f"Snapshot: {result.snapshot_id}[/dim]"
        )
    else:
        con.print(f"[red]✗ Failed.[/red]  [dim]{result.error}[/dim]")
        if result.rolled_back:
            con.print("[dim]Rolled back to original state.[/dim]")


def run_reject(patch_id: str, root: Path | None = None) -> None:
    """p patch reject <id>"""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    patch_dict = mem.get_patch(patch_id, r)
    if not patch_dict:
        con.print(f"[red]Patch {patch_id!r} not found.[/red]")
        return

    try:
        import json
        from datetime import datetime

        from patchi.core.constants import MEMORY_FILES, MemoryCategory

        patches = mem.list_patches(r)
        for p in patches:
            if p.get("id") == patch_id:
                p["state"] = PatchState.REJECTED.value
                p["rejected_at"] = datetime.now(UTC).isoformat()
                break
        mem_path = r / MEMORY_FILES[MemoryCategory.PATCHES]
        mem_path.write_text(json.dumps(patches, indent=2), encoding="utf-8")
        con.print(f"[dim]Patch {patch_id} rejected.[/dim]")
    except Exception as e:
        con.print(f"[red]Error: {e}[/red]")
