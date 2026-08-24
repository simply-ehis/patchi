"""
`p undo`, `p redo`, `p rollback` — Patch history navigation.

p undo              — undo last applied fix
p undo <id>         — undo specific patch by ID
p redo              — redo last undone fix
p redo <id>         — redo specific patch by ID
p rollback <id>     — rollback all patches back to before a specific patch
"""

from __future__ import annotations
from patchi.cli.console import con

from pathlib import Path

from rich.prompt import Confirm

from patchi.core import memory as mem
from patchi.core.config import require_project_root
from patchi.core.fix.applier import PatchApplier
from patchi.core.fix.patch import Patch, PatchState

import logging
_log = logging.getLogger("patchi.cli.undo_cmd")

def run_undo(patch_id: str | None = None, root: Path | None = None) -> None:
    """p undo [id]"""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    target = _find_for_undo(patch_id, r)
    if not target:
        con.print("[dim]Nothing to undo.[/dim]")
        return

    patch = Patch.from_dict(target)
    snapshot_id = patch.snapshot_id

    if not snapshot_id:
        con.print(f"[red]Patch {patch.id} has no snapshot — cannot undo.[/red]")
        return

    con.print(f"Undoing [bold]{patch.id}[/bold]: {patch.description[:60]}")

    applier = PatchApplier(r)
    result = applier.rollback(patch.id, snapshot_id)

    if result.success:
        _mark_undone(patch.id, r)
        con.print(
            f"[#4ADE80]✓ Undone.[/#4ADE80]  [dim]Files restored from snapshot {snapshot_id}[/dim]"
        )
    else:
        con.print(f"[red]✗ Undo failed.[/red]  [dim]{result.error}[/dim]")

def run_redo(patch_id: str | None = None, root: Path | None = None) -> None:
    """p redo [id]"""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    target = _find_for_redo(patch_id, r)
    if not target:
        con.print("[dim]Nothing to redo.[/dim]")
        return

    patch = Patch.from_dict(target)

    con.print(f"Re-applying [bold]{patch.id}[/bold]: {patch.description[:60]}")

    from patchi.core.fix.risk_gate import RiskGate

    gate_result = RiskGate(r).evaluate(patch)
    if gate_result.is_blocked:
        con.print(f"[red]Blocked:[/red] {gate_result.blocks[0]}")
        return

    # Re-apply the patch from its stored changes
    patch.state = PatchState.PENDING
    applier = PatchApplier(r)
    result = applier.apply(patch)

    if result.success:
        _mark_applied(patch.id, r)
        con.print(
            f"[#4ADE80]✓ Re-applied.[/#4ADE80]  "
            f"[dim]Tests: {'passed' if result.test_passed else 'skipped'}[/dim]"
        )
    else:
        con.print(f"[red]✗ Failed.[/red]  [dim]{result.error}[/dim]")

def run_rollback(patch_id: str, root: Path | None = None) -> None:
    """
    p rollback <id> — rollback all changes back to the state before this patch.

    Restores the snapshot taken before patch_id was applied.
    All patches applied AFTER patch_id are also undone (oldest first).
    """
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    patches_raw = mem.list_patches(r)
    target = next((p for p in patches_raw if p.get("id") == patch_id), None)

    if not target:
        con.print(f"[red]Patch {patch_id!r} not found.[/red]")
        return

    # Find all patches applied at or after target (in order)
    applied_patches = [p for p in patches_raw if p.get("state") in ("applied", "auto_applied")]
    applied_patches.sort(key=lambda p: p.get("applied_at", ""))

    try:
        target_idx = next(i for i, p in enumerate(applied_patches) if p.get("id") == patch_id)
    except StopIteration:
        con.print(
            f"[yellow]Patch {patch_id} was not applied (state: {target.get('state')})[/yellow]"
        )
        return

    patches_to_undo = applied_patches[target_idx:]
    count = len(patches_to_undo)

    con.print()
    con.print(f"[yellow]This will undo {count} patch(es):[/yellow]")
    for p in patches_to_undo:
        con.print(f"  [dim]● {p['id']}[/dim] {p.get('description', '')[:60]}")
    con.print()

    if not Confirm.ask("Proceed with rollback?", default=False):
        con.print("[dim]Cancelled.[/dim]")
        return

    applier = PatchApplier(r)
    undone = 0

    # Undo in reverse order (newest first)
    for p_dict in reversed(patches_to_undo):
        snap_id = p_dict.get("snapshot_id", "")
        if not snap_id:
            con.print(f"  [yellow]⚠[/yellow] {p_dict['id']} — no snapshot, skipping")
            continue
        result = applier.rollback(p_dict["id"], snap_id)
        if result.success:
            _mark_undone(p_dict["id"], r)
            con.print(f"  [#4ADE80]✓[/#4ADE80] {p_dict['id']} undone")
            undone += 1
        else:
            con.print(f"  [red]✗[/red] {p_dict['id']} — {result.error[:60]}")
            break  # Stop on first failure — don't continue partial rollback

    con.print()
    con.print(f"[dim]Rollback complete: {undone}/{count} patches undone.[/dim]")
    con.print()

# ── Finders ────────────────────────────────────────────────────────────────────

def _find_for_undo(patch_id: str | None, root: Path) -> dict | None:
    patches = mem.list_patches(root)
    applied = [p for p in patches if p.get("state") in ("applied", "auto_applied")]
    if not applied:
        return None
    if patch_id:
        return next((p for p in applied if p.get("id") == patch_id), None)
    # Last applied
    applied.sort(key=lambda p: p.get("applied_at", ""))
    return applied[-1]

def _find_for_redo(patch_id: str | None, root: Path) -> dict | None:
    patches = mem.list_patches(root)
    undone = [p for p in patches if p.get("state") == "undone"]
    if not undone:
        return None
    if patch_id:
        return next((p for p in undone if p.get("id") == patch_id), None)
    # Most recently undone
    undone.sort(key=lambda p: p.get("rolled_back_at", ""), reverse=True)
    return undone[0]

# ── State update ───────────────────────────────────────────────────────────────

def _mark_undone(patch_id: str, root: Path) -> None:
    try:
        import json
        from datetime import datetime, timezone

        from patchi.core.constants import MEMORY_FILES, MemoryCategory

        patches = mem.list_patches(root)
        for p in patches:
            if p.get("id") == patch_id:
                p["state"] = PatchState.UNDONE.value
                p["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
                break
        mem_path = root / MEMORY_FILES[MemoryCategory.PATCHES]
        mem_path.write_text(json.dumps(patches, indent=2), encoding="utf-8")
    except Exception as e:
        _log.warning("_mark_undone failed: %s", e)

def _mark_applied(patch_id: str, root: Path) -> None:
    """Mark a patch as applied (used after redo succeeds)."""
    try:
        import json
        from datetime import datetime, timezone

        from patchi.core.constants import MEMORY_FILES, MemoryCategory

        patches = mem.list_patches(root)
        for p in patches:
            if p.get("id") == patch_id:
                p["state"] = PatchState.APPLIED.value
                p["applied_at"] = datetime.now(timezone.utc).isoformat()
                break
        mem_path = root / MEMORY_FILES[MemoryCategory.PATCHES]
        mem_path.write_text(json.dumps(patches, indent=2), encoding="utf-8")
    except Exception as e:
        _log.warning("_mark_applied failed: %s", e)
