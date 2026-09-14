"""
`p fix review` — Interactive review of proposed fixes.

Usage:
  p fix review              — review all pending patches
  p fix review --patch <id> — review a specific patch

Interactive prompts:
  ✓ Accept  — apply the patch
  ✗ Reject  — discard the patch
  ↷ Skip    — keep in queue
  ↳ View    — show full diff
"""

from __future__ import annotations

import logging
from pathlib import Path

from rich.syntax import Syntax
from rich.table import Table

from patchi.cli.console import con
from patchi.cli.ux import (
    format_error,
    format_header,
    format_step,
    summary_panel,
)
from patchi.core.config import require_project_root
from patchi.core.fix.patch import Patch, PatchState

_log = logging.getLogger("patchi.cli.fix.review")


def _load_pending_patches(root: Path) -> list[Patch]:
    """Load pending patches from memory."""
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    pending = brain.get("pending_patches", [])

    patches = []
    for p_data in pending:
        try:
            patch = Patch(
                id=p_data.get("id", "unknown"),
                file=Path(p_data.get("file", "")),
                finding=p_data.get("finding", {}),
                message=p_data.get("message", ""),
                diff=p_data.get("diff", ""),
                strategy=p_data.get("strategy", ""),
                blast_radius=p_data.get("blast_radius"),
                requires_review=p_data.get("requires_review", False),
            )
            patch.state = PatchState.PENDING
            patches.append(patch)
        except Exception as e:
            _log.debug("Failed to load patch: %s", e)

    return patches


def _save_patch_status(root: Path, patch_id: str, accepted: bool) -> None:
    """Save patch acceptance status."""
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    pending = brain.get("pending_patches", [])

    # Remove from pending
    pending = [p for p in pending if isinstance(p, dict) and p.get("id") != patch_id]

    # Add to accepted or rejected list
    if accepted:
        accepted_list = brain.get("accepted_patches", [])
        accepted_list.append(patch_id)
        brain["accepted_patches"] = accepted_list[-100:]  # Keep last 100
    else:
        rejected_list = brain.get("rejected_patches", [])
        rejected_list.append(patch_id)
        brain["rejected_patches"] = rejected_list[-100:]

    brain["pending_patches"] = pending
    mem.save_brain(root, brain)


def _display_patch(patch: Patch, index: int, total: int) -> None:
    """Display a patch in a rich format."""
    con.print()
    con.print(
        format_step(
            index + 1,
            total,
            f"[cyan]{patch.id}[/cyan] — {patch.message[:60]}{'...' if len(patch.message) > 60 else ''}",
        )
    )
    con.print()

    # Patch details table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="cyan", ratio=1)
    table.add_column("Value", ratio=3)

    table.add_row("File", str(patch.file))
    table.add_row("Strategy", patch.strategy)
    if patch.blast_radius is not None:
        table.add_row("Blast Radius", str(patch.blast_radius))
    if patch.finding:
        table.add_row("Finding", patch.finding.get("type", "unknown"))
        table.add_row("Severity", patch.finding.get("severity", "unknown"))

    con.print(table)

    # Show diff if available
    if patch.diff:
        con.print()
        con.print("[dim]Diff:[/dim]")
        con.print(
            Syntax(
                patch.diff,
                "diff",
                theme="monokai",
                line_numbers=False,
                word_wrap=True,
            )
        )


def _prompt_action() -> str:
    """Prompt user for patch action."""
    con.print()
    con.print(
        "[dim]Actions:[/dim] "
        "[green]a[/green]ccept  "
        "[red]r[/red]eject  "
        "[yellow]s[/yellow]kip  "
        "[blue]v[/blue]iew diff  "
        "[dim]q[/dim]uit"
    )
    con.print()

    while True:
        try:
            choice = input("Action: ").strip().lower()
            if choice in ("a", "accept"):
                return "accept"
            elif choice in ("r", "reject"):
                return "reject"
            elif choice in ("s", "skip"):
                return "skip"
            elif choice in ("v", "view", "d", "diff"):
                return "view"
            elif choice in ("q", "quit", "exit"):
                return "quit"
            else:
                con.print("[dim]Invalid choice. Try a/r/s/v/q[/dim]")
        except (EOFError, KeyboardInterrupt):
            return "quit"


def _apply_patch(patch: Patch, root: Path) -> bool:
    """Apply a patch."""
    from patchi.core.fix.applier import PatchApplier

    applier = PatchApplier(root)
    result = applier.apply(patch)
    return result.success


def run(
    patch_id: str | None = None,
    root: Path | None = None,
) -> None:
    """Entry point for `p fix review`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(format_error(str(e)))
        return

    con.print()
    con.print(format_header("Fix Review", "Review and decide on proposed patches"))
    con.print()

    patches = _load_pending_patches(r)

    if not patches:
        con.print("[dim]No pending patches to review.[/dim]")
        con.print()
        con.print("[dim]Run [bold]p fix[/bold] to generate patches first.[/dim]")
        con.print()
        return

    # Filter by patch_id if specified
    if patch_id:
        patches = [p for p in patches if p.id == patch_id]
        if not patches:
            con.print(f"[red]Patch {patch_id} not found or not pending.[/red]")
            return

    total = len(patches)
    accepted = 0
    rejected = 0
    skipped = 0

    con.print(f"[dim]{total} patch(es) to review[/dim]")

    for i, patch in enumerate(patches):
        _display_patch(patch, i, total)

        action = _prompt_action()

        if action == "accept":
            if _apply_patch(patch, r):
                _save_patch_status(r, patch.id, accepted=True)
                con.print(f"[green]✓ Patch {patch.id} applied successfully[/green]")
                accepted += 1
            else:
                con.print(f"[red]✗ Failed to apply patch {patch.id}[/red]")
        elif action == "reject":
            _save_patch_status(r, patch.id, accepted=False)
            con.print(f"[yellow]✗ Patch {patch.id} rejected[/yellow]")
            rejected += 1
        elif action == "skip":
            con.print(f"[dim]– Patch {patch.id} skipped[/dim]")
            skipped += 1
        elif action == "view":
            # Show diff again (already shown above)
            con.print("[dim]Diff shown above. Continuing...[/dim]")
            # Re-prompt in a loop
            while True:
                action2 = _prompt_action()
                if action2 == "accept":
                    if _apply_patch(patch, r):
                        _save_patch_status(r, patch.id, accepted=True)
                        con.print(f"[green]✓ Patch {patch.id} applied successfully[/green]")
                        accepted += 1
                    else:
                        con.print(f"[red]✗ Failed to apply patch {patch.id}[/red]")
                    break
                elif action2 == "reject":
                    _save_patch_status(r, patch.id, accepted=False)
                    con.print(f"[yellow]✗ Patch {patch.id} rejected[/yellow]")
                    rejected += 1
                    break
                elif action2 == "skip":
                    con.print(f"[dim]– Patch {patch.id} skipped[/dim]")
                    skipped += 1
                    break
                elif action2 == "quit":
                    break
                # If they chose "view" again, just loop
        elif action == "quit":
            break

        con.print()

    # Summary
    items = {
        "Accepted": accepted > 0,
        "Rejected": rejected > 0,
        "Skipped": skipped > 0,
        "Remaining": total - accepted - rejected - skipped > 0,
    }

    con.print(summary_panel("Review Complete", items))
    con.print()
    con.print(f"[dim]Accepted: {accepted} | Rejected: {rejected} | Skipped: {skipped}[/dim]")
    con.print()
