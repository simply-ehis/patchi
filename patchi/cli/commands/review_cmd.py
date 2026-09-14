"""
`p review` — Interactive patch review panel.

Shows all pending patches with:
  - Color-coded unified diff
  - Risk score + confidence + blast radius
  - Accept / Reject prompt per patch
  - Bulk accept-all / reject-all

After review, accepted patches are applied via PatchApplier.
"""

from __future__ import annotations

import logging
from datetime import UTC
from pathlib import Path

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax

from patchi.cli.console import con
from patchi.core import memory as mem
from patchi.core.config import require_project_root
from patchi.core.fix.applier import PatchApplier
from patchi.core.fix.patch import Patch, PatchState

_log = logging.getLogger("patchi.cli.review_cmd")


def run(root: Path | None = None) -> None:
    """p review — show all pending patches."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    patches_raw = mem.list_patches(r)
    pending = [Patch.from_dict(p) for p in patches_raw if p.get("state") == PatchState.PENDING.value]

    con.print()

    if not pending:
        con.print(
            Panel(
                "[dim]Nothing waiting for your review. All clear.[/dim]\n",
                title="[bold #C8621A]Review Panel[/bold #C8621A]",
                border_style="#2A3D28",
            )
        )
        con.print()
        return

    con.print(
        f"[bold #F2EDD6]{len(pending)} patch(es) waiting for review.[/bold #F2EDD6]  "
        f"[dim]Accept all · Reject all · Review one by one[/dim]"
    )
    con.print()

    # Bulk actions first
    if len(pending) > 1:
        bulk = Prompt.ask(
            "Bulk action",
            choices=["all", "none", "one-by-one"],
            default="one-by-one",
        )
        if bulk == "all":
            _apply_all(pending, r)
            return
        elif bulk == "none":
            _reject_all(pending, r)
            return

    # One-by-one review
    applier = PatchApplier(r)
    accepted = 0
    rejected = 0

    for i, patch in enumerate(pending, 1):
        con.print(f"[dim]Patch {i} of {len(pending)}[/dim]")
        _show_patch_card(patch)

        decision = Confirm.ask(
            f"  Apply [bold]{patch.id}[/bold]?",
            default=False,
        )

        if decision:
            result = applier.apply(patch)
            if result.success:
                con.print(
                    f"  [#4ADE80]✓ Applied.[/#4ADE80]  "
                    f"[dim]Tests: {'passed' if result.test_passed else 'skipped (no tests)'}[/dim]"
                )
                accepted += 1
            else:
                con.print(f"  [red]✗ Failed and rolled back.[/red]  [dim]{result.error[:80]}[/dim]")
        else:
            _reject_patch(patch, r)
            con.print("  [dim]Rejected.[/dim]")
            rejected += 1

        con.print()

    con.print(f"[dim]Review complete: {accepted} applied, {rejected} rejected.[/dim]")
    con.print()


# ── Patch card renderer ────────────────────────────────────────────────────────


def _show_patch_card(patch: Patch) -> None:
    """Render a single patch with diff, scores, and metadata."""
    risk_colors = {
        "low": "#4ADE80",
        "medium": "#FACC15",
        "high": "#FF4D6D",
    }
    risk_color = risk_colors.get(patch.risk_level, "white")

    # Header
    con.print(
        Panel(
            f"[bold #F2EDD6]{patch.description}[/bold #F2EDD6]\n"
            f"[dim]Agent: {patch.agent}  ·  "
            f"Files: {patch.file_count}  ·  "
            f"Lines: {patch.total_lines_changed}[/dim]",
            title=f"[bold]Patch {patch.id}[/bold]",
            border_style=risk_color,
            padding=(0, 1),
        )
    )

    # Score bar
    con.print(
        f"  [bold {risk_color}]Risk: {patch.risk_score}/100 ({patch.risk_level.upper()})[/bold {risk_color}]"
        f"   [dim]Confidence: {patch.confidence}%"
        f"   Blast radius: {patch.blast_radius} file(s)[/dim]"
    )

    if patch.ai_explanation:
        con.print(f"  [dim italic]{patch.ai_explanation[:120]}[/dim italic]")

    con.print()

    # Diffs
    for change in patch.changes:
        if not change.diff.strip():
            continue
        con.print(
            f"  [bold #B8A898]{change.path}[/bold #B8A898]  [dim]+{change.lines_added} / -{change.lines_removed}[/dim]"
        )
        # Syntax-highlighted diff
        diff_syntax = Syntax(
            change.diff[:1500],
            "diff",
            theme="monokai",
            line_numbers=False,
            padding=1,
        )
        con.print(diff_syntax)


# ── Bulk actions ───────────────────────────────────────────────────────────────


def _apply_all(patches: list[Patch], root: Path) -> None:
    applier = PatchApplier(root)
    applied = 0
    for patch in patches:
        result = applier.apply(patch)
        if result.success:
            applied += 1
            con.print(f"  [#4ADE80]✓[/#4ADE80] {patch.id} — {patch.description[:60]}")
        else:
            con.print(f"  [red]✗[/red] {patch.id} — rolled back. {result.error[:60]}")
    con.print()
    con.print(f"[dim]Applied {applied}/{len(patches)} patches.[/dim]")
    con.print()


def _reject_all(patches: list[Patch], root: Path) -> None:
    for patch in patches:
        _reject_patch(patch, root)
    con.print(f"[dim]Rejected {len(patches)} patches.[/dim]")
    con.print()


def _reject_patch(patch: Patch, root: Path) -> None:
    """Mark a patch as rejected in memory + track rejection count for learning."""
    try:
        from datetime import datetime

        patches_raw = mem.list_patches(root)
        for p in patches_raw:
            if p.get("id") == patch.id:
                p["state"] = PatchState.REJECTED.value
                p["rejected_at"] = datetime.now(UTC).isoformat()
                break
        import json

        from patchi.core.constants import MEMORY_FILES, MemoryCategory

        mem_path = root / MEMORY_FILES[MemoryCategory.PATCHES]
        mem_path.write_text(json.dumps(patches_raw, indent=2), encoding="utf-8")
    except Exception as e:
        _log.warning("_reject_patch failed: %s", e)

    # Rejection learning — track count per patch type
    try:
        patch_type = getattr(patch, "patch_type", None)
        if patch_type:
            type_str = patch_type.value if hasattr(patch_type, "value") else str(patch_type)
            count = mem.record_rejection(type_str, root)
            if count == 3:
                con.print(f"\n[#C8621A]ℹ You've rejected [bold]{type_str}[/bold] patches 3 times.[/#C8621A]")
    except Exception as e:
        _log.warning("_reject_patch failed: %s", e)
