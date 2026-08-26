"""
`p watch` — Watch mode. Auto-scans on file saves.

Usage:
  p watch               — watch entire project
  p watch src/auth      — watch specific area only
  p watch --dry-run     — preview auto-fixes without applying

Runs until Ctrl+C. Every time a source file is saved, Patchi
re-scans the changed area and updates the brain.
"""

from __future__ import annotations

import logging
import signal
import time
from pathlib import Path

from patchi.cli.console import con
from patchi.core.brain.freshness import BrainWatcher
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.watch_cmd")


def run(
    area: str | None = None,
    root: Path | None = None,
    dry_run: bool = False,
) -> None:
    """Entry point for `p watch [area]`.

    Args:
        area: Optional subpath to watch.
        root: Override project root.
        dry_run: If True, preview auto-fixes without applying them.
    """
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    area_label = f" [dim]→ {area}[/dim]" if area else " [dim](full project)[/dim]"
    dry_label = " [yellow](dry-run)[/yellow]" if dry_run else ""
    con.print()
    con.print(f"[bold #C8621A]Watch mode{area_label}{dry_label}[/bold #C8621A]")
    con.print("[dim]Patchi is watching for file changes. Press Ctrl+C to stop.[/dim]")
    con.print()

    _running = [True]
    _scan_count = [0]

    def on_change(changed_paths: list[str]) -> None:
        _scan_count[0] += 1
        n = len(changed_paths)
        short = changed_paths[0] if changed_paths else "?"
        label = f"{short}" if n == 1 else f"{short} +{n - 1} more"

        # Respect quiet hours — skip auto-scan during quiet window (WIRE-05)
        try:
            from patchi.core import config as cfg_mod
            from patchi.core.notifications.quiet_hours import is_quiet_now

            conf = cfg_mod.load(r)
            qh = conf.get("quiet_hours", {})
            if is_quiet_now(qh):
                con.print(f"[dim]Quiet hours active — skipping auto-scan for {label}[/dim]")
                return
        except Exception as e:
            _log.warning("on_change failed: %s", e)

        con.print(f"[#C8621A]↺[/#C8621A] [dim]{label} changed — rescanning…[/dim]")

        # Determine minimal area to rescan
        rescan_area = area
        if not rescan_area and changed_paths:
            # Use the parent directory of the first changed file as the target
            parent = str(Path(changed_paths[0]).parent)
            if parent and parent != ".":
                rescan_area = parent

        try:
            from patchi.cli.commands.scan_cmd import run as run_scan

            run_scan(area=rescan_area, quiet=True, root=r)
            con.print("[#4ADE80]✓[/#4ADE80] [dim]Brain updated.[/dim]")
        except Exception as e:
            con.print(f"[yellow]⚠[/yellow] [dim]Rescan failed: {e}[/dim]")

        # ── Phase 4b: Proactive fixes on save (behind config flag) ─────────
        try:
            from patchi.core import config as cfg_mod
            from patchi.core.brain.proactive import (
                escalate_to_governor,
                run_proactive,
            )

            conf = cfg_mod.load(r)
            auto_fix = conf.get("auto_fix", {}) or {}
            af_enabled = bool(auto_fix.get("enabled", False))
            af_unsafe = bool(auto_fix.get("unsafe", False))

            norm = []
            for p in changed_paths:
                pp = Path(p)
                try:
                    norm.append(pp.relative_to(r).as_posix())
                except ValueError:
                    norm.append(pp.as_posix())
            if not norm:
                norm = changed_paths

            # Apply only if auto_fix enabled AND not in dry-run mode
            should_apply = af_enabled and not dry_run
            result = run_proactive(r, norm, apply=should_apply, unsafe=af_unsafe)
            if result["fixes"]:
                mode = "preview" if dry_run else "apply"
                con.print(
                    f"[dim]Proactive ({mode}): {len(result['fixes'])} fix(es) proposed "
                    f"({len(result['applied'])} applied, "
                    f"{len(result['escalated'])} need review).[/dim]"
                )
            for fix in result["escalated"]:
                escalate_to_governor(r, fix)
                con.print(
                    f"[#FACC15]⚠[/#FACC15] [yellow]Escalated to Governor:[/yellow] "
                    f"{fix.fix_type} → {fix.file}" + (f" ({fix.name})" if fix.name else "")
                )
                con.print(f"  [dim]{fix.description}[/dim]")
        except Exception as e:
            con.print(f"[dim]Proactive check skipped: {e}[/dim]")

        # ── Phase 4b: change-impact (blast radius) on save ────────────────
        try:
            from patchi.cli.commands.reason_cmd import run_impact

            if norm:
                run_impact(norm, root=r)
        except Exception as e:
            con.print(f"[dim]Impact analysis skipped: {e}[/dim]")

        # ── Phase 4b: secrets sweep on changed files only ─────────────────
        try:
            from patchi.core import memory as mem
            from patchi.core.brain.secrets import scan_secrets

            hits = scan_secrets(r, paths=norm) if norm else []
            for h in hits:
                mem.save_issue(
                    {
                        "source": "secrets",
                        "fix_type": "secret_leak",
                        "file": h.path,
                        "name": h.rule,
                        "description": f"Possible secret ({h.rule}) at line {h.line}: {h.snippet}",
                        "severity": "high",
                    }
                )
                con.print(
                    f"[#FACC15]🔒[/#FACC15] [yellow]Secret detected:[/yellow] "
                    f"{h.path}:{h.line} [{h.rule}]"
                )
                con.print(f"  [dim]{h.snippet}[/dim]")
            if hits:
                con.print(f"[dim]Escalated {len(hits)} secret hit(s) to Governor for review.[/dim]")
        except Exception as e:
            con.print(f"[dim]Secrets check skipped: {e}[/dim]")

        con.print()

    def handle_stop(sig, frame) -> None:
        _running[0] = False
        con.print()
        con.print(f"[dim]Watch stopped. {_scan_count[0]} rescan(s) triggered this session.[/dim]")
        con.print()

    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    try:
        watcher = BrainWatcher(root=r, on_change=on_change, area=area, debounce_ms=600)
        watcher.start()

        # Keep main thread alive
        while _running[0]:
            time.sleep(0.2)

        watcher.stop()

    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
    except Exception as e:
        con.print(f"[red]Watch error: {e}[/red]")
