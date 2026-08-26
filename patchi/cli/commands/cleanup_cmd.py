"""
`p cleanup` — Remove stale .patchi/ artifacts.

Cleans up generated/temporary files while preserving essential state:
  - JUnit XML reports from dev checks
  - Flake databases (patchi_history.db, *.db-journal, etc.)
  - Stale caches (AST, file_info, brain freshness, CVE, etc.)
  - Old log files
  - Ephemeral snapshots
  - Browser test screenshots/evidence (optional)
  - Profiling/stats files (.stats, .prof, .lprof)

Preserves:
  - config.json (project configuration)
  - memory/ (charter, layers, known issues, brain state)
  - api_key
  - queue.json

Usage:
  p cleanup              # Preview what would be removed (dry-run)
  p cleanup --apply      # Actually delete stale files
  p cleanup --all        # Also remove evidence/screenshots
"""

from __future__ import annotations

import os
from pathlib import Path

from patchi.cli.console import con
from patchi.core.config import find_project_root

# ── Artifact Patterns ────────────────────────────────────────────────────────
# (glob_pattern, description, keep_in_safe_mode)

CLEANUP_TARGETS = [
    # JUnit XML reports
    ("**/*junit*.xml", "JUnit test reports", False),
    ("**/*test-result*.xml", "pytest result files", False),
    ("**/dev-check-*.xml", "dev-check XML reports", False),

    # Flake/test databases
    ("**/*.db", "database files", False),
    ("**/*.db-journal", "database journals", False),
    ("**/*.db-wal", "database WAL files", False),
    ("**/*.db-shm", "database SHM files", False),

    # Stale caches
    ("ast_cache.json", "AST parse cache", False),
    ("file_info_cache.json", "file info cache", False),
    ("brain_freshness.json", "brain freshness cache", False),
    ("diff_activation_cache.json", "diff activation cache", False),
    ("threat_model.json", "threat model cache", False),
    ("queue.json", "queue state", False),
    ("cache/cve_cache.json", "CVE lookup cache", False),

    # Logs
    ("logs/*.log", "log files", False),
    ("logs/*.jsonl", "structured logs", False),

    # Snapshots
    ("snapshots/**/*", "ephemeral snapshots", False),

    # Profiling
    ("*.stats", "profiling stats", False),
    ("*.prof", "profiling data", False),
    ("*.lprof", "line profiling data", False),

    # Scratch files
    ("b.json", "scratch data", False),
    ("command_list.md", "generated command list", False),

    # Evidence (only with --all)
    ("evidence/dast/**/*", "DAST screenshots/evidence", True),
    ("evidence/browser_tests/**/*", "browser test evidence", True),
    ("evidence/test/**/*", "test evidence", True),
]


def cleanup(apply: bool = False, include_evidence: bool = False, root: Path | None = None):
    """Remove stale .patchi/ artifacts.

    Args:
        apply: If True, actually delete files. If False, just show what would be removed.
        include_evidence: If True, also remove evidence/screenshots.
        root: Override project root detection.
    """
    try:
        r = root or find_project_root()
    except Exception:
        try:
            from patchi.core.config import require_project_root
            r = require_project_root()
        except Exception as e:
            con.print(f"[red]{e}[/red]")
            return

    patchi_dir = r / ".patchi"
    if not patchi_dir.is_dir():
        con.print(f"[yellow]No .patchi directory found at {r}[/yellow]")
        return

    con.print()
    con.print("[bold #C8621A]Patchi Cleanup[/bold #C8621A]")
    con.print(f"[dim]Directory: {patchi_dir}[/dim]")
    mode_label = "DRY RUN (use --apply to delete)" if not apply else "[red]DELETING FILES[/red]"
    con.print(f"[dim]{mode_label}[/dim]")
    con.print()

    total_files = 0
    total_size = 0
    deleted_files = 0
    deleted_size = 0
    skipped_files = 0

    for pattern, description, evidence_only in CLEANUP_TARGETS:
        if evidence_only and not include_evidence:
            continue

        matches = list(patchi_dir.glob(pattern))

        if not matches:
            continue

        # Filter to actual files (not directories)
        files = [f for f in matches if f.is_file()]

        if not files:
            continue

        # Calculate size
        file_size = sum(f.stat().st_size for f in files if f.exists())
        total_files += len(files)
        total_size += file_size

        size_str = _format_size(file_size)
        count_str = f"{len(files)} file{'s' if len(files) != 1 else ''}"

        if apply:
            deleted_count = 0
            for f in files:
                try:
                    f.unlink()
                    deleted_count += 1
                    deleted_size += f.stat().st_size if f.exists() else 0
                except Exception as e:
                    skipped_files += 1
                    con.print(f"  [yellow]⚠ Could not delete {f.name}: {e}[/yellow]")

            if deleted_count > 0:
                con.print(f"  [red]✗[/red] {description}: {count_str} ({size_str})")
        else:
            con.print(f"  [yellow]?[/yellow] {description}: {count_str} ({size_str})")

    # Also clean empty directories
    empty_dirs = []
    for d in sorted(patchi_dir.rglob("*"), reverse=True):
        if d.is_dir() and not any(d.iterdir()):
            empty_dirs.append(d)

    if apply and empty_dirs:
        for d in empty_dirs:
            try:
                d.rmdir()
                con.print(f"  [red]✗[/red] Empty dir: {d.relative_to(patchi_dir)}")
            except Exception:
                pass

    # Summary
    con.print()
    if apply:
        if deleted_files > 0:
            con.print(f"[green]✓ Cleaned {deleted_files} files ({_format_size(deleted_size)} freed)[/green]")
        else:
            con.print("[dim]No stale files to clean.[/dim]")
        if skipped_files:
            con.print(f"[yellow]⚠ {skipped_files} files could not be deleted[/yellow]")
    else:
        con.print(f"[yellow]Would remove {total_files} files ({_format_size(total_size)})[/yellow]")
        con.print("[dim]Run with --apply to actually delete files.[/dim]")

    # Show what's preserved
    con.print()
    con.print("[dim]Preserved:[/dim]")
    preserved = []
    if (patchi_dir / "config.json").exists():
        preserved.append("config.json")
    if (patchi_dir / "memory").is_dir():
        preserved.append("memory/")
    if (patchi_dir / "api_key").exists():
        preserved.append("api_key")
    if preserved:
        con.print(f"[dim]  {', '.join(preserved)}[/dim]")
    else:
        con.print("[dim]  (nothing to preserve)[/dim]")
    con.print()


def _format_size(size: int) -> str:
    """Format bytes as human-readable string."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"
