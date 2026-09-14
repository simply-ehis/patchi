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
  p cleanup                          # Preview what would be removed (dry-run)
  p cleanup --apply                  # Actually delete stale files
  p cleanup --all                    # Also remove evidence/screenshots
  p cleanup --older-than 7d          # Only remove files older than 7 days
  p cleanup --dry-run --json         # JSON output for CI integration
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from patchi.cli.console import con
from patchi.core.config import find_project_root

_log = logging.getLogger("patchi.cli.commands.cleanup_cmd")


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


def _parse_age(age_str: str) -> float:
    """Parse age string like '7d', '24h', '30m' into seconds."""
    age_str = age_str.strip().lower()
    if age_str.endswith("d"):
        return float(age_str[:-1]) * 86400
    elif age_str.endswith("h"):
        return float(age_str[:-1]) * 3600
    elif age_str.endswith("m"):
        return float(age_str[:-1]) * 60
    else:
        # Assume days
        return float(age_str) * 86400


def _is_file_older_than(file_path: Path, max_age_seconds: float) -> bool:
    """Check if a file is older than the specified age."""
    try:
        mtime = file_path.stat().st_mtime
        age = time.time() - mtime
        return age > max_age_seconds
    except Exception:
        return False


def cleanup(
    apply: bool = False,
    include_evidence: bool = False,
    older_than: str | None = None,
    json_output: bool = False,
    no_backup: bool = False,
    root: Path | None = None,
):
    """Remove stale .patchi/ artifacts.

    Args:
        apply: If True, actually delete files. If False, just show what would be removed.
        include_evidence: If True, also remove evidence/screenshots.
        older_than: Only remove files older than this (e.g. '7d', '24h', '30m').
        json_output: If True, output as JSON for CI integration.
        root: Override project root detection.
    """
    try:
        r = root or find_project_root()
    except Exception:
        try:
            from patchi.core.config import require_project_root

            r = require_project_root()
        except Exception as e:
            if json_output:
                pass
            else:
                con.print(f"[red]{e}[/red]")
            return

    patchi_dir = r / ".patchi"
    if not patchi_dir.is_dir():
        if json_output:
            pass
        else:
            con.print(f"[yellow]No .patchi directory found at {r}[/yellow]")
        return

    # Parse age filter
    max_age_seconds = _parse_age(older_than) if older_than else None

    if not json_output:
        con.print()
        con.print("[bold #C8621A]Patchi Cleanup[/bold #C8621A]")
        con.print(f"[dim]Directory: {patchi_dir}[/dim]")
        mode_label = "DRY RUN (use --apply to delete)" if not apply else "[red]DELETING FILES[/red]"
        age_label = f" | Age filter: > {older_than}" if older_than else ""
        con.print(f"[dim]{mode_label}{age_label}[/dim]")
        con.print()

    total_files = 0
    total_size = 0
    deleted_files = 0
    deleted_size = 0
    skipped_files = 0
    filtered_out = 0
    cleanup_data = []

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

        # Apply age filter
        if max_age_seconds is not None:
            old_files = [f for f in files if _is_file_older_than(f, max_age_seconds)]
            filtered_out += len(files) - len(old_files)
            files = old_files

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
                    file_size_actual = f.stat().st_size if f.exists() else 0
                    f.unlink()
                    deleted_count += 1
                    deleted_files += 1
                    deleted_size += file_size_actual
                except Exception as e:
                    skipped_files += 1
                    if not json_output:
                        con.print(f"  [yellow]⚠ Could not delete {f.name}: {e}[/yellow]")

            if deleted_count > 0 and not json_output:
                con.print(f"  [red]✗[/red] {description}: {count_str} ({size_str})")
        else:
            if not json_output:
                con.print(f"  [yellow]?[/yellow] {description}: {count_str} ({size_str})")

        # Collect data for JSON output
        cleanup_data.append(
            {
                "description": description,
                "pattern": pattern,
                "count": len(files),
                "size_bytes": file_size,
                "files": [str(f.relative_to(patchi_dir)) for f in files[:20]],  # Limit to 20
            }
        )

    # Also clean empty directories
    empty_dirs = []
    for d in sorted(patchi_dir.rglob("*"), reverse=True):
        if d.is_dir() and not any(d.iterdir()):
            empty_dirs.append(d)

    if apply and empty_dirs:
        for d in empty_dirs:
            try:
                d.rmdir()
                if not json_output:
                    con.print(f"  [red]✗[/red] Empty dir: {d.relative_to(patchi_dir)}")
            except Exception as _exc:
                _log.warning("cleanup failed: %s", _exc)

    # JSON output for CI
    if json_output:
        {
            "dry_run": not apply,
            "older_than": older_than,
            "total_files": total_files,
            "total_size_bytes": total_size,
            "deleted_files": deleted_files,
            "deleted_size_bytes": deleted_size,
            "skipped_files": skipped_files,
            "filtered_out": filtered_out,
            "categories": cleanup_data,
            "preserved": _get_preserved(patchi_dir),
        }
        return

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
        if filtered_out > 0:
            con.print(f"[dim]Filtered out {filtered_out} files (newer than {older_than})[/dim]")
        con.print("[dim]Run with --apply to actually delete files.[/dim]")

    # Show what's preserved
    con.print()
    con.print("[dim]Preserved:[/dim]")
    preserved = _get_preserved(patchi_dir)
    if preserved:
        con.print(f"[dim]  {', '.join(preserved)}[/dim]")
    else:
        con.print("[dim]  (nothing to preserve)[/dim]")
    con.print()


def _get_preserved(patchi_dir: Path) -> list[str]:
    """Get list of preserved items."""
    preserved = []
    if (patchi_dir / "config.json").exists():
        preserved.append("config.json")
    if (patchi_dir / "memory").is_dir():
        preserved.append("memory/")
    if (patchi_dir / "api_key").exists():
        preserved.append("api_key")
    return preserved


def get_patchi_size(root: Path | None = None) -> dict:
    """Get the total size of .patchi/ directory for doctor warnings."""
    try:
        r = root or find_project_root()
    except Exception:
        return {"total_bytes": 0, "total_files": 0}

    patchi_dir = r / ".patchi"
    if not patchi_dir.is_dir():
        return {"total_bytes": 0, "total_files": 0}

    total_bytes = 0
    total_files = 0
    for f in patchi_dir.rglob("*"):
        if f.is_file():
            try:
                total_bytes += f.stat().st_size
                total_files += 1
            except Exception as _exc:
                _log.warning("get_patchi_size failed: %s", _exc)

    return {"total_bytes": total_bytes, "total_files": total_files}


def _format_size(size: int) -> str:
    """Format bytes as human-readable string."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"
