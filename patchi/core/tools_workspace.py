"""Per-scan scratch workspace for external security-tool reports.

Reports from gitleaks / osv-scanner / bandit / codeql used to be written to
system temp (``%TEMP%``) with pre-created ``NamedTemporaryFile`` paths. Two
failure classes followed (seen in the field on Windows):

1. gitleaks v8 refuses to write to a path that already exists, so a
   pre-created empty report file means the tool produces no report and the
   reader then crashes on the missing file.
2. System-temp paths can be swept by other processes mid-scan and are
   invisible in the project, making failures hard to diagnose.

Scratch files now live under ``<project>/.patchi/tmp/tool-runs/`` (or
``%LOCALAPPDATA%/patchi/tool-runs`` when there is no project root), are
never pre-created, and old files are swept on a delay so concurrent scans
don't race the cleanup.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

_log = logging.getLogger("patchi.core.tools_workspace")

_SWEEP_OLDER_THAN_S = 24 * 3600  # keep failed-run evidence for a day
_SWEEP_EVERY_S = 600.0
_last_sweep = 0.0


def _base() -> Path:
    """Scratch root: inside the project when one exists, else per-user."""
    try:
        from patchi.core.config import find_project_root

        root = find_project_root()
        if root is not None:
            return root / ".patchi" / "tmp" / "tool-runs"
    except Exception:  # noqa: BLE001 — scratch must never break a scan
        pass
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "patchi" / "tool-runs"


def scratch_dir() -> Path:
    """Create (if needed) and return the tool-run scratch directory."""
    d = _base()
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        _log.warning("tool scratch dir unavailable (%s); falling back to system temp", e)
        import tempfile

        d = Path(tempfile.gettempdir()) / "patchi-tool-runs"
        d.mkdir(parents=True, exist_ok=True)
    return d


def scratch_file(name: str) -> Path:
    """Unique path under the scratch dir. NOT created — the tool writes it."""
    _maybe_sweep()
    return scratch_dir() / name


def _maybe_sweep() -> None:
    """Best-effort cleanup of stale tool reports (rate-limited, never raises)."""
    global _last_sweep
    now = time.monotonic()
    if now - _last_sweep < _SWEEP_EVERY_S:
        return
    _last_sweep = now
    try:
        d = _base()
        if not d.is_dir():
            return
        cutoff = time.time() - _SWEEP_OLDER_THAN_S
        for p in d.iterdir():
            try:
                if p.is_file() and p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                continue
    except Exception as e:  # noqa: BLE001 — cleanup is opportunistic
        _log.debug("scratch sweep skipped: %s", e)
