"""
Rotating audit log for Patchi hosted mode.

Writes structured JSON-lines to .patchi/hosted/audit.log.
Rotates when file exceeds MAX_SIZE_BYTES, keeping MAX_BACKUPS old files.
Each entry: {timestamp, event, actor, data}.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

_LOG_FILE = ".patchi/hosted/audit.log"
MAX_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_BACKUPS = 3


_log = logging.getLogger("patchi.core.audit_log")


def _log_path(root: Path) -> Path:
    return root / _LOG_FILE


def _rotate(path: Path) -> None:
    """Rotate old log files, keeping MAX_BACKUPS copies."""
    # Shift existing backups down (remove oldest first to avoid conflicts)
    for i in range(MAX_BACKUPS - 1, 0, -1):
        src = Path(f"{path}.{i}")
        dst = Path(f"{path}.{i + 1}")
        if dst.exists():
            dst.unlink()
        if src.exists():
            src.rename(dst)
    # Move current log to .1
    if path.exists():
        dst = Path(f"{path}.1")
        if dst.exists():
            dst.unlink()
        path.rename(dst)


def write(root: Path, event: str, actor: str = "patchi", data: dict | None = None) -> None:
    """
    Append one audit entry. Rotates if log exceeds MAX_SIZE_BYTES.
    Never raises — audit logging must not crash the caller.
    """
    try:
        path = _log_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists() and path.stat().st_size >= MAX_SIZE_BYTES:
            _rotate(path)

        entry = json.dumps(
            {
                "timestamp": time.time(),
                "event": event,
                "actor": actor,
                "data": data or {},
            }
        )
        with path.open("a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception as e:
        _log.warning("write failed: %s", e)


def read_recent(root: Path, limit: int = 50) -> list[dict]:
    """Return the most recent `limit` audit entries, newest first."""
    path = _log_path(root)
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        entries = []
        for line in reversed(lines[-limit * 2 :]):
            try:
                entries.append(json.loads(line))
                if len(entries) >= limit:
                    break
            except json.JSONDecodeError:
                continue
        return entries
    except OSError:
        return []


def clear(root: Path) -> int:
    """Delete current log and all backups. Returns number of files removed."""
    path = _log_path(root)
    removed = 0
    for p in [path] + [Path(f"{path}.{i}") for i in range(1, MAX_BACKUPS + 2)]:
        try:
            if p.exists():
                p.unlink()
                removed += 1
        except OSError:
            pass
    return removed
