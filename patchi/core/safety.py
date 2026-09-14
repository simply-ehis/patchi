"""
Undo safety for destructive file operations.

Moves files/directories to a backup directory instead of permanently deleting
them, enabling restoration if needed.

Usage:
    from patchi.core.safety import safe_delete, safe_rmtree, list_backups, restore

    backup = safe_delete(Path("data/old_file.csv"))
    safe_rmtree(Path("data/cache"))
    restore(backup, Path("data/old_file.csv"))
"""

from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path

_log = logging.getLogger("patchi.core.safety")


def _backup_root(backup_dir: str | Path) -> Path:
    """Resolve backup directory relative to cwd."""
    return Path(backup_dir)


def safe_delete(
    path: Path,
    backup_dir: str | Path = ".patchi/backups",
) -> Path:
    """Move a file to the backup directory instead of deleting it.

    Returns the backup path.  If the move fails, the file is left in place
    and the original path is returned so callers never lose data silently.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {path}")

    dest_root = _backup_root(backup_dir)
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_name = f"{path.name}.{ts}"
    dest = dest_root / safe_name
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        shutil.move(str(path), str(dest))
        _log.info("safe_delete: %s -> %s", path, dest)
    except Exception:
        _log.warning("safe_delete: move failed for %s, leaving in place", path)
        return path

    return dest


def safe_rmtree(
    path: Path,
    backup_dir: str | Path = ".patchi/backups",
) -> Path:
    """Move a directory tree to the backup directory instead of deleting it.

    Returns the backup path.  If the move fails, the directory is left in
    place and the original path is returned.
    """
    path = Path(path)
    if not path.is_dir():
        raise FileNotFoundError(f"Not a directory: {path}")

    dest_root = _backup_root(backup_dir)
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_name = f"{path.name}.{ts}"
    dest = dest_root / safe_name
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        shutil.move(str(path), str(dest))
        _log.info("safe_rmtree: %s -> %s", path, dest)
    except Exception:
        _log.warning("safe_rmtree: move failed for %s, leaving in place", path)
        return path

    return dest


def list_backups(backup_dir: str | Path = ".patchi/backups") -> list[dict]:
    """List all backed-up items with timestamps.

    Returns a list of dicts with keys: name, path, size_bytes, mtime.
    """
    root = _backup_root(backup_dir)
    if not root.is_dir():
        return []

    results = []
    for item in sorted(root.iterdir()):
        try:
            stat = item.stat()
            results.append(
                {
                    "name": item.name,
                    "path": str(item),
                    "size_bytes": stat.st_size if item.is_file() else _dir_size(item),
                    "mtime": stat.st_mtime,
                }
            )
        except Exception as exc:
            _log.warning("list_backups: cannot stat %s: %s", item, exc)

    return results


def restore(backup_path: Path, original_path: Path) -> Path:
    """Restore a backed-up file or directory to its original location.

    Returns the restored path.  Raises if the backup doesn't exist or the
    destination already exists.
    """
    backup_path = Path(backup_path)
    original_path = Path(original_path)

    if not backup_path.exists():
        raise FileNotFoundError(f"Backup not found: {backup_path}")

    if original_path.exists():
        raise FileExistsError(f"Destination already exists: {original_path}")

    original_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(backup_path), str(original_path))
    _log.info("restore: %s -> %s", backup_path, original_path)
    return original_path


def _dir_size(path: Path) -> int:
    """Recursively sum file sizes in a directory."""
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total
