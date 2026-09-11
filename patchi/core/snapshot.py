"""
Snapshot / rollback system for Patchi.

Before any fix is applied, Patchi creates a snapshot of the target file(s).
If tests fail after a fix, the snapshot is used to restore the original state.

Snapshots are stored as JSON in .patchi/snapshots/<snapshot_id>.json.
They contain the full original file content, so rollback is always possible
regardless of how many changes were made.

Design decisions:
- Full-file snapshots rather than diffs: simpler to implement, always reliable.
- Diffs are computed separately for display (review panel) but rollback always
  uses the full-file snapshot.
- Snapshots are never deleted automatically. The user cleans them via `p memory`.
"""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchi.core.atomic import atomic_write_json
from patchi.core.config import require_project_root
from patchi.core.constants import SNAPSHOT_DIR

# ── Data model ─────────────────────────────────────────────────────────────────
#
# A snapshot record looks like:
# {
#   "id": "a1b2c3d4",
#   "patch_id": "e5f6g7h8",   # the fix this snapshot guards
#   "created": "2025-01-01T00:00:00+00:00",
#   "files": {
#     "src/auth/middleware.py": "<full original content>",
#     ...
#   }
# }


def _snapshots_dir(root: Path) -> Path:
    return root / SNAPSHOT_DIR


def _snapshot_path(snapshot_id: str, root: Path) -> Path:
    return _snapshots_dir(root) / f"{snapshot_id}.json"


def _root(root: Path | None) -> Path:
    return root or require_project_root()


# ── Create ─────────────────────────────────────────────────────────────────────


def create(file_paths: list[str], patch_id: str, root: Path | None = None) -> str:
    """
    Read the current content of every file in file_paths and store a snapshot.
    Returns the snapshot_id.

    file_paths should be relative to the project root.
    Files that don't exist are recorded with content = None (new-file case).
    """
    r = _root(root)
    _snapshots_dir(r).mkdir(parents=True, exist_ok=True)

    files: dict[str, str | None] = {}
    for rel_path in file_paths:
        abs_path = r / rel_path
        if abs_path.exists():
            files[rel_path] = abs_path.read_text(encoding="utf-8")
        else:
            files[rel_path] = None  # file doesn't exist yet (creation fix)

    snapshot_id = str(uuid.uuid4())[:8]
    record = {
        "id": snapshot_id,
        "patch_id": patch_id,
        "created": _now(),
        "files": files,
    }

    _write_json(_snapshot_path(snapshot_id, r), record)
    return snapshot_id


# ── Restore (rollback) ─────────────────────────────────────────────────────────


def restore(snapshot_id: str, root: Path | None = None) -> list[str]:
    """
    Roll back all files covered by this snapshot to their original content.
    Returns a list of file paths that were restored.

    If the original content was None (file didn't exist), the file is deleted.
    """
    r = _root(root)
    record = load(snapshot_id, r)
    if record is None:
        raise FileNotFoundError(f"Snapshot {snapshot_id!r} not found.")

    restored: list[str] = []
    for rel_path, original_content in record["files"].items():
        abs_path = r / rel_path
        if original_content is None:
            # File was created by the fix — delete it on rollback
            if abs_path.exists():
                abs_path.unlink()
        else:
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic write: tmp + rename to prevent half-rolled-back state
            tmp = abs_path.with_suffix(abs_path.suffix + ".rollback_tmp")
            tmp.write_text(original_content, encoding="utf-8")
            tmp.replace(abs_path)
        restored.append(rel_path)

    return restored


# ── Read ───────────────────────────────────────────────────────────────────────


def load(snapshot_id: str, root: Path | None = None) -> dict | None:
    """Return the snapshot record, or None if it doesn't exist."""
    r = _root(root)
    path = _snapshot_path(snapshot_id, r)
    if not path.exists():
        return None
    return _read_json(path)


def list_all(root: Path | None = None) -> list[dict]:
    """Return all snapshots, sorted newest first, with file content omitted."""
    r = _root(root)
    snap_dir = _snapshots_dir(r)
    if not snap_dir.exists():
        return []

    records: list[dict] = []
    for snap_file in sorted(snap_dir.glob("*.json"), reverse=True):
        record = _read_json(snap_file)
        # Strip file contents for the list view — only show paths
        records.append(
            {
                "id": record["id"],
                "patch_id": record.get("patch_id"),
                "created": record.get("created"),
                "file_count": len(record.get("files", {})),
                "file_paths": list(record.get("files", {}).keys()),
            }
        )
    return records


def get_by_patch_id(patch_id: str, root: Path | None = None) -> dict | None:
    """Find the snapshot that guards a specific patch."""
    r = _root(root)
    snap_dir = _snapshots_dir(r)
    if not snap_dir.exists():
        return None
    for snap_file in snap_dir.glob("*.json"):
        record = _read_json(snap_file)
        if record.get("patch_id") == patch_id:
            return record
    return None


# ── Delete ─────────────────────────────────────────────────────────────────────


def delete(snapshot_id: str, root: Path | None = None) -> bool:
    """Delete a single snapshot. Returns True if it existed."""
    r = _root(root)
    path = _snapshot_path(snapshot_id, r)
    if path.exists():
        path.unlink()
        return True
    return False


def delete_all(root: Path | None = None) -> int:
    """Delete all snapshots. Returns count deleted."""
    r = _root(root)
    snap_dir = _snapshots_dir(r)
    if not snap_dir.exists():
        return 0
    count = 0
    for snap_file in snap_dir.glob("*.json"):
        snap_file.unlink()
        count += 1
    return count


# ── Diff helper ────────────────────────────────────────────────────────────────


def compute_diff(snapshot_id: str, root: Path | None = None) -> dict[str, str]:
    """
    Compute unified diffs for all files in this snapshot vs their current state.
    Returns a dict of {relative_path: unified_diff_string}.
    """
    import difflib

    r = _root(root)
    record = load(snapshot_id, r)
    if record is None:
        return {}

    diffs: dict[str, str] = {}
    for rel_path, original in record["files"].items():
        abs_path = r / rel_path
        current = abs_path.read_text(encoding="utf-8") if abs_path.exists() else ""
        original = original or ""

        diff_lines = list(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                current.splitlines(keepends=True),
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
            )
        )
        diffs[rel_path] = "".join(diff_lines)

    return diffs


# ── Utilities ──────────────────────────────────────────────────────────────────


def _write_json(path: Path, data: Any) -> None:
    atomic_write_json(path, data)


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _now() -> str:
    return datetime.now(UTC).isoformat()
