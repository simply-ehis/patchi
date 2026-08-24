"""
Queue system for Patchi.

All tasks go through the queue. Nothing runs immediately.
Queue state persists to .patchi/queue.json between CLI invocations.

Three modes:
  single  — one task at a time, safest for low-end hardware
  multi   — parallel up to hardware-detected limit
  off     — no queue, tasks run immediately (power user mode)

The queue stores task definitions as JSON records.
Actual task execution is wired up in Agent System.
The queue here is the data layer + control layer — fully functional.
"""

import json
import platform
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from patchi.core.config import require_project_root
from patchi.core.constants import (
    QUEUE_FILE,
    QUEUE_MAX_DEPTH,
    QUEUE_WARN_DEPTH,
    QueueItemState,
)

# ── Cross-platform file lock ──────────────────────────────────────────────────


@contextmanager
def _file_lock(path: Path):
    """Simple cross-platform file lock using lock file + atomic create."""
    lock_path = path.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # Ensure lock file exists before opening
    lock_path.touch(exist_ok=True)

    if platform.system() == "Windows":
        # Windows: use msvcrt for file locking
        import msvcrt

        f = open(lock_path, "r+")
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            yield
        finally:
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            f.close()
    else:
        # Unix: use fcntl
        import fcntl

        f = open(lock_path, "r+")
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            f.close()


# ── Data model ─────────────────────────────────────────────────────────────────
#
# Queue file structure:
# {
#   "paused": false,
#   "items": [
#     {
#       "id": "a1b2c3",
#       "type": "scan | fix | test | security | ...",
#       "target": "full | src/auth/ | ...",
#       "state": "waiting | active | done | failed | skipped",
#       "created": "2025-01-01T00:00:00+00:00",
#       "started": null,
#       "completed": null,
#       "result": null,
#       "error": null,
#       "agent": null,
#       "priority": 0
#     }
#   ]
# }


def _queue_path(root: Path) -> Path:
    return root / QUEUE_FILE


def _root(r: Path | None) -> Path:
    return r or require_project_root()


# ── File I/O ───────────────────────────────────────────────────────────────────


def _read(root: Path) -> dict:
    path = _queue_path(root)
    if not path.exists():
        return {"paused": False, "items": []}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write(root: Path, data: dict) -> None:
    path = _queue_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp.replace(path)


# ── Queue CRUD ─────────────────────────────────────────────────────────────────


def enqueue(
    task_type: str,
    target: str = "full",
    agent: str | None = None,
    priority: int = 0,
    extra: dict | None = None,
    root: Path | None = None,
) -> str:
    """
    Add a task to the queue. Returns the new item's ID.
    Raises QueueFullError if the queue is at max depth.
    Warns (via return metadata) if approaching warn depth.
    """
    r = _root(root)
    queue_path = r / QUEUE_FILE
    with _file_lock(queue_path):
        data = _read(r)

        waiting = [i for i in data["items"] if i["state"] == QueueItemState.WAITING.value]
        if len(waiting) >= QUEUE_MAX_DEPTH:
            raise QueueFullError(
                f"Queue is full ({QUEUE_MAX_DEPTH} items). "
                "Clear some tasks or increase queue_max_depth in settings."
            )

        item_id = str(uuid.uuid4())[:8]
        item: dict[str, Any] = {
            "id": item_id,
            "type": task_type,
            "target": target,
            "state": QueueItemState.WAITING.value,
            "created": _now(),
            "started": None,
            "completed": None,
            "result": None,
            "error": None,
            "agent": agent,
            "priority": priority,
            **(extra or {}),
        }

        data["items"].append(item)
        _write(r, data)
    return item_id


def get_item(item_id: str, root: Path | None = None) -> dict | None:
    data = _read(_root(root))
    for item in data["items"]:
        if item["id"] == item_id:
            return item
    return None


def list_items(
    state: QueueItemState | None = None,
    root: Path | None = None,
) -> list[dict]:
    """Return all items, optionally filtered by state."""
    data = _read(_root(root))
    items = data["items"]
    if state is not None:
        items = [i for i in items if i["state"] == state.value]
    return items


def list_all(root: Path | None = None) -> dict:
    """Return full queue data including paused flag and all items."""
    return _read(_root(root))


# ── State transitions ──────────────────────────────────────────────────────────


def mark_active(item_id: str, root: Path | None = None) -> bool:
    return _update_item(
        item_id,
        {
            "state": QueueItemState.ACTIVE.value,
            "started": _now(),
        },
        root,
    )


def mark_done(item_id: str, result: Any = None, root: Path | None = None) -> bool:
    return _update_item(
        item_id,
        {
            "state": QueueItemState.DONE.value,
            "completed": _now(),
            "result": result,
        },
        root,
    )


def mark_failed(item_id: str, error: str, root: Path | None = None) -> bool:
    return _update_item(
        item_id,
        {
            "state": QueueItemState.FAILED.value,
            "completed": _now(),
            "error": error,
        },
        root,
    )


def mark_skipped(item_id: str, root: Path | None = None) -> bool:
    return _update_item(
        item_id,
        {
            "state": QueueItemState.SKIPPED.value,
            "completed": _now(),
        },
        root,
    )


def _update_item(item_id: str, updates: dict, root: Path | None = None) -> bool:
    r = _root(root)
    queue_path = r / QUEUE_FILE
    with _file_lock(queue_path):
        data = _read(r)
        for item in data["items"]:
            if item["id"] == item_id:
                item.update(updates)
                _write(r, data)
                return True
    return False


# ── Control ────────────────────────────────────────────────────────────────────


def pause(root: Path | None = None) -> None:
    r = _root(root)
    queue_path = r / QUEUE_FILE
    with _file_lock(queue_path):
        data = _read(r)
        data["paused"] = True
        _write(r, data)


def resume(root: Path | None = None) -> None:
    r = _root(root)
    queue_path = r / QUEUE_FILE
    with _file_lock(queue_path):
        data = _read(r)
        data["paused"] = False
        _write(r, data)


def is_paused(root: Path | None = None) -> bool:
    return _read(_root(root)).get("paused", False)


def skip_active(root: Path | None = None) -> str | None:
    """Mark the current active item as skipped. Returns its ID or None."""
    r = _root(root)
    data = _read(r)
    for item in data["items"]:
        if item["state"] == QueueItemState.ACTIVE.value:
            item["state"] = QueueItemState.SKIPPED.value
            item["completed"] = _now()
            _write(r, data)
            return item["id"]
    return None


def clear(root: Path | None = None) -> int:
    """
    Remove all WAITING items. Active/done/failed are preserved for history.
    Returns the number of items removed.
    """
    r = _root(root)
    data = _read(r)
    before = len([i for i in data["items"] if i["state"] == QueueItemState.WAITING.value])
    data["items"] = [i for i in data["items"] if i["state"] != QueueItemState.WAITING.value]
    _write(r, data)
    return before


def clear_all(root: Path | None = None) -> int:
    """Remove everything including done/failed history. Returns count removed."""
    r = _root(root)
    data = _read(r)
    count = len(data["items"])
    data["items"] = []
    _write(r, data)
    return count


# ── Stats ──────────────────────────────────────────────────────────────────────


def depth(root: Path | None = None) -> int:
    """Number of WAITING items."""
    return len(list_items(QueueItemState.WAITING, root))


def is_near_limit(root: Path | None = None) -> bool:
    return depth(root) >= QUEUE_WARN_DEPTH


def stats(root: Path | None = None) -> dict:
    data = _read(_root(root))
    counts: dict[str, int] = {s.value: 0 for s in QueueItemState}
    for item in data["items"]:
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    return {
        "paused": data.get("paused", False),
        "total": len(data["items"]),
        **counts,
    }


# ── Next item picker ─────────────────────────────────


def next_waiting(root: Path | None = None) -> dict | None:
    """
    Return the next WAITING item (highest priority first, then FIFO).
    Returns None if queue is empty or paused.
    """
    r = _root(root)
    if is_paused(r):
        return None
    waiting = list_items(QueueItemState.WAITING, r)
    if not waiting:
        return None
    # Sort by priority descending, then created ascending
    waiting.sort(key=lambda i: (-i.get("priority", 0), i.get("created", "")))
    return waiting[0]


# ── Error types ────────────────────────────────────────────────────────────────


class QueueFullError(Exception):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
