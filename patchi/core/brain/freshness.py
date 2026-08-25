"""
Brain freshness tracker.

Determines whether the Brain's knowledge is still current by comparing
file modification times against the last scan timestamp.

Also provides the file watcher used by `p watch`.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

FRESHNESS_FILE = ".patchi/brain_freshness.json"


# ── Freshness record ───────────────────────────────────────────────────────────


import logging

_log = logging.getLogger("patchi.brain.freshness")


def save_freshness_snapshot(root: Path, file_infos_paths: list[str]) -> None:
    """
    Record the current mtime of every scanned file.
    Called at the end of a successful brain scan.
    """
    snapshot: dict[str, float] = {}
    for rel_path in file_infos_paths:
        abs_path = root / rel_path
        try:
            snapshot[rel_path] = abs_path.stat().st_mtime
        except OSError:
            pass

    freshness_path = root / FRESHNESS_FILE
    freshness_path.parent.mkdir(parents=True, exist_ok=True)
    with freshness_path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "snapshot": snapshot,
                "recorded_at": datetime.now(UTC).isoformat(),
            },
            f,
            indent=2,
        )


def check_freshness(root: Path) -> dict:
    """
    Compare current file mtimes to the saved snapshot.

    Returns:
        {
            "is_stale": bool,
            "changed_files": [list of changed rel paths],
            "new_files": [list of new files not in snapshot],
            "deleted_files": [list of files that no longer exist],
            "last_recorded": ISO timestamp or None,
        }
    """
    freshness_path = root / FRESHNESS_FILE
    if not freshness_path.exists():
        return {
            "is_stale": True,
            "changed_files": [],
            "new_files": [],
            "deleted_files": [],
            "last_recorded": None,
            "reason": "No scan recorded yet.",
        }

    try:
        with freshness_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {
            "is_stale": True,
            "changed_files": [],
            "new_files": [],
            "deleted_files": [],
            "last_recorded": None,
            "reason": "Freshness file is corrupted.",
        }

    snapshot: dict[str, float] = data.get("snapshot", {})
    last_recorded: str = data.get("recorded_at", "")

    changed: list[str] = []
    deleted: list[str] = []

    for rel_path, old_mtime in snapshot.items():
        abs_path = root / rel_path
        try:
            current_mtime = abs_path.stat().st_mtime
            if current_mtime != old_mtime:
                changed.append(rel_path)
        except OSError:
            deleted.append(rel_path)

    # New files: scan for any source files not in snapshot
    # (lightweight — just check common source roots)
    new_files = _find_new_files(root, snapshot)

    is_stale = bool(changed or deleted or new_files)
    reason = ""
    if is_stale:
        parts: list[str] = []
        if changed:
            parts.append(f"{len(changed)} file(s) modified")
        if deleted:
            parts.append(f"{len(deleted)} file(s) deleted")
        if new_files:
            parts.append(f"{len(new_files)} new file(s) found")
        reason = "; ".join(parts) + " since last scan."

    return {
        "is_stale": is_stale,
        "changed_files": changed,
        "new_files": new_files,
        "deleted_files": deleted,
        "last_recorded": last_recorded,
        "reason": reason,
    }


def _find_new_files(root: Path, snapshot: dict[str, float]) -> list[str]:
    """
    Quick scan for source files that exist now but weren't in the snapshot.
    Checks only source directories, not node_modules etc.
    """
    from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS, Lang, detect_language

    new_files: list[str] = []
    count = 0

    for dirpath, dirnames, filenames in root_walk(root):
        # Prune ignored dirs
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORE_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                rel = fpath.relative_to(root).as_posix()
            except ValueError:
                continue
            if rel not in snapshot:
                lang = detect_language(fpath)
                if lang != Lang.UNKNOWN:
                    new_files.append(rel)
            count += 1
            if count > 5000:  # bail early on huge projects
                return new_files

    return new_files


def root_walk(root: Path):
    """os.walk wrapper that stays inside root."""
    import os

    yield from os.walk(root)


# ── File watcher (for p watch) ─────────────────────────────────────────────────


class BrainWatcher:
    """
    Watches the project directory for file changes using watchfiles (Rust-backed).

    watchfiles is significantly faster than watchdog — it uses native OS file
    events (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows)
    via a Rust extension. Debouncing is built-in.

    On change: marks brain stale and calls on_change callback with changed paths.

    Usage:
        watcher = BrainWatcher(root, on_change=lambda paths: ...)
        watcher.start()   # blocks until stop() is called
        watcher.stop()
    """

    def __init__(
        self,
        root: Path,
        on_change: Callable[[list[str]], None],
        area: str | None = None,
        debounce_ms: int = 500,
    ):
        self.root = root
        self.on_change = on_change
        self.area = area
        self.debounce_ms = debounce_ms
        self._stop_event: threading.Event | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start watching in a background thread. Returns immediately."""
        import threading

        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._watch_loop,
            daemon=True,
            name="BrainWatcher",
        )
        self._thread.start()

    def _watch_loop(self) -> None:
        """Background thread: runs watchfiles.watch() and dispatches changes."""
        try:
            from watchfiles import Change  # noqa: F401 — used to check availability
            from watchfiles import watch as wf_watch
        except ImportError:
            raise RuntimeError(
                "watchfiles is required for p watch. Install it with: pip install watchfiles"
            )

        from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS, Lang, detect_language

        watch_path = str(self.root / self.area) if self.area else str(self.root)

        # watchfiles accepts stop_event directly — clean shutdown
        for changes in wf_watch(
            watch_path,
            debounce=self.debounce_ms,
            stop_event=self._stop_event,
            ignore_permission_denied=True,
        ):
            if self._stop_event and self._stop_event.is_set():
                break

            changed_paths: list[str] = []
            for _change_type, raw_path in changes:
                path = Path(raw_path)

                # Skip patchi internals and build artifacts
                if any(part in DEFAULT_IGNORE_DIRS for part in path.parts):
                    continue

                lang = detect_language(path)
                if lang == Lang.UNKNOWN:
                    continue

                try:
                    rel = path.relative_to(self.root).as_posix()
                    changed_paths.append(rel)
                except ValueError:
                    continue

            if changed_paths:
                # Mark brain stale for these files
                try:
                    from patchi.core import memory as mem

                    mem.mark_brain_stale(changed_paths, self.root)
                except Exception as e:
                    _log.warning("BrainWatcher._watch_loop failed: %s", e)
                self.on_change(changed_paths)

    def stop(self) -> None:
        """Signal the watcher to stop and wait for the thread to exit."""
        if self._stop_event:
            self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
