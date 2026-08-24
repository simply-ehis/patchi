"""
Memory system for Patchi.

All persistent data outside config lives here. Organised JSON files,
one per category. Human-readable. Viewable and deletable from CLI and web UI.

Rules:
- Every write is atomic (write to temp, rename to target).
- Deleting any category triggers a rescan of that area on next run.
- Callers never read the JSON files directly — always go through these functions.
"""

import json
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from patchi.core.config import require_project_root
from patchi.core.constants import (
    MEMORY_FILES,
    MemoryCategory,
)

# ── Low-level read/write ───────────────────────────────────────────────────────


import logging
_log = logging.getLogger("patchi.core.memory")

# Serializes read-modify-write ops (e.g. save_scan_result) that the Coordinator
# calls from parallel agent threads — without it, concurrent writers race on
# the same .tmp file (PermissionError/FileNotFoundError on Windows).
_WRITE_LOCK = threading.RLock()

def _mem_path(category: MemoryCategory, root: Path) -> Path:
    return root / MEMORY_FILES[category]


def _read(category: MemoryCategory, root: Path) -> Any:
    path = _mem_path(category, root)
    if not path.exists():
        return [] if category in _list_categories() else {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _atomic_replace(src: Path, dst: Path, retries: int = 3) -> None:
    """Replace dst with src atomically, with retries for Windows file-lock races."""
    for attempt in range(retries):
        try:
            if sys.platform == "win32":
                if dst.exists():
                    dst.unlink()
            src.replace(dst)
            return
        except PermissionError:
            if attempt < retries - 1:
                time.sleep(0.05 * (attempt + 1))
                continue
            raise


def _write(category: MemoryCategory, data: Any, root: Path) -> None:
    with _WRITE_LOCK:
        path = _mem_path(category, root)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        _atomic_replace(tmp, path)


def _update(category: MemoryCategory, fn: Any, root: Path) -> Any:
    """Thread-safe read-modify-write: lock, read, mutate via fn, write back."""
    r = _root(root)
    with _WRITE_LOCK:
        data = _read(category, r)
        result = fn(data)
        _write(category, result, r)
    return result


def _list_categories() -> set[MemoryCategory]:
    return {
        MemoryCategory.PATCHES,
        MemoryCategory.FAILED,
        MemoryCategory.ISSUES,
        MemoryCategory.RESTRICTIONS,
        MemoryCategory.TOKENS,
    }


def _root(root: Path | None) -> Path:
    return root or require_project_root()


# ── Generic read / delete ──────────────────────────────────────────────────────


def read(category: MemoryCategory, root: Path | None = None) -> Any:
    """Return all memory data for a category."""
    return _read(category, _root(root))


def delete(category: MemoryCategory, root: Path | None = None) -> None:
    """
    Clear all memory for a category.
    Resets to empty list or dict (not deleting the file itself,
    so Patchi knows to re-scan on next run).
    """
    r = _root(root)
    empty: Any = [] if category in _list_categories() else {}
    _write(category, empty, r)


def delete_all(root: Path | None = None) -> None:
    """Wipe everything. Called after user types CONFIRM."""
    r = _root(root)
    for category in MemoryCategory:
        delete(category, r)


def summary(root: Path | None = None) -> dict[str, Any]:
    """High-level counts per category — used by `p memory` and Overview panel."""
    r = _root(root)
    out: dict[str, Any] = {}
    for category in MemoryCategory:
        data = _read(category, r)
        if isinstance(data, list):
            out[category.value] = {"count": len(data)}
        elif isinstance(data, dict):
            out[category.value] = {"keys": list(data.keys())}
        else:
            out[category.value] = {}
    return out


# ── Brain ──────────────────────────────────────────────────────────────────────


def get_brain(root: Path | None = None) -> dict:
    return _read(MemoryCategory.BRAIN, _root(root))


def save_brain(brain: dict, root: Path | None = None) -> None:
    _write(MemoryCategory.BRAIN, brain, _root(root))


# ── Layered brain ─────────────────────────────────────────────────────────────


def get_layers(root: Path | None = None) -> dict:
    return _read(MemoryCategory.LAYERS, _root(root))


def save_layers(layers: dict, root: Path | None = None) -> None:
    _write(MemoryCategory.LAYERS, layers, _root(root))


# ── Project charter (guard rails) ─────────────────────────────────────────────


def get_charter(root: Path | None = None) -> dict:
    return _read(MemoryCategory.CHARTER, _root(root))


def save_charter(charter: dict, root: Path | None = None) -> None:
    _write(MemoryCategory.CHARTER, charter, _root(root))


def mark_brain_stale(
    changed_files: list[str],
    root: Path | None = None,
    stale_layers: list[str] | None = None,
) -> None:
    r = _root(root)
    brain = _read(MemoryCategory.BRAIN, r)
    brain["stale"] = True
    brain["stale_reason"] = f"{len(changed_files)} file(s) changed"
    brain["changed_files"] = changed_files
    if stale_layers is not None:
        brain["stale_layers"] = sorted(stale_layers)
    _write(MemoryCategory.BRAIN, brain, r)


# ── Patches ────────────────────────────────────────────────────────────────────


def list_patches(root: Path | None = None) -> list[dict]:
    return _read(MemoryCategory.PATCHES, _root(root))


def save_patch(patch: dict, root: Path | None = None) -> str:
    """Append a patch record. Returns the patch ID."""
    r = _root(root)
    patches = _read(MemoryCategory.PATCHES, r)
    if "id" not in patch:
        patch["id"] = str(uuid.uuid4())[:8]
    patch.setdefault("timestamp", _now())
    patches.append(patch)
    _write(MemoryCategory.PATCHES, patches, r)
    return patch["id"]


def get_patch(patch_id: str, root: Path | None = None) -> dict | None:
    for p in list_patches(root):
        if p.get("id") == patch_id:
            return p
    return None


def delete_patches(root: Path | None = None) -> None:
    delete(MemoryCategory.PATCHES, root)


# ── Failed patches ─────────────────────────────────────────────────────────────


def list_failed(root: Path | None = None) -> list[dict]:
    return _read(MemoryCategory.FAILED, _root(root))


def save_failed(patch_id: str, reason: str, diff: str = "", root: Path | None = None) -> None:
    r = _root(root)
    failed = _read(MemoryCategory.FAILED, r)
    failed.append(
        {
            "id": patch_id,
            "reason": reason,
            "diff": diff,
            "timestamp": _now(),
        }
    )
    _write(MemoryCategory.FAILED, failed, r)


def delete_failed(root: Path | None = None) -> None:
    delete(MemoryCategory.FAILED, root)


# ── Scan results ───────────────────────────────────────────────────────────────


def get_scan_results(root: Path | None = None) -> dict:
    return _read(MemoryCategory.SCANS, _root(root))


def save_scan_result(scanner_name: str, result: dict, root: Path | None = None) -> None:
    def _mutate(scans: dict) -> dict:
        scans[scanner_name] = {**result, "timestamp": _now()}
        return scans

    _update(MemoryCategory.SCANS, _mutate, root)


# ── Known issues ───────────────────────────────────────────────────────────────


def list_issues(root: Path | None = None) -> list[dict]:
    return _read(MemoryCategory.ISSUES, _root(root))


def save_issue(issue: dict, root: Path | None = None) -> None:
    r = _root(root)
    issues = _read(MemoryCategory.ISSUES, r)
    issue.setdefault("id", str(uuid.uuid4())[:8])
    issue.setdefault("timestamp", _now())
    issues.append(issue)
    _write(MemoryCategory.ISSUES, issues, r)


def resolve_issue(issue_id: str, root: Path | None = None) -> bool:
    r = _root(root)
    issues = _read(MemoryCategory.ISSUES, r)
    before = len(issues)
    issues = [i for i in issues if i.get("id") != issue_id]
    _write(MemoryCategory.ISSUES, issues, r)
    return len(issues) < before


def delete_issues(root: Path | None = None) -> None:
    delete(MemoryCategory.ISSUES, root)


# ── Dev tokens (names only, not values) ───────────────────────────────────────


def list_tokens(root: Path | None = None) -> list[dict]:
    return _read(MemoryCategory.TOKENS, _root(root))


def save_token(name: str, env_var: str, root: Path | None = None) -> None:
    r = _root(root)
    tokens = _read(MemoryCategory.TOKENS, r)
    if not any(t["name"] == name for t in tokens):
        tokens.append({"name": name, "env_var": env_var, "added": _now()})
        _write(MemoryCategory.TOKENS, tokens, r)


def remove_token(name: str, root: Path | None = None) -> bool:
    r = _root(root)
    tokens = _read(MemoryCategory.TOKENS, r)
    before = len(tokens)
    tokens = [t for t in tokens if t["name"] != name]
    _write(MemoryCategory.TOKENS, tokens, r)
    return len(tokens) < before


# ── Helpers ────────────────────────────────────────────────────────────────────


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def clear_all(root: "Path | None" = None) -> None:
    """Wipe every memory category. Irreversible."""
    try:
        r = root or require_project_root()
        mem_dir = r / _PATCHI_DIR
        for f in mem_dir.glob("*.json"):
            if f.name != "config.json":
                tmp = f.with_suffix(".tmp")
                with tmp.open("w", encoding="utf-8") as fh:
                    json.dump({}, fh)
                _atomic_replace(tmp, f)
    except Exception as e:
        _log.warning("clear_all failed: %s", e)


# ── Health score history ───────────────────────────────────────────────────────

_PATCHI_DIR = ".patchi"


def log_health_score(score: int, finding_count: int, root: "Path | None" = None) -> None:
    """Append a health score data point to history.json after every scan."""
    r = root or require_project_root()
    path = r / _PATCHI_DIR / "history.json"
    try:
        history: list[dict] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except Exception as e:
        _log.warning("log_health_score failed: %s", e)
        history = []

    history.append(
        {
            "ts": int(time.time()),
            "health_score": score,
            "finding_count": finding_count,
            "type": "scan",
        }
    )
    # Keep last 500 entries
    history = history[-500:]
    # Atomic write: tmp + rename
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(history, indent=2), encoding="utf-8")
    _atomic_replace(tmp, path)


def get_health_history(root: "Path | None" = None) -> list[dict]:
    """Return all health score history entries."""
    r = root or require_project_root()
    path = r / _PATCHI_DIR / "history.json"
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except Exception as e:
        _log.warning("get_health_history failed: %s", e)
        return []


# ── Rejection learning ─────────────────────────────────────────────────────────


def record_rejection(finding_type: str, root: "Path | None" = None) -> int:
    """
    Track how many times the user has rejected a finding type.
    Returns the new rejection count for that type.
    """
    r = root or require_project_root()
    path = r / _PATCHI_DIR / "rejection_counts.json"
    try:
        counts: dict = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception as e:
        _log.warning("record_rejection failed: %s", e)
        counts = {}

    counts[finding_type] = counts.get(finding_type, 0) + 1
    # Atomic write: tmp + rename
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(counts, indent=2), encoding="utf-8")
    _atomic_replace(tmp, path)
    return counts[finding_type]


def get_rejection_counts(root: "Path | None" = None) -> dict[str, int]:
    """Return all rejection counts by finding type."""
    r = root or require_project_root()
    path = r / _PATCHI_DIR / "rejection_counts.json"
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception as e:
        _log.warning("get_rejection_counts failed: %s", e)
        return {}
