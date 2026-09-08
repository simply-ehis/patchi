"""
Atomic file operations for Patchi.

All persistent writes go through these helpers to prevent data loss on crash.
The pattern is: write to a temp file, then atomically rename to the target.

On Windows, ``Path.replace()`` fails if the target exists, so we unlink first.
Retries handle transient PermissionError from antivirus or indexer locks.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path


def atomic_replace(src: Path, dst: Path, retries: int = 3) -> None:
    """Replace *dst* with *src* atomically, with retries for Windows file-lock races.

    This is the single source of truth for atomic file replacement across Patchi.
    Every module that writes persistent JSON or source files should use this.
    """
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


def atomic_write_json(path: Path, data, indent: int = 2, **dump_kwargs) -> None:
    """Write *data* as JSON to *path* atomically (tmp + rename).

    Convenience wrapper: serializes to JSON, writes to a sibling ``.tmp`` file,
    then calls :func:`atomic_replace`.
    """
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, **dump_kwargs)
    atomic_replace(tmp, path)


def atomic_write_text(path: Path, text: str) -> None:
    """Write *text* to *path* atomically (tmp + rename).

    Used by the patch applier to write source files without risk of partial writes.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    atomic_replace(tmp, path)
