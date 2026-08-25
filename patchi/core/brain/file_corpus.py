"""
FileCorpus — parse-once file discovery layer for the Scan Bus.

Single-pass directory walker that:
  - Respects DEFAULT_IGNORE_DIRS consistently (fixes the 62-file rglob scatter)
  - Caches file content + parsed data for the duration of one scan
  - Provides language-filtered query API
  - Eliminates the O(n) redundant re-read pattern that caused the
    proactive.py O(n²) bug

Usage:
    corpus = FileCorpus(project_root)
    for fi in corpus.files():
        process(fi)
    for fi in corpus.by_language(Lang.PYTHON):
        process_python(fi)
    for fi in corpus.by_ext(".py"):
        ...
    content = corpus.read(fi.path)  # cached after first read
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS, Lang, detect_language

# ── Defaults ──────────────────────────────────────────────────────────────────

_SKIP_DIRS = frozenset(DEFAULT_IGNORE_DIRS)
_SKIP_FILES: frozenset[str] = frozenset()
_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


# ── Corpus entry ──────────────────────────────────────────────────────────────


@dataclass
class CorpusEntry:
    path: str  # relative to project root
    abs_path: Path
    language: Lang
    size_bytes: int
    _content: str | None = field(default=None, repr=False)
    _content_hash: str | None = field(default=None, repr=False)

    def read(self) -> str:
        if self._content is None:
            self._content = self.abs_path.read_text(encoding="utf-8", errors="replace")
        return self._content

    def content_hash(self) -> str:
        if self._content_hash is None:
            h = hashlib.md5()
            with open(self.abs_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            self._content_hash = h.hexdigest()
        return self._content_hash


# ── FileCorpus ────────────────────────────────────────────────────────────────


class FileCorpus:
    """Single-pass, parse-once file index for a project root."""

    def __init__(
        self,
        root: Path,
        skip_dirs: frozenset[str] = _SKIP_DIRS,
        skip_files: frozenset[str] = _SKIP_FILES,
        max_size: int = _MAX_FILE_SIZE,
        exclude_noise: bool = False,
        exclude_tests: bool = False,
    ):
        self.root = root.resolve()
        self._skip_dirs = skip_dirs
        self._skip_files = skip_files
        self._max_size = max_size
        self._exclude_noise = exclude_noise
        self._exclude_tests = exclude_tests
        # category -> count of files excluded during build (observability)
        self.noise_excluded: dict[str, int] = {}
        self._entries: dict[str, CorpusEntry] = {}  # rel_path -> entry
        self._built = False

    @property
    def entries(self) -> dict[str, CorpusEntry]:
        if not self._built:
            self._build()
        return self._entries

    def _build(self) -> None:
        self._entries.clear()
        self.noise_excluded.clear()
        skip_dirs = self._skip_dirs
        root = self.root

        # Lazy import: keeps noise classification optional and avoids a
        # brain -> security dependency at module load time.
        classify = None
        if self._exclude_noise or self._exclude_tests:
            from patchi.core.security.noise_filter import (
                classify as _classify,
            )

            classify = _classify

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            rel_dir = Path(dirpath).relative_to(root).as_posix()
            if rel_dir == ".":
                rel_dir = ""

            for fname in filenames:
                if fname in self._skip_files:
                    continue
                rel_path = f"{rel_dir}/{fname}" if rel_dir else fname
                abs_path = Path(dirpath) / fname

                if classify is not None:
                    cat = classify(rel_path)
                    if cat is not None and (
                        (cat != "tests" and self._exclude_noise)
                        or (cat == "tests" and self._exclude_tests)
                    ):
                        self.noise_excluded[cat] = (
                            self.noise_excluded.get(cat, 0) + 1
                        )
                        continue

                try:
                    stat = abs_path.stat()
                except OSError:
                    continue
                if stat.st_size > self._max_size:
                    continue
                if stat.st_size == 0:
                    continue

                lang = detect_language(abs_path)
                if lang == Lang.UNKNOWN:
                    continue

                self._entries[rel_path] = CorpusEntry(
                    path=rel_path,
                    abs_path=abs_path,
                    language=lang,
                    size_bytes=stat.st_size,
                )

        self._built = True

    # ── Query API ──────────────────────────────────────────────────────────

    def files(self) -> list[CorpusEntry]:
        return list(self.entries.values())

    def by_language(self, lang: Lang) -> list[CorpusEntry]:
        return [e for e in self.entries.values() if e.language == lang]

    def by_ext(self, *extensions: str) -> list[CorpusEntry]:
        exts = set(extensions)
        return [e for e in self.entries.values() if e.abs_path.suffix.lower() in exts]

    def by_glob(self, pattern: str) -> list[CorpusEntry]:
        from fnmatch import fnmatch

        return [e for e in self.entries.values() if fnmatch(e.path, pattern)]

    def get(self, rel_path: str) -> CorpusEntry | None:
        return self.entries.get(rel_path)

    def read(self, rel_path: str) -> str | None:
        entry = self.get(rel_path)
        if entry is None:
            return None
        return entry.read()

    def __len__(self) -> int:
        return len(self.entries)

    def __contains__(self, rel_path: str) -> bool:
        return rel_path in self.entries
