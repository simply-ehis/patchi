"""
Noise Filter — classifies and suppresses findings from non-source files.

The scanner's largest false-positive source is not weak detection logic —
it is scanning files whose contents are *supposed* to look dangerous:
test fixtures with fake secrets, migration SQL strings, lockfile blobs,
minified bundles, generated protobuf stubs.

NoiseFilter assigns every finding's file path to a category and either
discards or severity-caps the finding per config (``noise_filter``):

    enabled        default true
    mode           "cap" (default: downgrade to info + tag) | "discard"
    skip_tests     default true   — test_*, *_test.*, conftest, spec/, fixtures/
    skip_locks     default true   — package-lock.json, yarn.lock, poetry.lock, ...
    skip_generated default true   — *.min.js, *_pb2.py, *.map, *_pb2_grpc.py, ...
    skip_docs      default true   — *.md, *.rst, *.txt, *.csv

Honesty rule: capped findings are never deleted silently — they keep their
data, marked ``noise_category`` so the user can see exactly what was muted
and why.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

_log = logging.getLogger("patchi.noise_filter")

# ── Category definitions ─────────────────────────────────────────────────────

_LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "composer.lock",
        "Gemfile.lock",
        "packages.locker",
        "mix.lock",
        "go.sum",
        "bun.lockb",
    }
)

_GENERATED_PATTERNS = (
    "*.min.js",
    "*.min.css",
    "*.min.mjs",
    "*.map",
    "*.bundle.js",
    "*_pb2.py",
    "*_pb2_grpc.py",
    "*_pb.py",
    "*.pb.go",
    "*_pb2.pyi",
    "*-gen.py",
    "*_gen.go",
    "*.generated.*",
    "*.g.cs",
    "*.Designer.cs",
    "*.snap",
    "__snapshots__/*",
)

_DOC_PATTERNS = ("*.md", "*.mdx", "*.rst", "*.txt", "*.csv", "*.log")

_TEST_FILE_PATTERNS = (
    "test_*.py",
    "*_test.py",
    "*_test.go",
    "*_test.dart",
    "conftest.py",
    "test_utils.py",
    "*.spec.ts",
    "*.spec.tsx",
    "*.spec.js",
    "*.spec.jsx",
    "*.spec.mjs",
    "*.test.ts",
    "*.test.tsx",
    "*.test.js",
    "*.test.jsx",
    "*.test.mjs",
    "*_test.rb",
    "*.spec.rb",
)

_TEST_DIR_MARKERS = frozenset(
    {
        "test",
        "tests",
        "spec",
        "specs",
        "fixtures",
        "fixture",
        "testdata",
        "test_data",
        "mock",
        "mocks",
        "stubs",
        "__snapshots__",
        "__tests__",
        "testing",
    }
)

# Pre-compiled patterns for fast matching
_COMPILED_GENERATED = [(re.compile(fnmatch.translate(p)), p) for p in _GENERATED_PATTERNS]
_COMPILED_DOCS = [(re.compile(fnmatch.translate(p)), p) for p in _DOC_PATTERNS]
_COMPILED_TESTS = [(re.compile(fnmatch.translate(p)), p) for p in _TEST_FILE_PATTERNS]


def classify(path: str) -> str | None:
    """Return the noise category for a path, or None if it looks like source.

    Categories: "lockfile", "generated", "docs", "tests".
    Order matters: lockfile > generated > docs > tests.
    """
    p = PurePosixPath(path.replace("\\", "/"))
    name = p.name

    # 1. Lockfiles — exact name match anywhere in the tree (fastest path)
    if name in _LOCKFILE_NAMES:
        return "lockfile"

    # 2. Generated/minified — pattern match on filename (pre-compiled)
    for compiled, pat in _COMPILED_GENERATED:
        if "/" not in pat and compiled.match(name) is not None:
            return "generated"

    # 3. Docs — extension-based (pre-compiled)
    for compiled, _ in _COMPILED_DOCS:
        if compiled.match(name) is not None:
            return "docs"

    # 4. Tests — filename pattern OR directory marker in path (pre-compiled)
    for compiled, _ in _COMPILED_TESTS:
        if compiled.match(name) is not None:
            return "tests"
    parts = {seg.lower() for seg in p.parts[:-1]}
    if parts & _TEST_DIR_MARKERS:
        return "tests"

    return None


@dataclass
class NoiseReport:
    """Summary of what the filter suppressed and why."""

    total_in: int = 0
    kept: int = 0
    capped: int = 0
    discarded: int = 0
    by_category: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_in": self.total_in,
            "kept": self.kept,
            "capped": self.capped,
            "discarded": self.discarded,
            "by_category": dict(self.by_category),
            "statement": (
                f"{self.kept}/{self.total_in} findings kept "
                f"({self.capped} noise-capped, {self.discarded} discarded)"
            ),
        }


class NoiseFilter:
    """Filters or severity-caps findings originating from noise files."""

    def __init__(self, root=None, config: dict | None = None):
        cfg = (config or {}).get("noise_filter", {})
        self.enabled: bool = bool(cfg.get("enabled", True))
        self.mode: str = cfg.get("mode", "cap")  # "cap" | "discard"
        self.skip_tests: bool = bool(cfg.get("skip_tests", True))
        self.skip_locks: bool = bool(cfg.get("skip_locks", True))
        self.skip_generated: bool = bool(cfg.get("skip_generated", True))
        self.skip_docs: bool = bool(cfg.get("skip_docs", True))

    # ── Single-path API ─────────────────────────────────────────────────────

    def category_for(self, path: str) -> str | None:
        """Category for this path, honoring the skip_* toggles."""
        cat = classify(path)
        if cat == "lockfile" and not self.skip_locks:
            return None
        if cat == "generated" and not self.skip_generated:
            return None
        if cat == "docs" and not self.skip_docs:
            return None
        if cat == "tests" and not self.skip_tests:
            return None
        return cat

    def is_noise(self, path: str) -> bool:
        return self.category_for(path) is not None

    # ── Finding-list API ────────────────────────────────────────────────────

    def apply(self, findings: list) -> tuple[list, NoiseReport]:
        """Split findings into (kept, report).

        Accepts Finding objects *or* plain dicts (as produced by
        ``merge_results``); each entry needs a ``file`` key/attribute.
        In "cap" mode noisy findings stay in the kept list but their
        severity is downgraded to info and they gain a ``noise_category``
        annotation. In "discard" mode they are removed entirely.
        """
        report = NoiseReport(total_in=len(findings))
        kept: list = []
        for f in findings:
            path = _get(f, "file", "") or ""
            cat = self.category_for(path) if (self.enabled and path) else None
            if cat is None:
                kept.append(f)
                report.kept += 1
                continue
            report.by_category[cat] = report.by_category.get(cat, 0) + 1
            if self.mode == "discard":
                report.discarded += 1
                continue
            # cap mode: downgrade + annotate, never delete silently
            _set_severity_info(f)
            _set(f, "noise_category", cat)
            kept.append(f)
            report.capped += 1
            report.kept += 1
        if report.total_in and (report.capped or report.discarded):
            _log.info(
                "Noise filter: %d/%d findings from noise files (%s)",
                report.capped + report.discarded,
                report.total_in,
                ", ".join(f"{k}={v}" for k, v in sorted(report.by_category.items())),
            )
        return kept, report


# ── Polymorphic accessors (Finding objects vs merged dicts) ─────────────


def _get(f, key: str, default=None):
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def _set(f, key: str, value) -> None:
    if isinstance(f, dict):
        f[key] = value
        return
    try:
        setattr(f, key, value)
    except Exception as _exc:  # noqa: BLE001 — frozen/sealed objects: skip silently
        _log.debug('_set skipped: %s', _exc)


def _set_severity_info(f) -> None:
    """Downgrade severity to INFO, matching the container's own encoding."""
    if isinstance(f, dict):
        # merge_results dicts carry severity as a plain string
        f["severity"] = "info"
        return
    try:
        from patchi.core.agents.base import Severity

        f.severity = Severity.INFO
    except Exception as _exc:  # noqa: BLE001 — frozen/sealed objects: annotate only
        _log.debug('_set_severity_info skipped: %s', _exc)
