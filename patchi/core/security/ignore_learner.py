"""
Ignore Learner — Patchi builds its own ignore list from evidence.

Four evidence layers, each entry stamped with source, confidence, reason:

  static        deterministic rules (noise_filter.classify + DEFAULT_IGNORE_DIRS)
  git           non-negated .gitignore patterns
  fp_stats      directories whose findings keep getting rejected
                (aggregated upward from known_false_positives.json)
  composition   directories that are >=90% data files (yaml/json/md/toml),
                contain no executable entry points -> tool-owned data dirs
                (e.g. scanner rule packs, domain definitions, changelogs)

Entries generalize: literal directory evidence also emits a ``**/name/**``
glob once the same directory name proves noisy in enough distinct places,
so projects with different layouts inherit the lesson automatically.
A global store (~/.patchi/global_ignores.json) shares high-confidence
patterns across every project on the machine; project evidence always
overrides global.

Safety rails:
  - source-prefix dirs (src/, app/, lib/, pkg/, internal/) require
    overwhelming evidence before any ignore applies
  - user entries (p ignore add) always win over learned ones
  - every entry keeps machine-readable provenance
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

_log = logging.getLogger("patchi.ignore_learner")

PROJECT_STORE = ".patchi/memory/learned_ignores.json"
GLOBAL_STORE = Path.home() / ".patchi" / "global_ignores.json"

# Directory names that look like primary source containers — these need
# overwhelming evidence before we ever ignore them.
_SOURCE_PREFIXES = ("src", "app", "lib", "pkg", "internal")

# Executable extensions = files that can contain running code.
_EXEC_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
        ".rb",
        ".php",
        ".cs",
        ".swift",
        ".dart",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cc",
        ".sh",
        ".ps1",
        ".lua",
        ".sql",
    }
)

# Data/config extensions — presence signals tool-owned content.
_DATA_EXTENSIONS = frozenset(
    {
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".md",
        ".rst",
        ".txt",
        ".xml",
        ".csv",
        ".lock",
    }
)

_MIN_SAMPLES_FOR_GLOBAL = 3  # distinct projects before a pattern goes global
_MIN_FILES_FOR_COMPOSITION = 4  # dir must hold this many files to judge
_DATA_RATIO_THRESHOLD = 0.9  # >=90% data files => tool-owned candidate


@dataclass
class IgnoreEntry:
    """One learned/user ignore decision with provenance."""

    pattern: str  # glob, matched against rel paths
    category: str  # generated|lockfile|docs|tests|data_dir|...
    source: str  # static|git|fp_stats|composition|user
    reason: str = ""
    confidence: float = 1.0
    added_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> IgnoreEntry:
        return cls(
            pattern=d.get("pattern", ""),
            category=d.get("category", ""),
            source=d.get("source", "static"),
            reason=d.get("reason", ""),
            confidence=float(d.get("confidence", 1.0)),
            added_at=float(d.get("added_at", 0.0)),
        )


def _load_store(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — corrupt store = rebuild
        _log.warning("failed to load %s: %s", path, exc)
        return []


def _save_store(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    tmp.replace(path)


class IgnoreLearner:
    """Builds, stores, and applies Patchi's self-learned ignore list."""

    def __init__(self, root: Path, config: dict | None = None):
        self.root = root
        cfg = (config or {}).get("auto_ignore", {})
        self.enabled: bool = bool(cfg.get("enabled", True))
        self.min_fp_count: int = int(cfg.get("min_fp_count", 5))
        self.min_reject_ratio: float = float(cfg.get("min_reject_ratio", 0.8))
        self.use_global: bool = bool(cfg.get("share_globally", True))

        self.entries: list[IgnoreEntry] = []
        self._match_cache: dict[str, IgnoreEntry | None] = {}

    # ── Build ───────────────────────────────────────────────────────────────

    def build(
        self,
        known_fps: list[dict] | None = None,
        file_paths: list[str] | None = None,
    ) -> list[IgnoreEntry]:
        """Run all evidence layers. ``file_paths`` = relative paths in project."""
        self.entries = []
        if not self.enabled:
            return self.entries

        self._static_rules()
        self._gitignore_rules()
        if known_fps:
            self._fp_stats_rules(known_fps)
        if file_paths:
            self._composition_rules(file_paths)

        self._merge_global_and_user()
        return self.entries

    # ── Layer 1: static ─────────────────────────────────────────────────────

    def _static_rules(self) -> None:
        from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

        for d in sorted(DEFAULT_IGNORE_DIRS):
            self.entries.append(
                IgnoreEntry(
                    pattern=f"{d}/**",
                    category="environment",
                    source="static",
                    reason="default ignored directory",
                    confidence=1.0,
                )
            )

    # ── Layer 2: gitignore ──────────────────────────────────────────────────

    def _gitignore_rules(self) -> None:
        gi = self.root / ".gitignore"
        if not gi.is_file():
            return
        try:
            lines = gi.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):  # negation: git says KEEP — obey it
                continue
            pat = line.rstrip("/")
            if not pat or "*" not in pat and "/" in pat:
                # anchored literal path like docs/build-notes -> treat as dir glob
                pat = f"{pat}/**"
            elif "*" not in pat:
                pat = f"**/{pat}/**" if "/" not in line else f"{pat}/**"
            else:
                pat = f"**/{line}" if "/" not in line else line
            self.entries.append(
                IgnoreEntry(
                    pattern=pat.replace("\\", "/"),
                    category="gitignored",
                    source="git",
                    reason=".gitignore",
                    confidence=0.9,
                )
            )

    # ── Layer 3: false-positive statistics ──────────────────────────────────

    def _fp_stats_rules(self, known_fps: list[dict]) -> None:
        dir_total: dict[str, int] = {}
        dir_rejected: dict[str, int] = {}
        name_hits: dict[str, set] = {}  # dirname -> {other parent dirs}

        for e in known_fps:
            f = (e.get("file") or "").replace("\\", "/")
            if not f:
                continue
            parts = f.split("/")
            d = "/".join(parts[:-1])
            dir_total[d] = dir_total.get(d, 0) + 1
            if len(parts) > 1:
                dir_total.setdefault("/".join(parts[:-1]), 0)
            # rejected = present in FP store at all
            dir_rejected[d] = dir_rejected.get(d, 0) + 1
            if len(parts) > 2:
                name = parts[-2]
                name_hits.setdefault(name, set()).add(d.rsplit("/", 1)[0] if "/" in d else ".")

        for d, rejected in dir_rejected.items():
            total = max(dir_total.get(d, rejected), rejected)
            if rejected < self.min_fp_count:
                continue
            ratio = rejected / max(total, 1)
            if ratio < self.min_reject_ratio:
                continue
            guarded = d.split("/")[0] in _SOURCE_PREFIXES and ratio < 0.95
            if guarded:
                continue  # safety rail: source prefixes need overwhelming evidence
            self.entries.append(
                IgnoreEntry(
                    pattern=f"{d}/**",
                    category="fp_source",
                    source="fp_stats",
                    reason=f"{rejected}/{total} findings here were rejected",
                    confidence=min(0.95, 0.5 + 0.05 * rejected),
                )
            )
            # Generalize: same dir name already noisy elsewhere?
            leaf = d.rsplit("/", 1)[-1]
            others = name_hits.get(leaf, set()) - {d.rsplit("/", 1)[0] if "/" in d else "."}
            if (
                leaf
                and leaf not in _SOURCE_PREFIXES
                and (len(others) >= 1 or self._seen_elsewhere(leaf))
            ):
                self.entries.append(
                    IgnoreEntry(
                        pattern=f"**/{leaf}/**",
                        category="fp_source",
                        source="fp_stats",
                        reason=f"generalized from noisy '{leaf}' dirs across locations",
                        confidence=0.75,
                    )
                )

    def _seen_elsewhere(self, name: str) -> bool:
        """Has this dir name been learned noisy in another project (global)?"""
        if not self.use_global:
            return False
        for e in _load_store(GLOBAL_STORE):
            ent = IgnoreEntry.from_dict(e)
            if ent.source == "fp_stats" and f"/{name}/" in f"/{ent.pattern.strip('*/')}/":
                return True
        return False

    # ── Layer 4: composition analysis ───────────────────────────────────────

    def _composition_rules(self, file_paths: list[str]) -> None:
        dir_files: dict[str, list[str]] = {}
        for p in file_paths:
            p = p.replace("\\", "/")
            parts = p.split("/")
            if len(parts) < 2:
                continue
            d = parts[0] if len(parts) == 2 else "/".join(parts[:2])
            dir_files.setdefault(d, []).append(p)

        for d, files in dir_files.items():
            if len(files) < _MIN_FILES_FOR_COMPOSITION:
                continue
            exts = [os.path.splitext(f)[1].lower() for f in files]
            exec_count = sum(1 for e in exts if e in _EXEC_EXTENSIONS)
            data_count = sum(1 for e in exts if e in _DATA_EXTENSIONS)
            if exec_count == 0 and data_count / len(files) >= _DATA_RATIO_THRESHOLD:
                if d.split("/")[0] in _SOURCE_PREFIXES:
                    continue  # rail: never judge src/app/... as data-only
                self.entries.append(
                    IgnoreEntry(
                        pattern=f"{d}/**",
                        category="data_dir",
                        source="composition",
                        reason=(
                            f"{len(files)} files, zero executable "
                            f"({data_count}/{len(files)} config/data)"
                        ),
                        confidence=0.85,
                    )
                )

    # ── Merge global + user (user always wins) ──────────────────────────────

    def _merge_global_and_user(self) -> None:
        user_entries = [
            IgnoreEntry.from_dict(e)
            for e in _load_store(self.root / PROJECT_STORE)
            if e.get("source") == "user"
        ]
        user_bases = {u.pattern.removesuffix("/**").rstrip("/") for u in user_entries}

        kept = []
        for e in self.entries:
            base = e.pattern.removesuffix("/**").rstrip("/")
            overridden = any(
                base == ub or base.startswith(ub + "/") or ub.startswith(base + "/")
                for ub in user_bases
            )
            if not overridden:
                kept.append(e)
        self.entries = kept + user_entries

        if self.use_global:
            for g in _load_store(GLOBAL_STORE):
                ge = IgnoreEntry.from_dict(g)
                if ge.confidence >= 0.9 and ge.source in ("fp_stats", "composition"):
                    if not any(e.pattern == ge.pattern for e in self.entries):
                        ge.reason = f"global: {ge.reason}"
                        self.entries.append(ge)

    # ── Matching ────────────────────────────────────────────────────────────

    def matches(self, rel_path: str) -> IgnoreEntry | None:
        """Most specific matching entry for a project-relative path."""
        cached = self._match_cache.get(rel_path, KeyError)
        if cached is not KeyError:
            return cached

        p = rel_path.replace("\\", "/")
        best: IgnoreEntry | None = None
        best_len = -1
        for e in self.entries:
            pat = e.pattern
            if pat.endswith("/**"):
                base = pat[:-3]  # strip trailing /** -> "dir" or "**/dir"
                # fnmatch '*' crosses '/', so '**/build/**' hits nested too;
                # startswith covers plain 'dir/**' prefixes exactly.
                hit = fnmatch.fnmatch(p, pat) or p.startswith(base + "/")
            else:
                hit = fnmatch.fnmatch(p, pat)
            if hit and len(pat) > best_len:
                best, best_len = e, len(pat)

        self._match_cache[rel_path] = best
        return best

    # ── Persistence ─────────────────────────────────────────────────────────

    def promote_to_global(self, min_confidence: float = 0.9) -> int:
        """Share high-confidence project lessons to the cross-project store."""
        if not self.use_global:
            return 0
        existing = {IgnoreEntry.from_dict(e).pattern for e in _load_store(GLOBAL_STORE)}
        promoted = 0
        counts: dict[str, int] = {}
        for e in self.entries:
            if e.source not in ("fp_stats", "composition") or e.confidence < min_confidence:
                continue
            counts[e.pattern] = counts.get(e.pattern, 0) + 1
        store = _load_store(GLOBAL_STORE)
        for pat, n in counts.items():
            if n >= _MIN_SAMPLES_FOR_GLOBAL or pat in existing:
                continue
            src = next(e for e in self.entries if e.pattern == pat)
            store.append(src.to_dict())
            promoted += 1
        if promoted:
            _save_store(GLOBAL_STORE, store)
        return promoted


def build_ignore_learner(root: Path, config: dict | None = None) -> IgnoreLearner:
    """Convenience constructor used by FileCorpus / scan paths."""
    return IgnoreLearner(root, config)
