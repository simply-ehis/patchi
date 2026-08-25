"""FuzzCorpus — persistent corpus manager for accumulating interesting inputs.

Stores fuzz inputs that triggered interesting behavior (crashes, errors,
new code paths) so subsequent runs can build on prior discoveries.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_log = logging.getLogger("patchi.fuzz.corpus")

CORPUS_FILE = ".patchi/fuzz_corpus.json"


@dataclass
class CorpusEntry:
    """One entry in the fuzz corpus."""

    label: str
    value: Any
    strategy: str
    score: float  # interestingness score (higher = more interesting)
    hits: int = 1  # how many times this triggered something
    added_at: float = 0.0

    def __post_init__(self):
        if self.added_at == 0.0:
            self.added_at = time.time()

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "value": str(self.value)[:500],
            "strategy": self.strategy,
            "score": self.score,
            "hits": self.hits,
            "added_at": self.added_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CorpusEntry:
        return cls(
            label=d.get("label", "?"),
            value=d.get("value", ""),
            strategy=d.get("strategy", "unknown"),
            score=float(d.get("score", 0)),
            hits=int(d.get("hits", 1)),
            added_at=float(d.get("added_at", 0)),
        )


class FuzzCorpus:
    """Persistent corpus for accumulating interesting fuzz inputs."""

    def __init__(self, root: Path):
        self._root = root
        self._path = root / CORPUS_FILE
        self._entries: dict[str, CorpusEntry] = {}
        self._load()

    def _load(self) -> None:
        """Load corpus from disk."""
        if not self._path.is_file():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            for ed in data.get("entries", []):
                entry = CorpusEntry.from_dict(ed)
                self._entries[entry.label] = entry
        except Exception as e:
            _log.warning("Failed to load fuzz corpus: %s", e)

    def save(self) -> None:
        """Persist corpus to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "entries": [e.to_dict() for e in self._entries.values()],
        }
        tmp = self._path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self._path)

    def add(self, entry: CorpusEntry) -> None:
        """Add or update a corpus entry."""
        if entry.label in self._entries:
            existing = self._entries[entry.label]
            existing.hits += 1
            existing.score = max(existing.score, entry.score)
        else:
            self._entries[entry.label] = entry

    def get_interesting(self, min_score: float = 0.5, limit: int = 50) -> list[CorpusEntry]:
        """Get the most interesting entries, sorted by score."""
        candidates = [e for e in self._entries.values() if e.score >= min_score]
        candidates.sort(key=lambda e: (-e.score, -e.hits))
        return candidates[:limit]

    def get_all(self, limit: int = 200) -> list[CorpusEntry]:
        """Get all entries, sorted by score."""
        entries = list(self._entries.values())
        entries.sort(key=lambda e: (-e.score, -e.hits))
        return entries[:limit]

    def update_score(self, label: str, score: float) -> bool:
        """Update the score of an existing entry. Returns True if found."""
        if label in self._entries:
            self._entries[label].score = max(self._entries[label].score, score)
            self._entries[label].hits += 1
            return True
        return False

    def __len__(self) -> int:
        return len(self._entries)

    def stats(self) -> dict:
        """Return corpus statistics."""
        entries = list(self._entries.values())
        if not entries:
            return {"total": 0, "avg_score": 0, "strategies": {}}

        strategies: dict[str, int] = {}
        for e in entries:
            strategies[e.strategy] = strategies.get(e.strategy, 0) + 1

        return {
            "total": len(entries),
            "avg_score": sum(e.score for e in entries) / len(entries),
            "max_score": max(e.score for e in entries),
            "strategies": strategies,
        }
