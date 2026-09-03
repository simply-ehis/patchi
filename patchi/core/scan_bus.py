"""
ScanBus §MASTER_ROADMAP Scan Bus — FileCorpus parse-once + shards + FindingBus.

Shards FileInfos for parallel agents without re-walking filesystem.
FindingBus is thread-safe queue for findings (replaces per-agent list merging).

This is P1 of Scan Bus (XL). Full QueueRunner + shards + FindingBus follow.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from patchi.core.brain.file_corpus import FileCorpus
from patchi.core.brain.scanner import FileInfo


@dataclass
class ScanShard:
    idx: int
    files: list[FileInfo]
    total_shards: int


class ScanBus:
    """Shard-aware FileCorpus wrapper. Build once, reuse across agents."""

    def __init__(self, root: Path, shard_count: int = 4):
        self.root = root
        self.corpus = FileCorpus(root)
        self.shard_count = max(1, shard_count)
        self._shards: list[ScanShard] | None = None

    def build(self) -> None:
        # Force corpus build
        _ = self.corpus.entries

    def shards(self, file_infos: list[FileInfo] | None = None) -> list[ScanShard]:
        if file_infos is None:
            # Build from corpus if available, else scan
            from patchi.core.brain.scanner import FileScanner
            file_infos = FileScanner(self.root, corpus=self.corpus).scan()
        n = self.shard_count
        # shard by hash of path for even distribution
        buckets: list[list[FileInfo]] = [[] for _ in range(n)]
        for fi in file_infos:
            buckets[hash(fi.path) % n].append(fi)
        return [ScanShard(idx=i, files=buckets[i], total_shards=n) for i in range(n)]


@dataclass
class FindingBus:
    """Thread-safe bus for findings. Agents push, coordinator drains."""

    _q: queue.Queue = field(default_factory=queue.Queue)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _count: int = 0

    def publish(self, finding: Any) -> None:
        self._q.put(finding)
        with self._lock:
            self._count += 1

    def drain(self) -> list[Any]:
        out = []
        while not self._q.empty():
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        return out

    @property
    def count(self) -> int:
        with self._lock:
            return self._count
