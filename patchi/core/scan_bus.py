"""
ScanBus §MASTER_ROADMAP Scan Bus — FileCorpus parse-once + shards + FindingBus.

Shards FileInfos for parallel agents without re-walking filesystem.
FindingBus is thread-safe queue for findings (replaces per-agent list merging).
QueueRunner batches agent classes across shard workers sharing one corpus.

File-sharding per agent activates only once agents honor `AgentInput.scope`
(4 do today: sast, security_config, unit_test, live_v2) — until then every
agent receives the full input and the bus is the single merge point.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
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

    def shard_paths(self, file_infos: list[FileInfo] | None = None) -> list[list[str]]:
        """Relative path lists per shard — future per-agent scope input."""
        return [[fi.path for fi in s.files] for s in self.shards(file_infos)]


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


class QueueRunner:
    """Shard-worked parallel runner over agent classes.

    One ScanBus (single FileCorpus build) is shared by all workers. Agent
    classes are fanned out over `shard_count` threads with the same per-agent
    timeout semantics as the coordinator's thread pool. Every finished
    result's findings are auto-published to the FindingBus — agents never
    touch the bus directly — so `drain()` is the single merge point.
    """

    def __init__(self, bus: ScanBus, finding_bus: FindingBus | None = None):
        self.scan_bus = bus
        self.finding_bus = finding_bus or FindingBus()
        self.scan_bus.build()

    @property
    def shards(self) -> list[ScanShard]:
        return self.scan_bus.shards()

    def run(
        self,
        agent_classes: list,
        run_one: Callable[[Any], Any],
        on_done: Callable[[Any], None],
        default_timeout: int = 120,
    ) -> list:
        """Run every agent class, publish findings, call on_done per result."""
        from concurrent.futures import Future

        from patchi.core.agents.base import AgentGroup, AgentResult, AgentStatus

        results: list = []
        futures: dict[Future, str] = {}
        timeout_map: dict[Future, int] = {}
        with ThreadPoolExecutor(max_workers=self.scan_bus.shard_count) as ex:
            for cls in agent_classes:
                fut = ex.submit(self._run_and_publish, run_one, cls)
                futures[fut] = getattr(cls, "name", str(cls))
                timeout_map[fut] = getattr(cls, "timeout", default_timeout)
            for fut in as_completed(futures):
                try:
                    result = fut.result(timeout=timeout_map.get(fut, default_timeout))
                except Exception as e:
                    result = AgentResult(
                        agent_name=futures[fut],
                        agent_group=AgentGroup.SCANNER,
                        status=AgentStatus.FAILED,
                        errors=[f"QueueRunner caught: {e}"],
                    )
                on_done(result)
                results.append(result)
        return results

    def _run_and_publish(self, run_one: Callable[[Any], Any], cls: Any) -> Any:
        result = run_one(cls)
        for f in getattr(result, "findings", []):
            self.finding_bus.publish(f)
        return result

    def drain(self) -> list[Any]:
        return self.finding_bus.drain()
