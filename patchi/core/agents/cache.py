"""
Agent result cache — avoids re-running agents when project files haven't changed.

Cache key is an SHA-256 hash of:
  - agent name
  - all project source file (rel_path, mtime_ns, size) tuples
  - config hash

Stored in .patchi/cache/agent_cache/{agent_name}.json

On a full scan with zero file changes, this skips every agent → ~5-10x speedup.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from patchi.core.agents.base import AgentResult

_SOURCE_EXTS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb", ".php",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env", ".html", ".css",
    ".scss", ".vue", ".svelte", ".md", ".xml", ".gradle", ".kt", ".swift",
    ".mjs", ".cjs", ".mts", ".cts",
})


import logging
_log = logging.getLogger("patchi.agents.cache")

def _file_fingerprint(root: Path) -> str:
    """One fingerprint per project: hash of every source file's content.

    Content-hashed rather than metadata (mtime_ns, size): two writes landing in
    the same FS timestamp tick with the same size would yield an identical
    metadata fingerprint, so the agent cache would serve stale results after a
    same-sized edit instead of invalidating.
    """
    # .patchi is the tool's own state (memory, action log, agent cache, rules)
    # — never part of the project's source. Including it made the fingerprint
    # change every time a cache/memory file was written, so the cache kept
    # invalidating ITSELF mid-pipeline (found by the smoke-sweep --pipeline
    # orchestration gate: the Governor's SANDBOX_REVERIFY re-ran 267 agents
    # instead of hitting cache).
    _IGNORED_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", ".tox", ".eggs", "eggs", "dist", "build", ".ruff_cache", ".pytest_cache", ".mypy_cache", ".coverage", ".patchi"}

    hasher = hashlib.sha256()
    for fpath in sorted(root.rglob("*")):
        parts = fpath.relative_to(root).parts if fpath != root else ()
        if any(p in _IGNORED_DIRS for p in parts):
            continue
        if fpath.is_file() and fpath.suffix in _SOURCE_EXTS:
            try:
                rel = fpath.relative_to(root).as_posix()
                hasher.update(f"f:{rel}:".encode())
                with fpath.open("rb") as fh:
                    hasher.update(hashlib.sha256(fh.read()).digest())
                hasher.update(b"\n")
            except (OSError, ValueError):
                continue
    return hasher.hexdigest()[:16]


class AgentCache:
    """Per-agent on-disk result cache, invalidated when project files change."""

    def __init__(self, root: Path):
        self._root = root
        self._cache_dir = root / ".patchi" / "cache" / "agent_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._fingerprint: str | None = None

    def get_fingerprint(self) -> str:
        if self._fingerprint is None:
            self._fingerprint = _file_fingerprint(self._root)
        return self._fingerprint

    def _cache_path(self, agent_name: str) -> Path:
        safe = agent_name.replace("/", "_").replace("\\", "_")
        return self._cache_dir / f"{safe}.json"

    def get(self, agent_name: str) -> AgentResult | None:
        path = self._cache_path(agent_name)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("fp") == self.get_fingerprint():
                result = AgentResult.from_dict(data["result"])
                return result
        except Exception as e:
            _log.warning("AgentCache.get failed: %s", e)
        return None

    def put(self, agent_name: str, result: AgentResult) -> None:
        path = self._cache_path(agent_name)
        try:
            data: dict[str, Any] = {
                "fp": self.get_fingerprint(),
                "result": result.to_dict(),
                "ts": time.time(),
            }
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            _log.warning("AgentCache.put failed: %s", e)

    def invalidate_all(self) -> int:
        """Clear all cached agent results. Returns count of files removed."""
        count = 0
        if self._cache_dir.exists():
            for fpath in self._cache_dir.glob("*.json"):
                try:
                    fpath.unlink()
                    count += 1
                except OSError:
                    pass
        self._fingerprint = None
        return count

    def invalidate(self, agent_name: str) -> bool:
        """Clear cache for a single agent."""
        path = self._cache_path(agent_name)
        if path.exists():
            try:
                path.unlink()
                return True
            except OSError:
                pass
        return False

    def list_cached(self) -> list[str]:
        """Return agent names with valid cache entries."""
        results = []
        fp = self.get_fingerprint()
        if self._cache_dir.exists():
            for fpath in self._cache_dir.glob("*.json"):
                try:
                    data = json.loads(fpath.read_text(encoding="utf-8"))
                    if data.get("fp") == fp:
                        results.append(fpath.stem)
                except Exception as e:
                    _log.warning("AgentCache.list_cached failed: %s", e)
        return results
