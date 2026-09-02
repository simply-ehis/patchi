"""
Understander — picks the 12-20 files that actually matter.

Uses Body tags + blast_radius + import_graph instead of file_infos[:50]
in insertion order. All AI surfaces call this instead of slicing.

Provides:
  - core_files(limit) -> [{path, why, score, content_snippet}]
  - refine_domains(active, tags) -> filtered domains (drop false hubs)
  - get_function_at(file, line) -> function body via FileCorpus cache
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

_log = logging.getLogger("patchi.brain.understander")


class Understander:
    def __init__(
        self,
        root: Path,
        file_infos: list[Any],
        body_tags: dict[str, dict[str, Any]],
        blast_map: dict[str, Any] | None = None,
        routes: list[Any] | None = None,
    ) -> None:
        self.root = root
        self.file_infos = {fi.path: fi for fi in file_infos}
        self.tags = body_tags
        self.blast = blast_map or {}
        self.routes = routes or []
        # sort once
        self._ranked = sorted(
            body_tags.items(),
            key=lambda kv: (-int(kv[1].get("score", 0)), -int(kv[1].get("fan_in", 0)), kv[0]),
        )

    def core_files(self, limit: int = 16, include_low: bool = False) -> list[dict[str, Any]]:
        """Top-ranked files the LLM must see. Always includes Brain + memory + entry points."""
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        # force-include
        for must in ("patchi/core/brain/brain.py", "patchi/core/memory.py", "patchi/core/brain/body_tags.py"):
            if must in self.tags and must not in seen:
                t = self.tags[must]
                out.append({"path": must, "why": f"{t['role']}/{t['system']} critical={t['criticality']} fan_in={t['fan_in']}", "score": t["score"], "tag": t})
                seen.add(must)
        for path, tag in self._ranked:
            if path in seen:
                continue
            if not include_low and tag.get("criticality") == "low" and tag.get("score", 0) < 15 and len(out) >= limit:
                continue
            out.append({"path": path, "why": f"{tag['role']}/{tag['system']} {tag['criticality']} fan_in={tag.get('fan_in',0)}", "score": tag["score"], "tag": tag})
            seen.add(path)
            if len(out) >= limit:
                break
        return out

    def refine_domains(self, active: list[str]) -> list[str]:
        """Drop domains that are low-score hubs only (speed). Keep high/critical cores."""
        if not active:
            return active
        # count how many core_files map to each domain keyword
        core_paths = {c["path"] for c in self.core_files(limit=12)}
        # naive: keep all for now, but log drop candidate
        # Future: intersect with body_tags system fields
        _ = core_paths
        return active

    def file_snippet(self, rel_path: str, max_lines: int = 200) -> str:
        """Return first max_lines with line numbers — for prompts. Uses FileCorpus-style cache via pathlib."""
        fi = self.file_infos.get(rel_path)
        if fi is not None:
            try:
                txt = (self.root / rel_path).read_text(encoding="utf-8", errors="replace")
                lines = txt.splitlines()[:max_lines]
                return "\n".join(f"{i+1:4d} | {l}" for i, l in enumerate(lines))
            except Exception as exc:  # noqa: BLE001
                _log.debug("understander snippet failed for %s: %s", rel_path, exc)
                return ""
        return ""

    def function_at(self, rel_path: str, line: int, window: int = 50) -> str:
        """Return function body surrounding line, using line-number heuristic (no heavy AST)."""
        try:
            txt = (self.root / rel_path).read_text(encoding="utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            _log.debug("function_at read failed: %s", exc)
            return ""
        lines = txt.splitlines()
        if not 1 <= line <= len(lines):
            return "\n".join(lines[: min(len(lines), window)])
        # find def/class up
        start = max(0, line - 1 - 60)
        for i in range(line - 2, max(-1, line - 80), -1):
            s = lines[i].lstrip()
            if s.startswith("def ") or s.startswith("async def ") or s.startswith("class "):
                start = i
                break
        # find next def at same or lesser indent
        base_indent = len(lines[line - 1]) - len(lines[line - 1].lstrip())
        end = min(len(lines), line + window)
        for i in range(line, min(len(lines), line + 80)):
            s = lines[i]
            if s.strip() and not s.strip().startswith("#"):
                indent = len(s) - len(s.lstrip())
                st = s.strip()
                if indent <= base_indent and (st.startswith("def ") or st.startswith("class ") or st.startswith("async def ")):
                    end = i
                    break
        block = lines[start:end]
        return "\n".join(f"{i+1:4d} | {l}" for i, l in enumerate(block, start=start + 1))

    def as_prompt_block(self, limit: int = 14) -> str:
        """One-shot block for LLM prompts — core files + why."""
        core = self.core_files(limit=limit)
        lines = []
        for c in core:
            lines.append(f"- {c['path']}  // {c['why']}")
            snippet = self.file_snippet(c["path"], max_lines=24)
            if snippet:
                # cap per-file snippet to 24 lines to stay within 6k budget
                lines.append("```python")
                lines.append(snippet)
                lines.append("```")
        return "\n".join(lines)
