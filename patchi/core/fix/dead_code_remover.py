"""
DeadCodeRemover — proposes deletion of confirmed dead code files.

Three safety checks before ANY deletion proposal (per MASTER_REBUILD_BRIEF FIX 3C):
  1. Dynamic reference — search py/json/toml/yml for the filename stem.
     If found anywhere, skip: it might be loaded at runtime.
  2. Age check — skip if file was modified within the last 7 days.
     Recent files may be in-progress work not yet wired up.
  3. Intent check — skip if lines 1–5 contain TODO/FUTURE/PLANNED/PLUGIN/RESERVED.
     These signal the file is intentionally unlinked for now.

If all three pass: propose deletion with agent_certainty=0.75 (not 0.95).
"""

from __future__ import annotations

import time
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    register,
)
from patchi.core.brain.languages import EXTENSION_MAP
from patchi.core.fix.patch import FileChange, Patch, PatchType

from .base import _make_patch, _read_file, compute_blast_radius

_INTENT_KEYWORDS = frozenset({"TODO", "FUTURE", "PLANNED", "PLUGIN", "RESERVED", "COMING SOON"})

# Search every scanned source/config extension for a dynamic reference to the
# candidate file's stem — not just Python/JSON. A dead .js/.go/.rb/... file can
# be referenced from any language's string, config, or manifest.
_DYNAMIC_SEARCH_EXTS = set(EXTENSION_MAP.keys()) | {".json", ".toml", ".yml", ".yaml", ".lock"}


@register
class DeadCodeRemover(BaseAgent):
    """Proposes deletion of confirmed dead files after triple safety check."""

    name = "DeadCodeRemover"
    group = AgentGroup.FIX
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        dead_findings = [
            f
            for f in inp.extra.get("findings", [])
            if f.get("type") == "confirmed_dead" and f.get("fix_agent") == self.name
        ]

        patches: list[Patch] = []

        for finding in dead_findings[:20]:
            file_path = finding.get("file", "")
            path = inp.root / file_path
            original = _read_file(path)
            if not original:
                continue

            skip_reason = _safety_check(path, file_path, inp.root)
            if skip_reason:
                result.data.setdefault("skipped", []).append({"file": file_path, "reason": skip_reason})
                continue

            blast_radius = compute_blast_radius(file_path, inp.root)

            patch = _make_patch(
                agent_name=self.name,
                patch_type=PatchType.DEAD_CODE,
                changes=[FileChange(path=file_path, original=original, proposed="")],
                description=f"Remove dead file: {file_path}",
                ai_explanation=(
                    "File has no importers, is not an entry point, and passed all "
                    f"safety checks. Evidence: {finding.get('message', '')}"
                ),
                finding_id=finding.get("type", ""),
                blast_radius=blast_radius,
                agent_certainty=0.75,
            )
            patches.append(patch)
            result.data.setdefault("patches", []).append(patch.to_dict())

        result.data["patch_count"] = len(patches)


def _safety_check(path: Path, rel_path: str, root: Path) -> str | None:
    """
    Return a skip reason string if the file should NOT be deleted,
    or None if deletion can be proposed.
    """
    stem = path.stem

    # 1. Dynamic reference — stem appears in any config/source file
    for src_file in root.rglob("*"):
        if not src_file.is_file():
            continue
        if src_file.suffix not in _DYNAMIC_SEARCH_EXTS:
            continue
        if src_file == path:
            continue
        try:
            if stem in src_file.read_text(encoding="utf-8", errors="ignore"):
                return f"Skipped: referenced by name in {src_file.relative_to(root)}"
        except OSError:
            continue

    # 2. Age check — file modified within last 7 days
    try:
        age_days = (time.time() - path.stat().st_mtime) / 86400
        if age_days < 7:
            return "Skipped: file is less than 7 days old — may be in progress"
    except OSError:
        return "Skipped: could not determine file age"

    # 3. Intent check — early lines signal intentional placeholder
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for line in lines[:5]:
            upper = line.upper()
            if any(kw in upper for kw in _INTENT_KEYWORDS):
                return "Skipped: file appears intentionally unlinked"
    except OSError:
        pass

    return None
