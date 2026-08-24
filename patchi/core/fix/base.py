"""
Base functionality for fix agents.
"""

import os
import re
from pathlib import Path

from patchi.core.fix.patch import (
    FileChange,
    Patch,
    PatchState,
    PatchType,
    compute_confidence,
    compute_risk_score,
)


def _call_ai(prompt: str, config: dict, max_tokens: int = 1500, system_prompt: str = "") -> str:
    if os.environ.get("PATCHI_OFFLINE"):
        return ""
    """
    Call the configured AI model with a prompt.
    Delegates to the canonical client. Uses skill-specific system prompt when provided.
    """
    from patchi.core.ai.client import call_ai

    sys_prompt = system_prompt or "You are a helpful coding assistant."
    result = call_ai(config, sys_prompt, prompt, max_tokens)
    return result or ""


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _extract_code_block(text: str) -> str:
    """Extract the first ```...``` block from an AI response."""
    m = re.search(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
    return m.group(1) if m else text.strip()


def _make_patch(
    agent_name: str,
    patch_type: PatchType,
    changes: list[FileChange],
    description: str,
    ai_explanation: str,
    finding_id: str = "",
    blast_radius: int = 0,
    agent_certainty: float = 0.9,
    has_test_coverage: bool = True,
    scanner_agent: str = "",
    source_finding: dict | None = None,
) -> Patch:
    risk = compute_risk_score(changes, blast_radius)
    conf = compute_confidence(changes, agent_certainty, has_test_coverage=has_test_coverage)
    return Patch(
        agent=agent_name,
        patch_type=patch_type,
        finding_id=finding_id,
        changes=changes,
        description=description,
        ai_explanation=ai_explanation,
        risk_score=risk,
        confidence=conf,
        blast_radius=blast_radius,
        state=PatchState.PROPOSED,
        scanner_agent=scanner_agent,
        source_finding=source_finding or {},
        verify_retries=2,
    )


_SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts",
    ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php",
    ".cs", ".swift", ".dart", ".c", ".cpp", ".cxx", ".cc",
    ".h", ".hpp", ".scala", ".svelte", ".vue",
}


def compute_blast_radius(file_path: str, root: Path) -> int:
    """Count how many files in the project import this file."""
    rel = file_path
    stem = Path(rel).stem
    count = 0
    for src in root.rglob("*"):
        if src.suffix not in _SOURCE_EXTENSIONS or not src.is_file():
            continue
        try:
            content = src.read_text(encoding="utf-8", errors="ignore")
            if rel in content or stem in content:
                count += 1
        except OSError:
            pass
    return count
