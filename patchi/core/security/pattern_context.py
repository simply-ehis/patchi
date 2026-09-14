"""
Pattern-context suppression for security agents.

Detects when a flagged line lives inside:
  - A regex definition (re.compile, _PATTERNS list)
  - A docstring or multi-line comment block
  - A string literal in a variable named *pattern*, *regex*, *payload*, etc.
  - A test fixture file (tests/ or test_*.py)
"""

from __future__ import annotations

import re
from pathlib import Path


def _try_read(file_path: str) -> str | None:
    """Try reading a file, resolving relative paths against CWD."""
    p = Path(file_path)
    if not p.is_absolute():
        p = Path.cwd() / file_path
    if not p.is_file():
        return None
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def is_pattern_context(file_path: str, line_num: int) -> bool:
    """
    Return True if line_num in file_path is inside a pattern definition,
    docstring, or test fixture — meaning a security finding there is a
    self-referential false positive.
    """
    if line_num < 1:
        return False

    content = _try_read(file_path)
    if content is None:
        return False

    lines = content.splitlines()
    if line_num > len(lines):
        return False

    target_line = lines[line_num - 1].strip()

    # ── Test file check ───────────────────────────────────────────────────
    fp = file_path.replace("\\", "/")
    if "/tests/" in fp or fp.split("/")[-1].startswith("test_"):
        return True

    # ── Variable name check ───────────────────────────────────────────────
    assign_match = re.match(r"(\w+)\s*[:=]", target_line)
    if assign_match:
        var_name = assign_match.group(1).lower()
        if any(
            kw in var_name
            for kw in (
                "pattern",
                "regex",
                "payload",
                "explanation",
                "template",
                "descriptions",
                "protocol",
                "metadata",
                "indicator",
            )
        ):
            return True

    # ── re.compile() check ────────────────────────────────────────────────
    if "re.compile(" in target_line or "re.match(" in target_line:
        return True

    # ── Triple-quote / docstring check ────────────────────────────────────
    in_triple = False
    tq_char = None
    bracket_depth = 0

    for i in range(line_num - 1):
        line = lines[i].strip()
        for tq in ('"""', "'''"):
            count = line.count(tq)
            if count % 2 == 1:
                if in_triple and tq_char == tq:
                    in_triple = False
                elif not in_triple:
                    in_triple = True
                    tq_char = tq
        if in_triple:
            return True
        for ch in line:
            if ch in "({[":
                bracket_depth += 1
            elif ch in ")}]":
                bracket_depth -= 1

    # ── Pattern block in list/dict literal ─────────────────────────────────
    if bracket_depth > 0:
        start = max(0, line_num - 8)
        end = min(len(lines), line_num + 4)
        block = "\n".join(lines[start:end])
        if re.search(r're\.compile\(|r["\']|\\[dDwWsSbB]|\[\^', block):
            return True

    return False


def suppress_findings(result) -> int:
    """
    Remove pattern-context false positives from an AgentResult in place.
    Returns the count of findings removed.
    """
    from patchi.core.agents.base import AgentResult

    if not isinstance(result, AgentResult):
        return 0
    original = len(result.findings)
    result.findings = [f for f in result.findings if not is_pattern_context(f.file, f.line if f.line else 0)]
    return original - len(result.findings)
