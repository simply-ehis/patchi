"""IdempotencyAnalyzer — find operations that should be idempotent but aren't.

Detects side effects that happen on every call (file writes without checks,
DB inserts without upserts, network calls without deduplication).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger("patchi.reliability.idempotency")


@dataclass
class IdempotencyIssue:
    """An operation that should be idempotent but has side effects."""

    file: str
    line: int
    issue_type: str  # "append_without_check", "insert_without_upsert", "write_without_guard"
    description: str
    fix_suggestion: str

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "issue_type": self.issue_type,
            "description": self.description,
            "fix_suggestion": self.fix_suggestion,
        }


# Patterns indicating non-idempotent operations
_IDEMPOTENCY_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        r"\.append\(",
        "append_without_check",
        "List append without dedup check",
        "Check if item exists before appending",
    ),
    (
        r"conn\.execute\(['\"]INSERT",
        "insert_without_upsert",
        "SQL INSERT without upsert",
        "Use INSERT OR REPLACE or check existence first",
    ),
    (
        r"\.write_text\(",
        "write_without_guard",
        "File write without content comparison",
        "Compare content before writing to avoid unnecessary I/O",
    ),
    (
        r"json\.dumps.*\.write_text\(",
        "write_without_guard",
        "JSON write without read-compare",
        "Read existing content and compare before writing",
    ),
    (
        r"\.add\(",
        "set_add_without_check",
        "Set add without membership check",
        "Use set.add() (already idempotent) or document non-idempotent semantics",
    ),
]


class IdempotencyAnalyzer:
    """Analyze code for idempotency issues."""

    def __init__(self, root: Path):
        self._root = root

    def scan_file(self, file_path: Path) -> list[IdempotencyIssue]:
        """Scan a single file for idempotency issues."""
        results: list[IdempotencyIssue] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return results

        lines = content.splitlines()
        rel_path = str(file_path.relative_to(self._root)) if self._root in file_path.parents else str(file_path)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, issue_type, description, fix in _IDEMPOTENCY_PATTERNS:
                if re.search(pattern, line):
                    results.append(
                        IdempotencyIssue(
                            file=rel_path,
                            line=line_num,
                            issue_type=issue_type,
                            description=description,
                            fix_suggestion=fix,
                        )
                    )
                    break  # one per line

        return results

    def scan_project(self, max_files: int = 200) -> list[IdempotencyIssue]:
        """Scan the project for idempotency issues."""
        results: list[IdempotencyIssue] = []
        count = 0

        for py_file in sorted(self._root.rglob("*.py")):
            if count >= max_files:
                break
            if ".patchi" in str(py_file) or "__pycache__" in str(py_file):
                continue
            if ".venv" in str(py_file) or "node_modules" in str(py_file):
                continue
            results.extend(self.scan_file(py_file))
            count += 1

        return results
