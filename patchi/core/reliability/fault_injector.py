"""FaultInjector — identify fault injection points in code.

Scans for patterns that should handle failures gracefully but don't
(network calls without try/except, DB writes without rollback, file I/O
without close/finally, etc.).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from patchi.core.assurance.graph import AssuranceGraph

_log = logging.getLogger("patchi.reliability.fault_injection")


@dataclass
class FaultInjectionPoint:
    """A location in code where fault injection would be valuable."""

    file: str
    line: int
    fault_type: str  # "network", "disk", "database", "memory", "cpu"
    pattern: str  # what was detected
    recovery_strategy: str  # what should be there
    severity: str  # "high", "medium", "low"

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "fault_type": self.fault_type,
            "pattern": self.pattern,
            "recovery_strategy": self.recovery_strategy,
            "severity": self.severity,
        }


# Patterns that indicate missing fault handling
_FAULT_PATTERNS: list[tuple[str, str, str, str, str]] = [
    # (regex pattern, fault_type, description, recovery, severity)
    (
        r"\.read\(|\.write\(",
        "disk",
        "File I/O without try/except",
        "Add try/except with IOError handling",
        "medium",
    ),
    (
        r"requests\.(get|post|put|delete)\(",
        "network",
        "HTTP request without timeout/retry",
        "Add timeout and retry with backoff",
        "high",
    ),
    (
        r"subprocess\.run\(|subprocess\.Popen\(",
        "network",
        "Subprocess without error handling",
        "Add try/except and check returncode",
        "medium",
    ),
    (
        r"\.execute\(|\.commit\(",
        "database",
        "DB operation without rollback",
        "Add try/except with rollback in finally",
        "high",
    ),
    (
        r"json\.loads\(",
        "disk",
        "JSON parse without try/except",
        "Add try/except for JSONDecodeError",
        "medium",
    ),
    (
        r"open\(",
        "disk",
        "File open without context manager",
        "Use with-statement for guaranteed close",
        "medium",
    ),
    (
        r"pickle\.loads?\(",
        "memory",
        "Unsafe deserialization",
        "Use safe deserialization or json",
        "high",
    ),
    (
        r"eval\(|exec\(",
        "memory",
        "Dynamic code execution",
        "Replace with safe alternatives",
        "high",
    ),
]


class FaultInjector:
    """Analyze code for missing fault handling."""

    def __init__(self, root: Path, graph: AssuranceGraph | None = None):
        self._root = root
        self._graph = graph

    def scan_file(self, file_path: Path) -> list[FaultInjectionPoint]:
        """Scan a single file for fault injection points."""
        results: list[FaultInjectionPoint] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return results

        lines = content.splitlines()
        rel_path = (
            str(file_path.relative_to(self._root))
            if self._root in file_path.parents
            else str(file_path)
        )

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, fault_type, description, recovery, severity in _FAULT_PATTERNS:
                import re

                if re.search(pattern, line):
                    # Check if already has try/except nearby
                    if not self._has_error_handling(lines, line_num - 1):
                        results.append(
                            FaultInjectionPoint(
                                file=rel_path,
                                line=line_num,
                                fault_type=fault_type,
                                pattern=description,
                                recovery_strategy=recovery,
                                severity=severity,
                            )
                        )
                        break  # one finding per line

        return results

    def scan_project(self, max_files: int = 200) -> list[FaultInjectionPoint]:
        """Scan the project for fault injection points."""
        results: list[FaultInjectionPoint] = []
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

    def _has_error_handling(self, lines: list[str], line_idx: int) -> bool:
        """Check if a line is inside a try/except block (±5 lines)."""
        start = max(0, line_idx - 5)
        end = min(len(lines), line_idx + 6)
        block = "\n".join(lines[start:end])
        return "try:" in block and ("except" in block or "finally:" in block)
