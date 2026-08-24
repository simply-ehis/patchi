"""Base class for per-language type checkers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


import logging
_log = logging.getLogger("patchi.brain.base")

class BaseTypeChecker(ABC):
    """Abstract base for language-specific type checkers."""

    language: str = ""

    @abstractmethod
    def check(self, source: str, file_path: str) -> list[dict]:
        """Return list of type issue findings.
        Each finding: {
            "type": str,      # e.g. "explicit_any", "missing_return_type"
            "file": str,
            "line": int,
            "title": str,
            "description": str,
            "evidence": str,
            "severity": str,  # "low", "medium", "high"
        }
        """
        ...


def _node_text(source: str, node: Any) -> str:
    """Extract text from a tree-sitter node using the source string."""
    try:
        buf = source.encode("utf-8")
        return buf[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    except Exception as e:
        _log.debug("_node_text failed: %s", e)
        return ""


def make_finding(
    finding_type: str,
    file: str,
    line: int,
    title: str,
    description: str,
    evidence: str = "",
    severity: str = "medium",
) -> dict:
    return {
        "type": finding_type,
        "file": file,
        "line": line,
        "title": title,
        "description": description,
        "evidence": evidence,
        "severity": severity,
    }
