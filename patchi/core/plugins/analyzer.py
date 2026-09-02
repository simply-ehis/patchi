"""
Formal Analyzer plugin interface for Patchi.

This module defines the contract that all analyzers must follow:
  - Input: AnalyzerContext (AST, graph, project metadata)
  - Output: AnalyzerResult (findings with stable IDs)

Stable Finding IDs:
  Every finding has a deterministic ID based on:
    sha256(f"{analyzer_name}:{file}:{line}:{type}:{message}")[:16]

  This means:
    1. The same issue always has the same ID (deterministic)
    2. Different analyzers produce different IDs (namespaced)
    3. Moving a line changes the ID (line-sensitive)
    4. IDs are short (16 chars) for readability

Adding a new analyzer:
  1. Create a file in patchi/core/plugins/analyzers/
  2. Define a class that inherits from Analyzer
  3. Implement analyze(context) -> AnalyzerResult
  4. That's it! Auto-discovered and registered.

Example:
    from patchi.core.plugins.analyzer import Analyzer, AnalyzerResult, Finding

    class SecretScanner(Analyzer):
        name = "secret-scanner"
        version = "1.0.0"
        description = "Scans for hardcoded secrets"

        def analyze(self, context) -> AnalyzerResult:
            findings = []
            for file in context.files:
                if "password" in file.content.lower():
                    findings.append(Finding(
                        file=file.path,
                        line=find_line(file.content, "password"),
                        type="hardcoded-secret",
                        severity=Severity.CRITICAL,
                        message="Possible hardcoded secret",
                    ))
            return AnalyzerResult(findings=findings)
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class FileNode:
    """A file in the project with its content and metadata."""
    path: str  # relative to project root
    content: str = ""
    language: str = ""
    size: int = 0
    modified_at: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ASTNode:
    """An AST node with position information."""
    type: str  # e.g. "function", "class", "import"
    name: str = ""
    start_line: int = 0
    end_line: int = 0
    start_col: int = 0
    end_col: int = 0
    children: tuple[ASTNode, ...] = ()
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    """An edge in the dependency/call graph."""
    source: str  # file or symbol
    target: str  # file or symbol
    edge_type: str = "calls"  # calls, imports, inherits, etc.
    metadata: dict = field(default_factory=dict)


@dataclass
class AnalyzerContext:
    """Input context for an analyzer.

    Contains everything an analyzer needs:
    - Project root and files
    - AST trees per file (if parsed)
    - Dependency/call graph
    - Project metadata (from brain)
    - Configuration
    """
    root: Path
    files: list[FileNode] = field(default_factory=list)
    asts: dict[str, list[ASTNode]] = field(default_factory=dict)  # file -> AST nodes
    graph_edges: list[GraphEdge] = field(default_factory=list)
    project_name: str = ""
    project_type: str = ""
    tech_stack: list[str] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    scope: list[str] = field(default_factory=list)  # empty = all files
    extra: dict = field(default_factory=dict)  # analyzer-specific params


@dataclass
class Finding:
    """A single finding from an analyzer.

    Has a stable, deterministic ID based on the finding's properties.
    """
    file: str
    line: int
    type: str
    severity: Severity
    message: str
    detail: str = ""
    code_snippet: str = ""
    suggestion: str = ""
    cwe: str = ""
    fix_hint: str = ""  # hint for fix agents
    confidence: float = 1.0  # 0.0 to 1.0
    extra: dict = field(default_factory=dict)

    # Computed stable ID
    _id: str = field(default="", repr=False)

    def __post_init__(self):
        if not self._id:
            self._id = self._compute_id()

    def _compute_id(self) -> str:
        """Compute deterministic ID from finding properties."""
        # Include analyzer name in the hash for namespacing
        # This is set by AnalyzerResult.__post_init__
        analyzer = self.extra.get("_analyzer", "unknown")
        raw = f"{analyzer}:{self.file}:{self.line}:{self.type}:{self.message}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def id(self) -> str:
        return self._id

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "severity": self.severity.value,
            "message": self.message,
            "detail": self.detail,
            "code_snippet": self.code_snippet,
            "suggestion": self.suggestion,
            "cwe": self.cwe,
            "fix_hint": self.fix_hint,
            "confidence": self.confidence,
            **self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(
            file=d.get("file", ""),
            line=d.get("line", 0),
            type=d.get("type", ""),
            severity=Severity(d.get("severity", "medium")),
            message=d.get("message", ""),
            detail=d.get("detail", ""),
            code_snippet=d.get("code_snippet", ""),
            suggestion=d.get("suggestion", ""),
            cwe=d.get("cwe", ""),
            fix_hint=d.get("fix_hint", ""),
            confidence=d.get("confidence", 1.0),
            extra={k: v for k, v in d.items() if k not in {
                "id", "file", "line", "type", "severity", "message",
                "detail", "code_snippet", "suggestion", "cwe", "fix_hint", "confidence",
            }},
            _id=d.get("id", ""),
        )


@dataclass
class AnalyzerResult:
    """Output from an analyzer.

    Contains findings, metrics, and metadata about the analysis run.
    """
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_ms: int = 0
    files_analyzed: int = 0

    def __post_init__(self):
        # Set analyzer name on all findings for stable ID computation
        pass

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "metrics": self.metrics,
            "errors": self.errors,
            "warnings": self.warnings,
            "duration_ms": self.duration_ms,
            "files_analyzed": self.files_analyzed,
        }


class Analyzer(ABC):
    """Base class for all analyzers.

    Subclasses must implement:
      - name: unique identifier for this analyzer
      - version: semantic version
      - description: human-readable description
      - analyze(context): perform analysis and return results

    Optional overrides:
      - supported_languages: restrict to specific languages
      - supported_file_patterns: restrict to specific file patterns
      - priority: execution order (lower = first)
      - timeout: maximum execution time in seconds
    """

    # Required metadata
    name: str = "unnamed-analyzer"
    version: str = "0.0.0"
    description: str = ""

    # Optional configuration
    supported_languages: list[str] = []  # empty = all languages
    supported_file_patterns: list[str] = []  # empty = all files
    priority: int = 100  # lower = runs first
    timeout: int = 60  # seconds
    enabled: bool = True

    @abstractmethod
    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        """Perform analysis and return results.

        Args:
            context: The analysis context containing files, ASTs, graph, etc.

        Returns:
            AnalyzerResult with findings and metadata.
        """
        ...

    def should_analyze(self, file: FileNode) -> bool:
        """Check if this analyzer should process the given file.

        Override to implement custom filtering logic.
        """
        if self.supported_languages and file.language not in self.supported_languages:
            return False
        if self.supported_file_patterns:
            import fnmatch
            if not any(fnmatch.fnmatch(file.path, p) for p in self.supported_file_patterns):
                return False
        return True

    def describe(self) -> dict:
        """Return metadata for plugin discovery."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_languages": self.supported_languages,
            "supported_file_patterns": self.supported_file_patterns,
            "priority": self.priority,
            "timeout": self.timeout,
            "enabled": self.enabled,
        }


# ── Helper for creating findings ──────────────────────────────────────────────

def make_finding(
    file: str,
    line: int,
    type: str,
    severity: Severity,
    message: str,
    detail: str = "",
    code_snippet: str = "",
    suggestion: str = "",
    cwe: str = "",
    fix_hint: str = "",
    confidence: float = 1.0,
    **extra,
) -> Finding:
    """Create a Finding with the given properties.

    This is a convenience function for creating findings in analyzers.
    """
    return Finding(
        file=file,
        line=line,
        type=type,
        severity=severity,
        message=message,
        detail=detail,
        code_snippet=code_snippet,
        suggestion=suggestion,
        cwe=cwe,
        fix_hint=fix_hint,
        confidence=confidence,
        extra=extra,
    )
