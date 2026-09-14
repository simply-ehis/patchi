"""
TODO Scanner Analyzer — detects TODO, FIXME, HACK, and other code comments.

This is a built-in analyzer that scans for:
- TODO comments
- FIXME comments
- HACK comments
- XXX comments
- NOTE comments

Example usage:
    from patchi.core.plugins import get_registry, AnalyzerContext
    from pathlib import Path

    registry = get_registry()
    context = AnalyzerContext(root=Path("."))
    result = registry.run("todo-scanner", context)
"""

from __future__ import annotations

import re

from patchi.core.plugins.analyzer import (
    Analyzer,
    AnalyzerContext,
    AnalyzerResult,
    FileNode,
    Finding,
    Severity,
    make_finding,
)

# TODO-like patterns
TODO_PATTERNS = [
    (r"(?i)\bTODO\b", "todo-comment", Severity.LOW),
    (r"(?i)\bFIXME\b", "fixme-comment", Severity.MEDIUM),
    (r"(?i)\bHACK\b", "hack-comment", Severity.MEDIUM),
    (r"(?i)\bXXX\b", "xxx-comment", Severity.MEDIUM),
    (r"(?i)\bNOTE\b", "note-comment", Severity.INFO),
    (r"(?i)\bBUG\b", "bug-comment", Severity.MEDIUM),
    (r"(?i)\bOPTIMIZE\b", "optimize-comment", Severity.LOW),
    (r"(?i)\bREFACTOR\b", "refactor-comment", Severity.LOW),
]


class TodoScanner(Analyzer):
    """Scans for TODO, FIXME, HACK, and other code comments."""

    name = "todo-scanner"
    version = "1.0.0"
    description = "Detects TODO, FIXME, HACK, and other code comments"
    priority = 200  # Run last
    supported_file_patterns = []  # All files

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        findings: list[Finding] = []
        files_scanned = 0

        for file in context.files:
            if not self.should_analyze(file):
                continue

            files_scanned += 1
            file_findings = self._scan_file(file)
            findings.extend(file_findings)

        return AnalyzerResult(
            findings=findings,
            files_analyzed=files_scanned,
            metrics={
                "files_scanned": files_scanned,
                "findings_count": len(findings),
            },
        )

    def _scan_file(self, file: FileNode) -> list[Finding]:
        """Scan a single file for TODO-like comments."""
        findings: list[Finding] = []

        if not file.content:
            return findings

        lines = file.content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip non-comment lines
            if not any(stripped.startswith(p) for p in ["#", "//", "/*", "*", "<!--"]):
                # Check if it's inline comment
                if not any(p in line for p in ["#", "//", "/*", "<!--"]):
                    continue

            for pattern, finding_type, severity in TODO_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    # Extract the comment text
                    comment_text = line.strip()
                    if len(comment_text) > 200:
                        comment_text = comment_text[:200] + "..."

                    findings.append(
                        make_finding(
                            file=file.path,
                            line=line_num,
                            type=finding_type,
                            severity=severity,
                            message=f"Code comment: {match.group().upper()}",
                            detail=comment_text,
                            code_snippet=line.strip()[:200],
                            suggestion=f"Address the {match.group().upper()} comment or remove it",
                            confidence=1.0,
                        )
                    )

        return findings
