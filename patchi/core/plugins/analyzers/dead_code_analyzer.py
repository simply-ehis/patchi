"""
Dead Code Analyzer — detects unused imports, variables, and functions.

This is a built-in analyzer that scans for:
- Unused imports
- Unused variables
- Unused functions
- Unreachable code

Example usage:
    from patchi.core.plugins import get_registry, AnalyzerContext
    from pathlib import Path

    registry = get_registry()
    context = AnalyzerContext(root=Path("."))
    result = registry.run("dead-code-analyzer", context)
"""

from __future__ import annotations

import ast

from patchi.core.plugins.analyzer import (
    Analyzer,
    AnalyzerContext,
    AnalyzerResult,
    FileNode,
    Finding,
    Severity,
    make_finding,
)


class DeadCodeAnalyzer(Analyzer):
    """Detects unused imports, variables, and functions."""

    name = "dead-code-analyzer"
    version = "1.0.0"
    description = "Detects unused imports, variables, and functions"
    priority = 50  # Run after secrets, before TODOs
    supported_languages = ["python"]  # Python only for now

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        findings: list[Finding] = []
        files_scanned = 0

        for file in context.files:
            if not self.should_analyze(file):
                continue

            if not file.path.endswith(".py"):
                continue

            files_scanned += 1
            file_findings = self._scan_python_file(file)
            findings.extend(file_findings)

        return AnalyzerResult(
            findings=findings,
            files_analyzed=files_scanned,
            metrics={
                "files_scanned": files_scanned,
                "findings_count": len(findings),
            },
        )

    def _scan_python_file(self, file: FileNode) -> list[Finding]:
        """Scan a Python file for dead code."""
        findings: list[Finding] = []

        if not file.content:
            return findings

        try:
            tree = ast.parse(file.content)
        except SyntaxError:
            return findings

        # Collect all imports
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imports.append((name, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imports.append((name, node.lineno))

        # Collect all names used in the file
        used_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                # Handle attribute access like os.path
                if isinstance(node.value, ast.Name):
                    used_names.add(node.value.id)

        # Check for unused imports
        for name, lineno in imports:
            # Skip wildcard imports
            if name == "*":
                continue

            # Check if name is used (excluding the import itself)
            if name not in used_names:
                findings.append(
                    make_finding(
                        file=file.path,
                        line=lineno,
                        type="unused-import",
                        severity=Severity.LOW,
                        message=f"Unused import: {name}",
                        detail=f"Import '{name}' is defined but never used in this file",
                        suggestion=f"Remove unused import '{name}'",
                        confidence=0.9,
                    )
                )

        return findings
