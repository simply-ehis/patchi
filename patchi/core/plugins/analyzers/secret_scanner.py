"""
Secret Scanner Analyzer — detects hardcoded secrets and credentials.

This is a built-in analyzer that scans for:
- Hardcoded passwords
- API keys
- Private keys
- Connection strings
- Tokens

Example usage:
    from patchi.core.plugins import get_registry, AnalyzerContext
    from pathlib import Path

    registry = get_registry()
    context = AnalyzerContext(root=Path("."))
    result = registry.run("secret-scanner", context)
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

# Patterns that indicate secrets
SECRET_PATTERNS = [
    # Passwords
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "hardcoded-password", Severity.CRITICAL),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*([^\s"\'#]{8,})', "hardcoded-password", Severity.CRITICAL),

    # API Keys
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "hardcoded-api-key", Severity.HIGH),
    (r'(?i)(secret[_-]?key|client[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "hardcoded-secret-key", Severity.HIGH),

    # Private keys
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "private-key-exposure", Severity.CRITICAL),

    # Connection strings
    (r'(?i)(mysql|postgres|postgresql|mongodb|redis)://[^\s"\'<>]{20,}', "hardcoded-connection-string", Severity.HIGH),

    # Tokens
    (r'(?i)(token|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "hardcoded-token", Severity.HIGH),

    # AWS keys
    (r'AKIA[0-9A-Z]{16}', "aws-access-key", Severity.CRITICAL),

    # GitHub tokens
    (r'ghp_[A-Za-z0-9]{36}', "github-personal-access-token", Severity.CRITICAL),

    # JWT tokens
    (r'eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*', "jwt-token-exposure", Severity.HIGH),
]

# Files to skip
SKIP_PATTERNS = [
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "*.pyc",
    "__pycache__/*",
    "node_modules/*",
    ".git/*",
]


class SecretScanner(Analyzer):
    """Scans for hardcoded secrets and credentials."""

    name = "secret-scanner"
    version = "1.0.0"
    description = "Detects hardcoded passwords, API keys, tokens, and other secrets"
    priority = 10  # Run early
    supported_file_patterns = []  # All files

    def analyze(self, context: AnalyzerContext) -> AnalyzerResult:
        findings: list[Finding] = []
        files_scanned = 0

        for file in context.files:
            if not self.should_analyze(file):
                continue

            # Skip binary/minified files
            if any(re.match(p.replace("*", ".*"), file.path) for p in SKIP_PATTERNS):
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
        """Scan a single file for secrets."""
        findings: list[Finding] = []

        if not file.content:
            return findings

        lines = file.content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            for pattern, finding_type, severity in SECRET_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Skip false positives
                    if self._is_false_positive(line, match):
                        continue

                    findings.append(make_finding(
                        file=file.path,
                        line=line_num,
                        type=finding_type,
                        severity=severity,
                        message=f"Possible {finding_type.replace('-', ' ')} detected",
                        detail=f"Pattern matched: {match.group()[:50]}...",
                        code_snippet=line.strip()[:200],
                        suggestion="Move secrets to environment variables or a secrets manager",
                        confidence=0.8,
                    ))

        return findings

    def _is_false_positive(self, line: str, match: re.Match) -> bool:
        """Check if a match is likely a false positive."""
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            return True

        # Skip test files
        if "test" in line.lower() or "example" in line.lower() or "mock" in line.lower():
            return True

        # Skip placeholders
        if any(p in match.group().lower() for p in ["xxx", "yyy", "placeholder", "your-", "example"]):
            return True

        return False
