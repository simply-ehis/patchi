"""
TypeScanner — multi-language type issue detection.

Delegates to per-language type checkers in patchi.core.brain.type_checker.
Covers: TypeScript, Python, Java, Go, Rust, C#, Kotlin, Swift, PHP, Dart.

Does NOT call AI (detection only - fixes handled by TypeFixer).
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

from pathlib import Path

from patchi.core.brain.languages import (
    DEFAULT_IGNORE_DIRS,
    Lang,
    detect_language,
)
from patchi.core.brain.type_checker import check_types

from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    get_shard_files,
    make_finding,
    register,
    safe_rglob,
)

# Languages that have type checkers
TYPE_CHECKED_LANGS = {
    Lang.TYPESCRIPT,
    Lang.PYTHON,
    Lang.JAVA,
    Lang.GO,
    Lang.RUST,
    Lang.C_SHARP,
    Lang.KOTLIN,
    Lang.SWIFT,
    Lang.PHP,
    Lang.DART,
}

# Source file patterns for type-checked languages
TYPE_CHECKED_PATTERNS = [
    "*.ts",
    "*.tsx",
    "*.mts",
    "*.py",
    "*.pyw",
    "*.java",
    "*.go",
    "*.rs",
    "*.cs",
    "*.kt",
    "*.kts",
    "*.swift",
    "*.php",
    "*.dart",
]


@register
class TypeScanner(BaseAgent):
    """Scanner for type issues across all supported languages."""

    group = AgentGroup.SCANNER
    name = "TypeScanner"
    description = "Type issues: any/dynamic, missing types, unsafe assertions"
    shardable = True
    supported_languages = None

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan for type issues across all type-checked languages."""
        findings = []
        checked_files: list[Path] = []

        for pattern in TYPE_CHECKED_PATTERNS:
            for file_path in get_shard_files(inp, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        checked_files.append(file_path)

        if not checked_files:
            result.status = AgentStatus.SKIPPED
            result.findings = []
            result.data.update({"needs_ai": False})
            return

        # Skip trivially small files (no type issues) and cap total to avoid O(n) I/O
        _MIN_SIZE = 10  # bytes
        _MAX_FILES = 500
        scanned = 0
        for file_path in checked_files:
            if scanned >= _MAX_FILES:
                break
            try:
                if file_path.stat().st_size < _MIN_SIZE:
                    continue
            except OSError:
                continue
            rel_path = file_path.relative_to(inp.root).as_posix()
            lang = detect_language(file_path)
            findings.extend(self._scan_file(file_path, rel_path, lang))
            scanned += 1

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "files_scanned": len(checked_files),
                "findings_count": len(findings),
                "needs_ai": True,
            }
        )
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        from pathlib import PurePosixPath

        if any(p in DEFAULT_IGNORE_DIRS for p in PurePosixPath(file_path).parts):
            return True
        restrictions = inp.config.get("restrictions", [])
        for r in restrictions:
            if r.get("enabled", True):
                path = r["path"]
                if file_path.startswith(path) or PurePosixPath(file_path).match(path):
                    if r["type"] == "NO_TOUCH":
                        return True
                    elif r["type"] == "SCAN_ONLY" and self.__class__.__name__ == "FixAgent":
                        return True
        return False

    def _scan_file(self, file_path: Path, rel_path: str, lang: Lang) -> list[Finding]:
        """Scan a single file for type issues using the type checker module."""
        findings: list[Finding] = []

        if lang not in TYPE_CHECKED_LANGS:
            return findings

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="File read error",
                    description=f"Could not read {file_path.name}: {str(e)}",
                    evidence=str(e),
                )
            )
            return findings

        raw_findings = check_types(content, lang, rel_path)
        for rf in raw_findings:
            sev = Severity.MEDIUM
            if rf.get("severity") == "high":
                sev = Severity.HIGH
            elif rf.get("severity") == "low":
                sev = Severity.LOW
            findings.append(
                make_finding(
                    severity=sev,
                    file=rel_path,
                    line_start=rf.get("line", 0),
                    title=rf.get("title", "Type issue"),
                    finding_type=rf.get("type", "type_issue"),
                    description=rf.get("description", ""),
                    evidence=rf.get("evidence", ""),
                )
            )

        return findings
