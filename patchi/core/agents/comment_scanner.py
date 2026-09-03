"""
CommentScanner — TODO/FIXME/HACK technical debt markers.

Scans for technical debt markers in comments:
- TODO: Planned features or improvements
- FIXME: Known issues that need fixing
- HACK: Workarounds that should be addressed
- XXX: Critical issues requiring attention
- NOSONAR: SonarQube suppression markers
- TEMP: Temporary code that needs removal
- KLUDGE: Crude solutions that need refinement
- BUG: Known bug markers
- REVIEW: Code requiring review
- OPTIMIZE: Performance improvement opportunities

Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..brain.languages import DEFAULT_IGNORE_DIRS, Lang, detect_language
from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
    safe_rglob,
    scope_allows,
)


@register
class CommentScanner(BaseAgent):
    """Scanner for technical debt markers in comments."""

    group = AgentGroup.SCANNER
    name = "CommentScanner"
    description = "TODO/FIXME/HACK technical debt markers"

    # Technical debt patterns with severity levels.
    # Comment markers are hygiene, never vulnerabilities: capped at MEDIUM
    # (a "BUG" comment was flagging CRITICAL and drowning the gate).
    TECH_DEBT_PATTERNS = [
        (r"XXX\b", "XXX", Severity.MEDIUM),
        (r"BUG\b", "BUG", Severity.MEDIUM),
        (r"HACK\b", "HACK", Severity.MEDIUM),
        # Important issues
        (r"FIXME\b", "FIXME", Severity.MEDIUM),
        (r"TODO\b", "TODO", Severity.INFO),
        # Less urgent but still noteworthy
        (r"REVIEW\b", "REVIEW", Severity.LOW),
        (r"KLUDGE\b", "KLUDGE", Severity.MEDIUM),
        (r"TEMP\b", "TEMPORARY", Severity.LOW),
        (r"OPTIMIZE\b", "OPTIMIZE", Severity.LOW),
        (r"NOSONAR\b", "NOSONAR", Severity.LOW),  # SonarQube suppression
    ]

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan for technical debt markers in comments."""
        findings = []

        # Define file patterns for all supported languages
        patterns = [
            "*.js",
            "*.jsx",
            "*.ts",
            "*.tsx",
            "*.py",
            "*.java",
            "*.php",
            "*.rb",
            "*.go",
            "*.rs",
            "*.cpp",
            "*.cxx",
            "*.cc",
            "*.c",
            "*.h",
            "*.hpp",
            "*.cs",
            "*.scala",
            "*.kt",
            "*.swift",
            "*.dart",
        ]

        # Search for files
        for pattern in patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not scope_allows(inp, rel_path):
                        continue
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_file_comments(file_path, rel_path))

        # Add summary when technical debt markers exist
        debt_findings = [
            f
            for f in findings
            if any(marker_name in f.title for _, marker_name, _ in self.TECH_DEBT_PATTERNS)
        ]
        if debt_findings:
            findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file="__summary__",
                    line_start=0,
                    title=f"Technical Debt Markers Found: {len(debt_findings)}",
                    description=f"Discovered {len(debt_findings)} technical debt markers in project",
                    evidence=f"Markers found in {len({f.file for f in debt_findings})} files",
                )
            )

        by_type: dict[str, int] = {}
        for finding in debt_findings:
            match = re.search(r"Technical Debt Marker: (\w+)", finding.title)
            if match:
                marker = match.group(1)
                by_type[marker] = by_type.get(marker, 0) + 1

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "todo_count": len(
                    [
                        f
                        for f in findings
                        if f.type == "technical_debt" and "TODO" in f.message.upper()
                    ]
                ),
                "fixme_count": len(
                    [
                        f
                        for f in findings
                        if f.type == "technical_debt" and "FIXME" in f.message.upper()
                    ]
                ),
                "hack_count": len(
                    [
                        f
                        for f in findings
                        if f.type == "technical_debt" and "HACK" in f.message.upper()
                    ]
                ),
                "bug_count": len(
                    [
                        f
                        for f in findings
                        if f.type == "technical_debt" and "BUG" in f.message.upper()
                    ]
                ),
                "total_markers": len(debt_findings),
                "by_type": by_type,
                "needs_ai": False,
            }
        )
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        # Skip ignored directories (node_modules, .venv, etc.)
        from pathlib import PurePosixPath

        if any(p in DEFAULT_IGNORE_DIRS for p in PurePosixPath(file_path).parts):
            return True

        from pathlib import PurePosixPath

        # Check restrictions
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

    def _scan_file_comments(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan a file for technical debt markers in comments."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")
            lines = content.splitlines()

            # Different comment patterns for different languages
            lang = detect_language(file_path)
            comment_patterns = self._get_comment_patterns(lang)

            for line_num, line in enumerate(lines, 1):
                # Find all comment sections in the line
                for comment_pattern in comment_patterns:
                    comment_matches = re.finditer(comment_pattern, line)
                    for comment_match in comment_matches:
                        comment_text = comment_match.group(1)  # The content of the comment

                        # Look for technical debt markers in the comment
                        for pattern, marker_name, severity in self.TECH_DEBT_PATTERNS:
                            debt_matches = re.finditer(pattern, comment_text, re.IGNORECASE)
                            for debt_match in debt_matches:
                                # Extract context around the marker
                                start_idx = max(0, debt_match.start() - 20)
                                end_idx = min(len(comment_text), debt_match.end() + 40)
                                context = comment_text[start_idx:end_idx]

                                findings.append(
                                    make_finding(
                                        severity=severity,
                                        finding_type="technical_debt",
                                        file=rel_path,
                                        line_start=line_num,
                                        title=f"Technical Debt Marker: {marker_name}",
                                        description=f"Found {marker_name} marker in comment",
                                        evidence=f"Context: {context.strip()}",
                                    )
                                )

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Comment file read error",
                    description=f"Could not read file {file_path.name} for comment scanning: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _get_comment_patterns(self, lang: Lang) -> list[str]:
        """Get appropriate comment patterns for the language."""
        # Use a broad set of comment capture patterns for most languages.
        return [
            r"#(.*)$",  # Hash-style comment
            r"//(.*)$",  # Double-slash comment
            r"/\*(.*?)\*/",  # C-style multi-line comment
        ]

    def _get_language_extensions(self) -> dict[str, Lang]:
        """Map file extensions to language enums."""
        return {
            ".js": Lang.JAVASCRIPT,
            ".jsx": Lang.JAVASCRIPT,
            ".ts": Lang.TYPESCRIPT,
            ".tsx": Lang.TYPESCRIPT,
            ".py": Lang.PYTHON,
            ".java": Lang.JAVA,
            ".php": Lang.PHP,
            ".rb": Lang.RUBY,
            ".go": Lang.GO,
            ".rs": Lang.RUST,
            ".cpp": Lang.CPP,
            ".cxx": Lang.CPP,
            ".cc": Lang.CPP,
            ".c": Lang.C,
            ".h": Lang.C,
            ".hpp": Lang.CPP,
            ".cs": Lang.C_SHARP,
            ".scala": Lang.SCALA,
            ".kt": Lang.KOTLIN,
            ".swift": Lang.SWIFT,
            ".dart": Lang.DART,
        }
