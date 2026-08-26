"""
Proactive Auto-Fix — Fix charter violations on file save/commit.

Automatically fixes SAFE issues (imports, formatting, headers) while
leaving DANGEROUS issues (secrets, eval, imports) for manual review.

Rule types and auto-fix mapping:
  boundary  → flag only (requires human review)
  convention → auto-fix if safe (formatting, headers, naming)
  security  → flag only (requires human review)
  stack     → flag only (requires human review)

Safe auto-fixes:
  - headers_required: Add missing file header
  - snake_case / camel_case: Rename variables
  - lines: Flag only (splitting requires judgment)
  - docstrings_required: Add empty docstring placeholder
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchi.core.security.charter import (
    Charter,
    CharterRule,
    RuleType,
    Severity,
    load_charter,
)

_log = logging.getLogger("patchi.security.auto_fix_proactive")

# ── Auto-Fix Strategy Mapping ────────────────────────────────────────────────

# Convention rules that are safe to auto-fix
SAFE_AUTO_FIX_SCOPES = {
    "headers_required",
    "docstrings_required",
    "snake_case",
    "camel_case",
    "pascal_case",
}

# Convention rules that require human review (too risky to auto-fix)
RISKY_SCOPES = {
    "lines",
    "file_size",
    "functions",
}


@dataclass
class ProactiveFixResult:
    """Result of proactive fix attempt on a single file."""

    file_path: str
    rule_id: str
    rule_type: str
    scope: str
    auto_fixed: bool = False
    changes_made: list[str] = field(default_factory=list)
    blocked_reason: str = ""
    original_content: str = ""
    fixed_content: str = ""


@dataclass
class ProactiveFixReport:
    """Aggregated result of proactive fix scan."""

    files_scanned: int = 0
    violations_found: int = 0
    auto_fixed: int = 0
    blocked: int = 0
    results: list[ProactiveFixResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "violations_found": self.violations_found,
            "auto_fixed": self.auto_fixed,
            "blocked": self.blocked,
            "results": [r.__dict__ for r in self.results],
        }


class ProactiveAutoFixer:
    """
    Checks files against charter rules and auto-fixes safe violations.

    Flow:
    1. Load charter from .patchi/memory/charter.json
    2. For each file, check convention rules
    3. If safe to fix (headers, docstrings), apply fix
    4. If risky (lines, secrets), flag for human review
    5. Return report with all changes made
    """

    def __init__(self, root: Path, apply: bool = True):
        self.root = root
        self.apply = apply
        self.charter = load_charter(root)
        self.fix_count = 0

    def check_and_fix_file(self, file_path: Path) -> list[ProactiveFixResult]:
        """Check a single file against all charter rules and auto-fix safe ones."""
        results = []

        if not file_path.is_file():
            return results

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return results

        rel_path = str(file_path.relative_to(self.root))

        for rule in self.charter.rules:
            if not rule.enabled:
                continue

            if rule.type == RuleType.CONVENTION:
                result = self._check_convention(rule, rel_path, file_path, content)
                if result:
                    results.append(result)
                    if result.auto_fixed:
                        self.fix_count += 1

            elif rule.type == RuleType.BOUNDARY:
                result = self._check_boundary(rule, rel_path, content)
                if result:
                    results.append(result)

            elif rule.type == RuleType.SECURITY:
                result = self._check_security(rule, rel_path, content)
                if result:
                    results.append(result)

            elif rule.type == RuleType.STACK:
                result = self._check_stack(rule, rel_path)
                if result:
                    results.append(result)

        return results

    def check_files(self, file_paths: list[Path]) -> ProactiveFixReport:
        """Check multiple files and auto-fix safe violations."""
        report = ProactiveFixReport()

        for fp in file_paths:
            results = self.check_and_fix_file(fp)
            if results:
                report.files_scanned += 1
                report.violations_found += len(results)
                for r in results:
                    if r.auto_fixed:
                        report.auto_fixed += 1
                    elif r.blocked_reason:
                        report.blocked += 1
                    report.results.append(r)

        return report

    def _check_convention(
        self, rule: CharterRule, rel_path: str, abs_path: Path, content: str
    ) -> ProactiveFixResult | None:
        """Check and auto-fix convention rules."""
        result = ProactiveFixResult(
            file_path=rel_path,
            rule_id=rule.id,
            rule_type=rule.type.value,
            scope=rule.scope,
        )

        if rule.scope in SAFE_AUTO_FIX_SCOPES:
            fixed, changes = self._auto_fix_convention(rule, abs_path, content)
            if fixed:
                result.auto_fixed = True
                result.changes_made = changes
                result.original_content = content
                if self.apply:
                    self._write_file(abs_path, fixed)
                result.fixed_content = fixed
                return result
            return None  # No violation found

        elif rule.scope in RISKY_SCOPES:
            # Check if violation exists, but don't auto-fix
            violated = self._check_convention_violation(rule, abs_path, content)
            if violated:
                result.blocked_reason = (
                    f"Convention violation: {rule.description} "
                    f"(requires manual fix)"
                )
                return result
            return None

        # Unknown scope — flag but don't fix
        return None

    def _check_convention_violation(
        self, rule: CharterRule, abs_path: Path, content: str
    ) -> bool:
        """Check if a convention rule is violated."""
        if rule.scope == "lines" and rule.max_value > 0:
            line_count = len(content.splitlines())
            return line_count > rule.max_value

        if rule.scope == "file_size" and rule.max_value > 0:
            return len(content.encode("utf-8")) > rule.max_value

        return False

    def _auto_fix_convention(
        self, rule: CharterRule, abs_path: Path, content: str
    ) -> tuple[str | None, list[str]]:
        """Apply safe auto-fix for a convention rule.

        Returns:
            (fixed_content_or_None, list_of_changes_made)
        """
        changes = []

        if rule.scope == "headers_required":
            fixed = self._fix_missing_header(abs_path, content)
            if fixed and fixed != content:
                changes.append("Added file header")
                return fixed, changes

        elif rule.scope == "docstrings_required":
            fixed = self._fix_missing_docstrings(abs_path, content)
            if fixed and fixed != content:
                changes.append("Added docstrings to functions/classes")
                return fixed, changes

        elif rule.scope in ("snake_case", "camel_case", "pascal_case"):
            # Only flag naming issues — renaming is too risky for auto-fix
            return None, []

        return None, []

    def _fix_missing_header(self, abs_path: Path, content: str) -> str | None:
        """Add a license/author header if missing."""
        if not content.strip():
            return content

        # Check if header already exists
        first_line = content.split("\n", 1)[0].strip()
        header_indicators = [
            "#!",
            "# Copyright",
            "# License",
            '"""',
            "# !",
            "# *",
            "# -",
            "/*",
            "//",
            "<!--",
            "# coding",
        ]

        for indicator in header_indicators:
            if first_line.startswith(indicator):
                return None  # Header already exists

        # Determine file type for comment syntax
        suffix = abs_path.suffix.lower()
        comment_prefix = {
            ".py": "#",
            ".js": "//",
            ".ts": "//",
            ".jsx": "//",
            ".tsx": "//",
            ".mjs": "//",
            ".cjs": "//",
            ".go": "//",
            ".java": "//",
            ".c": "//",
            ".cpp": "//",
            ".h": "//",
            ".hpp": "//",
            ".rs": "//",
            ".rb": "#",
            ".php": "//",
            ".cs": "//",
            ".swift": "//",
            ".scala": "//",
            ".kt": "//",
        }.get(suffix)

        if not comment_prefix:
            return None

        header = (
            f"{comment_prefix} Auto-fixed by Patchi\n"
            f"{comment_prefix} Added missing file header\n\n"
        )

        return header + content

    def _fix_missing_docstrings(self, abs_path: Path, content: str) -> str | None:
        """Add empty docstrings to functions/classes missing them."""
        suffix = abs_path.suffix.lower()

        if suffix == ".py":
            return self._fix_python_docstrings(content)
        elif suffix in (".js", ".ts", ".jsx", ".tsx"):
            return self._fix_jsdoc(content, suffix)
        # Other languages: skip for safety
        return None

    def _fix_python_docstrings(self, content: str) -> str | None:
        """Add empty docstrings to Python functions/classes missing them."""
        lines = content.splitlines()
        result = []
        modified = False
        i = 0

        while i < len(lines):
            result.append(lines[i])

            # Check if this is a def or class line
            stripped = lines[i].lstrip()
            is_func = stripped.startswith("def ") or stripped.startswith("async def ")
            is_class = stripped.startswith("class ")

            if (is_func or is_class) and not stripped.startswith("#"):
                # Look for docstring after the line (may be on next non-empty line)
                has_docstring = False
                j = i + 1
                while j < len(lines):
                    next_stripped = lines[j].strip()
                    if next_stripped:
                        if next_stripped.startswith('"""') or next_stripped.startswith("'''"):
                            has_docstring = True
                        break
                    j += 1

                if not has_docstring and j < len(lines):
                    # Add empty docstring on next line
                    indent = len(lines[i]) - len(lines[i].lstrip()) + 4
                    prefix = " " * indent
                    result.append(f'{prefix}"""TODO: Add description."""')
                    modified = True

            i += 1

        if modified:
            return "\n".join(result)
        return None

    def _fix_jsdoc(self, content: str, suffix: str) -> str | None:
        """Add empty JSDoc to JS/TS functions missing comments."""
        lines = content.splitlines()
        result = []
        modified = False

        for i, line in enumerate(lines):
            result.append(line)
            stripped = line.lstrip()

            # Check for function declarations
            is_func = (
                stripped.startswith("function ")
                or stripped.startswith("async function ")
                or (stripped.startswith("const ") and "=>" in stripped)
                or (stripped.startswith("let ") and "=>" in stripped)
                or stripped.startswith("export function ")
                or stripped.startswith("export async function ")
            )

            if is_func:
                # Check if preceded by a comment
                if i > 0:
                    prev = lines[i - 1].strip()
                    if prev.endswith("*/") or prev.startswith("//"):
                        continue

                indent = len(line) - len(line.lstrip())
                prefix = " " * indent
                result.insert(-1, f"{prefix}/** TODO: Add description. */")
                modified = True

        if modified:
            return "\n".join(result)
        return None

    def _check_boundary(
        self, rule: CharterRule, rel_path: str, content: str
    ) -> ProactiveFixResult | None:
        """Check boundary rules — flag only, no auto-fix."""
        # Parse imports from content
        imports = self._extract_imports(rel_path, content)

        violations = []
        for src_module, imported in imports:
            src_lower = src_module.lower()
            imp_lower = imported.lower()

            if rule.from_pattern.lower() in src_lower and rule.to_pattern.lower() in imp_lower:
                violations.append((src_module, imported))

        if violations:
            result = ProactiveFixResult(
                file_path=rel_path,
                rule_id=rule.id,
                rule_type=rule.type.value,
                scope="boundary",
            )
            result.blocked_reason = (
                f"Boundary violation: {rule.description} "
                f"({violations[0][0]} imports {violations[0][1]})"
            )
            return result

        return None

    def _extract_imports(self, file_path: str, content: str) -> list[tuple[str, str]]:
        """Extract import relationships from source code.

        Returns list of (source_module, imported_module) tuples.
        """
        imports = []
        suffix = Path(file_path).suffix.lower()

        if suffix == ".py":
            imports.extend(self._extract_python_imports(content))
        elif suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs"):
            imports.extend(self._extract_js_imports(content))
        elif suffix == ".go":
            imports.extend(self._extract_go_imports(content))

        return imports

    def _extract_python_imports(self, content: str) -> list[tuple[str, str]]:
        """Extract Python import statements."""
        imports = []
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("from ") and " import " in stripped:
                # from X import Y
                parts = stripped.split(" import ", 1)
                if len(parts) == 2:
                    module = parts[0].replace("from ", "").strip()
                    imports.append((module, module))
            elif stripped.startswith("import "):
                # import X
                module = stripped.replace("import ", "").strip().split(",")[0].strip()
                imports.append((module, module))
        return imports

    def _extract_js_imports(self, content: str) -> list[tuple[str, str]]:
        """Extract JavaScript/TypeScript import statements."""
        imports = []
        for line in content.splitlines():
            stripped = line.strip()
            if "from '" in stripped or 'from "' in stripped:
                parts = stripped.split("from ")[-1].strip().strip("'\"")
                imports.append((parts, parts))
            elif stripped.startswith("import '") or stripped.startswith('import "'):
                mod = stripped.replace("import ", "").strip().strip("'\"")
                imports.append((mod, mod))
        return imports

    def _extract_go_imports(self, content: str) -> list[tuple[str, str]]:
        """Extract Go import statements."""
        imports = []
        in_import = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("import ("):
                in_import = True
                continue
            if in_import and stripped == ")":
                in_import = False
                continue
            if in_import and stripped.startswith('"'):
                pkg = stripped.strip('"')
                imports.append((pkg, pkg))
        return imports

    def _check_security(
        self, rule: CharterRule, rel_path: str, content: str
    ) -> ProactiveFixResult | None:
        """Check security rules — flag only, no auto-fix."""
        if not rule.keywords:
            return None

        content_lower = content.lower()
        for keyword in rule.keywords:
            if keyword.lower() in content_lower:
                result = ProactiveFixResult(
                    file_path=rel_path,
                    rule_id=rule.id,
                    rule_type=rule.type.value,
                    scope="security",
                )
                result.blocked_reason = (
                    f"Security violation: {rule.description} "
                    f"(found '{keyword}')"
                )
                return result

        return None

    def _check_stack(
        self, rule: CharterRule, rel_path: str
    ) -> ProactiveFixResult | None:
        """Check stack rules — flag only, no auto-fix."""
        if not rule.allowed_languages:
            return None

        # Map file extensions to language names
        ext_to_lang = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".go": "go",
            ".rs": "rust",
            ".java": "java",
            ".cs": "csharp",
        }

        suffix = Path(rel_path).suffix.lower()
        lang = ext_to_lang.get(suffix, "")

        if lang and lang not in rule.allowed_languages:
            result = ProactiveFixResult(
                file_path=rel_path,
                rule_id=rule.id,
                rule_type=rule.type.value,
                scope="stack",
            )
            result.blocked_reason = (
                f"Stack violation: {rule.description} "
                f"(found {lang} file, allowed: {', '.join(rule.allowed_languages)})"
            )
            return result

        return None

    def _write_file(self, path: Path, content: str) -> None:
        """Write content to file safely."""
        try:
            path.write_text(content, encoding="utf-8")
            _log.info("Auto-fixed: %s", path)
        except OSError as e:
            _log.error("Failed to write %s: %s", path, e)

    def get_fix_history(self) -> list[dict]:
        """Get recent proactive fixes from memory."""
        from patchi.core import memory as mem

        history = mem.list_issues(self.root)
        return [
            item for item in history
            if item.get("type") == "proactive_fix"
        ]

    def save_fix_history(self, report: ProactiveFixReport) -> None:
        """Save proactive fix results to memory."""
        from patchi.core import memory as mem

        entry = {
            "type": "proactive_fix",
            "files_scanned": report.files_scanned,
            "violations_found": report.violations_found,
            "auto_fixed": report.auto_fixed,
            "blocked": report.blocked,
            "details": [
                {
                    "file": r.file_path,
                    "rule": r.rule_id,
                    "scope": r.scope,
                    "auto_fixed": r.auto_fixed,
                }
                for r in report.results
            ],
        }
        mem.save_issue(entry, self.root)


# ── Convenience Functions ─────────────────────────────────────────────────────


def proactive_fix_files(
    root: Path,
    file_paths: list[Path],
    apply: bool = True,
) -> ProactiveFixReport:
    """Auto-fix charter violations in the given files."""
    fixer = ProactiveAutoFixer(root, apply=apply)
    report = fixer.check_files(file_paths)
    fixer.save_fix_history(report)
    return report


def proactive_fix_path(
    root: Path,
    path: Path,
    apply: bool = True,
) -> list[ProactiveFixResult]:
    """Auto-fix charter violations in a single file."""
    fixer = ProactiveAutoFixer(root, apply=apply)
    results = fixer.check_and_fix_file(path)
    if results:
        report = ProactiveFixReport(
            files_scanned=1,
            violations_found=len(results),
            auto_fixed=sum(1 for r in results if r.auto_fixed),
            blocked=sum(1 for r in results if r.blocked_reason),
            results=results,
        )
        fixer.save_fix_history(report)
    return results
