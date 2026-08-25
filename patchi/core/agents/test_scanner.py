"""
TestScanner — test file discovery, coverage mapping.

Scans for test files and maps which source files they cover:
- Jest/React (test.js, test.jsx, spec.js, spec.jsx, *.test.*, *.spec.*)
- PyTest/Python (test_*.py, *_test.py, test/*.py)
- JUnit/Java (Test*.java, *Test.java)
- PHPUnit/PHP (Test*.php, *Test.php)
- RSpec/Ruby (*_spec.rb, spec/*.rb)

Maps test → source relationships and identifies uncovered files.

Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

_log = logging.getLogger("patchi.agents.test_scanner")


@register
class TestScanner(BaseAgent):
    """Scanner for test files and coverage mapping."""

    group = AgentGroup.SCANNER
    name = "TestScanner"
    description = "Test file discovery, coverage mapping"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan for test files and map coverage."""
        findings = []

        # Define test file patterns
        test_patterns = [
            # JavaScript/TypeScript
            "*test*.js",
            "*test*.jsx",
            "*test*.ts",
            "*test*.tsx",
            "*spec*.js",
            "*spec*.jsx",
            "*spec*.ts",
            "*spec*.tsx",
            "*.test.js",
            "*.test.jsx",
            "*.test.ts",
            "*.test.tsx",
            "*.spec.js",
            "*.spec.jsx",
            "*.spec.ts",
            "*.spec.tsx",
            "**/test/**",
            "**/__tests__/**",
            "**/tests/**",
            # Python
            "test_*.py",
            "*_test.py",
            "tests/**/*.py",
            "**/test/**/*.py",
            "conftest.py",
            "pytest.ini",
            "tox.ini",
            # Java
            "*Test.java",
            "Test*.java",
            "**/test/**/java/**",
            "**/src/test/**",
            # PHP
            "*Test.php",
            "Test*.php",
            "*Test.php",
            "**/tests/**",
            # Ruby
            "*_spec.rb",
            "spec/**/*.rb",
            "**/spec/**",
            # Go
            "*_test.go",
            # Rust
            "*_test.rs",
            "tests/**/*.rs",
        ]

        # Search for test files
        test_files = set()
        for pattern in test_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        test_files.add(rel_path)

        # Map test files to source files
        test_mappings = self._map_tests_to_source(test_files, inp)

        # Count total test files
        findings.append(
            self._mkf(
                severity=Severity.INFO,
                file="__summary__",
                line_start=0,
                title=f"Test Files Found: {len(test_files)}",
                description=f"Discovered {len(test_files)} test files in project",
                evidence=f"Patterns: {len(test_patterns)} used",
            )
        )

        # Add findings for each test file
        for test_file in sorted(test_files):
            findings.append(
                self._mkf(
                    severity=Severity.INFO,
                    file=test_file,
                    line_start=0,
                    title="Test File",
                    description="Discovered test file",
                    evidence="Test file identified by pattern matching",
                )
            )

        # Add findings for coverage mappings
        for test_file, source_files in test_mappings.items():
            if source_files:
                findings.append(
                    self._mkf(
                        severity=Severity.INFO,
                        file=test_file,
                        line_start=0,
                        title="Covers Source Files",
                        description=f"Test file covers: {', '.join(sorted(source_files)[:3])}{'...' if len(source_files) > 3 else ''}",
                        evidence=f"Covers {len(source_files)} source files",
                    )
                )

        # Identify uncovered source files
        all_source_files = self._find_all_source_files(inp)
        covered_files = set()
        for source_list in test_mappings.values():
            covered_files.update(source_list)

        uncovered_files = all_source_files - covered_files
        for uncovered in sorted(uncovered_files):
            findings.append(
                self._mkf(
                    severity=Severity.MEDIUM,
                    file=uncovered,
                    line_start=0,
                    title="Uncovered Source File",
                    description="Source file has no corresponding test coverage",
                    evidence="Not referenced by any test file",
                )
            )

        # Calculate coverage percentage
        total_sources = len(all_source_files)
        covered_count = len(covered_files)
        coverage_pct = (covered_count / total_sources * 100) if total_sources > 0 else 0

        findings.append(
            self._mkf(
                severity=Severity.INFO,
                file="__coverage__",
                line_start=0,
                title=f"Test Coverage: {coverage_pct:.1f}%",
                description=f"Coverage: {covered_count}/{total_sources} files covered",
                evidence=f"{covered_count} covered, {len(uncovered_files)} uncovered",
            )
        )

        for finding in findings:
            result.add_finding(finding)

        result.data["test_files"] = sorted(test_files)
        result.data["source_files"] = sorted(all_source_files)
        result.data["coverage_pct"] = coverage_pct
        result.data["uncovered_files"] = sorted(uncovered_files)
        result.data["test_files_found"] = len(test_files)
        result.data["covered_files"] = covered_count
        result.data["uncovered_file_count"] = len(uncovered_files)
        result.data["needs_ai"] = False
        result.files_scanned = len(test_files) + len(all_source_files)

    def _mkf(self, *args, **kwargs) -> Finding:
        """Compatibility wrapper for finding construction."""
        if args and isinstance(args[0], Severity):
            severity = args[0]
            file = args[1] if len(args) > 1 else ""
            line_start = args[2] if len(args) > 2 else 0
            title = args[3] if len(args) > 3 else ""
            description = args[4] if len(args) > 4 else ""
            evidence = args[5] if len(args) > 5 else ""
            finding_type = kwargs.pop("finding_type", None) or title.lower().replace(
                " ", "_"
            ).replace(":", "").replace("'", "").replace("-", "_")
            return make_finding(
                self.name,
                finding_type,
                severity,
                file,
                description,
                line=line_start,
                evidence=evidence,
                **kwargs,
            )

        if "severity" in kwargs and ("file" in kwargs or "file_path" in kwargs):
            severity = kwargs.pop("severity")
            file = kwargs.pop("file", kwargs.pop("file_path", ""))
            line_start = kwargs.pop("line_start", kwargs.pop("line", 0))
            title = kwargs.pop("title", "")
            description = kwargs.pop("description", title)
            evidence = kwargs.pop("evidence", "")
            finding_type = kwargs.pop("finding_type", None) or title.lower().replace(
                " ", "_"
            ).replace(":", "").replace("'", "").replace("-", "_")
            return make_finding(
                self.name,
                finding_type,
                severity,
                file,
                description,
                line=line_start,
                evidence=evidence,
                **kwargs,
            )

        return make_finding(*args, **kwargs)

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        # Skip ignored directories (node_modules, .venv, etc.)
        from pathlib import PurePosixPath

        if any(p in DEFAULT_IGNORE_DIRS for p in PurePosixPath(file_path).parts):
            return True

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

    def _map_tests_to_source(self, test_files: set[str], inp: AgentInput) -> dict[str, list[str]]:
        """Map test files to the source files they likely cover."""
        mappings = {}

        for test_file in test_files:
            test_path = Path(test_file)
            test_name = test_path.stem.replace(".test", "").replace(".spec", "")

            # Remove common test suffixes/prefixes
            clean_test_name = test_name
            for suffix in ["_test", "test_", "_spec", "spec_"]:
                if clean_test_name.endswith(suffix):
                    clean_test_name = clean_test_name[: -len(suffix)]
                if clean_test_name.startswith(suffix):
                    clean_test_name = clean_test_name[len(suffix) :]

            # Find potential source file matches
            potential_matches = []

            # Look for source file with same name in adjacent directories
            test_dir = test_path.parent
            for ext in [".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".php", ".rb", ".go", ".rs"]:
                # Same directory
                alt_name = test_dir / f"{clean_test_name}{ext}"
                if (inp.root / alt_name).exists():
                    potential_matches.append(str(alt_name))

                # Adjacent src directory
                if "test" in str(test_dir).lower() or "spec" in str(test_dir).lower():
                    # We're in a test directory, look for source in sibling src/ directory
                    parts = test_dir.parts
                    for i, part in enumerate(parts):
                        if part in ["test", "tests", "__tests__", "spec"]:
                            # Try replacing with 'src'
                            new_parts = list(parts)
                            new_parts[i] = "src"
                            src_dir = Path(*new_parts)
                            src_file = src_dir / f"{clean_test_name}{ext}"
                            if (inp.root / src_file).exists():
                                potential_matches.append(str(src_file))

                # Look for source in src directory
                src_alt = (
                    Path("src") / test_path.relative_to(test_dir).parent / f"{clean_test_name}{ext}"
                )
                if (inp.root / src_alt).exists():
                    potential_matches.append(str(src_alt))

            # Also look for imports/requires in the test file that might indicate covered sources
            try:
                test_content_path = inp.root / test_file
                if test_content_path.exists():
                    content = test_content_path.read_text(encoding="utf-8")
                    imported_sources = self._find_imported_sources(content, test_file, inp)
                    potential_matches.extend(imported_sources)
            except Exception as e:
                _log.warning("TestScanner._map_tests_to_source failed: %s", e)

            # Remove duplicates and filter to actual existing files
            unique_matches = []
            for match in potential_matches:
                if match not in unique_matches and (inp.root / match).exists():
                    unique_matches.append(match)

            mappings[test_file] = unique_matches

        return mappings

    def _find_imported_sources(self, content: str, test_file: str, inp: AgentInput) -> list[str]:
        """Find source files imported by the test file."""
        matches = []
        test_ext = Path(test_file).suffix

        # Different import patterns based on language
        if test_ext in [".js", ".jsx", ".ts", ".tsx"]:
            # JavaScript/TypeScript import patterns
            patterns = [
                r"from\s+['\"](\.{1,2}/[^'\"]+)['\"]",  # ES6 imports
                r"import\s+['\"](\.{1,2}/[^'\"]+)['\"]",  # import statements
                r"require\s*\(\s*['\"](\.{1,2}/[^'\"]+)['\"]\s*\)",  # require calls
                r"require\.resolve\s*\(\s*['\"](\.{1,2}/[^'\"]+)['\"]\s*\)",  # require.resolve
            ]

            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    import_path = match.group(1)
                    # Resolve relative path
                    resolved_path = Path(test_file).parent / import_path
                    resolved_path = resolved_path.resolve().relative_to(inp.root.resolve())
                    source_path = str(resolved_path).replace("\\", "/")

                    # Check if it exists and is not another test file
                    if (inp.root / source_path).exists() and not self._is_test_file(source_path):
                        matches.append(source_path)

        elif test_ext == ".py":
            # Python import patterns
            patterns = [
                r"from\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s+import",  # from x import y
                r"import\s+([a-zA-Z_][a-zA-Z0-9_.]+)",  # import x
                r"from\s+\.{1,2}/?([a-zA-Z_][a-zA-Z0-9_/]+)",  # relative imports
            ]

            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    import_module = match.group(1).replace(".", "/")
                    # Try to convert module name to file path
                    for ext in [".py", ".pyx"]:
                        module_path = f"{import_module}{ext}"
                        if (inp.root / module_path).exists() and not self._is_test_file(
                            module_path
                        ):
                            matches.append(module_path)

        return matches

    def _is_test_file(self, file_path: str) -> bool:
        """Check if a file is a test file."""
        path = Path(file_path)
        stem = path.stem.lower()
        parent_dirs = [part.lower() for part in path.parts]

        # Check if filename contains test/spec patterns
        test_indicators = ["test", "spec"]
        if any(indicator in stem for indicator in test_indicators):
            return True

        # Check if file is in test directories
        if any(test_dir in parent_dirs for test_dir in ["test", "tests", "__tests__", "spec"]):
            return True

        # Check if it's a test file by extension pattern
        if any(
            test_pattern in file_path.lower()
            for test_pattern in ["test.", "spec.", ".test", ".spec"]
        ):
            return True

        return False

    def _find_all_source_files(self, inp: AgentInput) -> set[str]:
        """Find all source files in the project (excluding test files)."""
        source_extensions = {
            ".js",
            ".jsx",
            ".ts",
            ".tsx",  # JavaScript/TypeScript
            ".py",  # Python
            ".java",  # Java
            ".php",  # PHP
            ".rb",  # Ruby
            ".go",  # Go
            ".rs",  # Rust
            ".cpp",
            ".cxx",
            ".cc",
            ".c",
            ".h",
            ".hpp",  # C/C++
            ".cs",  # C#
        }

        all_files = set()

        for ext in source_extensions:
            for file_path in safe_rglob(inp.root, f"*{ext}"):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._is_test_file(rel_path) and not self._should_skip_file(
                        rel_path, inp
                    ):
                        all_files.add(rel_path)

        return all_files
