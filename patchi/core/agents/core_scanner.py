"""
CoreScanner — AST analysis: functions, classes, exports, purpose.

Parses all source files with tree-sitter. Extracts:
- Functions (name, params, line, is_async, decorators)
- Classes (name, base classes, line)
- Exports (named, default, types)
- Entry points (main, app.listen, etc.)
- Purpose (via AI classification per file)

Does NOT call AI (that's the fix agents' job).
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import time
from pathlib import PurePosixPath

from ..brain.languages import (
    DEFAULT_IGNORE_DIRS,
    Lang,
    get_parser,
)
from ..brain.scanner import FileScanner
from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
)


@register
class CoreScanner(BaseAgent):
    """Core scanner for AST analysis of source files."""

    group = AgentGroup.SCANNER
    name = "CoreScanner"
    description = "Main application files: functions, classes, exports, entry points, purpose"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan core application files for structure and purpose.

        Populates `result.data['file_map']` and `result.data['language_breakdown']`.
        Adds `parse_error` findings when parsing fails.
        """
        start_time = time.time()

        corpus = inp.extra.get("file_corpus")
        scanner = FileScanner(root=inp.root, ignore_paths=inp.config.get("ignore_paths", []), corpus=corpus)
        try:
            infos = scanner.scan(area=None, on_progress=None)
        except Exception as e:
            result.add_error(f"FileScanner failed: {e}")
            return

        file_map: dict = {}
        lang_breakdown: dict = {}
        parsed_count = 0

        for info in infos:
            # Skip files per restrictions
            if self._should_skip_file(info.path, inp):
                continue

            parsed_count += 1
            file_map[info.path] = {
                "purpose": info.purpose or "",
                "type": info.language.value,
            }

            lang_breakdown.setdefault(info.language.value, 0)
            lang_breakdown[info.language.value] += 1

            # Report parse errors as findings
            if info.error:
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="parse_error",
                        severity=Severity.LOW,
                        file=info.path,
                        message="Parse error",
                        line=0,
                        detail=info.error,
                    )
                )

        duration = time.time() - start_time

        result.data["file_map"] = file_map
        result.data["language_breakdown"] = lang_breakdown
        result.data["needs_ai"] = True
        result.files_scanned = parsed_count
        result.data["duration"] = round(duration, 2)

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        # Check restrictions
        # Skip ignored directories (node_modules, .venv, etc.)
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

    def _extract_basic_info(self, file_path: str, content: str) -> list[Finding]:
        """Extract basic info for unsupported languages."""
        lines = content.splitlines()
        findings = []

        # Look for common patterns in any text file
        for i, line in enumerate(lines, 1):
            if any(
                keyword in line.lower()
                for keyword in ["entry", "main", "start", "init", "constructor"]
            ):
                findings.append(
                    make_finding(
                        severity=Severity.INFO,
                        file=file_path,
                        line_start=i,
                        title="Potential entry point",
                        description=line.strip(),
                        evidence=line.strip(),
                    )
                )

        return findings

    def _parse_with_treesitter(self, file_path: str, content: str, lang: Lang) -> list[Finding]:
        """Parse file with tree-sitter and extract structured info."""
        try:
            parser, lang_obj = get_parser(lang)
            tree = parser.parse(bytes(content, "utf8"))

            findings = []
            self._walk_tree(tree.root_node, file_path, content, findings, lang)
            return findings
        except Exception as e:
            return [
                make_finding(
                    severity=Severity.LOW,
                    file=file_path,
                    line_start=0,
                    title="Tree-sitter parse error",
                    description=f"Failed to parse with tree-sitter: {str(e)}",
                    evidence=str(e),
                )
            ]

    def _walk_tree(self, node, file_path: str, content: str, findings: list[Finding], lang: Lang):
        """Walk the AST tree and extract relevant nodes."""
        if node.type in ["function_definition", "function", "method_definition"]:
            self._extract_function(node, file_path, content, findings, lang)
        elif node.type in ["class_definition", "class", "class_declaration"]:
            self._extract_class(node, file_path, content, findings, lang)
        elif node.type in ["import_statement", "import_declaration"]:
            self._extract_import(node, file_path, content, findings, lang)
        elif node.type in ["export_statement", "export_declaration"]:
            self._extract_export(node, file_path, content, findings, lang)

        # Recursively walk children
        for child in node.children:
            self._walk_tree(child, file_path, content, findings, lang)

    def _extract_function(
        self, node, file_path: str, content: str, findings: list[Finding], lang: Lang
    ):
        """Extract function information."""
        # Get function name
        name_node = None
        for child in node.children:
            if child.type in ["identifier", "function_name"]:
                name_node = child
                break

        if name_node:
            func_name = content[name_node.start_byte : name_node.end_byte]
            line_no = name_node.start_point[0] + 1

            findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file=file_path,
                    line_start=line_no,
                    title=f"Function: {func_name}",
                    description=f"Defined at line {line_no}",
                    evidence=content[node.start_byte : node.end_byte][:100] + "..."
                    if node.end_byte - node.start_byte > 100
                    else content[node.start_byte : node.end_byte],
                )
            )

    def _extract_class(
        self, node, file_path: str, content: str, findings: list[Finding], lang: Lang
    ):
        """Extract class information."""
        name_node = None
        for child in node.children:
            if child.type in ["identifier", "type_identifier", "class_name"]:
                name_node = child
                break

        if name_node:
            class_name = content[name_node.start_byte : name_node.end_byte]
            line_no = name_node.start_point[0] + 1

            findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file=file_path,
                    line_start=line_no,
                    title=f"Class: {class_name}",
                    description=f"Defined at line {line_no}",
                    evidence=content[node.start_byte : node.end_byte][:100] + "..."
                    if node.end_byte - node.start_byte > 100
                    else content[node.start_byte : node.end_byte],
                )
            )

    def _extract_import(
        self, node, file_path: str, content: str, findings: list[Finding], lang: Lang
    ):
        """Extract import information."""
        import_text = content[node.start_byte : node.end_byte]
        line_no = node.start_point[0] + 1

        findings.append(
            make_finding(
                severity=Severity.INFO,
                file=file_path,
                line_start=line_no,
                title="Import statement",
                description=import_text,
                evidence=import_text,
            )
        )

    def _extract_export(
        self, node, file_path: str, content: str, findings: list[Finding], lang: Lang
    ):
        """Extract export information."""
        export_text = content[node.start_byte : node.end_byte]
        line_no = node.start_point[0] + 1

        findings.append(
            make_finding(
                severity=Severity.INFO,
                file=file_path,
                line_start=line_no,
                title="Export statement",
                description=export_text,
                evidence=export_text,
            )
        )
