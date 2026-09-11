"""
DuplicateScanner — function-level similarity detection.

Scans for duplicated code blocks at the function/method level:
- Identifies functions with high similarity (>85%)
- Finds duplicated logic that should be extracted to shared functions
- Reports duplicate code across files
- Provides similarity scores and locations
"""

from __future__ import annotations

import ast as py_ast
import logging
import re
from pathlib import Path
from typing import Any

from ..brain.languages import (
    DEFAULT_IGNORE_DIRS,
    TREE_SITTER_LANGS,
    Lang,
    detect_language,
    get_parser,
    parse_source,
)
from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    get_shard_files,
    make_finding,
)

_log = logging.getLogger("patchi.agents.duplicate_scanner")


def _ts_node_text(node: Any, buf: bytes) -> str:
    try:
        if hasattr(node, "start_byte") and hasattr(node, "end_byte"):
            return buf[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    except Exception as e:
        _log.debug("_ts_node_text failed: %s", e)
    return ""


def _ts_child_by_field(node: Any, field: str) -> Any | None:
    try:
        return node.child_by_field_name(field) if hasattr(node, "child_by_field_name") else None
    except Exception as e:
        _log.debug("_ts_child_by_field failed: %s", e)
        return None


def _ts_children(node: Any) -> list[Any]:
    try:
        return list(node.children) if hasattr(node, "children") else []
    except Exception as e:
        _log.debug("_ts_children failed: %s", e)
        return []


def _ts_node_type(node: Any) -> str:
    try:
        return node.type if hasattr(node, "type") else ""
    except Exception as e:
        _log.debug("_ts_node_type failed: %s", e)
        return ""


# @register — disabled: duplicate detection is noise in production code.
# Common patterns (getters, setters, framework boilerplate) are intentional,
# not bugs. The agent produced 42k+ false positives on a 1250-file project.
class DuplicateScanner(BaseAgent):
    """Scanner for duplicated code blocks."""

    group = AgentGroup.SCANNER
    name = "DuplicateScanner"
    description = "Repeated logic blocks that should be extracted to shared functions"
    shardable = True
    supported_languages = None

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan for duplicated code blocks."""
        findings = []

        all_source_files = self._find_source_files(inp)

        all_functions = []
        for file_path in all_source_files:
            abs_path = inp.root / file_path
            if not abs_path.exists():
                continue

            try:
                content = abs_path.read_text(encoding="utf-8")
                lang = detect_language(abs_path)

                if lang == Lang.PYTHON:
                    functions = self._extract_python_functions(file_path, content)
                elif lang in [Lang.JAVASCRIPT, Lang.TYPESCRIPT]:
                    functions = self._extract_javascript_functions(file_path, content)
                elif lang in TREE_SITTER_LANGS:
                    functions = self._extract_functions_treesitter(file_path, content, lang)
                else:
                    functions = self._extract_functions_basic(file_path, content)

                all_functions.extend(functions)
            except Exception as e:
                findings.append(
                    make_finding(
                        severity=Severity.LOW,
                        file=file_path,
                        line_start=0,
                        title="Duplicate scanner file read error",
                        description=f"Could not analyze {file_path} for duplicates: {str(e)}",
                        evidence=str(e),
                    )
                )

        duplicate_pairs = self._find_duplicate_functions(all_functions)

        for func1, func2, similarity in duplicate_pairs:
            findings.append(
                make_finding(
                    severity=Severity.MEDIUM,
                    file=func1["file"],
                    line_start=func1["line"],
                    title=f"DUPLICATE CODE: {similarity:.1f}% similar to {func2['file']}:{func2['line']}",
                    description=f"Function '{func1['name']}' is {similarity:.1f}% similar to '{func2['name']}' in {func2['file']}",
                    evidence=f"Similarity: {similarity:.1f}%\nLocation: {func2['file']}:{func2['line']}\nFunction: {func2['name']}",
                )
            )

        # Add summary
        findings.append(
            make_finding(
                severity=Severity.INFO,
                file="__summary__",
                line_start=0,
                title=f"Duplicates Found: {len(duplicate_pairs)} pairs",
                description=f"Found {len(duplicate_pairs)} pairs of duplicate functions",
                evidence=f"From {len(all_functions)} total functions analyzed",
            )
        )

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "duplicate_pairs_found": len(duplicate_pairs),
                "duplicate_pairs": duplicate_pairs,
                "total_functions_analyzed": len(all_functions),
                "functions_scanned": len(all_functions),
                "needs_ai": True,  # Refactoring suggestions require AI
            }
        )
        return

    def _find_source_files(self, inp: AgentInput) -> list[str]:
        """Find all source files to analyze."""
        source_extensions = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".rb",
            ".go", ".rs", ".cpp", ".cxx", ".cc", ".c", ".h", ".hpp", ".cs",
        }

        # Use corpus if available
        corpus = inp.extra.get("file_corpus")
        _MAX_FILES = 500
        if corpus and corpus.entries:
            files = []
            count = 0
            for rel_key in corpus.entries:
                if count >= _MAX_FILES:
                    break
                ext = Path(rel_key).suffix.lower()
                if ext in source_extensions:
                    if not self._should_skip_file(rel_key, inp):
                        files.append(rel_key)
                        count += 1
            return files

        files = []
        for ext in source_extensions:
            for file_path in get_shard_files(inp, f"*{ext}"):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        files.append(rel_path)
        return files

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

    def _extract_python_functions(self, file_path: str, content: str) -> list[dict]:
        """Extract functions from Python code."""
        try:
            tree = py_ast.parse(content)
        except SyntaxError:
            return []

        functions = []

        for node in py_ast.walk(tree):
            if isinstance(node, (py_ast.FunctionDef, py_ast.AsyncFunctionDef)):
                # Get function body
                body_lines = []
                for item in node.body:
                    start_line = item.lineno - 1  # Convert to 0-indexed
                    end_line = getattr(item, "end_lineno", start_line)
                    if end_line <= len(content.splitlines()):
                        body_lines.extend(content.splitlines()[start_line:end_line])

                functions.append(
                    {
                        "file": file_path,
                        "name": node.name,
                        "line": node.lineno,
                        "body": "\n".join(body_lines),
                        "normalized_body": self._normalize_code("\n".join(body_lines)),
                    }
                )

        return functions

    def _extract_javascript_functions(self, file_path: str, content: str) -> list[dict]:
        """Extract functions from JavaScript/TypeScript code."""
        functions = []

        # Pattern for function declarations
        func_pattern = r"(?:function\s+)?(\w+)\s*\([^)]*\)\s*\{([^}]*(?:\{[^}]*}[^}]*)*?)\}"
        matches = re.finditer(func_pattern, content, re.DOTALL)

        for match in matches:
            name = match.group(1)
            body = match.group(2)
            line_start = content[: match.start()].count("\n") + 1

            functions.append(
                {
                    "file": file_path,
                    "name": name,
                    "line": line_start,
                    "body": body,
                    "normalized_body": self._normalize_code(body),
                }
            )

        # Pattern for arrow functions
        arrow_pattern = (
            r"(const|let|var)\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{([^}]*(?:\{[^}]*}[^}]*)*?)\};?"
        )
        arrow_matches = re.finditer(arrow_pattern, content, re.DOTALL)

        for match in arrow_matches:
            name = match.group(2)
            body = match.group(3)
            line_start = content[: match.start()].count("\n") + 1

            functions.append(
                {
                    "file": file_path,
                    "name": name,
                    "line": line_start,
                    "body": body,
                    "normalized_body": self._normalize_code(body),
                }
            )

        return functions

    def _extract_functions_treesitter(self, file_path: str, content: str, lang: Lang) -> list[dict]:
        try:
            # Svelte: extract <script> content and parse as JavaScript
            if lang == Lang.SVELTE:
                return self._extract_svelte_functions(file_path, content)
            parser = get_parser(lang)
            if parser is None:
                return self._extract_functions_basic(file_path, content)
            tree = parse_source(lang, content)
            functions = []
            self._walk_tree_for_functions(tree.root_node, file_path, content, functions, lang)
            return functions
        except Exception as e:
            _log.warning("DuplicateScanner._extract_functions_treesitter failed: %s", e)
            return self._extract_functions_basic(file_path, content)

    def _extract_svelte_functions(self, file_path: str, content: str) -> list[dict]:
        """Extract functions from a Svelte file by parsing its <script> block as JavaScript."""
        import re

        m = re.search(r"<script[^>]*>(.*?)</script>", content, re.DOTALL)
        if not m:
            return self._extract_functions_basic(file_path, content)
        script_src = m.group(1).strip()
        if not script_src:
            return []
        js_parser = get_parser(Lang.JAVASCRIPT)
        if js_parser is None:
            return self._extract_functions_basic(file_path, content)
        tree = parse_source(Lang.JAVASCRIPT, script_src)
        functions = []
        self._walk_tree_for_functions(
            tree.root_node, file_path, script_src, functions, Lang.JAVASCRIPT
        )
        return functions

    def _walk_tree_for_functions(
        self, node, file_path: str, content: str, functions: list[dict], lang: Lang
    ):
        nt = _ts_node_type(node)
        buf = bytes(content, "utf-8")

        # Language-specific function-like node types
        func_types: set[str] = set()
        match lang:
            case Lang.RUST:
                func_types = {"function_item"}
            case Lang.JAVA:
                func_types = {"method_declaration", "constructor_declaration"}
            case Lang.GO:
                func_types = {"function_declaration", "method_declaration"}
            case Lang.C | Lang.CPP:
                func_types = {"function_definition"}
            case Lang.SWIFT:
                func_types = {
                    "function_declaration",
                    "initializer_declaration",
                    "deinitializer_declaration",
                    "subscript_declaration",
                }
            case Lang.RUBY:
                func_types = {"method", "singleton_method"}
            case Lang.PHP:
                func_types = {"function_definition", "method_declaration"}
            case Lang.C_SHARP:
                func_types = {"method_declaration", "constructor_declaration"}
            case Lang.KOTLIN:
                func_types = {"function_declaration", "method_declaration"}
            case Lang.DART:
                func_types = {"function_declaration", "method_declaration"}
            case Lang.JAVASCRIPT | Lang.TYPESCRIPT | Lang.SVELTE:
                func_types = {"function_declaration", "method_definition", "arrow_function"}
            case _:
                func_types = set()

        if nt in func_types:
            if lang == Lang.C or lang == Lang.CPP:
                name = _ts_node_text(self._find_c_identifier(node), buf)
                body = _ts_child_by_field(node, "body")
            elif lang == Lang.GO and nt == "method_declaration":
                name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
                body = _ts_child_by_field(node, "body")
            elif lang == Lang.RUBY:
                name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
                body = next(
                    (c for c in _ts_children(node) if _ts_node_type(c) == "body_statement"), None
                )
            else:
                name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
                body = _ts_child_by_field(node, "body")

            body_text = _ts_node_text(body, buf) if body else ""
            line_start = (node.start_point.row + 1) if hasattr(node, "start_point") else 0

            functions.append(
                {
                    "file": file_path,
                    "name": name or f"<anonymous>:{line_start}",
                    "line": line_start,
                    "body": body_text,
                    "normalized_body": self._normalize_code(body_text),
                }
            )

        for child in _ts_children(node):
            self._walk_tree_for_functions(child, file_path, content, functions, lang)

    def _find_c_identifier(self, func_def_node):
        declarator = _ts_child_by_field(func_def_node, "declarator")
        if declarator is None:
            return func_def_node
        for candidate in [
            _ts_child_by_field(declarator, "declarator"),
            _ts_child_by_field(declarator, "name"),
        ]:
            if candidate is None:
                continue
            ct = _ts_node_type(candidate)
            if ct == "identifier":
                return candidate
            if ct in (
                "function_declarator",
                "pointer_declarator",
                "array_declarator",
                "initializer_pair",
            ):
                found = self._find_c_identifier(candidate)
                if found is not None and _ts_node_type(found) == "identifier":
                    return found
        return None

    def _extract_functions_basic(self, file_path: str, content: str) -> list[dict]:
        """Basic function extraction for unsupported languages."""
        # Very basic approach - look for common function patterns
        import re

        functions = []

        # Generic function pattern
        func_pattern = r"(?:function|def|fun|func)\s+(\w+)([^{]*)\{([^}]*(?:\{[^}]*}[^}]*)*?)\}"
        matches = re.finditer(func_pattern, content, re.DOTALL)

        for match in matches:
            name = match.group(1)
            body = match.group(3)
            line_start = content[: match.start()].count("\n") + 1

            functions.append(
                {
                    "file": file_path,
                    "name": name,
                    "line": line_start,
                    "body": body,
                    "normalized_body": self._normalize_code(body),
                }
            )

        return functions

    def _normalize_code(self, code: str) -> str:
        """Normalize code to remove formatting differences for comparison."""
        # Remove extra whitespace
        normalized = re.sub(r"\s+", " ", code)
        # Remove comments (basic approach)
        normalized = re.sub(r"//.*", "", normalized)  # Single-line comments
        normalized = re.sub(r"/\*.*?\*/", "", normalized, flags=re.DOTALL)  # Multi-line comments
        # Remove strings (basic approach)
        normalized = re.sub(r'"([^"]|"")*"', '""', normalized)  # Double-quoted strings
        normalized = re.sub(r"'([^']|'')*'", "''", normalized)  # Single-quoted strings

        return normalized.strip()

    def _find_duplicate_functions(self, functions: list[dict]) -> list[tuple]:
        """Find pairs of functions that are highly similar (>95% Jaccard).

        Only considers functions with >= 5 lines to avoid trivial short
        helpers (getter/setter boilerplate, one-liner wrappers) that inflate
        counts without indicating real duplication.

        Candidate generation replaces the former O(n²) all-pairs scan:
          * tokenize each normalized body once and tally global token frequency
          * index every function under its ``int(0.26·|S|)+1`` globally-rarest
            tokens (capped at the set size; floor+1 ≥ 0.26·|S| keeps the recall
            bound below, and ties are broken by token string for determinism)
          * any pair with Jaccard > 0.95 shares its rarest *shared* token,
            which is provably a key for BOTH functions (sizes must be within
            1.176× and the intersection exceeds 91.9% of the smaller set, so
            the number of tokens strictly rarer than it is < 0.081·|S| in the
            smaller set and < 0.257·|S| in the larger — both < 0.26·|S|+1),
            so every true duplicate is generated as a candidate — zero false
            negatives
          * candidates are verified with the exact same `_calculate_similarity`
            and 0.95 threshold, and results are re-sorted to the original
            (i, j) enumeration order — output is identical, but sub-quadratic.

        Tradeoff: a common token (e.g. a frequent literal) can be the "rarest"
        token of a tiny function, so one bucket may gather O(m) small functions
        and verify O(m²) candidates. That is wasted-but-correct work; the
        size-ratio pre-filter prunes the worst of it. Output is unaffected.
        """
        n = len(functions)
        if n < 2:
            return []

        # Filter out trivially short functions (< 5 lines) — these are
        # getter/setter boilerplate that inflates duplicate counts.
        MIN_LINES = 5
        filtered = [
            f for f in functions
            if len(f.get("body", "").splitlines()) >= MIN_LINES
        ]
        if len(filtered) < 2:
            return []
        functions = filtered
        n = len(functions)

        # 1. Tokenize each body once + global token frequencies.
        uniq_sets: list[set[str]] = []
        freq: dict[str, int] = {}
        for f in functions:
            us = set(f["normalized_body"].split())
            uniq_sets.append(us)
            for t in us:
                freq[t] = freq.get(t, 0) + 1

        # 2. Index each function under its rarest tokens (guaranteed recall).
        buckets: dict[str, list[int]] = {}
        for i, us in enumerate(uniq_sets):
            if not us:
                continue
            k = min(len(us), int(0.26 * len(us)) + 1)
            # Secondary key (token string) makes tie-breaking deterministic
            # across processes; the recall bound only needs the strict-ranker.
            rarest = sorted(us, key=lambda t: (freq[t], t))[:k]
            for t in rarest:
                buckets.setdefault(t, []).append(i)

        # 3. Collect candidate pairs (deduped across shared buckets).
        seen: set[tuple[int, int]] = set()
        candidates: list[tuple[int, int]] = []
        for idxs in buckets.values():
            m = len(idxs)
            if m < 2:
                continue
            for a in range(m - 1):
                i = idxs[a]
                for b in range(a + 1, m):
                    j = idxs[b]
                    key = (i, j) if i < j else (j, i)
                    if key not in seen:
                        seen.add(key)
                        candidates.append(key)

        # 4. Verify candidates with the exact same metric + threshold.
        results: list[tuple[int, int, float]] = []
        for i, j in candidates:
            si, sj = uniq_sets[i], uniq_sets[j]
            ni, nj = len(si), len(sj)
            if ni == 0 or nj == 0:
                continue
            # Jaccard > 0.95 forces the two set sizes within 1.053× — cheap
            # pre-filter that never excludes a true positive.
            if max(ni, nj) * 100 > min(ni, nj) * 106:
                continue
            similarity = self._calculate_similarity(
                functions[i]["normalized_body"], functions[j]["normalized_body"]
            )
            if similarity > 0.95:
                results.append((i, j, similarity))

        # 5. Restore the original (i, j) enumeration order.
        results.sort()
        return [(functions[i], functions[j], sim * 100) for i, j, sim in results]

    def _calculate_similarity(self, code1: str, code2: str) -> float:
        """Calculate similarity between two code blocks using a simple algorithm."""
        if not code1 or not code2:
            return 0.0

        # If they're exactly equal, return 1.0
        if code1 == code2:
            return 1.0

        # Simple similarity calculation based on common substrings
        # This is a simplified version - in practice, you might want to use
        # more sophisticated algorithms like Levenshtein distance or AST comparison
        set1 = set(code1.split())
        set2 = set(code2.split())

        intersection = set1.intersection(set2)
        union = set1.union(set2)

        if len(union) == 0:
            return 0.0

        return len(intersection) / len(union)
