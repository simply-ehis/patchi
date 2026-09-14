"""Test-name / assertion extraction as comprehension evidence (Item 21).

Scans a list of FileInfo objects and extracts evidence that the project
has tests: test function names and the assertion calls they contain.
This is pure Tier-1 extraction — no AI calls, just AST (Python) and
regex (JS/TS) parsing of existing scan data.

Usage:
    from patchi.core.brain.scanner import FileScanner
    from patchi.core.brain.test_evidence import build_test_evidence

    scanner = FileScanner(root)
    files = scanner.scan()
    evidence = build_test_evidence(files)
"""

from __future__ import annotations

import ast as py_ast
import re
from dataclasses import dataclass, field
from typing import Any

from patchi.core.brain.languages import Lang
from patchi.core.brain.scanner import FileInfo

# ── Test-framework import fingerprints ─────────────────────────────────────────

_PYTHON_TEST_IMPORTS = frozenset(
    {
        "pytest",
        "unittest",
        "nose",
        "nose.tools",
    }
)

_JS_TEST_IMPORTS = frozenset(
    {
        "jest",
        "vitest",
        "mocha",
        "chai",
        "assert",
    }
)

# ── Python assertion function names (inside unittest / pytest) ────────────────

_PYTHON_ASSERT_CALLS = frozenset(
    {
        "assert_",
        "assertEqual",
        "assertNotEqual",
        "assertTrue",
        "assertFalse",
        "assertIs",
        "assertIsNot",
        "assertIsNone",
        "assertIsNotNone",
        "assertIn",
        "assertNotIn",
        "assertIsInstance",
        "assertNotIsInstance",
        "assertAlmostEqual",
        "assertNotAlmostEqual",
        "assertGreater",
        "assertGreaterEqual",
        "assertLess",
        "assertLessEqual",
        "assertRegex",
        "assertNotRegex",
        "assertCountEqual",
        "assertDictContainsSubset",
        "assertMultiLineEqual",
        "assertListEqual",
        "assertTupleEqual",
        "assertSetEqual",
        "assertWarns",
        "assertWarnsRegex",
        "assertRaises",
        "assertRaisesRegex",
        "fail",
        "assert_called_once",
        "assert_called_with",
        "assert_called_once_with",
        "assert_not_called",
        "assert_any_call",
        "assert_has_calls",
        "assert_called",
        "assertLogs",
        "assertNoLogs",
    }
)

# Also bare assert is valid Python — we detect it as a keyword, not a call.

_JS_ASSERT_CALLS = re.compile(
    r"""
    \b(?:expect|assert|should|assertEqual|assertEquals|assertNotNull|
       assertNull|assertTrue|assertFalse|toBe|toEqual|toMatch|toContain|
       toHaveLength|toThrow|toStrictEqual|toBeUndefined|toBeDefined|
       toBeFalsy|toBeTruthy|toBeGreaterThan|toBeGreaterThanOrEqual|
       toBeLessThan|toBeLessThanOrEqual|toBeCloseTo|toHaveProperty|
       toHaveBeenCalled|toHaveLength|toBeInstanceOf)\s*\(
    """,
    re.VERBOSE | re.DOTALL,
)


# ── Data model ─────────────────────────────────────────────────────────────────


@dataclass
class TestEvidence:
    """One test function with its extracted assertions."""

    file: str  # relative path from project root
    test_name: str
    assertions: list[str] = field(default_factory=list)
    evidence_type: str = "test"  # always "test" — reserved for future sub-types

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "file": self.file,
            "test_name": self.test_name,
            "evidence_type": self.evidence_type,
        }
        if self.assertions:
            d["assertions"] = self.assertions
        return d


@dataclass
class TestEvidenceCollection:
    """Full test-evidence extraction for a project."""

    entries: list[TestEvidence] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def unique_assertions(self) -> int:
        seen: set[str] = set()
        for e in self.entries:
            seen.update(e.assertions)
        return len(seen)

    def to_dict(self) -> dict:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "total": self.total,
            "unique_assertions": self.unique_assertions,
        }

    def summary(self) -> str:
        if not self.entries:
            return "No test evidence found"
        return (
            f"{self.total} test functions, "
            f"{self.unique_assertions} unique assertion types"
        )


# ── Test-file detection ────────────────────────────────────────────────────────

_TEST_DIR_NAMES = frozenset(
    {
        "tests",
        "test",
        "__tests__",
        "spec",
        "specs",
        "test_units",
        "unittests",
    }
)


def _is_test_file(fi: FileInfo) -> bool:
    """Return True if a FileInfo looks like a test file.

    Two signals, checked in order:
      1. Path contains a known test directory segment.
      2. Imports include a test framework.
    """
    parts = fi.path.replace("\\", "/").split("/")
    if any(p.lower() in _TEST_DIR_NAMES for p in parts):
        return True

    lower_imports = {(imp.source or "").lower() for imp in (fi.imports or [])}
    # Check top-level module name for each import (e.g. "from pytest import ..."
    # has source="pytest", but "import unittest.mock" has source="unittest.mock")
    for src in lower_imports:
        top = src.split(".")[0]
        if top in _PYTHON_TEST_IMPORTS or top in _JS_TEST_IMPORTS:
            return True
    return False


def _has_test_framework_import(fi: FileInfo) -> bool:
    """Quick check: does any import look like a test framework?"""
    for imp in fi.imports or []:
        top = (imp.source or "").lower().split(".")[0]
        if top in _PYTHON_TEST_IMPORTS or top in _JS_TEST_IMPORTS:
            return True
    return False


# ── Python extraction (AST) ────────────────────────────────────────────────────


def _extract_python_tests(fi: FileInfo) -> list[TestEvidence]:
    """Walk the AST of a Python file and pull test functions + assertions."""
    results: list[TestEvidence] = []
    source = _read_source(fi)
    if source is None:
        return results

    try:
        tree = py_ast.parse(source, type_comments=False)
    except SyntaxError:
        return results

    for node in py_ast.walk(tree):
        if not isinstance(node, (py_ast.FunctionDef, py_ast.AsyncFunctionDef)):
            continue
        if not _is_py_test_func(node):
            continue

        assertions = _py_assertions_in_func(node)
        results.append(
            TestEvidence(
                file=fi.path,
                test_name=node.name,
                assertions=assertions,
            )
        )
    return results


def _is_py_test_func(node: py_ast.FunctionDef | py_ast.AsyncFunctionDef) -> bool:
    """True if the function name signals a test case."""
    name = node.name
    if name.startswith("test_") or name.endswith("_test"):
        return True
    # unittest-style: method inside a TestCase subclass (heuristic: name starts with test)
    # We rely on the name convention — class inheritance check is too expensive
    # without full project context.
    return False


def _py_assertions_in_func(
    node: py_ast.FunctionDef | py_ast.AsyncFunctionDef,
) -> list[str]:
    """Collect assertion calls inside a test function body."""
    found: list[str] = []
    for child in py_ast.walk(node):
        # self.assertXxx(...) or assertEqual(...)
        if isinstance(child, py_ast.Call):
            func_name = _py_call_name(child)
            if func_name and func_name in _PYTHON_ASSERT_CALLS:
                if func_name not in found:
                    found.append(func_name)
        # bare assert statement
        elif isinstance(child, py_ast.Assert):
            if "assert" not in found:
                found.append("assert")
    return found


def _py_call_name(node: py_ast.Call) -> str | None:
    """Return the dotted name of a Call node (e.g. 'self.assertEqual')."""
    func = node.func
    if isinstance(func, py_ast.Name):
        return func.id
    if isinstance(func, py_ast.Attribute):
        parts = [func.attr]
        value = func.value
        while isinstance(value, py_ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, py_ast.Name):
            parts.append(value.id)
        parts.reverse()
        return ".".join(parts)
    return None


# ── JS / TS extraction (regex) ─────────────────────────────────────────────────

_JS_TEST_FUNC_RE = re.compile(
    r"""
    (?:^|\s)                          # start or whitespace
    (?:it|test|spec)\s*\(             # it( / test( / spec(
    \s*['"`]                          # opening quote
    ([^'"`]+)                         # test name
    """,
    re.VERBOSE | re.MULTILINE,
)

_JS_DESCRIBE_RE = re.compile(
    r"""
    (?:^|\s)
    describe\s*\(
    \s*['"`]
    ([^'"`]+)
    """,
    re.VERBOSE | re.MULTILINE,
)


def _extract_js_ts_tests(fi: FileInfo) -> list[TestEvidence]:
    """Regex extraction of JS/TS test names and assertion calls."""
    results: list[TestEvidence] = []
    source = _read_source(fi)
    if source is None:
        return results

    for m in _JS_TEST_FUNC_RE.finditer(source):
        test_name = m.group(1)
        assertions = _js_assertions_near(source, m.start())
        results.append(
            TestEvidence(
                file=fi.path,
                test_name=test_name,
                assertions=assertions,
            )
        )
    return results


def _js_assertions_near(source: str, start: int) -> list[str]:
    """Find assertion-style calls near a given offset (within ~2KB window)."""
    window = source[start : start + 2048]
    found: list[str] = []
    for m in _JS_ASSERT_CALLS.finditer(window):
        name = m.group(1).strip()
        if name and name not in found:
            found.append(name)
    return found


# ── Helpers ────────────────────────────────────────────────────────────────────


def _read_source(fi: FileInfo) -> str | None:
    """Read source from disk given a FileInfo.

    The scanner stores relative paths — callers are expected to provide
    file_infos rooted at the same project.  We use the path as-is and
    rely on the caller working directory.
    """
    from pathlib import Path

    # Best-effort: try the path relative to cwd
    try:
        return Path(fi.path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ── Public API ─────────────────────────────────────────────────────────────────


def build_test_evidence(
    file_infos: list[Any] | None = None,
) -> TestEvidenceCollection:
    """Extract test evidence from a list of FileInfo objects.

    Parameters
    ----------
    file_infos:
        Parsed FileInfo list from ``FileScanner.scan()``.  Only files
        identified as test files (by path or imports) are processed.

    Returns
    -------
    TestEvidenceCollection
        Aggregated test function names and assertion calls.
    """
    collection = TestEvidenceCollection()

    if not file_infos:
        return collection

    for fi in file_infos:
        if not _is_test_file(fi):
            continue

        lang = getattr(fi, "language", Lang.UNKNOWN)
        if lang == Lang.PYTHON:
            collection.entries.extend(_extract_python_tests(fi))
        elif lang in (Lang.JAVASCRIPT, Lang.TYPESCRIPT):
            collection.entries.extend(_extract_js_ts_tests(fi))
        # Other languages: extend with regex parsers as needed.

    return collection
