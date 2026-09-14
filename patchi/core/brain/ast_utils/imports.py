"""
AST utilities — import statement finding across languages.
"""

from __future__ import annotations

import ast as _py_ast
import logging
from typing import Any

from patchi.core.brain.languages import Lang, get_parser

from .config import IMPORT_NODE_TYPES
from .helpers import child_by_field, children, node_text

_log = logging.getLogger("patchi.brain.imports")


def find_imports(content: str, lang: Lang, names: set[str]) -> list[dict]:
    """
    Find all import statements matching one of `names`.
    Returns list of dicts with keys: name, line, full_text.
    """
    if lang == Lang.PYTHON:
        return _find_imports_python(content, names)
    parser = get_parser(lang)
    if not parser:
        return []
    try:
        tree = parser.parse(content.encode("utf-8"))
    except Exception as e:
        _log.warning("find_imports failed: %s", e)
        return []
    import_types = IMPORT_NODE_TYPES.get(lang, set())
    results: list[dict] = []
    _walk_imports(tree.root_node, import_types, names, results, lang)
    return results


def _find_imports_python(content: str, names: set[str]) -> list[dict]:
    results: list[dict] = []
    try:
        tree = _py_ast.parse(content)
    except SyntaxError:
        return results
    for node in _py_ast.walk(tree):
        if isinstance(node, _py_ast.Import):
            for alias in node.names:
                if alias.name in names:
                    results.append(
                        {
                            "name": alias.name,
                            "line": getattr(node, "lineno", 0),
                            "full_text": _ast_text(node, content),
                        }
                    )
        elif isinstance(node, _py_ast.ImportFrom):
            if node.module and node.module in names:
                results.append(
                    {
                        "name": node.module,
                        "line": getattr(node, "lineno", 0),
                        "full_text": _ast_text(node, content),
                    }
                )
    return results


def _ast_text(node: _py_ast.AST, source: str) -> str:
    try:
        lines = source.splitlines()
        start = getattr(node, "lineno", 1) - 1
        end = getattr(node, "end_lineno", start + 1) - 1
        return "\n".join(lines[start : end + 1])
    except Exception as e:
        _log.debug("_ast_text failed: %s", e)
        return ""


def _walk_imports(node: Any, import_types: set[str], names: set[str], results: list[dict], lang: Lang) -> None:
    try:
        ntype = node.type if hasattr(node, "type") else ""
    except Exception as e:
        _log.warning("_walk_imports failed: %s", e)
        return

    if ntype in import_types:
        imp_name = _extract_import_name(node, lang)
        if imp_name and any(n in imp_name for n in names):
            try:
                line = node.start_point[0] + 1 if node.start_point else 0
            except Exception as e:
                _log.warning("_walk_imports failed: %s", e)
                line = 0
            results.append(
                {
                    "name": imp_name,
                    "line": line,
                    "full_text": node_text(node),
                }
            )

    for child in children(node):
        _walk_imports(child, import_types, names, results, lang)


def _extract_import_name(node: Any, lang: Lang) -> str:
    if lang in (Lang.JAVASCRIPT, Lang.TYPESCRIPT):
        source = child_by_field(node, "source")
        if source:
            return node_text(source).strip("\"'")
        return ""
    if lang in (Lang.RUST, Lang.JAVA, Lang.GO, Lang.SWIFT, Lang.C_SHARP, Lang.KOTLIN, Lang.DART):
        # Try named fields first
        src = child_by_field(node, "source") or child_by_field(node, "name") or child_by_field(node, "alias")
        if src:
            return node_text(src).strip("\"'<>")
        # Walk children for identifier / scoped_identifier / string
        for child in children(node):
            ct = child.type
            if ct == "scoped_identifier":
                return node_text(child)
            if ct in ("identifier", "name"):
                return node_text(child)
            if lang == Lang.GO and ct == "import_spec":
                for c2 in children(child):
                    if c2.type == "interpreted_string_literal":
                        return node_text(c2).strip('"')
            if lang in (Lang.C_SHARP,) and ct == "string_literal":
                return node_text(child).strip("\"'")
            if lang == Lang.C_SHARP and ct == "alias_qualified_name":
                for c2 in children(child):
                    if c2.type == "identifier":
                        return node_text(c2)
        return ""
    if lang in (Lang.C, Lang.CPP):
        for child in children(node):
            if child.type == "string_literal":
                return node_text(child).strip('"<>')
        return ""
    if lang == Lang.RUBY:
        for child in children(node):
            if child.type in ("string", "simple_symbol"):
                return node_text(child).strip("\"':")
            if child.type == "argument_list":
                for c2 in children(child):
                    if c2.type in ("string", "simple_symbol"):
                        return node_text(c2).strip("\"':")
        return ""
    if lang == Lang.PHP:
        name_node = child_by_field(node, "name")
        if name_node:
            return node_text(name_node)
        for child in children(node):
            ct = child.type
            if ct == "namespace_use_clause":
                for c2 in children(child):
                    if c2.type == "qualified_name":
                        return node_text(c2)
            if ct in ("namespace_name", "name", "qualified_name"):
                return node_text(child)
        return ""
    return ""
