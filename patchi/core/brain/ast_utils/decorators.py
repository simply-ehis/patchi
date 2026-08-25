"""
AST utilities — decorator/annotation finding across languages.
"""

from __future__ import annotations

import ast as _py_ast
import logging
from typing import Any

from patchi.core.brain.languages import Lang, get_parser

from .config import DECORATOR_NODE_TYPES
from .helpers import child_by_field, children, node_text

_log = logging.getLogger("patchi.brain.decorators")

def find_decorators(content: str, lang: Lang, names: set[str]) -> list[dict]:
    """
    Find all decorators/annotations matching one of `names`.
    Returns list of dicts with keys: name, line, full_text.
    """
    if lang == Lang.PYTHON:
        return _find_decorators_python(content, names)
    parser = get_parser(lang)
    if not parser:
        return []
    try:
        tree = parser.parse(content.encode("utf-8"))
    except Exception as e:
        _log.warning("find_decorators failed: %s", e)
        return []
    dec_types = DECORATOR_NODE_TYPES.get(lang, set())
    results: list[dict] = []
    _walk_decorators(tree.root_node, dec_types, names, results)
    return results


def _find_decorators_python(content: str, names: set[str]) -> list[dict]:
    results: list[dict] = []
    try:
        tree = _py_ast.parse(content)
    except SyntaxError:
        return results
    for node in _py_ast.walk(tree):
        if isinstance(node, (_py_ast.FunctionDef, _py_ast.AsyncFunctionDef, _py_ast.ClassDef)):
            for dec in node.decorator_list:
                dec_name = _py_decorator_name(dec)
                if dec_name in names:
                    results.append({
                        "name": dec_name,
                        "line": getattr(dec, "lineno", getattr(node, "lineno", 0)),
                        "full_text": _ast_text(dec, content) if content else "",
                    })
    return results


def _ast_text(node: _py_ast.AST, source: str) -> str:
    try:
        lines = source.splitlines()
        start = getattr(node, "lineno", 1) - 1
        end = getattr(node, "end_lineno", start + 1) - 1
        return "\n".join(lines[start:end + 1])
    except Exception as e:
        _log.debug("_ast_text failed: %s", e)
        return ""


def _py_decorator_name(node: _py_ast.AST) -> str:
    if isinstance(node, _py_ast.Name):
        return node.id
    if isinstance(node, _py_ast.Attribute):
        return node.attr
    if isinstance(node, _py_ast.Call):
        return _py_decorator_name(node.func)
    return ""


def _walk_decorators(node: Any, dec_types: set[str], names: set[str], results: list[dict]) -> None:
    try:
        ntype = node.type if hasattr(node, "type") else ""
    except Exception as e:
        _log.warning("_walk_decorators failed: %s", e)
        return

    if ntype in dec_types:
        name_node = child_by_field(node, "name") or child_by_field(node, "type")
        if name_node:
            dec_name = node_text(name_node)
            if any(n in dec_name.lower() for n in names):
                try:
                    line = node.start_point[0] + 1 if node.start_point else 0
                except Exception as e:
                    _log.warning("_walk_decorators failed: %s", e)
                    line = 0
                results.append({
                    "name": dec_name,
                    "line": line,
                    "full_text": node_text(node),
                })

    for child in children(node):
        _walk_decorators(child, dec_types, names, results)
