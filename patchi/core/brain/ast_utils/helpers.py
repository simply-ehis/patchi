"""
AST utilities — generic tree-sitter node helpers.
"""

from __future__ import annotations

import ast as _py_ast
import logging
from typing import Any

from patchi.core.brain.languages import Lang, get_parser

_log = logging.getLogger("patchi.brain.helpers")


def _py_call_name(node: _py_ast.Call) -> str:
    """Full dotted name of a Python ``Call`` node's function.

    Single source of truth shared by ``calls.find_calls`` and the cached
    single-pass scan (``scan.scan_python``) so name resolution can never
    drift between the two.
    """
    if isinstance(node.func, _py_ast.Name):
        return node.func.id
    if isinstance(node.func, _py_ast.Attribute):
        parts = []
        cur = node.func
        while isinstance(cur, _py_ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, _py_ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _py_assign_target_name(node: _py_ast.AST) -> str:
    """Dotted name of a Python assignment target.

    Single source of truth shared by ``assignments.find_assignments`` and the
    cached single-pass scan.
    """
    if isinstance(node, _py_ast.Name):
        return node.id
    if isinstance(node, _py_ast.Attribute):
        parts = []
        cur = node
        while isinstance(cur, _py_ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, _py_ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""

def parse_source(content: str, lang: Lang) -> Any | None:
    """Parse `content` with the tree-sitter parser for `lang`.

    Returns the parse tree (with `.root_node`) or None if no parser is
    available or parsing fails. All languages use tree-sitter so callers
    can walk a uniform node interface.
    """
    parser = get_parser(lang)
    if not parser:
        return None
    try:
        return parser.parse(content.encode("utf-8"))
    except Exception as e:
        _log.debug("parse_source failed: %s", e)
        return None


def node_text(node: Any) -> str:
    try:
        raw = getattr(node, "text", b"")
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)
    except Exception as e:
        _log.debug("node_text failed: %s", e)
        return ""


def child_by_field(node: Any, field: str) -> Any | None:
    if hasattr(node, "child_by_field_name"):
        return node.child_by_field_name(field)
    return None


def children(node: Any) -> list[Any]:
    try:
        return list(node.children) if hasattr(node, "children") else []
    except Exception as e:
        _log.debug("children failed: %s", e)
        return []


def named_children(node: Any) -> list[Any]:
    try:
        return list(node.named_children) if hasattr(node, "named_children") else []
    except Exception as e:
        _log.debug("named_children failed: %s", e)
        return []


def _leaf_name(fn: str) -> str:
    """Extract the leaf symbol from a possibly dotted / scoped name.

    Handles both `.` (Python, JS, Java) and `::` (Rust, C++) separators.
    """
    for sep in (".", "::"):
        if sep in fn:
            return fn.split(sep)[-1]
    return fn


def get_call_arg(call_full_text: str, position: int = 0) -> str:
    """Extract the positional argument at `position` from a call text."""
    try:
        paren = call_full_text.index("(")
        rest = call_full_text[paren + 1:]
        depth = 0
        arg_start = 0
        arg_idx = 0
        for i, ch in enumerate(rest):
            if ch in ("(", "[", "{"):
                depth += 1
            elif ch in (")", "]", "}"):
                depth -= 1
                if depth < 0:
                    if arg_idx == position:
                        return rest[arg_start:i].strip()
                    break
            elif ch == "," and depth == 0:
                if arg_idx == position:
                    return rest[arg_start:i].strip()
                arg_start = i + 1
                arg_idx += 1
        if arg_idx == position:
            return rest[arg_start:].strip().rstrip(")")
    except (ValueError, IndexError):
        pass
    return ""
