"""
AST utilities — variable assignment / declaration finding across languages.

Used by env-var analysis, secret scanning, and taint tracking. Returns the
assigned target name plus the source expression so callers can follow how a
value (e.g. a secret, a user-controlled string) flows into code.
"""

from __future__ import annotations

import logging

from patchi.core.brain.languages import get_parser

from .config import Lang
from .helpers import child_by_field, children, node_text

_log = logging.getLogger("patchi.brain.assignments")

def find_assignments(content: str, lang: Lang) -> list[dict]:
    """
    Find all variable assignments in `content`.

    Returns list of dicts with keys:
        target   — assigned name (str)
        value    — RHS expression text (str)
        line     — 1-based line number (int)
        full_text— full assignment text (str)

    Python is served from the shared single-pass AST scan (one parse + walk
    per file per process, cached).
    """
    if lang == Lang.PYTHON:
        return _find_assignments_python(content)
    parser = get_parser(lang)
    if not parser:
        return []
    try:
        tree = parser.parse(content.encode("utf-8"))
    except Exception as e:
        _log.warning("find_assignments failed: %s", e)
        return []
    results: list[dict] = []
    _walk_assignments(tree.root_node, results, lang)
    return results


# ── Python ────────────────────────────────────────────────────────────────────

def _find_assignments_python(content: str) -> list[dict]:
    """Walk the AST for variable assignments."""
    import ast

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    src_lines = content.splitlines()
    results: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    line_no = node.lineno
                    full_text = src_lines[line_no - 1] if 0 < line_no <= len(src_lines) else ""
                    try:
                        value = ast.unparse(node.value)
                    except Exception:
                        value = ""
                    results.append({
                        "target": target.id,
                        "value": value,
                        "line": line_no,
                        "full_text": full_text,
                    })
    return results


# ── Tree-sitter languages ──────────────────────────────────────────────────────

# Per-language assignment node types
_ASSIGN_NODE_TYPES: dict[Lang, set[str]] = {
    Lang.JAVASCRIPT: {"variable_declarator", "assignment_expression"},
    Lang.TYPESCRIPT: {"variable_declarator", "assignment_expression"},
    Lang.JAVA: {"local_variable_declaration", "assignment_expression"},
    Lang.GO: {"short_var_declaration", "var_declaration", "assignment_statement"},
    Lang.RUST: {"let_declaration", "assignment_expression"},
    Lang.C: {"declaration", "assignment_expression"},
    Lang.CPP: {"declaration", "assignment_expression"},
    Lang.SWIFT: {"variable_declaration"},
    Lang.RUBY: {"assignment"},
    Lang.PHP: {"assignment_expression"},
    Lang.C_SHARP: {"local_declaration_statement", "assignment_expression"},
    Lang.KOTLIN: {"property_declaration", "assignment"},
    Lang.DART: {"variable_declaration"},
}


def _walk_assignments(node: object, results: list[dict], lang: Lang) -> None:
    try:
        ntype = node.type if hasattr(node, "type") else ""
    except Exception as e:
        _log.warning("_walk_assignments failed: %s", e)
        return

    assign_types = _ASSIGN_NODE_TYPES.get(lang, set())
    if ntype in assign_types:
        target, value = _extract_assignment(node, lang)
        if target:
            try:
                line = node.start_point[0] + 1 if node.start_point else 0
            except Exception as e:
                _log.warning("_walk_assignments failed: %s", e)
                line = 0
            results.append({
                "target": target,
                "value": value,
                "line": line,
                "full_text": node_text(node),
            })

    for child in children(node):
        _walk_assignments(child, results, lang)


def _extract_assignment(node: object, lang: Lang) -> tuple[str, str]:
    """Return (target_name, value_text) for an assignment node."""
    if lang in (Lang.JAVASCRIPT, Lang.TYPESCRIPT):
        # variable_declarator: name + value ; assignment_expression: left + right
        if ntype := getattr(node, "type", ""):
            if ntype == "variable_declarator":
                name_node = child_by_field(node, "name")
                val_node = child_by_field(node, "value")
                return node_text(name_node), node_text(val_node)
            if ntype == "assignment_expression":
                left = child_by_field(node, "left")
                right = child_by_field(node, "right")
                return node_text(left), node_text(right)
    if lang == Lang.RUST and getattr(node, "type", "") == "let_declaration":
        # let x = ... ; pattern = identifier, value = value
        pat = child_by_field(node, "pattern") or child_by_field(node, "name")
        val = child_by_field(node, "value")
        return node_text(pat), node_text(val)
    if lang in (Lang.JAVA, Lang.C_SHARP) and getattr(node, "type", "") in (
        "local_variable_declaration", "local_declaration_statement"
    ):
        decl = children(node)
        # Find the declarator child holding name/value
        for child in decl:
            ct = child.type
            if ct in ("variable_declarator", "declarator"):
                name_node = child_by_field(child, "name")
                val_node = child_by_field(child, "value")
                return node_text(name_node), node_text(val_node)
        return "", ""
    if lang == Lang.GO:
        if getattr(node, "type", "") == "short_var_declaration":
            left = child_by_field(node, "left")
            right = child_by_field(node, "right")
            return node_text(left), node_text(right)
        if getattr(node, "type", "") in ("var_declaration", "assignment_statement"):
            left = child_by_field(node, "name") or child_by_field(node, "left")
            right = child_by_field(node, "value") or child_by_field(node, "right")
            return node_text(left), node_text(right)
    if lang in (Lang.C, Lang.CPP) and getattr(node, "type", "") == "declaration":
        decl = children(node)
        for child in decl:
            if child.type == "init_declarator":
                name_node = child_by_field(child, "declarator")
                val_node = child_by_field(child, "value")
                return node_text(name_node), node_text(val_node)
        return "", ""
    if lang == Lang.SWIFT and getattr(node, "type", "") == "variable_declaration":
        pat = child_by_field(node, "pattern")
        val = child_by_field(node, "value")
        return node_text(pat), node_text(val)
    if lang == Lang.RUBY and getattr(node, "type", "") == "assignment":
        left = child_by_field(node, "left")
        right = child_by_field(node, "right")
        return node_text(left), node_text(right)
    if lang == Lang.PHP and getattr(node, "type", "") == "assignment_expression":
        left = child_by_field(node, "left")
        right = child_by_field(node, "right")
        return node_text(left), node_text(right)
    if lang == Lang.KOTLIN and getattr(node, "type", "") in ("property_declaration", "assignment"):
        if getattr(node, "type", "") == "property_declaration":
            name_node = child_by_field(node, "name")
            val = child_by_field(node, "initializer")
            return node_text(name_node), node_text(val)
        left = child_by_field(node, "left")
        right = child_by_field(node, "right")
        return node_text(left), node_text(right)
    if lang == Lang.DART and getattr(node, "type", "") == "variable_declaration":
        # Dart uses declarator children
        for child in children(node):
            if child.type == "declared_identifier":
                name_node = child_by_field(child, "name")
                val = child_by_field(node, "value")
                return node_text(name_node), node_text(val)
        return "", ""
    return "", ""
