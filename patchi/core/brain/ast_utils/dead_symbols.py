"""
AST utilities — intra-file dead-symbol detection across languages.

Finds top-level (file-scope) functions / classes / methods / constants that are
never referenced anywhere else in the same file. Cross-file references are the
job of the import graph (file-level dead detection); this complements it with a
symbol-level signal that works for every tree-sitter language without external
tooling (vulture, ts-prune, etc.).

Conservative by design — only flags file-scope symbols that:
  - are not exported (no `export` / `pub` modifier),
  - are not entry-point names (main/app/index/...),
  - have a length >= 3 (avoids false positives on trivial names),
  - never appear as an identifier/reference on any line other than their own.
"""

from __future__ import annotations

import ast as _py_ast
import logging

from patchi.core.brain.languages import Lang, get_parser

from .helpers import child_by_field, node_text

# Node types that introduce a named symbol at file scope.
_DEF_NODE_TYPES = {
    "function_definition",
    "function_declaration",
    "function_item",
    "function_method_definition",
    "method_definition",
    "method_declaration",
    "method",
    "class_definition",
    "class_declaration",
    "class_item",
    "decorated_definition",
    "lexical_declaration",
    "variable_declaration",
    "const_declaration",
    "abstract_method_signature",
}

# Containers whose direct children may be top-level definitions.
_ROOT_CONTAINERS = {
    "program",
    "source_file",
    "module",
    "translation_unit",
    "compilation_unit",
    "block",
    "text",
    "namespace_definition",
}

# Node types whose text counts as a reference to a name.
_REF_NODE_TYPES = {
    "identifier",
    "name",
    "property_identifier",
    "field_identifier",
    "type_identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
}

_ENTRY_NAMES = frozenset(
    {
        "main",
        "app",
        "index",
        "run",
        "start",
        "server",
        "init",
        "__init__",
        "setup",
        "handler",
    }
)


_log = logging.getLogger("patchi.brain.dead_symbols")


def find_dead_symbols(content: str, lang: Lang, *, min_name_len: int = 3) -> list[dict]:
    """
    Return a list of intra-file dead symbols.

    Each entry: {name, line, kind, file_scope}.
    `file_scope` is True for module/file-level symbols (safe to report as dead),
    False for nested symbols (report with care).
    """
    if lang == Lang.PYTHON:
        return _find_dead_python(content, min_name_len)
    parser = get_parser(lang)
    if not parser:
        return []
    try:
        tree = parser.parse(content.encode("utf-8"))
    except Exception as e:
        _log.warning("find_dead_symbols failed: %s", e)
        return []

    refs = _collect_refs(tree.root_node)
    dead: list[dict] = []
    _walk_defs(tree.root_node, refs, dead, min_name_len)
    return dead


# ── Python ─────────────────────────────────────────────────────────────────────


def _find_dead_python(content: str, min_name_len: int) -> list[dict]:
    try:
        tree = _py_ast.parse(content)
    except SyntaxError:
        return []

    def_lines: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, (_py_ast.FunctionDef, _py_ast.AsyncFunctionDef, _py_ast.ClassDef)):
            if len(node.name) >= min_name_len and node.name not in _ENTRY_NAMES:
                def_lines[node.name] = node.lineno

    if not def_lines:
        return []

    ref_lines: dict[str, set[int]] = {}
    for node in _py_ast.walk(tree):
        if isinstance(node, _py_ast.Name):
            ref_lines.setdefault(node.id, set()).add(getattr(node, "lineno", 0))

    dead: list[dict] = []
    for name, def_line in def_lines.items():
        occurrences = ref_lines.get(name, set())
        used = any(ln != def_line for ln in occurrences)
        if not used:
            dead.append({"name": name, "line": def_line, "kind": "function_or_class", "file_scope": True})
    return dead


# ── Tree-sitter (all other languages) ─────────────────────────────────────────


def _collect_refs(node) -> dict[str, set[int]]:
    """Map every identifier-like text to the set of lines it appears on."""
    refs: dict[str, set[int]] = {}
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type in _REF_NODE_TYPES:
            text = cur.text.decode("utf-8", errors="replace")
            if text:
                refs.setdefault(text, set()).add(cur.start_point[0] + 1)
        stack.extend(cur.children)
    return refs


def _def_name(node) -> str | None:
    nf = child_by_field(node, "name")
    if nf is not None:
        return node_text(nf).strip()
    # variable / const declarations carry a declarator with a `name` field
    if node.type in ("lexical_declaration", "variable_declaration", "const_declaration"):
        for child in node.children:
            if child.type in ("variable_declarator", "declarator", "pair"):
                name_node = child_by_field(child, "name")
                if name_node is not None:
                    return node_text(name_node).strip()
    return None


def _is_exported(line_text: str) -> bool:
    stripped = line_text.lstrip()
    return stripped.startswith("export") or " pub " in line_text or stripped.startswith("pub ")


def _walk_defs(node, refs: dict[str, set[int]], dead: list[dict], min_name_len: int) -> None:
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type in _DEF_NODE_TYPES:
            name = _def_name(cur)
            if name and len(name) >= min_name_len and name not in _ENTRY_NAMES:
                line_no = cur.start_point[0] + 1
                line_text = cur.text.decode("utf-8", errors="replace")
                if _is_exported(line_text):
                    stack.extend(cur.children)
                    continue
                occurrences = refs.get(name, set())
                used = any(ln != line_no for ln in occurrences)
                parent = cur.parent
                file_scope = parent is not None and parent.type in _ROOT_CONTAINERS
                if not used and file_scope:
                    kind = "method" if cur.type == "method_definition" else cur.type
                    dead.append({"name": name, "line": line_no, "kind": kind, "file_scope": True})
            stack.extend(cur.children)
        else:
            stack.extend(cur.children)


__all__ = ["find_dead_symbols"]
