"""
AST utilities — control flow and data flow helpers.

Provides generic building blocks used by taint tracking:
  - tracking which variables are declared in which scope
  - following a variable's aliases (a = b; c = a; use(c))
"""

from __future__ import annotations

from typing import Any

from patchi.core.brain.languages import Lang

from .helpers import children

# Tree-sitter node types that open a new scope / block
_SCOPE_NODE_TYPES = {
    "block", "function_declaration", "function_item", "method_declaration",
    "function_definition", "lambda_expression", "arrow_function", "class_declaration",
    "class_definition", "do_statement", "while_statement", "for_statement",
    "for_in_statement", "if_statement", "compound_statement", "method_definition",
}


def named_children_of_type(node: Any, type_name: str) -> list[Any]:
    """Return immediate children whose type matches `type_name`."""
    out = []
    for child in children(node):
        if getattr(child, "type", "") == type_name:
            out.append(child)
    return out


def walk_blocks(node: Any, lang: Lang | None = None) -> Any:
    """Yield every node in a tree (generic pre-order walk)."""
    yield node
    for child in children(node):
        yield from walk_blocks(child, lang)


def collect_call_arguments(call_node: Any) -> list[Any]:
    """Return argument child nodes for a tree-sitter call/invocation node."""
    args = (
        child_by_field_any(call_node, "arguments")
        or child_by_field_any(call_node, "argument_list")
        or child_by_field_any(call_node, "value_arguments")
        or child_by_field_any(call_node, "argument_part")
    )
    if args is None:
        return []
    return [c for c in children(args) if c.type not in ("(", ")", ",", "[", "]", "{", "}")]


def child_by_field_any(node: Any, *fields: str) -> Any | None:
    """child_by_field_name for the first matching field name."""
    for f in fields:
        if hasattr(node, "child_by_field_name"):
            res = node.child_by_field_name(f)
            if res is not None:
                return res
    return None
