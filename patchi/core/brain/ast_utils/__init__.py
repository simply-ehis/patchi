"""
AST utilities — language-generic tree-sitter / Python `ast` walking utilities.

This package exposes language-generic helpers used by security agents, type
checkers, and route detectors. The implementation is split into submodules
but re-exported here so existing imports keep working:

    from patchi.core.brain.ast_utils import find_calls, find_imports, node_text
    calls = find_calls(content, Lang.PYTHON, ["execute", "eval"])

Submodules:
    config.py       — per-language node type configs + common sink sets
    helpers.py      — node_text, child_by_field, children, get_call_arg, ...
    calls.py        — find_calls (+ Python / tree-sitter walkers)
    imports.py      — find_imports
    decorators.py   — find_decorators
    assignments.py  — find_assignments
    control_flow.py — scope / argument walking helpers
    taint.py        — source-to-sink taint tracking
    dead_symbols.py — intra-file dead-symbol detection
"""

from __future__ import annotations

# Re-export public API from submodules
from .config import (
    CALL_NODE_TYPES,
    DECORATOR_NODE_TYPES,
    EXEC_SINKS,
    HTTP_CLIENTS,
    IMPORT_NODE_TYPES,
    SQL_SINKS,
)
from .helpers import (
    child_by_field,
    children,
    get_call_arg,
    named_children,
    node_text,
    parse_source,
)
from .calls import find_calls
from .imports import find_imports
from .decorators import find_decorators
from .assignments import find_assignments
from .control_flow import (
    child_by_field_any,
    collect_call_arguments,
    named_children_of_type,
    walk_blocks,
)
from .taint import SOURCES, SANITIZERS, track_taint
from .dead_symbols import find_dead_symbols

__all__ = [
    "CALL_NODE_TYPES",
    "DECORATOR_NODE_TYPES",
    "EXEC_SINKS",
    "HTTP_CLIENTS",
    "IMPORT_NODE_TYPES",
    "SQL_SINKS",
    "child_by_field",
    "children",
    "get_call_arg",
    "named_children",
    "node_text",
    "parse_source",
    "find_calls",
    "find_imports",
    "find_decorators",
    "find_assignments",
    "child_by_field_any",
    "collect_call_arguments",
    "named_children_of_type",
    "walk_blocks",
    "SOURCES",
    "SANITIZERS",
    "track_taint",
    "find_dead_symbols",
]
