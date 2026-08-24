"""
AST utilities — function/method call finding across languages.
"""

from __future__ import annotations

from typing import Any

from .config import CALL_NODE_TYPES
from .helpers import child_by_field, children, node_text, _leaf_name
from .scan import _slice, scan_python
from patchi.core.brain.languages import Lang, get_parser


import logging
_log = logging.getLogger("patchi.brain.calls")

def find_calls(content: str, lang: Lang, names: set[str]) -> list[dict]:
    """
    Find all function/method calls in source whose name matches one of `names`.

    Returns list of dicts with keys: name, line, col, full_text.

    Python is served from the shared single-pass AST scan (one parse + walk
    per file per process, cached) — repeated calls with different sink sets
    no longer re-parse the file.
    """
    if lang == Lang.PYTHON:
        return _find_calls_python(content, names)
    parser = get_parser(lang)
    if not parser:
        return []
    try:
        tree = parser.parse(content.encode("utf-8"))
    except Exception as e:
        _log.warning("find_calls failed: %s", e)
        return []
    call_types = CALL_NODE_TYPES.get(lang, set())
    results: list[dict] = []
    _walk_calls(tree.root_node, call_types, names, results)
    return results


def _find_calls_python(content: str, names: set[str]) -> list[dict]:
    """Filter the cached single-pass scan; same nodes/fields as the old walker."""
    scan = scan_python(content)
    lines = scan["lines"]
    results: list[dict] = []
    for call in scan["calls"]:
        fn = call["name"]
        leaf = _leaf_name(fn)
        if fn in names or leaf in names:
            results.append({
                "name": fn,
                "line": call["line"],
                "col": call["col"],
                "full_text": _slice(lines, call["start"], call["end"]) if content else "",
            })
    return results


def _extract_call_name(node: Any) -> str:
    fn = child_by_field(node, "function") or child_by_field(node, "name")
    if fn is not None:
        return node_text(fn).split("(")[0].strip()
    # Fallback: join all identifier/simple children before argument_list
    parts: list[str] = []
    for child in children(node):
        if child.type in ("argument_list", "arguments", "value_arguments", "argument_part"):
            break
        txt = node_text(child)
        if txt and txt not in ("(", ")", ".", "::"):
            parts.append(txt)
    if parts:
        return ".".join(parts)
    return ""


def _walk_calls(node: Any, call_types: set[str], names: set[str], results: list[dict]) -> None:
    try:
        ntype = node.type if hasattr(node, "type") else ""
    except Exception as e:
        _log.warning("_walk_calls failed: %s", e)
        return

    if ntype in call_types:
        fn = _extract_call_name(node)
        if fn:
            leaf = _leaf_name(fn)
            if fn in names or leaf in names:
                try:
                    line = node.start_point[0] + 1 if node.start_point else 0
                    col = node.start_point[1] if node.start_point else 0
                except Exception as e:
                    _log.warning("_walk_calls failed: %s", e)
                    line, col = 0, 0
                results.append({
                    "name": fn,
                    "line": line,
                    "col": col,
                    "full_text": node_text(node),
                })

        # For Ruby: also check call method name (avoid duplicate of existing match)
        if ntype == "call" and not any(r["name"] == fn for r in results):
            method = child_by_field(node, "method")
            if method:
                fn_name = node_text(method)
                leaf = _leaf_name(fn_name)
                if fn_name in names or leaf in names:
                    try:
                        line = node.start_point[0] + 1 if node.start_point else 0
                    except Exception as e:
                        _log.warning("_walk_calls failed: %s", e)
                        line = 0
                    results.append({
                        "name": fn_name,
                        "line": line,
                        "col": 0,
                        "full_text": node_text(node),
                    })

    for child in children(node):
        _walk_calls(child, call_types, names, results)
