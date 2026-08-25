"""
AST utilities — source-to-sink taint tracking.

Follows data flow from untrusted SOURCES (user input, request objects, env
vars, etc.) into dangerous SINKS (SQL execution, command execution, eval,
HTML rendering, ...) and reports a tainted call only when the value reaches a
sink without being sanitized.

The analysis is intra-procedural and best-effort: it tracks simple local
aliasing (`x = src; sink(x)`) and string concatenation of tainted values.
"""

from __future__ import annotations

import ast

from patchi.core.brain.languages import Lang, get_parser

from .assignments import find_assignments
from .config import CALL_NODE_TYPES
from .helpers import child_by_field, children, node_text

# Untrusted data origins
SOURCES = {
    "request.args",
    "request.form",
    "request.json",
    "request.data",
    "request.GET",
    "request.POST",
    "request.body",
    "request.headers",
    "request.query_params",
    "request.path_params",
    "request.cookies",
    "req.query",
    "req.body",
    "req.params",
    "req.headers",
    "input",
    "sys.argv",
    "os.environ",
    "os.getenv",
    "self.request",
    "self.params",
    "params",
    "query",
    "payload",
    "event.target",
    "event.data",
    "document.location",
    "location.search",
}

# Sanitizers that neutralize common taint categories
SANITIZERS = {
    "escape",
    "sanitize",
    "html.escape",
    "markupsafe.escape",
    "bleach.clean",
    "django.utils.html.escape",
    "parameterized",
    "prepare",
    "quote",
    "urlencode",
    "encode_for_sql",
}


import logging

_log = logging.getLogger("patchi.brain.taint")


def _is_source(text: str) -> bool:
    t = text.strip()
    return (
        t in SOURCES
        or any(t.startswith(s + ".") for s in SOURCES)
        or t
        in (
            "request",
            "req",
            "input()",
            "event",
            "location",
        )
    )


def _is_sanitized(text: str) -> bool:
    return any(s in text for s in SANITIZERS)


def track_taint(content: str, lang: Lang, sinks: set[str]) -> list[dict]:
    """
    Track tainted data from SOURCES into `sinks`.

    Returns list of dicts with keys: name, line, col, full_text, tainted_via.
    A sink call is reported when at least one of its arguments is either a
    direct source or an alias of a source.
    """
    if lang == Lang.PYTHON:
        return _track_python(content, sinks)
    parser = get_parser(lang)
    if not parser:
        return []
    try:
        tree = parser.parse(content.encode("utf-8"))
    except Exception as e:
        _log.warning("track_taint failed: %s", e)
        return []
    call_types = CALL_NODE_TYPES.get(lang, set())
    results: list[dict] = []
    aliases = _collect_aliases(content, lang)
    _walk_taint(tree.root_node, call_types, sinks, aliases, results)
    return results


def _collect_aliases(content: str, lang: Lang) -> dict[str, str]:
    """Map variable name -> source text it was assigned from (one hop)."""
    aliases: dict[str, str] = {}
    for asg in find_assignments(content, lang):
        target = asg.get("target", "")
        value = asg.get("value", "")
        if target and value and _is_source(value):
            aliases[target.split(".")[0]] = value
    return aliases


def _argument_texts(call_node: object) -> list[str]:
    arg_nodes = (
        child_by_field(call_node, "arguments")
        or child_by_field(call_node, "argument_list")
        or child_by_field(call_node, "value_arguments")
        or child_by_field(call_node, "argument_part")
    )
    if arg_nodes is None:
        return []
    out = []
    for c in children(arg_nodes):
        if c.type in ("(", ")", ",", "[", "]", "{", "}"):
            continue
        out.append(node_text(c))
    return out


def _walk_taint(
    node: object,
    call_types: set[str],
    sinks: set[str],
    aliases: dict[str, str],
    results: list[dict],
) -> None:
    try:
        ntype = node.type if hasattr(node, "type") else ""
    except Exception as e:
        _log.warning("_walk_taint failed: %s", e)
        return

    if ntype in call_types:
        fn = _call_name(node)
        leaf = fn.split(".")[-1] if "." in fn else fn
        if fn in sinks or leaf in sinks:
            arg_texts = _argument_texts(node)
            tainted = []
            for arg in arg_texts:
                base = arg.split(".")[0].split("[")[0].strip()
                if (
                    _is_source(arg)
                    or base in aliases
                    or (any(s in arg for s in aliases) and not _is_sanitized(arg))
                ):
                    tainted.append(arg)
            if tainted:
                try:
                    line = node.start_point[0] + 1 if node.start_point else 0
                    col = node.start_point[1] if node.start_point else 0
                except Exception as e:
                    _log.warning("_walk_taint failed: %s", e)
                    line, col = 0, 0
                results.append(
                    {
                        "name": fn,
                        "line": line,
                        "col": col,
                        "full_text": node_text(node),
                        "tainted_via": tainted,
                    }
                )

    for child in children(node):
        _walk_taint(child, call_types, sinks, aliases, results)


def _call_name(node: object) -> str:
    fn = child_by_field(node, "function") or child_by_field(node, "name")
    if fn is not None:
        return node_text(fn).split("(")[0].strip()
    parts = []
    for child in children(node):
        if child.type in ("argument_list", "arguments", "value_arguments", "argument_part"):
            break
        txt = node_text(child)
        if txt and txt not in ("(", ")", ".", "::"):
            parts.append(txt)
    return ".".join(parts) if parts else ""


def _track_python(content: str, sinks: set[str]) -> list[dict]:
    import ast

    results: list[dict] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return results

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and isinstance(node.value, ast.Call):
                    call = node.value
                    if isinstance(call.func, ast.Name) and _is_source(_py_src_expr(call.func.id)):
                        aliases[t.id] = call.func.id
                    elif isinstance(call.func, ast.Attribute) and _is_source(
                        _py_src_expr(_py_attr_str(call.func))
                    ):
                        aliases[t.id] = _py_attr_str(call.func)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn_str = _py_call_str(node.func)
            leaf = fn_str.split(".")[-1]
            if fn_str in sinks or leaf in sinks:
                tainted = []
                for arg in node.args:
                    arg_str = _py_arg_str(arg)
                    base = arg_str.split(".")[0].split("[")[0].strip()
                    if (
                        _is_source(arg_str)
                        or base in aliases
                        or (
                            any(a in arg_str for a in aliases.values())
                            and not _is_sanitized(arg_str)
                        )
                    ):
                        tainted.append(arg_str)
                if tainted:
                    results.append(
                        {
                            "name": fn_str,
                            "line": getattr(node, "lineno", 0),
                            "col": getattr(node, "col_offset", 0),
                            "full_text": _ast_text(node, content),
                            "tainted_via": tainted,
                        }
                    )
    return results


# ── Python helpers ─────────────────────────────────────────────────────────────


def _py_src_expr(s: str) -> str:
    return s


def _py_attr_str(node: ast.AST) -> str:
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _py_call_str(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _py_attr_str(node)
    return ""


def _py_arg_str(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _py_call_str(node.func)
    if isinstance(node, ast.Attribute):
        return _py_attr_str(node)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Subscript):
        return _py_arg_str(node.value)
    return _py_call_str(node) or _py_attr_str(node)


def _ast_text(node: ast.AST, source: str) -> str:
    try:
        lines = source.splitlines()
        start = getattr(node, "lineno", 1) - 1
        end = getattr(node, "end_lineno", start + 1) - 1
        return "\n".join(lines[start : end + 1])
    except Exception as e:
        _log.debug("_ast_text failed: %s", e)
        return ""
