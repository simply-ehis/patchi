"""
Shared syntax queries over tree-sitter — the replacement for per-agent regex.

Agents used to detect code constructs (setInterval calls, `var` declarations,
JSX text, `require()` …) with regular expressions, which misfire on comments,
strings, and formatting variants. These helpers parse once with tree-sitter
(error-tolerant: partial trees still yield captures) and answer structural
questions. All functions are fail-open: unparseable input returns empty
collections, never raises.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

_log = logging.getLogger("patchi.brain.code_query")


@dataclass
class JsCall:
    """A call site: property name, full dotted callee, line, argument kinds."""

    name: str
    line: int
    arg_kinds: list[str] = field(default_factory=list)
    full: str = ""


def _parser(lang: str):
    try:
        if lang == "tsx":
            import tree_sitter_typescript as tsts
            from tree_sitter import Language, Parser

            return Parser(Language(tsts.language_tsx()))
        from patchi.core.brain.languages import Lang, get_parser

        return get_parser(Lang(lang))
    except Exception as exc:  # noqa: BLE001
        _log.debug("code_query parser unavailable: %s", exc)
        return None


def _query_text(lang_obj, pattern: str, node):
    from tree_sitter import Query, QueryCursor

    try:
        return QueryCursor(Query(lang_obj, pattern)).captures(node)
    except Exception as exc:  # noqa: BLE001
        _log.debug("code_query pattern failed %r: %s", pattern, exc)
        return {}


def _lang_obj(lang: str):
    from tree_sitter import Language

    if lang == "typescript":
        import tree_sitter_typescript as tsts

        return Language(tsts.language_typescript())
    if lang == "tsx":
        import tree_sitter_typescript as tsts

        return Language(tsts.language_tsx())
    import tree_sitter_javascript as tsjs

    return Language(tsjs.language())


def lang_for_file(filename: str) -> str:
    """Tree-sitter language key for a path (tsx needs its own grammar)."""
    name = filename.lower()
    if name.endswith(".tsx"):
        return "tsx"
    if name.endswith((".ts", ".mts", ".cts")):
        return "typescript"
    return "javascript"


def _node_text(node) -> str:
    t = node.text
    if isinstance(t, bytes):
        return t.decode("utf-8", errors="replace")
    return str(t)


def _line(node) -> int:
    return node.start_point[0] + 1


def parse_js(text: str, lang: str = "javascript"):
    """Parse JS/JSX/TS/TSX source. Returns the tree or None (fail-open)."""
    parser = _parser(lang)
    if parser is None:
        return None
    try:
        return parser.parse(text.encode("utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001
        _log.debug("code_query parse failed: %s", exc)
        return None


def _callee_name(call_node) -> str:
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return ""
    if fn.type == "identifier":
        return _node_text(fn)
    if fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        if prop is not None:
            return _node_text(prop)
        text = _node_text(fn)
        return text.rsplit(".", 1)[-1] if "." in text else text
    return ""


def js_calls(tree, lang: str = "javascript") -> list[JsCall]:
    """Every call site with callee name, full dotted path, line, arg kinds."""
    if tree is None:
        return []
    lang_obj = _lang_obj(lang)
    out: list[JsCall] = []
    for nodes in _query_text(lang_obj, "(call_expression) @c", tree.root_node).values():
        for node in nodes:
            args = node.child_by_field_name("arguments")
            kinds = [c.type for c in args.named_children] if args is not None else []
            fn = node.child_by_field_name("function")
            full = _node_text(fn) if fn is not None else ""
            out.append(
                JsCall(name=_callee_name(node), line=_line(node), arg_kinds=kinds, full=full)
            )
    return out


def js_useeffect_without_cleanup(tree, lang: str = "javascript") -> list[int]:
    """Lines of useEffect calls whose callback has no return statement."""
    if tree is None:
        return []
    lang_obj = _lang_obj(lang)
    out: list[int] = []
    for nodes in _query_text(lang_obj, "(call_expression) @c", tree.root_node).values():
        for node in nodes:
            if _callee_name(node) != "useEffect":
                continue
            args = node.child_by_field_name("arguments")
            if args is None:
                continue
            has_return = False
            for arg in args.named_children:
                if arg.type in ("arrow_function", "function_expression", "function"):
                    ret = _query_text(lang_obj, "(return_statement) @r", arg)
                    if any(ret.values()):
                        has_return = True
                        break
            if not has_return:
                out.append(_line(node))
    return out


def js_call_names(tree, lang: str = "javascript") -> set[str]:
    """Set of callee names called anywhere in the file."""
    return {c.name for c in js_calls(tree, lang) if c.name}


def js_var_kinds(tree, lang: str = "javascript") -> list[tuple[str, int]]:
    """(kind, line) for every var/let/const declaration."""
    lang_obj = _lang_obj(lang)
    out: list[tuple[str, int]] = []
    if tree is None:
        return []
    found = _query_text(
        lang_obj, "[(variable_declaration) (lexical_declaration)] @d", tree.root_node
    )
    for nodes in found.values():
        for node in nodes:
            text = _node_text(node).lstrip()
            kind = text.split(None, 1)[0] if text else ""
            if kind in ("var", "let", "const"):
                out.append((kind, _line(node)))
    return out


def js_has_await(tree, lang: str = "javascript") -> bool:
    if tree is None:
        return False
    lang_obj = _lang_obj(lang)
    return bool(_query_text(lang_obj, "(await_expression) @a", tree.root_node))


def js_new_names(tree, lang: str = "javascript") -> set[str]:
    """Constructor names from `new X(...)` expressions."""
    lang_obj = _lang_obj(lang)
    out: set[str] = set()
    found = _query_text(lang_obj, "(new_expression constructor: (_) @c)", tree.root_node)
    for nodes in found.values():
        for node in nodes:
            out.add(_node_text(node))
    return out


def js_jsx_texts(tree, lang: str = "javascript") -> list[tuple[str, int]]:
    """Visible JSX text fragments with lines."""
    lang_obj = _lang_obj(lang)
    out: list[tuple[str, int]] = []
    for nodes in _query_text(lang_obj, "(jsx_text) @t", tree.root_node).values():
        for node in nodes:
            text = _node_text(node).strip()
            if text:
                out.append((text, _line(node)))
    return out


def js_class_heritages(tree, lang: str = "javascript") -> list[tuple[str, int]]:
    """`extends ...` clause text with lines."""
    lang_obj = _lang_obj(lang)
    out: list[tuple[str, int]] = []
    for nodes in _query_text(lang_obj, "(class_heritage) @h", tree.root_node).values():
        for node in nodes:
            out.append((_node_text(node), _line(node)))
    return out


def js_identifiers(tree, lang: str = "javascript") -> set[str]:
    """All identifier spellings (for $store-style prefix checks)."""
    lang_obj = _lang_obj(lang)
    out: set[str] = set()
    for nodes in _query_text(lang_obj, "(identifier) @i", tree.root_node).values():
        for node in nodes:
            out.add(_node_text(node))
    return out


def js_string_literals(tree, lang: str = "javascript") -> list[tuple[str, int]]:
    """String literal contents with lines (quotes stripped)."""
    lang_obj = _lang_obj(lang)
    out: list[tuple[str, int]] = []
    for nodes in _query_text(lang_obj, "(string) @s", tree.root_node).values():
        for node in nodes:
            text = _node_text(node)
            if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'`":
                text = text[1:-1]
            out.append((text, _line(node)))
    return out


def js_has_try(tree, lang: str = "javascript") -> bool:
    if tree is None:
        return False
    lang_obj = _lang_obj(lang)
    return bool(_query_text(lang_obj, "(try_statement) @t", tree.root_node))


def _catch_in_subtree(lang_obj, node) -> bool:
    sub = _query_text(lang_obj, "(call_expression) @c", node)
    return any(_callee_name(n) == "catch" for ns in sub.values() for n in ns)


def _assigned_name(stmt) -> str:
    if stmt.type == "variable_declarator":
        name_node = stmt.child_by_field_name("name")
        if name_node is not None:
            return _node_text(name_node)
    return ""


def js_new_without_catch(tree, names=("Promise",), lang: str = "javascript") -> list[int]:
    """Lines of `new X(...)` with no `.catch` — same statement or later `v.catch`."""
    if tree is None:
        return []
    lang_obj = _lang_obj(lang)
    out: list[int] = []
    for nodes in _query_text(lang_obj, "(new_expression) @n", tree.root_node).values():
        for node in nodes:
            ctor = node.child_by_field_name("constructor")
            cname = _node_text(ctor) if ctor is not None else ""
            if cname not in names:
                continue
            stmt = node
            var_name = ""
            while stmt.parent is not None and stmt.type not in (
                "expression_statement",
                "variable_declaration",
                "lexical_declaration",
                "return_statement",
            ):
                if stmt.type == "variable_declarator" and not var_name:
                    var_name = _assigned_name(stmt)
                stmt = stmt.parent
            if _catch_in_subtree(lang_obj, stmt):
                continue
            if var_name:
                parent = stmt.parent
                if parent is not None:
                    kids = parent.named_children
                    try:
                        idx = kids.index(stmt)
                    except ValueError:
                        idx = -1
                    handled = False
                    for sib in kids[idx + 1 :]:
                        sib_calls = _query_text(lang_obj, "(call_expression) @c", sib)
                        for ns in sib_calls.values():
                            for n in ns:
                                fn = n.child_by_field_name("function")
                                if (
                                    fn is not None
                                    and fn.type == "member_expression"
                                    and _node_text(fn).startswith(var_name + ".")
                                    and _callee_name(n) == "catch"
                                ):
                                    handled = True
                                    break
                            if handled:
                                break
                        if handled:
                            break
                    if handled:
                        continue
            out.append(_line(node))
    return out


def js_jsx_attributes(tree, lang: str = "javascript") -> list[tuple[str, str, int]]:
    """(tag, attribute_name, line) for every JSX attribute."""
    if tree is None:
        return []
    lang_obj = _lang_obj(lang)
    out: list[tuple[str, str, int]] = []
    found = _query_text(lang_obj, "(jsx_opening_element) @o", tree.root_node)
    for nodes in found.values():
        for node in nodes:
            tag = ""
            for child in node.named_children:
                if child.type == "identifier":
                    tag = _node_text(child)
                    break
            for child in node.named_children:
                if child.type == "jsx_attribute":
                    name_node = child.child_by_field_name("name")
                    if name_node is None and child.named_children:
                        name_node = child.named_children[0]
                    if name_node is not None:
                        out.append((tag, _node_text(name_node), _line(child)))
    return out


def vue_template_attrs(text: str) -> list[tuple[str, str, int]]:
    """(tag, attr_name, line) from Vue/SFC template markup via html.parser.

    tree-sitter-javascript cannot parse HTML templates; the stdlib HTML parser
    reads real tag structure instead of regexing angle brackets.
    """
    from html.parser import HTMLParser

    out: list[tuple[str, str, int]] = []

    class _P(HTMLParser):
        def handle_starttag(self, tag, attrs):
            line, _ = self.getpos()
            for name, _value in attrs:
                out.append((tag, name, line))

    try:
        _P().feed(text)
    except Exception as exc:  # noqa: BLE001
        _log.debug("vue template parse failed: %s", exc)
    return out
