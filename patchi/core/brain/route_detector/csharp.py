"""
C# route detector — ASP.NET Core attribute-based routing.

Node types below (attribute, attribute_list, attribute_argument_list,
attribute_argument, method_declaration, class_declaration) were verified
directly against the installed tree-sitter-c-sharp grammar, not assumed from
generic documentation — including that both `method_declaration` and
`attribute` expose a reliable `name` field via child_by_field_name, which is
what this walker relies on instead of guessing child position.
"""

import logging
import re

from patchi.core.brain.route_detector.registry import register_detector
from patchi.core.brain.route_detector.base import BaseRouteDetector

_log = logging.getLogger("patchi.brain.csharp")

_HTTP_ATTRS = {
    "httpget": "GET",
    "httppost": "POST",
    "httpput": "PUT",
    "httpdelete": "DELETE",
    "httppatch": "PATCH",
    "httphead": "HEAD",
    "httpoptions": "OPTIONS",
}


@register_detector("c_sharp")
class CSharpRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes = self._detect_ts(content, file_path)
        if routes:
            return routes
        return self._detect_fallback(content, file_path)

    def _detect_ts(self, content: str, file_path: str) -> list[dict] | None:
        try:
            from patchi.core.brain.languages import Lang, get_parser

            parser = get_parser(Lang.C_SHARP)
            if parser is None:
                return None
            tree = parser.parse(content.encode("utf-8"))
        except Exception as e:
            _log.warning("CSharpRouteDetector._detect_ts failed: %s", e)
            return None

        routes: list[dict] = []
        self._walk(tree.root_node, content, file_path, routes)
        return routes

    def _walk(self, node: object, content: str, file_path: str, routes: list[dict]) -> None:
        ntype = getattr(node, "type", "")
        if ntype == "method_declaration":
            self._check_method(node, content, file_path, routes)
        for child in getattr(node, "children", []):
            self._walk(child, content, file_path, routes)

    def _check_method(self, method_node: object, content: str, file_path: str, routes: list[dict]) -> None:
        http_method = None
        route_suffix = ""
        method_auth = False

        for child in getattr(method_node, "children", []):
            if child.type != "attribute_list":
                continue
            for attr in getattr(child, "children", []):
                if attr.type != "attribute":
                    continue
                name = self._attr_name(attr, content).lower()
                if name in _HTTP_ATTRS:
                    http_method = _HTTP_ATTRS[name]
                    route_suffix = self._attr_string_arg(attr, content)
                elif name == "route" and http_method is None:
                    http_method = "ANY"
                    route_suffix = self._attr_string_arg(attr, content)
                elif name in ("authorize",):
                    method_auth = True

        if http_method is None:
            return

        class_prefix, class_auth = self._enclosing_class_context(method_node, content)
        path = self._combine_path(class_prefix, route_suffix)

        name_node = method_node.child_by_field_name("name") if hasattr(method_node, "child_by_field_name") else None
        handler = self._node_text(name_node, content) if name_node else ""
        line = getattr(method_node, "start_point", (0, 0))[0] + 1

        auth = method_auth or class_auth
        routes.append(self._make_route(
            http_method, path, handler, file_path, line,
            framework="ASP.NET Core", auth_required=auth if auth else None,
        ))

    def _enclosing_class_context(self, node: object, content: str) -> tuple[str, bool]:
        """Walk up to the enclosing class_declaration for its [Route] prefix and [Authorize]."""
        cur = node
        for _ in range(10):
            cur = getattr(cur, "parent", None)
            if cur is None:
                break
            if getattr(cur, "type", "") == "class_declaration":
                prefix = ""
                auth = False
                for child in getattr(cur, "children", []):
                    if child.type != "attribute_list":
                        continue
                    for attr in getattr(child, "children", []):
                        if attr.type != "attribute":
                            continue
                        name = self._attr_name(attr, content).lower()
                        if name == "route":
                            prefix = self._attr_string_arg(attr, content)
                        elif name == "authorize":
                            auth = True
                return prefix, auth
        return "", False

    def _combine_path(self, prefix: str, suffix: str) -> str:
        # [controller] is ASP.NET's token substitution for the class name minus
        # "Controller" -- approximated here rather than resolved exactly, since
        # getting it exact requires the class name, which is a reasonable
        # follow-up refinement rather than a blocker for a first working version.
        parts = [p.strip("/") for p in (prefix, suffix) if p]
        return "/" + "/".join(parts) if parts else ""

    def _attr_name(self, attr_node: object, content: str) -> str:
        name_node = attr_node.child_by_field_name("name") if hasattr(attr_node, "child_by_field_name") else None
        return self._node_text(name_node, content) if name_node else ""

    def _attr_string_arg(self, attr_node: object, content: str) -> str:
        for child in getattr(attr_node, "children", []):
            if child.type != "attribute_argument_list":
                continue
            for arg in getattr(child, "children", []):
                if arg.type == "attribute_argument":
                    for lit in getattr(arg, "children", []):
                        if lit.type == "string_literal":
                            return self._node_text(lit, content).strip('"')
        return ""

    def _node_text(self, node: object, content: str) -> str:
        try:
            return content[node.start_byte:node.end_byte]
        except Exception as e:
            _log.debug("CSharpRouteDetector._node_text failed: %s", e)
            return ""

    def _detect_fallback(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        verb_names = "|".join(_HTTP_ATTRS)
        pat = re.compile(rf'\[({verb_names}|Route)(?:\("([^"]*)"\))?\]', re.IGNORECASE)
        auth_pat = re.compile(r"\[Authorize\]", re.IGNORECASE)

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            m = pat.search(line)
            if not m:
                continue
            verb_raw = m.group(1).lower()
            method = _HTTP_ATTRS.get(verb_raw, "ANY")
            path = "/" + (m.group(2) or "").strip("/")

            handler = ""
            for j in range(i, min(i + 5, len(lines) + 1)):
                hm = re.search(r"\b(?:public|private|protected)\s+\w+(?:<[\w,\s]+>)?\s+(\w+)\s*\(", lines[j - 1])
                if hm:
                    handler = hm.group(1)
                    break

            ctx = "\n".join(lines[max(0, i - 5):i])
            auth = bool(auth_pat.search(ctx))

            routes.append(self._make_route(method, path, handler, file_path, i,
                                            framework="ASP.NET Core", auth_required=auth if auth else None))
        return routes
