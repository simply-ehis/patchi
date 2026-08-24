import re

from patchi.core.brain.route_detector.registry import register_detector
from patchi.core.brain.route_detector.base import BaseRouteDetector

_RUST_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "connect", "trace", "any"}


import logging
_log = logging.getLogger("patchi.brain.rust")

@register_detector("rust")
class RustRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes = self._detect_ts(content, file_path)
        if routes:
            return routes
        return self._detect_fallback(content, file_path)

    def _detect_ts(self, content: str, file_path: str) -> list[dict] | None:
        try:
            from patchi.core.brain.languages import Lang, _build_parser

            parser = _build_parser(Lang.RUST)
            tree = parser.parse(bytes(content, "utf-8"))
        except Exception as e:
            _log.warning("RustRouteDetector._detect_ts failed: %s", e)
            return None

        routes: list[dict] = []
        self._walk(tree.root_node, bytes(content, "utf-8"), content, file_path, routes)
        return routes

    def _walk(self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]) -> None:
        ntype = getattr(node, "type", "")
        if ntype == "attribute_item":
            self._check_actix_attr(node, buf, content, file_path, routes)
        elif ntype == "call_expression":
            self._check_axum_call(node, buf, content, file_path, routes)

        for child in (getattr(node, "named_children", None) or getattr(node, "children", [])):
            self._walk(child, buf, content, file_path, routes)

    def _check_actix_attr(self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]) -> None:
        attr = self._child_by_field(node, "attribute")
        if attr is None:
            return
        attr_type = getattr(attr, "type", "")
        if attr_type != "attribute":
            return

        path_node = self._child_by_field(attr, "path") or self._child_by_field(attr, "name")
        if path_node is None:
            return
        try:
            raw = self._node_text(path_node).lower()
        except Exception as e:
            _log.warning("RustRouteDetector._check_actix_attr failed: %s", e)
            return

        if raw not in _RUST_HTTP_METHODS:
            return

        args = self._child_by_field(attr, "arguments")
        path = ""
        if args:
            for child in (getattr(args, "named_children", None) or getattr(args, "children", [])):
                if child.type in ("string_literal", "raw_string_literal"):
                    raw = self._node_text(child)
                    path = raw.strip("\"")
                    break

        handler = self._find_fn_name(node)
        line = getattr(node, "start_point", (0, 0))[0] + 1

        routes.append(self._make_route(raw.upper(), path, handler, file_path, line, framework="Actix Web"))

    def _check_axum_call(self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]) -> None:
        func = self._child_by_field(node, "function")
        if func is None:
            return
        if getattr(func, "type", "") != "field_expression":
            return
        method_name = self._child_by_field(func, "field")
        if method_name is None or self._node_text(method_name) != "route":
            return

        args = self._child_by_field(node, "arguments")
        if args is None or getattr(args, "named_child_count", 0) < 2:
            return

        path = ""
        first = args.named_child(0)
        if first and first.type in ("string_literal", "raw_string_literal"):
            path = self._node_text(first).strip("\"")
        if not path:
            return

        second = args.named_child(1)
        http_method = ""
        handler = ""
        if second and second.type == "call_expression":
            inner_fn = self._child_by_field(second, "function")
            if inner_fn and inner_fn.type == "identifier":
                http_method = self._node_text(inner_fn).lower()
                if http_method in _RUST_HTTP_METHODS:
                    inner_args = self._child_by_field(second, "arguments")
                    if inner_args and inner_args.named_child_count > 0:
                        h = inner_args.named_child(0)
                        if h and h.type == "identifier":
                            handler = self._node_text(h)

        if not http_method:
            return

        line = getattr(node, "start_point", (0, 0))[0] + 1
        routes.append(self._make_route(http_method.upper(), path, handler, file_path, line, framework="Axum"))

    def _find_fn_name(self, node: object) -> str:
        cur = node
        for _ in range(10):
            cur = getattr(cur, "parent", None)
            if cur is None:
                break
            if getattr(cur, "type", "") == "function_item":
                name_node = self._child_by_field(cur, "name")
                if name_node:
                    return self._node_text(name_node)
        return ""

    def _child_by_field(self, node: object, field: str) -> object | None:
        if hasattr(node, "child_by_field_name"):
            return node.child_by_field_name(field)
        return None

    def _node_text(self, node: object) -> str:
        try:
            raw = getattr(node, "text", b"")
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="replace")
            return str(raw)
        except Exception as e:
            _log.debug("RustRouteDetector._node_text failed: %s", e)
            return ""

    def _detect_fallback(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        http = "|".join(_RUST_HTTP_METHODS)

        actix_pat = re.compile(
            rf"#\[\s*({http})\s*\(\s*\"([^\"]+)\"\s*\)",
            re.IGNORECASE,
        )
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            m = actix_pat.search(line)
            if not m:
                continue
            method = m.group(1).upper()
            path = m.group(2)
            handler = ""
            for j in range(i, min(i + 5, len(lines) + 1)):
                hline = lines[j - 1].strip()
                if not hline or hline.startswith("#["):
                    continue
                hm = re.match(r"\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)", hline)
                if hm:
                    handler = hm.group(1)
                    break
            routes.append(self._make_route(method, path, handler, file_path, i, framework="Actix Web"))

        axum_pat = re.compile(
            rf"""\.route\s*\(\s*["']([^"']+)["']\s*,\s*({http})\s*\(""",
            re.IGNORECASE,
        )
        for i, line in enumerate(lines, 1):
            m = axum_pat.search(line)
            if not m:
                continue
            path = m.group(1)
            method = m.group(2).upper()
            handler = ""
            hm = re.search(rf"""({http})\s*\(\s*(\w+)""", line[m.end():] if m.end() < len(line) else line, re.IGNORECASE)
            if hm:
                handler = hm.group(2)
            routes.append(self._make_route(method, path, handler, file_path, i, framework="Axum"))

        return routes
