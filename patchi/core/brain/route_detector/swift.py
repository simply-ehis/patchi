import re

from patchi.core.brain.route_detector.registry import register_detector
from patchi.core.brain.route_detector.base import BaseRouteDetector

_SWIFT_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options"}


import logging
_log = logging.getLogger("patchi.brain.swift")

@register_detector("swift")
class SwiftRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes = self._detect_ts(content, file_path)
        if routes:
            return routes
        return self._detect_fallback(content, file_path)

    def _detect_ts(self, content: str, file_path: str) -> list[dict] | None:
        try:
            from patchi.core.brain.languages import Lang, _build_parser

            parser = _build_parser(Lang.SWIFT)
            tree = parser.parse(bytes(content, "utf-8"))
        except Exception as e:
            _log.warning("SwiftRouteDetector._detect_ts failed: %s", e)
            return None

        routes: list[dict] = []
        self._walk(tree.root_node, bytes(content, "utf-8"), content, file_path, routes)
        return routes

    def _walk(self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]) -> None:
        ntype = getattr(node, "type", "")
        if ntype == "function_call_expression":
            self._check_call(node, buf, content, file_path, routes)
        for child in (getattr(node, "named_children", None) or getattr(node, "children", [])):
            self._walk(child, buf, content, file_path, routes)

    def _check_call(self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]) -> None:
        func = self._child_by_field(node, "function") or self._child_by_field(node, "name")
        if func is None:
            return

        ftype = getattr(func, "type", "")
        if ftype == "member_access_expression":
            obj = self._child_by_field(func, "object")
            member = self._child_by_field(func, "member") or self._child_by_field(func, "name")
            if obj is None or member is None:
                return
            obj_name = self._node_text(obj).lower()
            if obj_name != "app":
                return
            method_name = self._node_text(member).lower()
        elif ftype == "identifier":
            method_name = self._node_text(func).lower()
            if method_name not in _SWIFT_HTTP_METHODS:
                return
        else:
            return

        if method_name not in _SWIFT_HTTP_METHODS:
            return

        args = self._child_by_field(node, "arguments")
        path = ""
        if args:
            for child in (getattr(args, "named_children", None) or getattr(args, "children", [])):
                if child.type == "string_literal":
                    path = self._node_text(child).strip("\"")
                    break

        if not path:
            return

        line = getattr(node, "start_point", (0, 0))[0] + 1
        routes.append(self._make_route(method_name.upper(), path, "", file_path, line, framework="Vapor"))

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
            _log.debug("SwiftRouteDetector._node_text failed: %s", e)
            return ""

    def _detect_fallback(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        http = "|".join(_SWIFT_HTTP_METHODS)
        pat = re.compile(
            rf"""app\.({http})\s*\(\s*["']([^"']+)["']""",
            re.IGNORECASE,
        )
        for i, line in enumerate(content.splitlines(), 1):
            m = pat.search(line)
            if not m:
                continue
            routes.append(self._make_route(m.group(1).upper(), m.group(2), "", file_path, i, framework="Vapor"))
        return routes
