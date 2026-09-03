import logging
import re

from patchi.core.brain.route_detector.base import BaseRouteDetector
from patchi.core.brain.route_detector.registry import register_detector

_GO_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}

_GIN_PATTERNS = {"r", "router", "engine"}
_ECHO_PATTERNS = {"e", "echo"}
_FIBER_PATTERNS = {"app"}

_FRAMEWORK_MAP: list[tuple[set[str], str]] = [
    (_GIN_PATTERNS, "Gin"),
    (_ECHO_PATTERNS, "Echo"),
    (_FIBER_PATTERNS, "Fiber"),
]


_log = logging.getLogger("patchi.brain.go")


@register_detector("go")
class GoRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes = self._detect_ts(content, file_path)
        if routes:
            return routes
        return self._detect_fallback(content, file_path)

    def _detect_ts(self, content: str, file_path: str) -> list[dict] | None:
        try:
            from patchi.core.brain.languages import Lang, _build_parser

            parser = _build_parser(Lang.GO)
            tree = parser.parse(bytes(content, "utf-8"))
        except Exception as e:
            _log.warning("GoRouteDetector._detect_ts failed: %s", e)
            return None

        routes: list[dict] = []
        self._walk(tree.root_node, bytes(content, "utf-8"), content, file_path, routes)
        return routes

    def _walk(
        self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]
    ) -> None:
        ntype = getattr(node, "type", "")
        if ntype == "call_expression":
            self._check_call(node, buf, content, file_path, routes)
        for child in getattr(node, "named_children", None) or getattr(node, "children", []):
            self._walk(child, buf, content, file_path, routes)

    def _check_call(
        self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]
    ) -> None:
        func = self._child_by_field(node, "function")
        if func is None or getattr(func, "type", "") != "selector_expression":
            return

        operand = self._child_by_field(func, "operand")
        field = self._child_by_field(func, "field")
        if operand is None or field is None:
            return

        obj_name = self._node_text(operand).lower()
        method_name = self._node_text(field).lower()

        if method_name not in _GO_HTTP_METHODS:
            return

        framework = ""
        for patterns, fw in _FRAMEWORK_MAP:
            if obj_name in patterns:
                framework = fw
                break
        if not framework:
            return

        args = self._child_by_field(node, "arguments")
        path = ""
        if args and getattr(args, "named_child_count", 0) > 0:
            first = args.named_child(0)
            if first and first.type in (
                "interpreted_string_literal",
                "raw_string_literal",
                "string_literal",
            ):
                raw = self._node_text(first)
                path = raw.strip('"`')

        if not path:
            return

        handler = ""
        if args and getattr(args, "named_child_count", 0) >= 2:
            second = args.named_child(1)
            if second and second.type == "identifier":
                handler = self._node_text(second)

        line = getattr(node, "start_point", (0, 0))[0] + 1
        routes.append(
            self._make_route(
                method_name.upper(), path, handler, file_path, line, framework=framework
            )
        )

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
            _log.debug("GoRouteDetector._node_text failed: %s", e)
            return ""

    def _detect_fallback(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        http = "|".join(m.upper() for m in _GO_HTTP_METHODS)
        for patterns, framework in _FRAMEWORK_MAP:
            for obj in patterns:
                pat = re.compile(
                    rf"""{re.escape(obj)}\.({http})\s*\(\s*["']([^"']+)["']""",
                    re.IGNORECASE,
                )
                for i, line in enumerate(content.splitlines(), 1):
                    m = pat.search(line)
                    if not m:
                        continue
                    handler = ""
                    hm = re.search(
                        r""",\s*(\w+)\s*\)""", line[m.end() :] if m.end() < len(line) else line
                    )
                    if hm:
                        handler = hm.group(1)
                    routes.append(
                        self._make_route(
                            m.group(1).upper(),
                            m.group(2),
                            handler,
                            file_path,
                            i,
                            framework=framework,
                        )
                    )
        return routes
