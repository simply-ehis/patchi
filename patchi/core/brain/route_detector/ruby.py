import logging
import re

from patchi.core.brain.route_detector.base import BaseRouteDetector
from patchi.core.brain.route_detector.registry import register_detector

_RUBY_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "resources"}


_log = logging.getLogger("patchi.brain.ruby")


@register_detector("ruby")
class RubyRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes = self._detect_ts(content, file_path)
        if routes:
            return routes
        return self._detect_fallback(content, file_path)

    def _detect_ts(self, content: str, file_path: str) -> list[dict] | None:
        try:
            from patchi.core.brain.languages import Lang, _build_parser

            parser = _build_parser(Lang.RUBY)
            tree = parser.parse(bytes(content, "utf-8"))
        except Exception as e:
            _log.warning("RubyRouteDetector._detect_ts failed: %s", e)
            return None

        routes: list[dict] = []
        self._walk(tree.root_node, bytes(content, "utf-8"), content, file_path, routes)
        return routes

    def _walk(
        self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]
    ) -> None:
        ntype = getattr(node, "type", "")
        if ntype == "call":
            self._check_call(node, buf, content, file_path, routes)
        for child in getattr(node, "named_children", None) or getattr(node, "children", []):
            self._walk(child, buf, content, file_path, routes)

    def _check_call(
        self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]
    ) -> None:
        method_node = self._child_by_field(node, "method")
        if method_node is None:
            return
        method_name = self._node_text(method_node).lower()
        if method_name not in _RUBY_HTTP_METHODS:
            return

        args = self._child_by_field(node, "arguments")
        path = ""
        handler = ""
        framework = "Ruby on Rails"

        if args:
            for child in getattr(args, "named_children", None) or getattr(args, "children", []):
                if child.type in ("string", "simple_symbol"):
                    raw = self._node_text(child).strip("':\"")
                    if not path:
                        path = raw
                    elif not handler and "@" in raw:
                        handler = raw
                elif child.type == "hash" and method_name == "resources":
                    pass

        if not path:
            return

        if method_name == "resources":
            method_str = "GET"
            route_path = f"/{path}"
        else:
            method_str = method_name.upper()
            route_path = path if path.startswith("/") else f"/{path}"

        line = getattr(node, "start_point", (0, 0))[0] + 1
        routes.append(
            self._make_route(method_str, route_path, handler, file_path, line, framework=framework)
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
            _log.debug("RubyRouteDetector._node_text failed: %s", e)
            return ""

    def _detect_fallback(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        lines = content.splitlines()

        rails_pat = re.compile(
            r"""(get|post|put|patch|delete|resources)\s+[":']([^":']+)[":']""", re.IGNORECASE
        )
        for i, line in enumerate(lines, 1):
            m = rails_pat.search(line)
            if not m:
                continue
            verb = m.group(1).upper()
            path = m.group(2)
            if verb == "RESOURCES":
                verb = "GET"
                route_path = f"/{path}"
            else:
                route_path = path if path.startswith("/") else f"/{path}"
            routes.append(
                self._make_route(verb, route_path, "", file_path, i, framework="Ruby on Rails")
            )

        sinatra_pat = re.compile(
            r"""^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"]""", re.IGNORECASE
        )
        for i, line in enumerate(lines, 1):
            m = sinatra_pat.search(line)
            if m:
                routes.append(
                    self._make_route(
                        m.group(1).upper(), m.group(2), "", file_path, i, framework="Sinatra"
                    )
                )

        return routes
