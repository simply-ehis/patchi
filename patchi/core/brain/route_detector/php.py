import logging
import re

from patchi.core.brain.route_detector.base import BaseRouteDetector
from patchi.core.brain.route_detector.registry import register_detector

_PHP_METHODS = {"get", "post", "put", "delete", "patch", "any", "match", "resource", "apiresource"}


_log = logging.getLogger("patchi.brain.php")


@register_detector("php")
class PhpRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes = self._detect_ts(content, file_path)
        if routes:
            return routes
        return self._detect_fallback(content, file_path)

    def _detect_ts(self, content: str, file_path: str) -> list[dict] | None:
        try:
            from patchi.core.brain.languages import Lang, _build_parser

            parser = _build_parser(Lang.PHP)
            tree = parser.parse(bytes(content, "utf-8"))
        except Exception as e:
            _log.warning("PhpRouteDetector._detect_ts failed: %s", e)
            return None

        routes: list[dict] = []
        self._walk(tree.root_node, bytes(content, "utf-8"), content, file_path, routes)
        return routes

    def _walk(
        self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]
    ) -> None:
        ntype = getattr(node, "type", "")
        if ntype in ("scoped_call_expression", "function_call_expression"):
            self._check_call(node, buf, content, file_path, routes)
        for child in getattr(node, "named_children", None) or getattr(node, "children", []):
            self._walk(child, buf, content, file_path, routes)

    def _check_call(
        self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]
    ) -> None:
        func = self._child_by_field(node, "function")
        if func is None:
            return
        ftype = getattr(func, "type", "")

        if ftype == "name":
            fn_name = self._node_text(func)
        elif ftype == "scoped_property_access_expression":
            scope = self._child_by_field(func, "scope")
            name = self._child_by_field(func, "member")
            if scope is None or name is None:
                return
            scope_text = self._node_text(scope)
            if scope_text != "Route":
                return
            fn_name = self._node_text(name)
        else:
            return

        method = fn_name.lower()
        if method not in _PHP_METHODS:
            return

        args = self._child_by_field(node, "arguments")
        path = ""
        handler = ""

        if args:
            for child in getattr(args, "named_children", None) or getattr(args, "children", []):
                if child.type in ("string", "string_literal", "encapsed_string"):
                    raw = self._node_text(child).strip("'\"")
                    if not path:
                        path = raw
                    elif not handler and "@" in raw:
                        handler = raw
                elif child.type == "class_constant_access_expression" and not handler:
                    handler = self._node_text(child)

        if not path:
            return

        line = getattr(node, "start_point", (0, 0))[0] + 1

        auth = self._check_auth(node, buf, content)

        routes.append(
            self._make_route(
                method.upper(),
                path,
                handler,
                file_path,
                line,
                framework="Laravel",
                auth_required=auth if auth else None,
            )
        )

    def _check_auth(self, node: object, buf: bytes, content: str) -> bool:
        try:
            text = self._node_text(node)
            if "->middleware" in text and "'auth'" in text:
                return True
        except Exception as e:
            _log.warning("PhpRouteDetector._check_auth failed: %s", e)
        return False

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
            _log.debug("PhpRouteDetector._node_text failed: %s", e)
            return ""

    def _detect_fallback(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        http = "|".join(_PHP_METHODS)
        pat = re.compile(
            rf"""Route::({http})\s*\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        )
        auth_pat = re.compile(r"""->middleware\s*\(\s*['"]auth""")
        for i, line in enumerate(content.splitlines(), 1):
            m = pat.search(line)
            if not m:
                continue
            method = m.group(1).upper()
            path = m.group(2)
            auth = bool(auth_pat.search(line))
            handler = ""
            hm = re.search(r"""['"](\w+@\w+)['"]|(\w+Controller)::class""", line)
            if hm:
                handler = hm.group(1) or hm.group(2)
            routes.append(
                self._make_route(
                    method,
                    path,
                    handler,
                    file_path,
                    i,
                    framework="Laravel",
                    auth_required=auth if auth else None,
                )
            )
        return routes
