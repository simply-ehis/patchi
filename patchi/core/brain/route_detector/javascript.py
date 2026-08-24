import re

from patchi.core.brain.route_detector.registry import register_detector
from patchi.core.brain.route_detector.base import BaseRouteDetector

_AUTH_MIDDLEWARE = {"auth", "authenticate", "requireauth", "verifytoken", "isauthenticated"}

_EXPRESS_OBJECTS = {"app", "router", "route"}
_FASTIFY_OBJECTS = {"fastify"}
_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "all", "use", "head", "options"}


import logging
_log = logging.getLogger("patchi.brain.javascript")

@register_detector("javascript")
@register_detector("typescript")
class JavaScriptRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes = self._detect_ts(content, file_path)
        if routes:
            return routes

        routes = self._detect_ts_fallback(content, file_path)
        return routes

    def _detect_ts(self, content: str, file_path: str) -> list[dict] | None:
        try:
            from patchi.core.brain.languages import Lang, _build_parser

            parser = _build_parser(Lang.TYPESCRIPT)
            tree = parser.parse(bytes(content, "utf-8"))
        except Exception as e:
            _log.warning("JavaScriptRouteDetector._detect_ts failed: %s", e)
            return None

        routes: list[dict] = []
        self._walk(tree.root_node, bytes(content, "utf-8"), content, file_path, routes)
        return routes

    def _walk(self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]) -> None:
        ntype = getattr(node, "type", "")
        if ntype == "call_expression":
            self._check_call(node, buf, content, file_path, routes)

        for child in (getattr(node, "named_children", None) or getattr(node, "children", [])):
            self._walk(child, buf, content, file_path, routes)

    def _check_call(self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]) -> None:
        func = self._child_by_field(node, "function")
        if func is None:
            return

        obj_name, method_name = self._get_member_expression(func)
        if obj_name is None or method_name is None:
            return

        method_lower = method_name.lower()
        if method_lower not in _HTTP_METHODS:
            return

        if obj_name in _EXPRESS_OBJECTS:
            framework = "Express"
        elif obj_name in _FASTIFY_OBJECTS:
            framework = "Fastify"
        else:
            return

        args = self._child_by_field(node, "arguments")
        path = ""
        if args and getattr(args, "named_child_count", 0) > 0:
            first_arg = args.named_child(0)
            if first_arg and first_arg.type in ("string", "template_string", "string_fragment"):
                try:
                    raw = buf[first_arg.start_byte:first_arg.end_byte].decode("utf-8", errors="replace")
                    path = raw.strip("'\"`")
                except Exception as e:
                    _log.warning("JavaScriptRouteDetector._check_call failed: %s", e)
                    path = ""

        if not path:
            return

        handler = self._extract_handler(args, buf, content) if args else ""
        line = getattr(node, "start_point", (0, 0))[0] + 1
        auth = self._check_auth(args, content) if args else False

        routes.append(self._make_route(
            method=method_lower.upper(),
            path=path,
            handler=handler,
            file_path=file_path,
            line=line,
            framework=framework,
            auth_required=auth if auth else None,
        ))

    def _get_member_expression(self, func: object) -> tuple[str | None, str | None]:
        ftype = getattr(func, "type", "")
        if ftype == "member_expression":
            obj = self._child_by_field(func, "object")
            prop = self._child_by_field(func, "property")
            if obj and prop:
                obj_name = self._node_text(obj) if hasattr(obj, "text") else ""
                prop_name = self._node_text(prop) if hasattr(prop, "text") else ""
                return obj_name, prop_name
        return None, None

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
            _log.debug("JavaScriptRouteDetector._node_text failed: %s", e)
            return ""

    def _extract_handler(self, args: object, buf: bytes, content: str) -> str:
        try:
            for i in range(getattr(args, "named_child_count", 0)):
                child = args.named_child(i)
                if child and child.type == "identifier":
                    return self._node_text(child)
            for i in range(getattr(args, "named_child_count", 0)):
                child = args.named_child(i)
                if child and child.type == "arrow_function":
                    parent = getattr(child, "parent", None)
                    if parent and parent.type == "variable_declarator":
                        name_node = self._child_by_field(parent, "name")
                        if name_node:
                            return self._node_text(name_node)
        except Exception as e:
            _log.warning("JavaScriptRouteDetector._extract_handler failed: %s", e)
        return ""

    def _check_auth(self, args: object, content: str) -> bool:
        try:
            for i in range(getattr(args, "named_child_count", 0)):
                child = args.named_child(i)
                if child and child.type == "identifier":
                    name = self._node_text(child).lower()
                    if name in _AUTH_MIDDLEWARE:
                        return True
        except Exception as e:
            _log.warning("JavaScriptRouteDetector._check_auth failed: %s", e)
        return False

    def _detect_ts_fallback(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        for obj in _EXPRESS_OBJECTS | _FASTIFY_OBJECTS:
            framework = "Express" if obj in _EXPRESS_OBJECTS else "Fastify"
            pat = re.compile(
                rf"""{re.escape(obj)}\.({"|".join(_HTTP_METHODS)})\s*\(\s*["'`]([^"'`]+)["'`]""",
                re.IGNORECASE,
            )
            for i, line in enumerate(content.splitlines(), 1):
                m = pat.search(line)
                if not m:
                    continue
                method = m.group(1).upper()
                path = m.group(2)
                handler = ""
                hm = re.search(r""",\s*(?:async\s+)?(\w+)\s*\)?\s*$""", line)
                if hm and hm.group(1) not in {"function", "async", "req", "res", "next"}:
                    handler = hm.group(1)
                auth = bool(re.search(r"(?:auth|authenticate|requireAuth|verifyToken|isAuthenticated)", line))
                routes.append(self._make_route(method, path, handler, file_path, i, framework=framework, auth_required=auth if auth else None))
        return routes
