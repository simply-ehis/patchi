import logging
import re

from patchi.core.brain.route_detector.base import BaseRouteDetector
from patchi.core.brain.route_detector.registry import register_detector

_SPRING_MAPPINGS = {
    "getmapping": "GET",
    "postmapping": "POST",
    "putmapping": "PUT",
    "deletemapping": "DELETE",
    "patchmapping": "PATCH",
    "requestmapping": "ANY",
}
_SPRING_AUTH_ANNOTATIONS = {"preauthorize", "secured", "rolesallowed"}


_log = logging.getLogger("patchi.brain.java")


@register_detector("java")
class JavaRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes = self._detect_ts(content, file_path)
        if routes:
            return routes
        return self._detect_fallback(content, file_path)

    def _detect_ts(self, content: str, file_path: str) -> list[dict] | None:
        try:
            from patchi.core.brain.languages import Lang, _build_parser

            parser = _build_parser(Lang.JAVA)
            tree = parser.parse(bytes(content, "utf-8"))
        except Exception as e:
            _log.warning("JavaRouteDetector._detect_ts failed: %s", e)
            return None

        routes: list[dict] = []
        self._walk(tree.root_node, bytes(content, "utf-8"), content, file_path, routes)
        return routes

    def _walk(
        self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]
    ) -> None:
        ntype = getattr(node, "type", "")
        if ntype in ("marker_annotation", "annotation"):
            self._check_annotation(node, buf, content, file_path, routes)

        for child in getattr(node, "named_children", None) or getattr(node, "children", []):
            self._walk(child, buf, content, file_path, routes)

    def _check_annotation(
        self, node: object, buf: bytes, content: str, file_path: str, routes: list[dict]
    ) -> None:
        name_node = self._child_by_field(node, "name") or node
        try:
            ann_name = self._node_text(name_node).lower()
        except Exception as e:
            _log.warning("JavaRouteDetector._check_annotation failed: %s", e)
            return

        method = _SPRING_MAPPINGS.get(ann_name)
        if method is None:
            return

        path = ""
        args_node = self._child_by_field(node, "arguments")
        if args_node:
            try:
                for child in getattr(args_node, "named_children", None) or getattr(
                    args_node, "children", []
                ):
                    if child.type in ("string_literal", "string"):
                        raw = self._node_text(child)
                        path = raw.strip('"')
                        break
            except Exception as e:
                _log.warning("JavaRouteDetector._check_annotation failed: %s", e)

        if not path:
            path = ""

        handler = self._find_method_name(node)
        line = getattr(node, "start_point", (0, 0))[0] + 1

        auth = self._check_auth_annotations(node)

        routes.append(
            self._make_route(
                method,
                path,
                handler,
                file_path,
                line,
                framework="Spring Boot",
                auth_required=auth if auth else None,
            )
        )

    def _find_method_name(self, node: object) -> str:
        cur = node
        for _ in range(10):
            cur = getattr(cur, "parent", None)
            if cur is None:
                break
            if getattr(cur, "type", "") == "method_declaration":
                name_node = self._child_by_field(cur, "name")
                if name_node:
                    return self._node_text(name_node)
        return ""

    def _check_auth_annotations(self, node: object) -> bool:
        cur = node
        for _ in range(15):
            cur = getattr(cur, "parent", None)
            if cur is None:
                break
            if getattr(cur, "type", "") == "class_declaration":
                for child in getattr(cur, "named_children", None) or getattr(cur, "children", []):
                    if child.type in ("marker_annotation", "annotation"):
                        try:
                            name = self._node_text(
                                self._child_by_field(child, "name") or child
                            ).lower()
                            if any(a in name for a in _SPRING_AUTH_ANNOTATIONS):
                                return True
                        except Exception as e:
                            _log.warning("JavaRouteDetector._check_auth_annotations failed: %s", e)
                break
        for child in getattr(node, "named_children", None) or getattr(node, "children", []):
            if child.type in ("marker_annotation", "annotation"):
                try:
                    name = self._node_text(self._child_by_field(child, "name") or child).lower()
                    if name in _SPRING_AUTH_ANNOTATIONS:
                        return True
                except Exception as e:
                    _log.warning("JavaRouteDetector._check_auth_annotations failed: %s", e)
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
            _log.debug("JavaRouteDetector._node_text failed: %s", e)
            return ""

    def _detect_fallback(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        ann_names = "|".join(_SPRING_MAPPINGS)
        pat = re.compile(
            rf"""@({ann_names})\s*\(\s*["']([^"']+)["']""",
            re.IGNORECASE,
        )
        auth_pat = re.compile(r"@PreAuthorize|@Secured|@RolesAllowed", re.IGNORECASE)

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            m = pat.search(line)
            if not m:
                continue
            method_str = m.group(1).upper()
            path = m.group(2)
            method = "ANY" if method_str == "REQUESTMAPPING" else method_str.replace("MAPPING", "")

            handler = ""
            for j in range(i, min(i + 5, len(lines) + 1)):
                hm = re.match(r"\s*(?:public\s+)?\w+\s+(\w+)\s*\(", lines[j - 1])
                if hm:
                    handler = hm.group(1)
                    break

            ctx = "\n".join(lines[i : min(i + 5, len(lines))])
            auth = bool(auth_pat.search(ctx))

            routes.append(
                self._make_route(
                    method,
                    path,
                    handler,
                    file_path,
                    i,
                    framework="Spring Boot",
                    auth_required=auth if auth else None,
                )
            )
        return routes
