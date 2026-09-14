import ast

from patchi.core.brain.route_detector.base import BaseRouteDetector
from patchi.core.brain.route_detector.registry import register_detector

_FASTAPI_METHODS = {
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "websocket",
    "api_route",
}
_FLASK_METHODS = {"route"}
_DJANGO_ROUTERS = {"path", "re_path", "url"}


@register_detector("python")
class PythonRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    route = self._check_fastapi_decorator(dec, node, file_path, content)
                    if route:
                        routes.append(route)
                        continue
                    flask_routes = self._check_flask_decorator(dec, node, file_path, content)
                    if flask_routes:
                        routes.extend(flask_routes)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._get_name(node.func) in _DJANGO_ROUTERS:
                route = self._check_django_call(node, file_path)
                if route:
                    routes.append(route)

        return routes

    def _check_fastapi_decorator(self, dec: ast.AST, func: ast.AST, file_path: str, content: str) -> dict | None:
        if not isinstance(dec, ast.Call):
            return None
        fn = self._get_dotted_name(dec.func)
        if not fn:
            return None

        parts = fn.split(".")
        method = parts[-1].lower() if len(parts) >= 2 else ""
        if method not in _FASTAPI_METHODS:
            return None

        path = ""
        if dec.args:
            path = self._get_str(dec.args[0])
        if not path:
            for kw in dec.keywords or []:
                if kw.arg == "path":
                    path = self._get_str(kw.value)

        if not path:
            return None

        if method == "api_route":
            methods = "ANY"
            for kw in dec.keywords or []:
                if kw.arg == "methods" and isinstance(kw.value, ast.List):
                    ms = [self._get_str(el).upper() for el in kw.value.elts if self._get_str(el)]
                    methods = ",".join(ms) if ms else "ANY"
            method_str = methods
        else:
            method_str = method.upper()

        auth = self._check_auth_defaults(func)

        return self._make_route(
            method_str,
            path,
            func.name,
            file_path,
            func.lineno,
            framework="FastAPI",
            auth_required=auth if auth else None,
        )

    def _check_flask_decorator(self, dec: ast.AST, func: ast.AST, file_path: str, content: str) -> list[dict] | None:
        if not isinstance(dec, ast.Call):
            return None
        fn = self._get_dotted_name(dec.func)
        if not fn:
            return None
        parts = fn.split(".")
        if len(parts) < 2 or parts[-1].lower() not in _FLASK_METHODS:
            return None

        path = self._get_str(dec.args[0]) if dec.args else ""
        if not path:
            return None

        methods = ["GET"]
        for kw in dec.keywords or []:
            if kw.arg == "methods" and isinstance(kw.value, ast.List):
                methods = [self._get_str(el) for el in kw.value.elts if self._get_str(el)]

        auth = self._check_auth_defaults(func)

        return [
            self._make_route(
                m.upper(),
                path,
                func.name,
                file_path,
                func.lineno,
                framework="Flask",
                auth_required=auth if auth else None,
            )
            for m in methods
        ]

    def _check_django_call(self, node: ast.Call, file_path: str) -> dict | None:
        path = self._get_str(node.args[0]) if node.args else ""
        if not path:
            return None
        handler = ""
        if len(node.args) >= 2:
            arg = node.args[1]
            handler = self._get_dotted_name(arg)
            if not handler and isinstance(arg, ast.Call):
                handler = self._get_dotted_name(arg.func)
        return self._make_route(
            "ANY",
            path,
            handler,
            file_path,
            node.lineno if hasattr(node, "lineno") else 0,
            framework="Django",
        )

    def _get_dotted_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = self._get_dotted_name(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        if isinstance(node, ast.Call):
            return self._get_dotted_name(node.func)
        if isinstance(node, ast.Subscript):
            return self._get_dotted_name(node.value)
        return ""

    def _get_name(self, node: ast.AST) -> str:
        return node.id if isinstance(node, ast.Name) else ""

    def _get_str(self, node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Str):
            return node.s
        return ""

    def _check_auth_defaults(self, func: ast.AST) -> bool:
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        for dec in func.decorator_list:
            dn = self._get_dotted_name(dec)
            if dn and "login_required" in dn:
                return True
            if isinstance(dec, ast.Call):
                cname = self._get_dotted_name(dec.func)
                if cname and "login_required" in cname:
                    return True
        for arg in func.args.args:
            idx = func.args.args.index(arg)
            defaults_offset = len(func.args.defaults) - len(func.args.args)
            if defaults_offset <= idx < len(func.args.defaults):
                default = func.args.defaults[idx]
                if isinstance(default, ast.Call):
                    callee = self._get_dotted_name(default.func)
                    if callee and "Depends" in callee:
                        return True
        return False
