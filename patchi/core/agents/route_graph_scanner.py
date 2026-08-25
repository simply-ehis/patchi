"""
RouteGraphScanner — framework-aware route extraction.

Detects and extracts routes from various frameworks:
- Express.js: app.get/post/put/delete/use() calls
- FastAPI: @app.get/post/put/delete() decorators
- Flask: @app.route() decorators
- Django: urlpatterns list entries
- Next.js: pages/ and app/ directory structure
- Spring Boot: @GetMapping/@PostMapping annotations
- ASP.NET Core: [HttpGet]/[HttpPost] attributes
- Ruby on Rails: routes.rb definitions

Extracts:
- HTTP method
- Route path
- Handler function name
- Middleware chain
- Authentication status

Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import ast as py_ast
import logging
import re
from pathlib import Path
from typing import Any

from ..brain.languages import Lang, detect_language, get_parser, parse_source
from .base import (
    _SKIP_DIRS,
    _SKIP_FILES,
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

_log = logging.getLogger("patchi.agents.route_graph_scanner")


@register
class RouteGraphScanner(BaseAgent):
    """Scanner for web framework routes."""

    group = AgentGroup.SCANNER
    name = "RouteGraphScanner"
    description = "Framework-aware route extraction"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan for routes in web framework files."""
        findings = []

        # Define route file patterns
        route_patterns = [
            # JavaScript/TypeScript (Express, Next.js, etc.)
            "*.js",
            "*.jsx",
            "*.ts",
            "*.tsx",
            "**/routes/**",
            "**/api/**",
            "**/pages/**",
            "**/app/**",
            # Python (FastAPI, Flask, Django)
            "*.py",
            "**/urls.py",
            "**/views.py",
            "**/routes.py",
            "**/api/**",
            # Java (Spring Boot)
            "*.java",
            # Ruby (Rails)
            "*.rb",
            "routes.rb",
            # PHP (Laravel, Symfony)
            "*.php",
            # C# (ASP.NET)
            "*.cs",
        ]

        # Search for route files and avoid scanning the same file twice
        scanned_files = set()
        # ponytail: rglob traverses node_modules (30k+ files). Walk with pruning.
        import fnmatch
        import os

        for dirpath, dirnames, filenames in os.walk(inp.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            rel_dir = Path(dirpath).relative_to(inp.root).as_posix()
            for fname in filenames:
                if fname in _SKIP_FILES:
                    continue
                for pattern in route_patterns:
                    if "**" in pattern:
                        parts = pattern.split("/")
                        if len(parts) == 1:
                            if fnmatch.fnmatch(fname, parts[0]):
                                break
                        else:
                            mid = parts[1] if len(parts) > 2 else None
                            if mid and mid in rel_dir.split("/"):
                                break
                    else:
                        if fnmatch.fnmatch(fname, pattern):
                            break
                else:
                    continue
                file_path = Path(dirpath) / fname
                rel_path = f"{rel_dir}/{fname}" if rel_dir != "." else fname
                if rel_path not in scanned_files:
                    scanned_files.add(rel_path)
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_route_file(file_path, rel_path))

        # Get only the route findings
        route_findings = [f for f in findings if f.type.startswith("route_")]

        # Guard at top: if no routes found, return early
        if not route_findings:
            result.status = AgentStatus.SUCCEEDED
            result.findings = findings
            result.data.update(
                {
                    "routes_found": 0,
                    "route_map": {},
                    "framework_detected": self._detect_framework(inp),
                    "needs_ai": False,
                }
            )
            return

        findings.extend(self._detect_sensitive_routes(route_findings))
        route_map = self._build_route_map(route_findings)

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "routes_found": len(route_findings),
                "route_map": route_map,
                "framework_detected": self._detect_framework(inp),
                "needs_ai": False,
            }
        )
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        from pathlib import PurePosixPath

        p = PurePosixPath(file_path)
        if any(s in p.parts for s in _SKIP_DIRS):
            return True
        if p.name in _SKIP_FILES:
            return True

        # Check restrictions
        restrictions = inp.config.get("restrictions", [])
        for r in restrictions:
            if r.get("enabled", True):
                path = r["path"]
                if file_path.startswith(path) or PurePosixPath(file_path).match(path):
                    if r["type"] == "NO_TOUCH":
                        return True
                    elif r["type"] == "SCAN_ONLY" and self.__class__.__name__ == "FixAgent":
                        return True
        return False

    def _scan_route_file(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan a file for routes."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")
            lang = detect_language(file_path)

            if lang in [Lang.JAVASCRIPT, Lang.TYPESCRIPT]:
                findings.extend(self._scan_js_routes(content, rel_path))
            elif lang == Lang.PYTHON:
                findings.extend(self._scan_py_routes(content, rel_path))
            elif lang == Lang.JAVA:
                findings.extend(self._scan_java_routes(content, rel_path))
            elif lang == Lang.RUBY:
                findings.extend(self._scan_ruby_routes(content, rel_path))
            elif lang == Lang.PHP:
                findings.extend(self._scan_php_routes(content, rel_path))
            elif lang == Lang.C_SHARP:
                findings.extend(self._scan_cs_routes(content, rel_path))

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Route file read error",
                    description=f"Could not read route file {file_path.name}: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_py_routes(self, content: str, rel_path: str) -> list[Finding]:
        """Scan Python files for routes (Flask, FastAPI, Django) using AST parsing."""
        findings = []

        try:
            tree = py_ast.parse(content)
        except SyntaxError:
            # If AST parsing fails, fall back to basic pattern matching
            return self._scan_py_routes_fallback(content, rel_path)

        for node in py_ast.walk(tree):
            # FastAPI patterns - look for decorator calls like @app.get("/path")
            if isinstance(node, py_ast.FunctionDef) and node.decorator_list:
                for decorator in node.decorator_list:
                    if isinstance(decorator, py_ast.Call) and isinstance(
                        decorator.func, py_ast.Attribute
                    ):
                        func_attr = decorator.func.attr
                        if func_attr in [
                            "get",
                            "post",
                            "put",
                            "delete",
                            "patch",
                            "options",
                            "head",
                            "trace",
                        ]:
                            # Check if this is a FastAPI app method
                            if isinstance(
                                decorator.func.value, py_ast.Name
                            ) and decorator.func.value.id in ["app", "router"]:
                                # Extract the route path from the decorator arguments
                                path_arg = None
                                if decorator.args:
                                    # First argument should be the path
                                    first_arg = decorator.args[0]
                                    if isinstance(first_arg, py_ast.Constant):
                                        path_arg = first_arg.value
                                    elif isinstance(first_arg, py_ast.Str):  # Python < 3.8
                                        path_arg = first_arg.s

                                if path_arg:
                                    findings.append(
                                        make_finding(
                                            severity=Severity.INFO,
                                            file=rel_path,
                                            line_start=node.lineno,
                                            title=f"Route: {func_attr.upper()} {path_arg} (FastAPI)",
                                            description=f"FastAPI HTTP {func_attr.upper()} route: {path_arg}",
                                            evidence=f"@app.{func_attr}('{path_arg}')",
                                        )
                                    )

            # Flask patterns - look for @app.route decorator
            elif isinstance(node, py_ast.FunctionDef) and node.decorator_list:
                for decorator in node.decorator_list:
                    if (
                        isinstance(decorator, py_ast.Call)
                        and isinstance(decorator.func, py_ast.Attribute)
                        and isinstance(decorator.func.value, py_ast.Name)
                        and decorator.func.value.id == "app"
                        and decorator.func.attr == "route"
                    ):
                        # Extract the route path from the decorator arguments
                        path_arg = None
                        if decorator.args:
                            first_arg = decorator.args[0]
                            if isinstance(first_arg, py_ast.Constant):
                                path_arg = first_arg.value
                            elif isinstance(first_arg, py_ast.Str):  # Python < 3.8
                                path_arg = first_arg.s

                        if path_arg:
                            # Check for methods in keyword arguments
                            methods = ["GET"]  # Default for Flask
                            for keyword in decorator.keywords:
                                if keyword.arg == "methods" and isinstance(
                                    keyword.value, py_ast.List
                                ):
                                    for elt in keyword.value.elts:
                                        if isinstance(elt, py_ast.Constant):
                                            methods.append(elt.value)
                                        elif isinstance(elt, py_ast.Str):  # Python < 3.8
                                            methods.append(elt.s)

                            method_str = ", ".join(methods)
                            findings.append(
                                make_finding(
                                    severity=Severity.INFO,
                                    file=rel_path,
                                    line_start=node.lineno,
                                    title=f"Route: {method_str} {path_arg} (Flask)",
                                    description=f"Flask HTTP {method_str} route: {path_arg}",
                                    evidence=f"@app.route('{path_arg}')",
                                )
                            )

        return findings

    def _scan_py_routes_fallback(self, content: str, rel_path: str) -> list[Finding]:
        """Fallback regex-based scanning for Python routes."""
        findings = []

        # FastAPI patterns
        fastapi_methods = ["get", "post", "put", "delete", "patch", "options", "head", "trace"]
        for method in fastapi_methods:
            pattern = rf'@app\.{method}\s*\(\s*["\']([^"\']*)["\']'
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                path = match.group(1)
                line_start = content[: match.start()].count("\n") + 1

                findings.append(
                    make_finding(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=line_start,
                        title=f"Route: {method.upper()} {path} (FastAPI)",
                        description=f"FastAPI HTTP {method.upper()} route: {path}",
                        evidence=match.group(0)[:100],
                    )
                )

        # Flask patterns
        flask_route_pattern = r'@app\.route\s*\(\s*["\']([^"\']*)["\']'
        flask_matches = re.finditer(flask_route_pattern, content, re.MULTILINE)
        for match in flask_matches:
            path = match.group(1)
            line_start = content[: match.start()].count("\n") + 1

            # Check if there are method restrictions
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
            method_matches = []
            for method in methods:
                if (
                    f"methods=['{method}']" in content[match.start() : match.start() + 200]
                    or f'methods=["{method}"]' in content[match.start() : match.start() + 200]
                ):
                    method_matches.append(method)

            if method_matches:
                method_str = ", ".join(method_matches)
            else:
                method_str = "GET"  # Default for Flask routes

            findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file=rel_path,
                    line_start=line_start,
                    title=f"Route: {method_str} {path} (Flask)",
                    description=f"Flask HTTP {method_str} route: {path}",
                    evidence=match.group(0)[:100],
                )
            )

        # Django patterns - look for url patterns
        django_patterns = [
            r"url\s*\(\s*['\"]([^'\"]*?)['\"]\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*[.])*([a-zA-Z_][a-zA-Z0-9_]*)",
            r"path\s*\(\s*['\"]([^'\"]*?)['\"]\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*[.])*([a-zA-Z_][a-zA-Z0-9_]*)",
        ]

        for pattern in django_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                path = match.group(1) if len(match.groups()) >= 1 else "dynamic"
                handler = match.group(3) if len(match.groups()) >= 3 else "unknown"
                line_start = content[: match.start()].count("\n") + 1

                findings.append(
                    make_finding(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=line_start,
                        title=f"Route: * {path} (Django) -> {handler}",
                        description=f"Django route: {path} handled by {handler}",
                        evidence=match.group(0)[:100],
                    )
                )

        return findings

    def _detect_sensitive_routes(self, route_findings: list[Finding]) -> list[Finding]:
        """Detect unprotected sensitive routes like login/auth endpoints."""
        findings: list[Finding] = []

        # Only check actual route findings (not all findings)
        for finding in route_findings:
            # Extract route path from the finding title or description
            # Look for patterns like "Route: METHOD /path (Framework)"
            route_match = re.search(
                r"Route:\s*(?:([A-Z]+(?:,\s*[A-Z]+)*)\s+)?(/[-_a-zA-Z0-9/{}:.*\[\]]+)",
                finding.title,
                re.IGNORECASE,
            )

            if route_match:
                methods_part = route_match.group(1)
                path = route_match.group(2).lower()

                # Determine methods if not specified
                methods = [m.strip() for m in methods_part.split(",")] if methods_part else ["GET"]

                # Check if the path contains sensitive keywords
                sensitive_keywords = [
                    "/auth",
                    "/login",
                    "/signin",
                    "/signup",
                    "/register",
                    "/password",
                    "/admin",
                    "/dashboard",
                ]

                for keyword in sensitive_keywords:
                    if keyword in path:
                        for method in methods:
                            method_upper = method.strip().upper()
                            # Flag sensitive routes that use unsafe methods
                            if method_upper in {"POST", "PUT", "PATCH", "DELETE"}:
                                findings.append(
                                    make_finding(
                                        severity=Severity.MEDIUM,
                                        finding_type="unprotected_sensitive_route",
                                        file=finding.file,
                                        line_start=finding.line,
                                        title=f"Unprotected sensitive route: {method_upper} {path}",
                                        description=f"Sensitive route {path} with potentially unsafe HTTP method {method_upper} appears unprotected",
                                        evidence=finding.title,
                                    )
                                )
                        break  # Break to avoid duplicate checks for the same path

        return findings

    def _build_route_map(self, route_findings: list[Finding]) -> dict:
        """Build a map of routes for analysis."""
        route_map = {}
        for finding in route_findings:
            route_match = re.search(
                r"Route:\s*(?:([A-Z]+(?:,\s*[A-Z]+)*)\s+)?(/[-_a-zA-Z0-9/{}:.*\[\]]+)",
                finding.title,
                re.IGNORECASE,
            )
            if route_match:
                methods_part = route_match.group(1)
                path = route_match.group(2)
                methods = [m.strip() for m in methods_part.split(",")] if methods_part else ["GET"]

                route_map[path] = {
                    "methods": methods,
                    "file": finding.file,
                    "line": finding.line,
                    "framework": finding.title.split("(")[-1].split(")")[0]
                    if "(" in finding.title
                    else "unknown",
                }
        return route_map

    def _detect_framework(self, inp: AgentInput) -> str:
        """Detect the web framework used in the project."""
        # Look for framework-specific files
        framework_indicators = {
            "FastAPI": ["main.py", "app.py"],
            "Flask": ["app.py", "application.py"],
            "Django": ["manage.py", "settings.py"],
            "Express.js": ["server.js", "app.js"],
            "Next.js": ["next.config.js", "pages/", "app/"],
            "Spring Boot": ["pom.xml", "build.gradle", "Application.java"],
        }

        for framework, indicators in framework_indicators.items():
            for indicator in indicators:
                if (inp.root / indicator).exists() or any(safe_rglob(inp.root, indicator)):
                    return framework

        return "unknown"

    def _scan_js_routes(self, content: str, rel_path: str) -> list[Finding]:
        """Scan JavaScript/TypeScript files for routes using tree-sitter AST."""
        findings: list[Finding] = []

        parser = get_parser(Lang.JAVASCRIPT)
        if parser is None:
            return self._scan_js_routes_regex(content, rel_path)

        try:
            tree = parse_source(Lang.JAVASCRIPT, content)
            buf = content.encode("utf-8")
            self._walk_js_route_node(tree.root_node, buf, content, rel_path, findings, None)
        except Exception as e:
            _log.warning("RouteGraphScanner._scan_js_routes failed: %s", e)
            return self._scan_js_routes_regex(content, rel_path)

        return findings

    def _scan_js_routes_regex(self, content: str, rel_path: str) -> list[Finding]:
        """Regex fallback for JS/TS routes."""
        findings = []
        for pattern, framework in [
            (
                r'app\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']*)["\']',
                "Express.js",
            ),
            (
                r'router\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']*)["\']',
                "Express.js Router",
            ),
            (
                r'fastify\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']*)["\']',
                "Fastify",
            ),
        ]:
            for m in re.finditer(pattern, content, re.MULTILINE):
                findings.append(
                    self._make_route_finding(
                        rel_path, content, m, m.group(1).upper(), m.group(2), framework
                    )
                )
        return findings

    def _walk_js_route_node(
        self,
        node: Any,
        buf: bytes,
        content: str,
        rel_path: str,
        findings: list[Finding],
        current_obj: str | None,
    ) -> None:
        ntype = node.type

        if ntype == "call_expression":
            method = ""
            path = ""
            obj = ""

            for child in node.children:
                if child.type == "member_expression":
                    for sub in child.children:
                        if sub.type == "identifier":
                            obj = (
                                buf[sub.start_byte : sub.end_byte].decode()
                                if hasattr(sub, "start_byte")
                                else ""
                            )
                        elif sub.type == "property_identifier":
                            method = (
                                buf[sub.start_byte : sub.end_byte].decode()
                                if hasattr(sub, "start_byte")
                                else ""
                            )
                elif child.type == "arguments":
                    for arg in child.children:
                        if arg.type == "string":
                            path = (
                                buf[arg.start_byte : arg.end_byte].decode()
                                if hasattr(arg, "start_byte")
                                else ""
                            )
                            path = path.strip("'\"")
                            break

            if method.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                if obj in ("app", "router", "fastify"):
                    framework = {
                        "app": "Express.js",
                        "router": "Express.js Router",
                        "fastify": "Fastify",
                    }.get(obj, "")
                    findings.append(
                        self._make_route_finding(
                            rel_path,
                            content,
                            None,
                            method.upper(),
                            path,
                            framework,
                            line=node.start_point[0] + 1 if node.start_point else 0,
                        )
                    )
                elif method.lower() == "get" and obj:
                    # Could be a route declaration
                    pass

        for child in node.children:
            self._walk_js_route_node(child, buf, content, rel_path, findings, current_obj)

    def _make_route_finding(
        self,
        rel_path: str,
        content: str,
        match: Any | None,
        method: str,
        path: str,
        framework: str,
        line: int = 0,
    ) -> Finding:
        if match:
            line = content[: match.start()].count("\n") + 1
        evidence = f"{method} {path}"
        return make_finding(
            severity=Severity.INFO,
            file=rel_path,
            line_start=line,
            title=f"Route: {method} {path} ({framework})",
            description=f"HTTP {method} route: {path}",
            evidence=evidence,
        )

    def _scan_java_routes(self, content: str, rel_path: str) -> list[Finding]:
        """Scan Java files for routes (Spring Boot) using tree-sitter AST."""
        findings: list[Finding] = []

        parser = get_parser(Lang.JAVA)
        if parser is None:
            return self._scan_java_routes_regex(content, rel_path)

        try:
            tree = parse_source(Lang.JAVA, content)
            buf = content.encode("utf-8")
            self._walk_java_route_node(tree.root_node, buf, rel_path, findings)
        except Exception as e:
            _log.warning("RouteGraphScanner._scan_java_routes failed: %s", e)
            return self._scan_java_routes_regex(content, rel_path)

        return findings

    def _scan_java_routes_regex(self, content: str, rel_path: str) -> list[Finding]:
        """Regex fallback for Java routes."""
        findings = []
        for m in re.finditer(
            r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*["\']([^"\']*)["\']',
            content,
        ):
            annotation = m.group(1).replace("Mapping", "").upper()
            if annotation == "REQUEST":
                annotation = "GET"
            findings.append(
                self._make_route_finding(
                    rel_path, content, m, annotation, m.group(2), "Spring Boot"
                )
            )
        return findings

    def _walk_java_route_node(
        self, node: Any, buf: bytes, rel_path: str, findings: list[Finding]
    ) -> None:
        ntype = node.type

        if ntype == "marker_annotation":
            ann_text = _node_text_buf(node, buf)
            route_methods = {
                "GetMapping": "GET",
                "PostMapping": "POST",
                "PutMapping": "PUT",
                "DeleteMapping": "DELETE",
                "PatchMapping": "PATCH",
            }
            for ann_name, method in route_methods.items():
                if ann_text.startswith("@" + ann_name):
                    path = ""
                    for child in node.children:
                        if hasattr(child, "type") and child.type == "annotation_argument_list":
                            _node_text_buf(child, buf)
                            for arg in child.children:
                                if arg.type == "string":
                                    p = _node_text_buf(arg, buf).strip("\"'")
                                    if p:
                                        path = p
                                        break
                    findings.append(
                        self._make_route_finding(
                            rel_path,
                            "",
                            None,
                            method,
                            path or "/",
                            "Spring Boot",
                            line=node.start_point[0] + 1,
                        )
                    )
                    return
            # Handle @RequestMapping with value=
            if ann_text.startswith("@RequestMapping"):
                path = ""
                for child in node.children:
                    if hasattr(child, "type") and child.type == "annotation_argument_list":
                        for arg in child.children:
                            if arg.type == "string":
                                p = _node_text_buf(arg, buf).strip("\"'")
                                if p:
                                    path = p
                                    break
                findings.append(
                    self._make_route_finding(
                        rel_path,
                        "",
                        None,
                        "GET",
                        path or "/",
                        "Spring Boot",
                        line=node.start_point[0] + 1,
                    )
                )

        for child in node.children if hasattr(node, "children") else []:
            self._walk_java_route_node(child, buf, rel_path, findings)

    def _scan_ruby_routes(self, content: str, rel_path: str) -> list[Finding]:
        """Scan Ruby files for routes (Rails) using tree-sitter AST."""
        findings: list[Finding] = []

        parser = get_parser(Lang.RUBY)
        if parser is None:
            return self._scan_ruby_routes_regex(content, rel_path)

        try:
            tree = parse_source(Lang.RUBY, content)
            buf = content.encode("utf-8")
            self._walk_ruby_route_node(tree.root_node, buf, rel_path, findings)
        except Exception as e:
            _log.warning("RouteGraphScanner._scan_ruby_routes failed: %s", e)
            return self._scan_ruby_routes_regex(content, rel_path)

        return findings

    def _scan_ruby_routes_regex(self, content: str, rel_path: str) -> list[Finding]:
        """Regex fallback for Ruby routes."""
        findings = []
        for m in re.finditer(r'(get|post|put|patch|delete)\s+["\']([^"\']*)["\']', content):
            findings.append(
                self._make_route_finding(
                    rel_path, content, m, m.group(1).upper(), m.group(2), "Rails"
                )
            )
        for m in re.finditer(r"resources\s+:(\w+)", content):
            findings.append(
                self._make_route_finding(rel_path, content, m, "RESOURCE", m.group(1), "Rails")
            )
        return findings

    def _walk_ruby_route_node(
        self, node: Any, buf: bytes, rel_path: str, findings: list[Finding]
    ) -> None:
        ntype = node.type
        if ntype == "call":
            method_name = ""
            for child in node.children:
                if child.type == "identifier":
                    method_name = _node_text_buf(child, buf)
                    break
            route_methods = {"get", "post", "put", "patch", "delete", "resources"}
            if method_name.lower() in route_methods:
                path = ""
                for child in node.children:
                    if child.type == "argument_list":
                        for arg in child.children:
                            if arg.type == "simple_symbol":
                                path = _node_text_buf(arg, buf)
                                if path.startswith(":"):
                                    path = path[1:]
                                break
                            elif arg.type == "string":
                                path = _node_text_buf(arg, buf).strip("\"'")
                                break
                if path:
                    method_display = (
                        method_name.upper() if method_name.lower() != "resources" else "RESOURCE"
                    )
                    findings.append(
                        self._make_route_finding(
                            rel_path,
                            "",
                            None,
                            method_display,
                            path,
                            "Rails",
                            line=node.start_point[0] + 1,
                        )
                    )

        for child in node.children if hasattr(node, "children") else []:
            self._walk_ruby_route_node(child, buf, rel_path, findings)

    def _scan_php_routes(self, content: str, rel_path: str) -> list[Finding]:
        """Scan PHP files for routes (Laravel) using tree-sitter AST."""
        findings: list[Finding] = []

        parser = get_parser(Lang.PHP)
        if parser is None:
            return self._scan_php_routes_regex(content, rel_path)

        try:
            tree = parse_source(Lang.PHP, content)
            buf = content.encode("utf-8")
            self._walk_php_route_node(tree.root_node, buf, rel_path, findings)
        except Exception as e:
            _log.warning("RouteGraphScanner._scan_php_routes failed: %s", e)
            return self._scan_php_routes_regex(content, rel_path)

        return findings

    def _scan_php_routes_regex(self, content: str, rel_path: str) -> list[Finding]:
        """Regex fallback for PHP routes."""
        findings = []
        for m in re.finditer(
            r"Route::(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]*)['\"]\s*,", content
        ):
            findings.append(
                self._make_route_finding(
                    rel_path, content, m, m.group(1).upper(), m.group(2), "Laravel"
                )
            )
        return findings

    def _walk_php_route_node(
        self, node: Any, buf: bytes, rel_path: str, findings: list[Finding]
    ) -> None:
        ntype = node.type
        if ntype == "function_call_expression" or ntype == "scoped_call_expression":
            call_text = _node_text_buf(node, buf)
            route_match = __import__("re").match(
                r"Route::(get|post|put|patch|delete)\s*\(", call_text
            )
            if route_match:
                method = route_match.group(1).upper()
                path = ""
                for child in node.children if hasattr(node, "children") else []:
                    if child.type == "arguments" or child.type == "argument_list":
                        for arg in child.children if hasattr(child, "children") else []:
                            if arg.type in ("encapsed_string", "string"):
                                path = _node_text_buf(arg, buf).strip("'\"")
                                break
                        break
                if path:
                    findings.append(
                        self._make_route_finding(
                            rel_path,
                            "",
                            None,
                            method,
                            path,
                            "Laravel",
                            line=node.start_point[0] + 1,
                        )
                    )

        for child in node.children if hasattr(node, "children") else []:
            self._walk_php_route_node(child, buf, rel_path, findings)

    def _scan_cs_routes(self, content: str, rel_path: str) -> list[Finding]:
        """Scan C# files for routes (ASP.NET Core) using tree-sitter AST."""
        findings: list[Finding] = []

        parser = get_parser(Lang.C_SHARP)
        if parser is None:
            return self._scan_cs_routes_regex(content, rel_path)

        try:
            tree = parse_source(Lang.C_SHARP, content)
            buf = content.encode("utf-8")
            self._walk_cs_route_node(tree.root_node, buf, rel_path, findings)
        except Exception as e:
            _log.warning("RouteGraphScanner._scan_cs_routes failed: %s", e)
            return self._scan_cs_routes_regex(content, rel_path)

        return findings

    def _scan_cs_routes_regex(self, content: str, rel_path: str) -> list[Finding]:
        """Regex fallback for C# routes."""
        findings = []
        for pattern, method in [
            (r'\[HttpGet\(["\']([^"\']*)["\']\s*\)\]', "GET"),
            (r'\[HttpPost\(["\']([^"\']*)["\']\s*\)\]', "POST"),
            (r'\[HttpPut\(["\']([^"\']*)["\']\s*\)\]', "PUT"),
            (r'\[HttpDelete\(["\']([^"\']*)["\']\s*\)\]', "DELETE"),
            (r'\[Route\(["\']([^"\']*)["\']\s*\)\]', "ROUTE"),
        ]:
            for m in re.finditer(pattern, content):
                findings.append(
                    self._make_route_finding(
                        rel_path, content, m, method, m.group(1), "ASP.NET Core"
                    )
                )
        return findings

    def _walk_cs_route_node(
        self, node: Any, buf: bytes, rel_path: str, findings: list[Finding]
    ) -> None:
        ntype = node.type
        if ntype == "attribute":
            attr_text = _node_text_buf(node, buf)
            route_methods = {
                "HttpGet": "GET",
                "HttpPost": "POST",
                "HttpPut": "PUT",
                "HttpDelete": "DELETE",
                "Route": "ROUTE",
            }
            for attr_name, method in route_methods.items():
                if attr_text.startswith("[" + attr_name) or attr_text.startswith(attr_name):
                    path = ""
                    for child in node.children if hasattr(node, "children") else []:
                        if child.type == "attribute_argument_list":
                            for arg in child.children if hasattr(child, "children") else []:
                                if arg.type == "string_literal":
                                    path = _node_text_buf(arg, buf).strip("\"'")
                                    break
                            break
                    findings.append(
                        self._make_route_finding(
                            rel_path,
                            "",
                            None,
                            method,
                            path or "/",
                            "ASP.NET Core",
                            line=node.start_point[0] + 1,
                        )
                    )
                    return

        for child in node.children if hasattr(node, "children") else []:
            self._walk_cs_route_node(child, buf, rel_path, findings)


def _node_text_buf(node: Any, buf: bytes) -> str:
    """Extract text from a tree-sitter node using byte buffer."""
    try:
        return buf[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    except Exception as e:
        _log.debug("_node_text_buf failed: %s", e)
        return ""
