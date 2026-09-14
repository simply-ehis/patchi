"""
AuthZAgent — authorization bypass, privilege escalation.

Detects authorization issues:
- Missing authentication checks
- Broken access control
- Privilege escalation vulnerabilities
- Horizontal/vertical privilege escalation
- Missing authorization middleware
- Overly permissive access controls
- Insecure direct object references (IDOR)

Uses pattern matching and AST analysis.
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import ast as py_ast
import logging
import re
from pathlib import Path

from ..agents.base import (
    AgentDomain,
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
from ..brain.ast_utils import node_text, parse_source
from ..brain.languages import TREE_SITTER_LANGS, Lang, detect_language, get_parser

_log = logging.getLogger("patchi.security.authz_agent")


@register
class AuthZAgent(BaseAgent):
    """Agent for detecting authorization vulnerabilities."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "AuthZAgent"
    description = "Authorization bypass, privilege escalation, IDOR, missing auth checks"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        from patchi.core.brain.project_context import agent_is_relevant

        relevant, reason = agent_is_relevant(inp.domain, inp.purpose, self.name, inp.active_domains)
        if not relevant:
            result.status = AgentStatus.SKIPPED
            result.data.update({"skip_reason": reason, "needs_ai": False})
            return

        findings = []

        # Define source file patterns to scan
        source_patterns = [
            "*.py",
            "*.js",
            "*.jsx",
            "*.ts",
            "*.tsx",
            "*.java",
            "*.php",
            "*.rb",
            "*.go",
            "*.rs",
            "*.cpp",
            "*.cxx",
            "*.cc",
            "*.c",
            "*.h",
            "*.hpp",
            "*.cs",
        ]

        # Search for source files
        for pattern in source_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_file_authz(file_path, rel_path))

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "authz_findings": len(
                    [
                        f
                        for f in findings
                        if any(word in f.title.lower() for word in ["authorization", "auth", "privilege", "idor"])
                    ]
                ),
                "needs_ai": False,
            }
        )
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        from pathlib import PurePosixPath

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

    def _scan_file_authz(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan a file for authorization vulnerabilities."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")
            lang = detect_language(file_path)

            # Apply language-specific authorization checks
            if lang == Lang.PYTHON:
                findings.extend(self._scan_python_authz(content, rel_path))
            elif lang in [Lang.JAVASCRIPT, Lang.TYPESCRIPT]:
                findings.extend(self._scan_javascript_authz(content, rel_path, lang))
            elif lang == Lang.JAVA:
                findings.extend(self._scan_java_authz(content, rel_path))
            elif lang == Lang.PHP:
                findings.extend(self._scan_php_authz(content, rel_path))
            elif lang == Lang.RUBY:
                findings.extend(self._scan_ruby_authz(content, rel_path))
            elif lang in TREE_SITTER_LANGS:
                findings.extend(self._scan_treesitter_authz(content, rel_path, lang))
            else:
                # Apply general authorization checks
                findings.extend(self._scan_general_authz(content, rel_path))

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="AuthZ scanner file read error",
                    description=f"Could not analyze {file_path.name} for authorization issues: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_python_authz(self, content: str, rel_path: str) -> list[Finding]:
        """Scan Python code for authorization vulnerabilities."""
        findings = []

        try:
            tree = py_ast.parse(content)
        except SyntaxError:
            # If we can't parse the AST, fall back to pattern matching
            return self._scan_general_authz(content, rel_path)

        # Walk the AST to find authorization issues
        routes_with_auth = set()
        routes_without_auth = set()

        for node in py_ast.walk(tree):
            # Look for route definitions in common frameworks
            if isinstance(node, py_ast.FunctionDef):
                func_name = node.name
                has_auth_decorator = False

                # Check for authentication/authorization decorators
                for decorator in node.decorator_list:
                    if isinstance(decorator, py_ast.Name):
                        if decorator.id.lower() in [
                            "login_required",
                            "auth_required",
                            "admin_required",
                            "permission_required",
                        ]:
                            has_auth_decorator = True
                            break
                    elif isinstance(decorator, py_ast.Attribute):
                        if decorator.attr.lower() in [
                            "login_required",
                            "auth_required",
                            "admin_required",
                            "permission_required",
                        ]:
                            has_auth_decorator = True
                            break

                # Check if this looks like a route handler
                has_route_decorator = any(
                    isinstance(d, py_ast.Attribute)
                    and d.attr
                    in (
                        "get",
                        "post",
                        "put",
                        "delete",
                        "patch",
                        "route",
                        "add_url_rule",
                        "before_request",
                    )
                    or (
                        isinstance(d, py_ast.Call)
                        and isinstance(d.func, py_ast.Attribute)
                        and d.func.attr
                        in (
                            "get",
                            "post",
                            "put",
                            "delete",
                            "patch",
                        )
                    )
                    for d in node.decorator_list
                )
                # Also flag functions named like route handlers (get_X, post_X, delete_X)
                is_route_name = any(
                    func_name.lower().startswith(v) for v in ("get_", "post_", "put_", "delete_", "patch_", "handle_")
                )
                if has_route_decorator or is_route_name:
                    if has_auth_decorator:
                        routes_with_auth.add(func_name)
                    else:
                        routes_without_auth.add(func_name)

        # Report routes without authentication
        for node in py_ast.walk(tree):
            if isinstance(node, py_ast.FunctionDef) and node.name in routes_without_auth:
                if node.name not in routes_with_auth:
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=getattr(node, "lineno", 0),
                            title="Missing Authentication Check",
                            description=f"Route '{node.name}' may lack proper authentication/authorization",
                            evidence=f"Function {node.name} does not have authentication decorator",
                        )
                    )

        # General pattern matching for Python
        findings.extend(self._scan_general_authz(content, rel_path))

        return findings

    def _scan_javascript_authz(self, content: str, rel_path: str, lang: Lang = Lang.JAVASCRIPT) -> list[Finding]:
        """Scan JavaScript/TypeScript code for authorization vulnerabilities.

        Uses tree-sitter to locate route-definition call expressions (e.g.
        ``app.get(...)`` / ``router.post(...)``) and inspects the full call
        text (including any multi-line handler chain) for an authentication /
        authorization guard. Falls back to the line-regex scanner if the file
        cannot be parsed.
        """
        tree = parse_source(content, lang)
        if tree is None:
            return self._scan_javascript_authz_regex(content, rel_path)

        findings: list[Finding] = []
        lines = content.splitlines()
        route_verbs = {"get", "post", "put", "delete", "patch"}
        auth_words = {
            "authenticate",
            "authorize",
            "jwt",
            "session",
            "login",
            "requireauth",
            "isloggedin",
            "permission",
            "hasrole",
            "hasauthority",
            "secured",
            "preauthorize",
        }
        sensitive_re = re.compile(r"/api/.*(?:/users?|/admin|/settings|/profile|/account)", re.IGNORECASE)

        for node in self._iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            fn = node.child_by_field_name("function")
            if fn is None or fn.type != "member_expression":
                continue
            name = self._node_name(fn)
            leaf = name.split(".")[-1].lower()
            if leaf not in route_verbs:
                continue

            call_text = node_text(node)
            line = node.start_point[0] + 1
            lowered = call_text.lower()
            has_auth = any(w in lowered for w in auth_words)
            evidence_line = lines[line - 1].strip() if 0 < line <= len(lines) else call_text.strip()
            if not has_auth:
                # Part 7: auth may live in a decorator above the route or in
                # same-file global middleware (app.use(auth…)) — both are
                # structural coverage, not absence. Only verdict when neither
                # is present, and say what to verify.
                above = "\n".join(lines[max(0, line - 6):line - 1]).lower()
                covered = any(w in above for w in auth_words) or bool(
                    re.search(r"(?i)app\.use\s*\([^)]*(?:auth|jwt|session|login|protect)", content)
                )
                if covered:
                    continue
                sensitive = bool(sensitive_re.search(call_text))
                findings.append(
                    make_finding(
                        severity=Severity.HIGH if sensitive else Severity.MEDIUM,
                        file=rel_path,
                        line_start=line,
                        title=(
                            "Sensitive Endpoint Without Authorization"
                            if sensitive
                            else "Potential Missing Authorization Check"
                        ),
                        description="Route definition may lack authentication/authorization middleware"
                        " — verify decorator-above and global middleware in other files",
                        evidence=evidence_line,
                    )
                )
        return findings

    def _scan_javascript_authz_regex(self, content: str, rel_path: str) -> list[Finding]:
        """Line-based fallback for JS/TS when tree-sitter is unavailable."""
        findings: list[Finding] = []
        express_route_patterns = [
            r'app\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']\s*,\s*(?!.*(?:authenticate|authorize|\bjwt\b|\bsession\b|\blogin\b|requireAuth|isLoggedIn)).*?=>',
            r'router\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']\s*,\s*(?!.*(?:authenticate|authorize|\bjwt\b|\bsession\b|\blogin\b|requireAuth|isLoggedIn)).*?=>',
        ]
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern in express_route_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        make_finding(
                            severity=Severity.MEDIUM,
                            file=rel_path,
                            line_start=i,
                            title="Potential Missing Authorization Check",
                            description="Route definition may lack authentication/authorization middleware",
                            evidence=line.strip(),
                        )
                    )
        sensitive_re = re.compile(r"/api/.*(?:/users?|/admin|/settings|/profile|/account)", re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if sensitive_re.search(line) and not any(
                w in line.lower() for w in ["auth", "login", "jwt", "session", "verify"]
            ):
                # Part 7: single-line fallback misses chained/multiline
                # middleware — check the lines above before calling it HIGH.
                above = "\n".join(lines[max(0, i - 4):i - 1]).lower()
                if any(
                    w in above
                    for w in ["auth", "login", "jwt", "session", "verify", "middleware", "guard"]
                ):
                    continue
                findings.append(
                    make_finding(
                        severity=Severity.HIGH,
                        file=rel_path,
                        line_start=i,
                        title="Sensitive Endpoint Without Authorization",
                        description="API endpoint for sensitive data may lack authorization"
                        " — verify global middleware in other files",
                        evidence=line.strip(),
                    )
                )
        return findings

    # ── Shared tree-sitter helpers ─────────────────────────────────────────

    def _iter_nodes(self, node):
        yield node
        for child in node.children:
            yield from self._iter_nodes(child)

    def _node_name(self, node: object) -> str:
        """Recursively reconstruct a dotted/scoped call name from a node."""
        if node is None:
            return ""
        ntype = getattr(node, "type", "")
        if ntype == "identifier":
            return node_text(node)
        if ntype == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if obj is not None and prop is not None:
                return f"{self._node_name(obj)}.{node_text(prop)}"
            return node_text(node)
        if ntype in ("scoped_identifier", "qualified_name", "scoped_type_identifier"):
            return node_text(node)
        return node_text(node)

    def _scan_java_authz(self, content: str, rel_path: str) -> list[Finding]:
        """Scan Java code for authorization vulnerabilities."""
        findings = []

        # Check if security annotations are present
        has_security_annotation = any(
            sec_word in content.lower()
            for sec_word in [
                "@secured",
                "@preauthorize",
                "@postauthorize",
                "hasrole",
                "hasauthority",
            ]
        )

        if not has_security_annotation:
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # Look for controller or mapping annotations
                if any(
                    annotation in line
                    for annotation in [
                        "@Controller",
                        "@RestController",
                        "@GetMapping",
                        "@PostMapping",
                        "@PutMapping",
                        "@DeleteMapping",
                        "@RequestMapping",
                    ]
                ):
                    findings.append(
                        make_finding(
                            severity=Severity.MEDIUM,
                            file=rel_path,
                            line_start=i,
                            title="Potential Missing Authorization Check",
                            description="Controller or endpoint may lack authorization annotations",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_php_authz(self, content: str, rel_path: str) -> list[Finding]:
        """Scan PHP code for authorization vulnerabilities."""
        findings = []

        # Look for PHP route definitions without auth checks
        php_auth_patterns = [
            r'Route::(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']\s*,\s*function\s*\(',
            r"function\s+\w+Action\s*\(\s*\)",
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern in php_auth_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    # Check surrounding LINES for authentication (Part 7: the
                    # old code sliced characters [i-10:i+10] using a line
                    # number as a char offset — a ~20-char window).
                    window = "\n".join(lines[max(0, i - 6):min(len(lines), i + 5)])
                    if not any(
                        auth_word in window
                        for auth_word in [
                            "auth",
                            "Auth",
                            "login",
                            "Login",
                            "middleware",
                            "Middleware",
                        ]
                    ):
                        findings.append(
                            make_finding(
                                severity=Severity.MEDIUM,
                                file=rel_path,
                                line_start=i,
                                title="Potential Missing Authorization Check",
                                description="Route or controller method may lack authentication/authorization",
                                evidence=line.strip(),
                            )
                        )

        return findings

    def _scan_ruby_authz(self, content: str, rel_path: str) -> list[Finding]:
        """Scan Ruby code for authorization vulnerabilities."""
        findings = []

        # Look for Rails controller actions without authentication
        ruby_auth_patterns = [
            r"\bdef\s+(show|edit|update|destroy)\b",
        ]

        # Check if authentication methods are called
        has_auth_check = any(
            auth_method in content
            for auth_method in [
                "before_action",
                "before_filter",
                "authenticate_",
                "logged_in",
                "authorized",
            ]
        )

        if not has_auth_check:
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                for pattern in ruby_auth_patterns:
                    matches = re.finditer(pattern, line)
                    for _match in matches:
                        findings.append(
                            make_finding(
                                severity=Severity.MEDIUM,
                                file=rel_path,
                                line_start=i,
                                title="Potential Missing Authorization Check",
                                description="Controller action may lack authentication/authorization",
                                evidence=line.strip(),
                            )
                        )

        return findings

    def _scan_treesitter_authz(self, content: str, rel_path: str, lang: Lang) -> list[Finding]:
        """Scan using tree-sitter for supported languages."""
        findings = []

        try:
            parser, lang_obj = get_parser(lang)
            parser.parse(bytes(content, "utf8"))

            # For now, fall back to general pattern matching
            findings.extend(self._scan_general_authz(content, rel_path))
        except Exception as e:
            # If tree-sitter fails, use general patterns
            _log.warning("AuthZAgent._scan_treesitter_authz failed: %s", e)
            findings.extend(self._scan_general_authz(content, rel_path))

        return findings

    def _scan_general_authz(self, content: str, rel_path: str) -> list[Finding]:
        """Apply general authorization pattern matching."""
        findings = []

        # General authorization patterns. Part 7: snake_case names
        # (delete_user, is_admin) have no \b boundaries inside — match
        # word-char-joined forms too, or real code never fires. The
        # (?<![A-Za-z]) guard keeps mid-word matches ("together" has no
        # "get" finding) while allowing _-joined identifiers.
        authz_patterns = [
            (
                r"(?<![A-Za-z])(?:delete|remove|update|modify)[\w_]*(?:user|account|profile|record)",
                "Potential Missing Authorization",
                Severity.HIGH,
            ),
            (
                r"(?<![A-Za-z])(?:change|set|update)[\w_]*(?:password|passwd|pwd)",
                "Potential Missing Authorization",
                Severity.HIGH,
            ),
            (
                r"(?<![A-Za-z])(?:admin|administrator|superuser)",
                "Admin Functionality",
                Severity.MEDIUM,
            ),
            (
                r"(?<![A-Za-z])(?:get|fetch|retrieve)[\w_]*.*\b(?:config|setting)\b",
                "Configuration Access",
                Severity.MEDIUM,
            ),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Part 7: English words in comments/docs are not code behavior.
            if stripped.startswith(("#", "//", "*", "/*", "<!--")):
                continue
            for pattern, description, severity in authz_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    # Only flag if there's no obvious auth check in the vicinity
                    context = " ".join(lines[max(0, i - 3) : min(len(lines), i + 3)])
                    if not any(
                        auth_word in context.lower()
                        for auth_word in [
                            "auth",
                            "login",
                            "verify",
                            "validate",
                            "permission",
                            "authorize",
                            "allow",
                        ]
                    ):
                        # Part 7: English-word pairs ("delete"+"user") cap at
                        # MEDIUM with verify language — never HIGH as fact.
                        # (Severity is a StrEnum: min() would compare
                        # alphabetically, so the cap is explicit.)
                        capped = (
                            Severity.MEDIUM
                            if severity in (Severity.CRITICAL, Severity.HIGH)
                            else severity
                        )
                        findings.append(
                            make_finding(
                                severity=capped,
                                file=rel_path,
                                line_start=i,
                                title=description,
                                description=f"Found potential {description.lower()} without clear authorization check"
                                " — verify an authorization check covers this operation",
                                evidence=line.strip(),
                            )
                        )

        return findings
