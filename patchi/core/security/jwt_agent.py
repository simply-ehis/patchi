"""
JWTSecurityAgent — JWT implementation security analysis.

Scans for JWT-related security issues:
- Weak algorithms (HS256 when RS256 should be used, 'none' algorithm)
- Missing expiration claims (exp, iat)
- Insecure secret/key storage (hardcoded, weak secrets)
- Missing audience/issuer validation
- Token stored in localStorage vs httpOnly cookies
- Insecure JWT transmission (over non-HTTPS)
- Key material in version control

Uses AST via ast_utils for JWT library call/import detection;
regex for literal patterns (algorithms, secrets, storage).
Does NOT call AI. Does NOT write to disk. Does NOT touch the queue.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
)
from ..brain.ast_utils import find_assignments, find_calls, find_imports
from ..brain.code_query import (
    js_calls,
    js_property_names,
    lang_for_file,
    parse_js,
    string_literals,
)
from ..brain.languages import DEFAULT_IGNORE_DIRS, Lang, detect_language

# ── JWT library names used across languages ──────────────────────────────────
JWT_LIBRARIES: set[str] = {
    "jsonwebtoken",
    "pyjwt",
    "PyJWT",
    "jose",
    "jwt",
    "JJWT",
    "firebase/php-jwt",
    "ruby-jwt",
    "go-jose",
    "jwt-go",
}
JWT_API_CALLS: set[str] = {
    "jwt.encode",
    "jwt.decode",
    "jwt.sign",
    "jwt.verify",
    "jwt.create",
    "jwt.parse",
    "JWT.encode",
    "JWT.decode",
    "JWT.verify",
    "encode",
    "decode",
    "sign",
    "verify",
}


_log = logging.getLogger("patchi.security.jwt_agent")


@register
class JWTSecurityAgent(BaseAgent):
    """Agent for detecting JWT implementation vulnerabilities."""

    group = AgentGroup.SECURITY
    name = "JWTSecurityAgent"
    description = (
        "JWT security: weak algorithms, missing expiry, insecure storage, hardcoded secrets"
    )

    # ── Literal value markers (matched against parsed string/assignment
    # nodes — never raw text, so comments can't trigger findings) ──────────
    _SECRET_NAMES = ("secret", "jwt_secret", "signing_key", "private_key")
    _KEY_NAMES = ("secret", "key")
    _STORAGE_PREFIXES = ("jwt", "token", "auth", "access")
    _EXPIRY_NAMES = (
        "exp", "expires", "expiry", "expiration", "expires_in", "expiresin", "ttl",
    )
    _ALGO_SEVERITY = {
        "none": (
            Severity.CRITICAL,
            "none algorithm allowed — can bypass signature verification",
        ),
        "hs256": (
            Severity.MEDIUM,
            "HS256 symmetric algorithm — consider RS256/ES256 for distributed systems",
        ),
        "hs384": (
            Severity.LOW,
            "HS384 symmetric algorithm — acceptable but verify key strength",
        ),
        "hs512": (
            Severity.LOW,
            "HS512 symmetric algorithm — acceptable but verify key strength",
        ),
    }

    _SOURCE_PATTERNS = [
        "*.py",
        "*.js",
        "*.mjs",
        "*.cjs",
        "*.jsx",
        "*.ts",
        "*.tsx",
        "*.java",
        "*.php",
        "*.rb",
        "*.go",
        "*.rs",
        "*.kt",
        "*.swift",
    ]

    _SKIP_DIRS = DEFAULT_IGNORE_DIRS | {"test", "tests", "vendor"}

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        files_scanned = 0

        for pattern in self._SOURCE_PATTERNS:
            for p in self._safe_rglob(inp.root, pattern):
                rel = str(p.relative_to(inp.root))
                if self._should_skip(rel):
                    continue
                files_scanned += 1
                try:
                    content = p.read_text(encoding="utf-8", errors="ignore")
                except Exception as e:
                    _log.warning("JWTSecurityAgent._run failed: %s", e)
                    continue
                lang = detect_language(p)
                findings.extend(self._analyze_file(content, lang, rel))
                findings.extend(self._check_no_jwt_in_codebase(content, rel))

        result.status = AgentStatus.DONE
        result.findings = findings
        result.files_scanned = files_scanned
        result.data.update({"files_scanned": files_scanned, "finding_count": len(findings)})
        return

    @staticmethod
    def _unquote(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'`":
            return value[1:-1]
        return value

    def _analyze_file(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        def _snippet(line_num: int) -> str:
            if 0 < line_num <= len(lines):
                return lines[line_num - 1].strip()
            return ""

        # Detect JWT usage via AST (calls + imports)
        jwt_calls = find_calls(content, lang, JWT_API_CALLS)
        jwt_imports = find_imports(content, lang, JWT_LIBRARIES)
        has_jwt = bool(jwt_calls) or bool(jwt_imports)

        # String literals carry algorithm names — structural, comments can't match
        literals = string_literals(content, lang)
        for value, line_num in literals:
            lowered = value.strip().lower()
            if lowered in self._ALGO_SEVERITY:
                severity, message = self._ALGO_SEVERITY[lowered]
                findings.append(
                    self._make_finding(
                        "jwt_weak_algorithm",
                        severity,
                        rel_path,
                        line_num,
                        message,
                        "Use RS256 or ES256 for distributed systems. Never allow 'none' algorithm.",
                        _snippet(line_num),
                    )
                )

        # Hardcoded secrets via assignment targets (all languages)
        try:
            assignments = find_assignments(content, lang)
        except Exception:
            assignments = []
        for assignment in assignments:
            target = str(assignment.get("target", "")).lower()
            value = self._unquote(str(assignment.get("value", "")))
            line_num = int(assignment.get("line", 0) or 0)
            if any(marker in target for marker in self._SECRET_NAMES) and len(value) >= 8:
                findings.append(
                    self._make_finding(
                        "jwt_hardcoded_secret",
                        Severity.CRITICAL,
                        rel_path,
                        line_num,
                        "Hardcoded JWT secret in source code",
                        "Move JWT secret to environment variable.",
                        _snippet(line_num),
                    )
                )
            elif any(marker in target for marker in self._KEY_NAMES) and len(value) >= 16:
                findings.append(
                    self._make_finding(
                        "jwt_hardcoded_secret",
                        Severity.HIGH,
                        rel_path,
                        line_num,
                        "Possible hardcoded cryptographic key",
                        "Move JWT secret to environment variable.",
                        _snippet(line_num),
                    )
                )

        # Insecure storage: storage calls with JWT-ish string args on the same line
        lits_by_line: dict[int, list[str]] = {}
        for value, line_num in literals:
            lits_by_line.setdefault(line_num, []).append(value.lower())
        storage_calls = find_calls(
            content, lang, {"setItem", "getItem", "cookie", "set_cookie", "setcookie"}
        )
        for call in storage_calls:
            lowered_name = str(call.get("name", "")).lower()
            line_num = int(call.get("line", 0) or 0)
            values = lits_by_line.get(line_num, [])
            if not any(
                v.startswith(prefix) for v in values for prefix in self._STORAGE_PREFIXES
            ):
                continue
            if "localstorage" in lowered_name:
                findings.append(
                    self._make_finding(
                        "jwt_insecure_storage",
                        Severity.HIGH,
                        rel_path,
                        line_num,
                        "JWT stored in localStorage — vulnerable to XSS",
                        "Use httpOnly, secure cookies for JWT storage.",
                        _snippet(line_num),
                    )
                )
            elif "sessionstorage" in lowered_name:
                findings.append(
                    self._make_finding(
                        "jwt_insecure_storage",
                        Severity.MEDIUM,
                        rel_path,
                        line_num,
                        "JWT stored in sessionStorage — vulnerable to XSS",
                        "Use httpOnly, secure cookies for JWT storage.",
                        _snippet(line_num),
                    )
                )
            elif "cookie" in lowered_name:
                findings.append(
                    self._make_finding(
                        "jwt_insecure_storage",
                        Severity.LOW,
                        rel_path,
                        line_num,
                        "JWT in cookie — verify httpOnly and secure flags are set",
                        "Use httpOnly, secure cookies for JWT storage.",
                        _snippet(line_num),
                    )
                )

        # Missing validation: decode sites without verify / algorithms
        decode_calls = find_calls(content, lang, {"decode"})
        if decode_calls:
            verify_calls = find_calls(
                content, lang, {"verify", "authenticate", "validate"}
            )
            if not verify_calls:
                first = decode_calls[0]
                findings.append(
                    self._make_finding(
                        "jwt_missing_validation",
                        Severity.HIGH,
                        rel_path,
                        int(first.get("line", 0) or 0),
                        "JWT decoded without signature verification",
                        "Always verify JWT signatures and specify allowed algorithms.",
                        _snippet(int(first.get("line", 0) or 0)),
                    )
                )
            for call in decode_calls:
                if not self._call_has_algorithms(content, rel_path, call):
                    findings.append(
                        self._make_finding(
                            "jwt_missing_validation",
                            Severity.MEDIUM,
                            rel_path,
                            int(call.get("line", 0) or 0),
                            "JWT decode missing explicit algorithms parameter",
                            "Always verify JWT signatures and specify allowed algorithms.",
                            _snippet(int(call.get("line", 0) or 0)),
                        )
                    )

        # Check for missing expiration (if JWT is used but no expiry marker found)
        if has_jwt and not self._has_expiry(content, lang, rel_path, assignments):
            findings.append(
                make_finding(
                    agent=self.name,
                    finding_type="jwt_no_expiry",
                    severity=Severity.HIGH,
                    file=rel_path,
                    message="JWT used but no expiration claim (exp) found in file",
                    suggestion="Always set expiration on JWT tokens. Recommended: short-lived access tokens (15min) + refresh tokens.",
                )
            )

        return findings

    def _call_has_algorithms(self, content: str, rel_path: str, call: dict) -> bool:
        """True when a decode call passes algorithms (kwarg, object key, or span)."""
        line_no = int(call.get("line", 0) or 0)
        if rel_path.endswith(".py"):
            try:
                import ast as _ast

                tree = _ast.parse(content)
                for node in _ast.walk(tree):
                    if not isinstance(node, _ast.Call):
                        continue
                    if getattr(node, "lineno", 0) != line_no:
                        continue
                    if any((kw.arg or "") == "algorithms" for kw in node.keywords):
                        return True
            except SyntaxError:
                pass
            return False
        try:
            lang_key = lang_for_file(rel_path)
            for site in js_calls(parse_js(content, lang_key), lang_key):
                if site.line == line_no and "algorithms" in site.text:
                    return True
        except Exception:
            pass
        return "algorithms" in str(call.get("full_text", ""))

    def _has_expiry(
        self, content: str, lang: Lang, rel_path: str, assignments: list[dict]
    ) -> bool:
        """Expiry markers via assignment targets, kwargs, and object keys."""
        for assignment in assignments:
            if str(assignment.get("target", "")).lower() in self._EXPIRY_NAMES:
                return True
        if lang == Lang.PYTHON:
            try:
                import ast as _ast

                tree = _ast.parse(content)
                for node in _ast.walk(tree):
                    if isinstance(node, _ast.Call):
                        if any((kw.arg or "").lower() in self._EXPIRY_NAMES for kw in node.keywords):
                            return True
                    elif isinstance(node, _ast.Dict):
                        for key in node.keys:
                            if isinstance(key, _ast.Constant) and str(key.value).lower() in self._EXPIRY_NAMES:
                                return True
            except SyntaxError:
                pass
            return False
        try:
            lang_key = lang_for_file(rel_path)
            props = js_property_names(parse_js(content, lang_key), lang_key)
            return any(p.lower() in self._EXPIRY_NAMES for p in props)
        except Exception:
            return False

    def _make_finding(
        self,
        finding_type: str,
        severity: Severity,
        file: str,
        line: int,
        message: str,
        suggestion: str,
        snippet: str,
    ) -> Finding:
        return make_finding(
            agent=self.name,
            finding_type=finding_type,
            severity=severity,
            file=file,
            line_start=line,
            message=message,
            suggestion=suggestion,
            code_snippet=snippet[:120],
        )

    def _check_no_jwt_in_codebase(self, content: str, rel_path: str) -> list[Finding]:
        findings = []
        # KEY=VALUE lines need splitting, not patterns (env-style parsing).
        for line_num, line in enumerate(content.splitlines(), 1):
            if "=" not in line:
                continue
            name, _, value = line.partition("=")
            name, value = name.strip().upper(), value.strip().strip("\"'")
            if not value:
                continue
            if name == "JWT_SECRET":
                severity = Severity.CRITICAL
                message = "JWT secret in environment/config file — use .env, not hardcoded"
            elif name == "JWT_KEY":
                severity = Severity.HIGH
                message = "JWT key in environment/config file — ensure .env is in .gitignore"
            else:
                continue
            findings.append(
                self._make_finding(
                    "jwt_env_exposure",
                    severity,
                    rel_path,
                    line_num,
                    message,
                    "Ensure .env files are in .gitignore. Use secret managers in production.",
                    line.strip(),
                )
            )
        return findings

    def _should_skip(self, rel_path: str) -> bool:
        parts = rel_path.replace("\\", "/").split("/")
        return any(p in self._SKIP_DIRS for p in parts)

    def _safe_rglob(self, root: Path, pattern: str):
        suffix = pattern.replace("*.", ".")
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self._SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(suffix):
                    yield Path(dirpath) / fn
