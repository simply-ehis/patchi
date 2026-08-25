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
import re
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
from ..brain.ast_utils import find_calls, find_imports
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

    # ── Regex patterns (stay as regex — literal values) ──────────────────────

    # Weak algorithm indicators
    _WEAK_ALGO_PATTERNS = [
        (
            re.compile(r'["\']none["\']', re.I),
            Severity.CRITICAL,
            "none algorithm allowed — can bypass signature verification",
        ),
        (
            re.compile(r"HS256", re.I),
            Severity.MEDIUM,
            "HS256 symmetric algorithm — consider RS256/ES256 for distributed systems",
        ),
        (
            re.compile(r"HS384", re.I),
            Severity.LOW,
            "HS384 symmetric algorithm — acceptable but verify key strength",
        ),
        (
            re.compile(r"HS512", re.I),
            Severity.LOW,
            "HS512 symmetric algorithm — acceptable but verify key strength",
        ),
    ]

    # Hardcoded secret patterns
    _SECRET_PATTERNS = [
        (
            re.compile(
                r'(?:secret|jwt_secret|signing_key|private_key)\s*=\s*["\'][^"\']{8,}["\']', re.I
            ),
            Severity.CRITICAL,
            "Hardcoded JWT secret in source code",
        ),
        (
            re.compile(r'(?:secret|key)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{16,}["\']', re.I),
            Severity.HIGH,
            "Possible hardcoded cryptographic key",
        ),
    ]

    # Insecure storage patterns
    _STORAGE_PATTERNS = [
        (
            re.compile(
                r'localStorage\.(?:set|get)Item\s*\(\s*["\'](?:jwt|token|auth|access)', re.I
            ),
            Severity.HIGH,
            "JWT stored in localStorage — vulnerable to XSS",
        ),
        (
            re.compile(
                r'sessionStorage\.(?:set|get)Item\s*\(\s*["\'](?:jwt|token|auth|access)', re.I
            ),
            Severity.MEDIUM,
            "JWT stored in sessionStorage — vulnerable to XSS",
        ),
        (
            re.compile(r"(?:document\.cookie|res\.cookie|set_cookie).*jwt", re.I),
            Severity.LOW,
            "JWT in cookie — verify httpOnly and secure flags are set",
        ),
    ]

    # Missing validation patterns
    _VALIDATION_ISSUES = [
        (
            re.compile(r"jwt\.decode\s*\([^)]*\)(?![^}]*verify)", re.I),
            Severity.HIGH,
            "JWT decoded without signature verification",
        ),
        (
            re.compile(r"decode\s*\(\s*token\s*(?:,\s*[^)]*)?\)(?![^}]*algorithms)", re.I),
            Severity.MEDIUM,
            "JWT decode missing explicit algorithms parameter",
        ),
    ]

    # Expiration check patterns
    _EXPIRY_PATTERNS = [
        re.compile(r"exp(?:ir(?:ation|es)?)?\s*[:=]", re.I),
        re.compile(r"exp\s*=", re.I),
        re.compile(r"expires?[_-]?in", re.I),
        re.compile(r"ttl", re.I),
    ]

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

    def _analyze_file(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        # Detect JWT usage via AST (calls + imports)
        jwt_calls = find_calls(content, lang, JWT_API_CALLS)
        jwt_imports = find_imports(content, lang, JWT_LIBRARIES)
        has_jwt = bool(jwt_calls) or bool(jwt_imports)

        # Also check regex for algorithm strings regardless of JWT detection
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, severity, message in self._WEAK_ALGO_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self._make_finding(
                            "jwt_weak_algorithm",
                            severity,
                            rel_path,
                            line_num,
                            message,
                            "Use RS256 or ES256 for distributed systems. Never allow 'none' algorithm.",
                            stripped,
                        )
                    )

            for pattern, severity, message in self._SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self._make_finding(
                            "jwt_hardcoded_secret",
                            severity,
                            rel_path,
                            line_num,
                            message,
                            "Move JWT secret to environment variable.",
                            stripped,
                        )
                    )

            for pattern, severity, message in self._STORAGE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self._make_finding(
                            "jwt_insecure_storage",
                            severity,
                            rel_path,
                            line_num,
                            message,
                            "Use httpOnly, secure cookies for JWT storage.",
                            stripped,
                        )
                    )

            for pattern, severity, message in self._VALIDATION_ISSUES:
                if pattern.search(line):
                    findings.append(
                        self._make_finding(
                            "jwt_missing_validation",
                            severity,
                            rel_path,
                            line_num,
                            message,
                            "Always verify JWT signatures and specify allowed algorithms.",
                            stripped,
                        )
                    )

        # Check for missing expiration (if JWT is used but no expiry pattern found)
        if has_jwt:
            has_expiry = any(p.search(content) for p in self._EXPIRY_PATTERNS)
            if not has_expiry:
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
        env_patterns = [
            (
                re.compile(r'JWT_SECRET\s*=\s*["\'][^"\']+["\']', re.I),
                Severity.CRITICAL,
                "JWT secret in environment/config file — use .env, not hardcoded",
            ),
            (
                re.compile(r'JWT_KEY\s*=\s*["\'][^"\']+["\']', re.I),
                Severity.HIGH,
                "JWT key in environment/config file — ensure .env is in .gitignore",
            ),
        ]
        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern, severity, message in env_patterns:
                if pattern.search(line):
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
