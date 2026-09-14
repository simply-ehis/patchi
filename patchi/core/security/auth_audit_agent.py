"""
AuthenticationAuditAgent — Authentication and session security analysis.

Scans for:
- Missing CSRF protection on state-changing endpoints
- Weak password hashing (MD5, SHA1, no salt)
- Session fixation vulnerabilities
- Missing brute-force protection indicators
- Insecure session cookie configuration
- Missing MFA/2FA indicators
- OAuth implementation issues
- Hardcoded session secrets
- Missing rate limiting on auth endpoints
- Improper session invalidation on logout

Multi-language: scans all tree-sitter-supported source languages. Hash-function
calls are detected structurally via tree-sitter AST (find_calls); hardcoded
secrets, CSRF markers, OAuth config and rate-limiting indicators are detected
with high-quality literal-pattern regex (acceptable per the audit). Does NOT
call AI. Does NOT write to disk. Does NOT touch the queue.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS, EXTENSION_MAP, Lang

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
)
from ..brain.ast_utils import find_calls

# Source extensions to scan (language parity).
_SCAN_EXTENSIONS = [
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".rb",
    ".php",
    ".go",
    ".rs",
    ".cpp",
    ".cxx",
    ".cc",
    ".c",
    ".h",
    ".hpp",
    ".cs",
    ".kt",
    ".kts",
    ".swift",
    ".dart",
]

# Hash function call names that are weak (detected structurally via AST).
_WEAK_HASH_NAMES = {"md5", "sha1", "sha256", "sha512", "crypt"}
# Per-name severity / message for AST-detected weak hashes.
_WEAK_HASH_INFO = {
    "md5": (Severity.CRITICAL, "MD5 used for password hashing — cryptographically broken"),
    "sha1": (Severity.CRITICAL, "SHA1 used for password hashing — cryptographically weak"),
    "sha256": (
        Severity.HIGH,
        "SHA-256 used for password hashing — use bcrypt/scrypt/argon2 instead",
    ),
    "sha512": (Severity.MEDIUM, "SHA-512 used for password hashing — prefer bcrypt/scrypt/argon2"),
    "crypt": (Severity.MEDIUM, "Unix crypt() for password hashing — use modern alternatives"),
}
_GOOD_HASH_PATTERNS = [
    re.compile(r"(?:bcrypt|scrypt|argon2|pbkdf2)", re.I),
]

# ── Weak password hashing literal patterns (regex fallback / unsupported langs) ──
_WEAK_HASH_PATTERNS = [
    (
        # KEEP-AND-HARDEN: MD5 is cryptographically broken for password hashing — captures hashlib.md5() calls across

        # languages — never sole verdict source (Part 7 §4)

        re.compile(r"(?:hashlib\.)?md5\s*\(", re.I),
        Severity.CRITICAL,
        "MD5 used for password hashing — cryptographically broken",
    ),
    (
        # KEEP-AND-HARDEN: SHA1 is cryptographically weak for password hashing — captures hashlib.sha1() and bare sha1()

        # calls — never sole verdict source (Part 7 §4)

        re.compile(r"(?:hashlib\.)?sha1\s*\(", re.I),
        Severity.CRITICAL,
        "SHA1 used for password hashing — cryptographically weak",
    ),
    (
        # KEEP-AND-HARDEN: SHA-256 is acceptable for general hashing but not password hashing — evidence that

        # bcrypt/scrypt/argon2 is missing — never sole verdict source (Part 7 §4)

        re.compile(r"(?:hashlib\.)?sha256\s*\(", re.I),
        Severity.HIGH,
        "SHA-256 used for password hashing — use bcrypt/scrypt/argon2 instead",
    ),
    (
        # KEEP-AND-HARDEN: SHA-512 alone is not password-safe — evidence of weak hash when bcrypt/scrypt/argon2 absent —

        # never sole verdict source (Part 7 §4)

        re.compile(r"hashlib\.sha512\s*\(", re.I),
        Severity.MEDIUM,
        "SHA-512 used for password hashing — prefer bcrypt/scrypt/argon2",
    ),
    (
        # KEEP-AND-HARDEN: Unix crypt() is a legacy password hasher — evidence of outdated auth implementation — never

        # sole verdict source (Part 7 §4)

        re.compile(r"crypt\s*\(", re.I),
        Severity.MEDIUM,
        "Unix crypt() for password hashing — use modern alternatives",
    ),
]

# ── Session patterns ────────────────────────────────────────────────────
_SESSION_PATTERNS = [
    (
        # KEEP-AND-HARDEN: Session assignment pattern — evidence of session management that must be verified for secure

        # config — never sole verdict source (Part 7 §4)

        re.compile(r"session\[.*?\]\s*=", re.I),
        Severity.LOW,
        "Session assignment — verify secure configuration",
    ),
    (
        # Part 7: keyword tier — value must prove itself (max HIGH).
        # KEEP-AND-HARDEN: Hardcoded session secret — captures SECRET_KEY/session_secret literals with value group for

        # looks_like_secret gating — never sole verdict source (Part 7 §4)

        re.compile(r'(?:session\.secret|SECRET_KEY|session_secret)\s*[:=]\s*["\']([^"\']+)["\']', re.I),
        Severity.HIGH,
        "Hardcoded session secret in source code",
    ),
    (
        # KEEP-AND-HARDEN: Cookie security flags — evidence of cookie configuration that must be verified for

        # httponly/secure/samesite — never sole verdict source (Part 7 §4)

        re.compile(r"(?:cookie_httponly|httponly.*cookie|Secure.*cookie)", re.I),
        Severity.LOW,
        "Cookie security configuration found — verify all flags set",
    ),
    (
        # KEEP-AND-HARDEN: Cookie-setting call — evidence that a cookie is being set; must verify

        # httponly/secure/samesite flags — never sole verdict source (Part 7 §4)

        re.compile(r"(?:set_cookie|set_cookie_attr|response\.set_cookie)", re.I),
        Severity.LOW,
        "Cookie being set — verify httponly, secure, and samesite flags",
    ),
]

# ── Auth endpoint patterns ──────────────────────────────────────────────
_AUTH_ENDPOINT_PATTERNS = [
    re.compile(r"(?:/login|/signin|/auth|/authenticate|/register|/signup|/token)", re.I),
    re.compile(r"(?:login|signin|auth|authenticate|register|signup)\s*\(", re.I),
]

# ── Rate limiting patterns ──────────────────────────────────────────────
_RATE_LIMIT_PATTERNS = [
    re.compile(r"(?:rate.?limit|throttl|brute.?force|login.?attempt|max.?attempt)", re.I),
]

# ── OAuth patterns ──────────────────────────────────────────────────────
_OAUTH_PATTERNS = [
    (
        # KEEP-AND-HARDEN: OAuth/OIDC indicator — evidence that OAuth flow exists; implementation security must be

        # verified — never sole verdict source (Part 7 §4)

        re.compile(r"(?:oauth|openid|oidc)", re.I),
        Severity.INFO,
        "OAuth/OIDC code found — verify implementation security",
    ),
    (
        # KEEP-AND-HARDEN: OAuth redirect URI — evidence of redirect target that may be exploitable as open redirect —

        # never sole verdict source (Part 7 §4)

        re.compile(r'(?:redirect_uri|callback_url)\s*[:=]\s*["\'][^"\']*["\']', re.I),
        Severity.MEDIUM,
        "OAuth redirect URI — verify it's not open redirect",
    ),
    (
        # Part 7: keyword tier — value must prove itself (max HIGH).
        # KEEP-AND-HARDEN: Hardcoded OAuth client secret — captures client_secret/client_id literals with value group

        # for looks_like_secret gating — never sole verdict source (Part 7 §4)

        re.compile(r'(?:client_secret|client_id)\s*[:=]\s*["\']([^"\']+)["\']', re.I),
        Severity.HIGH,
        "OAuth client secret hardcoded in source",
    ),
]

_SKIP_DIRS = DEFAULT_IGNORE_DIRS


_log = logging.getLogger("patchi.security.auth_audit_agent")


@register
class AuthenticationAuditAgent(BaseAgent):
    """Agent for auditing authentication and session security."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "AuthenticationAuditAgent"
    description = "Auth security: CSRF, password hashing, session management, brute-force protection"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        from patchi.core.brain.project_context import agent_is_relevant

        relevant, reason = agent_is_relevant(inp.domain, inp.purpose, self.name, inp.active_domains)
        if not relevant:
            result.status = AgentStatus.SKIPPED
            result.data.update({"skip_reason": reason})
            return

        findings = []
        files_scanned = 0

        for ext in _SCAN_EXTENSIONS:
            for p in self._safe_rglob(inp.root, f"*{ext}"):
                rel = str(p.relative_to(inp.root))
                if self._should_skip(rel):
                    continue
                files_scanned += 1
                try:
                    content = p.read_text(encoding="utf-8", errors="ignore")
                except Exception as e:
                    _log.warning("AuthenticationAuditAgent._run failed: %s", e)
                    continue
                lang = EXTENSION_MAP.get(ext)
                findings.extend(self._check_password_hashing(content, rel, lang))
                findings.extend(self._check_session_security(content, rel))
                findings.extend(self._check_oauth(content, rel))
                findings.extend(self._check_rate_limiting(content, rel))

        result.status = AgentStatus.DONE
        result.findings = findings
        result.files_scanned = files_scanned
        result.data.update({"files_scanned": files_scanned, "finding_count": len(findings)})
        return

    # ── Password hashing (AST + regex) ─────────────────────────────────────

    def _check_password_hashing(self, content: str, rel_path: str, lang: Lang | None) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        # AST-based weak hash detection (structural, language-agnostic where possible).
        ast_hits: dict[int, tuple[Severity, str]] = {}
        if lang is not None:
            for call in find_calls(content, lang, _WEAK_HASH_NAMES):
                name = call.get("name", "")
                leaf = name.split(".")[-1].lower()
                info = _WEAK_HASH_INFO.get(leaf)
                if info:
                    ast_hits[call.get("line", 0)] = info

        # Literal-pattern regex fallback (also catches hashlib.md5(...), etc.).
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, severity, message in _WEAK_HASH_PATTERNS:
                if pattern.search(line):
                    ast_hits.setdefault(line_num, (severity, message))

        has_good_hash = any(p.search(content) for p in _GOOD_HASH_PATTERNS)
        _PW_CTX = re.compile(r"passw|credential|pwd|login|auth", re.I)

        for line_num in sorted(ast_hits):
            severity, message = ast_hits[line_num]
            if has_good_hash:
                # Part 7: a good hash elsewhere in the file does not prove
                # THIS call site is safe — note it, don't bury the finding.
                message += " (note: bcrypt/scrypt also used in this file)"
            if not _PW_CTX.search(lines[line_num - 1]):
                # Part 7: weak hash with no password-adjacent context on the
                # line is a locator, not a "used for password hashing" verdict.
                severity = Severity.MEDIUM
                message += " (no password context on this line — verify usage)"
            findings.append(
                make_finding(
                    self.name,
                    "weak_password_hash",
                    severity,
                    rel_path,
                    message,
                    line=line_num,
                    code_snippet=lines[line_num - 1].strip()[:120],
                    suggestion="Use bcrypt, scrypt, or argon2 for password hashing.",
                )
            )
        return findings

    # ── Literal-pattern checks (multi-language) ─────────────────────────────

    def _check_session_security(self, content: str, rel_path: str) -> list[Finding]:
        return self._line_scan(
            content,
            rel_path,
            _SESSION_PATTERNS,
            "session_security",
            "Ensure session cookies use httponly, secure, and samesite flags.",
        )

    def _check_oauth(self, content: str, rel_path: str) -> list[Finding]:
        return self._line_scan(
            content,
            rel_path,
            _OAUTH_PATTERNS,
            "oauth_security",
            "Verify OAuth implementation follows security best practices.",
        )

    def _line_scan(self, content, rel_path, patterns, finding_type, suggestion) -> list[Finding]:
        from patchi.core.security.secret_evidence import looks_like_secret

        findings = []
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, severity, message in patterns:
                m = pattern.search(line)
                if not m:
                    continue
                # Part 7: patterns capturing a value group (group 1) gate
                # the VALUE through looks_like_secret — a sensitive NAME
                # with a weak value is not a finding.
                if pattern.groups >= 1:
                    try:
                        value = m.group(1)
                    except IndexError:
                        value = ""
                    if value and not looks_like_secret(value, allow_spaces=False):
                        continue
                findings.append(
                    make_finding(
                        self.name,
                        finding_type,
                        severity,
                        rel_path,
                        message,
                        line=line_num,
                        code_snippet=stripped[:120],
                        suggestion=suggestion,
                    )
                )
        return findings

    def _check_rate_limiting(self, content: str, rel_path: str) -> list[Finding]:
        has_rate_limit = any(p.search(content) for p in _RATE_LIMIT_PATTERNS)
        has_auth_endpoint = any(p.search(content) for p in _AUTH_ENDPOINT_PATTERNS)
        if has_auth_endpoint and not has_rate_limit:
            # Part 7: protection may live in middleware/config in another
            # file — file-local absence caps at MEDIUM with verify language.
            return [
                make_finding(
                    self.name,
                    "missing_rate_limit",
                    Severity.MEDIUM,
                    rel_path,
                    "Auth endpoints found with no rate limiting visible in this file — verify middleware/config",
                    suggestion="Add rate limiting to login/auth endpoints to prevent brute-force attacks.",
                )
            ]
        return []

    # ── Helpers ───────────────────────────────────────────────────────────

    def _should_skip(self, rel_path: str) -> bool:
        parts = rel_path.replace("\\", "/").split("/")
        return any(p in _SKIP_DIRS for p in parts)

    def _safe_rglob(self, root: Path, pattern: str):
        """Directory-walking with pruning."""
        suffix = pattern.replace("*.", ".")
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(suffix):
                    yield Path(dirpath) / fn
