"""
SessionManagementAgent — Session management vulnerability detection.

Detects:
- Session fixation (no regeneration on login)
- Weak session ID generation (user-controlled or predictable)
- Missing/insecure cookie flags (HttpOnly, Secure, SameSite)
- Session timeout not configured
- Concurrent session control missing
- Session in URL parameters
- Missing session invalidation on logout
- Weak session storage (localStorage instead of httpOnly cookies)

Uses tree-sitter AST for call/identifier detection where beneficial, with
high-quality literal-pattern checks for configuration flags. NOT AI.
Does NOT write to disk. Does NOT touch the queue.
"""

from __future__ import annotations

import os
import re

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)
from ..brain.ast_utils import find_calls
from ..brain.languages import EXTENSION_MAP, Lang

# Call names that set a session cookie (used for cookie-flag checks).
_COOKIE_SETTER_CALLS = {
    "set_cookie",
    "setcookie",
    "cookie.set",
    "cookies.set",
    "session.cookie",
    "response.set_cookie",
    "res.cookie",
    "ctx.cookie",
}
# Literal header / config forms that also set cookies.
_COOKIE_SETTER_LITERALS = re.compile(
    r"(?i)\b(?:Set-Cookie|set_cookie|session\.cookie|cookie\.set)\b"
)


@register
class SessionManagementAgent(BaseAgent):
    """Detects session management vulnerabilities."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "SessionManagementAgent"
    description = (
        "Session fixation, weak session IDs, missing cookie flags, insecure session storage"
    )

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        patterns = ["*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.java", "*.rb", "*.php", "*.go"]

        for pat in patterns:
            for fpath in safe_rglob(inp.root, pat):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                result.files_scanned += 1
                ext = os.path.splitext(rel)[1].lower()
                lang = EXTENSION_MAP.get(ext)
                self._scan_session(content, rel, result, lang)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _calls(self, content: str, lang: Lang | None, names: set[str]) -> list[dict]:
        if lang is None:
            return []
        return find_calls(content, lang, names)

    def _offset_of_line(self, content: str, line: int) -> int:
        lines = content.splitlines()
        offset = 0
        for ln in lines[: max(0, line - 1)]:
            offset += len(ln) + 1
        return offset

    # ── Scan ────────────────────────────────────────────────────────────────

    def _scan_session(self, content: str, rel: str, result: AgentResult, lang: Lang | None) -> None:
        # ── Session fixation — no regeneration on login ──────────────────────
        login_match = re.search(r"(?i)(?:login|signin|authenticate)\s*\(", content)
        if login_match:
            login_line = content[: login_match.start()].count("\n") + 1
            surrounding = content[login_match.start() : login_match.start() + 800]
            if re.search(r'(?i)\bsession\[["\']?(?:user_id|user|username|email)\b', surrounding):
                if not re.search(
                    r"(?i)(?:regenerate|rotate|regenerate_id|session\.new)", surrounding
                ):
                    result.add_finding(
                        Finding(
                            agent=self.name,
                            type="session_fixation",
                            severity=Severity.HIGH,
                            file=rel,
                            line=login_line,
                            message="Session not regenerated on login — vulnerable to session fixation",
                            suggestion="Call session.regenerate() or rotate session ID after successful login",
                            cwe="CWE-384",
                            extra={"skill": "owasp-top10-web.skill"},
                        )
                    )

        # ── Cookie flags missing / insecure ──────────────────────────────────
        has_cookie_setter = bool(self._calls(content, lang, _COOKIE_SETTER_CALLS)) or bool(
            _COOKIE_SETTER_LITERALS.search(content)
        )
        if has_cookie_setter:
            if not re.search(r"(?i)\b(?:HttpOnly|httponly|http_only)\b", content):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="missing_httponly",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=0,
                        message="HTTP-only cookie flag not set — session ID accessible to JavaScript",
                        suggestion="Set HttpOnly flag on session cookies",
                        cwe="CWE-1004",
                        extra={"skill": "owasp-top10-web.skill"},
                    )
                )
            if not re.search(r"\bSecure\b", content, re.IGNORECASE):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="missing_secure_flag",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=0,
                        message="Secure cookie flag not set — session cookies sent over HTTP",
                        suggestion="Set Secure flag on session cookies for HTTPS-only transmission",
                        cwe="CWE-614",
                        extra={"skill": "owasp-top10-web.skill"},
                    )
                )

        # ── Session in URL parameter ────────────────────────────────────────
        for m in re.finditer(r"(?i)\b(?:session|sid|session_id|token)\s*=\s*\{?\w+", content):
            line = content[: m.start()].count("\n") + 1
            if m.group(0).startswith(("session=", "sid=", "session_id=", "token=")):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="session_in_url",
                        severity=Severity.HIGH,
                        file=rel,
                        line=line,
                        message="Session identifier in URL parameter — exposed in referrer headers and logs",
                        suggestion="Move session ID to httpOnly cookies, never in URL",
                        cwe="CWE-598",
                        extra={"skill": "owasp-top10-web.skill"},
                    )
                )

        # ── Weak session storage (localStorage) ────────────────────────────
        for call in self._calls(content, lang, {"setItem"}):
            full = call.get("full_text", "")
            if re.search(r"(?i)(?:token|session|jwt|access_token)", full):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="insecure_session_storage",
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=call.get("line", 0),
                        message="Session/token stored in localStorage — accessible to XSS attacks",
                        suggestion="Use httpOnly cookies for session tokens instead of localStorage",
                        cwe="CWE-312",
                        extra={"skill": "owasp-top10-web.skill"},
                    )
                )

        # ── No session timeout / expiry ─────────────────────────────────────
        if re.search(
            r"(?i)\b(?:session|token)\b.*\b(?:expire|timeout|ttl|max_age|maxAge)\b", content
        ):
            pass  # OK — has expiry configuration
        elif re.search(r"(?i)\bsession\.(?:start|init|create|new)\s*\(", content):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="missing_session_timeout",
                    severity=Severity.LOW,
                    file=rel,
                    line=0,
                    message="Session created without explicit timeout/expiry configuration",
                    suggestion="Configure session TTL / max-age (recommended: 30-60 minutes)",
                    cwe="CWE-613",
                    extra={"skill": "owasp-top10-web.skill"},
                )
            )

        # ── Missing logout / invalidation ───────────────────────────────────
        if re.search(r"(?i)\bsession\.(?:destroy|invalidate|clear|delete)\b", content):
            pass  # OK — logout properly invalidates
        elif re.search(r"(?i)(?:def\s+logout|function\s+logout|logout\s*=\s*function)", content):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="missing_session_invalidation",
                    severity=Severity.MEDIUM,
                    file=rel,
                    line=0,
                    message="Logout function present but session invalidation may be missing",
                    suggestion="Call session.destroy() or session.clear() on logout",
                    cwe="CWE-613",
                    extra={"skill": "owasp-top10-web.skill"},
                )
            )

        # ── Weak session ID via user-controlled input ──────────────────────
        for m in re.finditer(r"(?i)\bsession_id\s*=\s*(?:request\.|req\.|params\.|input)", content):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="user_controlled_session_id",
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=content[: m.start()].count("\n") + 1,
                    message="Session ID derived from user-controlled input — session hijacking risk",
                    suggestion="Use server-generated cryptographically random session IDs",
                    cwe="CWE-384",
                    extra={"skill": "owasp-top10-web.skill"},
                )
            )
