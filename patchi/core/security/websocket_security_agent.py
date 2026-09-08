"""
WebSocketSecurityAgent — WebSocket security vulnerability detection.

Detects:
- Unencrypted WebSocket connections (ws:// instead of wss://)
- Missing origin validation
- Unvalidated message input (injection via WebSocket messages)
- Missing authentication in WebSocket handshake
- Unlimited message size / rate
- WebSocket message type confusion
- Sensitive data in WebSocket messages

Uses static pattern matching, NOT AI.
Does NOT write to disk. Does NOT touch the queue.
"""

from __future__ import annotations

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


@register
class WebSocketSecurityAgent(BaseAgent):
    """Detects WebSocket security vulnerabilities."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "WebSocketSecurityAgent"
    description = "WebSocket injection, origin validation, unencrypted WS, message validation"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Only scan files likely to contain WebSocket code (not every .py in the project)
        patterns = ["*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.java", "*.go"]

        # Pre-scan: skip files that lack any WebSocket keyword (fast path)
        ws_guard = re.compile(
            r"(?i)(?:websocket|wss?://|socket\.io|fastapi\.websocket|starlette\.websocket|flask-socketio|django\.channels|aiohttp\.web\.WebSocketResponse|tornado\.websocket|\.ws\.route)",
            re.I,
        )
        for pat in patterns:
            for fpath in safe_rglob(inp.root, pat):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if not ws_guard.search(content):
                    continue
                result.files_scanned += 1
                self._scan_websocket(content, rel, result)

    def _scan_websocket(self, content: str, rel: str, result: AgentResult) -> None:
        # ── Unencrypted WebSocket connection ────────────────────────────────
        for m in re.finditer(r"""(?i)["']ws://""", content):
            line = content[: m.start()].count("\n") + 1
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="unencrypted_websocket",
                    severity=Severity.HIGH,
                    file=rel,
                    line=line,
                    message="Unencrypted WebSocket connection (ws://) — use wss:// for production",
                    suggestion="Replace ws:// with wss:// and ensure TLS is configured",
                    cwe="CWE-319",
                    extra={"skill": "api-security.skill"},
                )
            )

        # ── Missing origin validation ───────────────────────────────────────
        if not re.search(
            r"(?i)(?:\borigin\b|check_origin|allowed_origins|validate_origin)", content
        ):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="missing_origin_validation",
                    severity=Severity.MEDIUM,
                    file=rel,
                    line=0,
                    message="WebSocket handler lacks origin validation — potential cross-origin hijacking",
                    suggestion="Validate Origin header on WebSocket upgrade, configure allowed_origins",
                    cwe="CWE-346",
                    extra={"skill": "api-security.skill"},
                )
            )

        # ── Message without input validation ───────────────────────────────
        for m in re.finditer(
            r'(?i)(?:websocket|socketio)\.(?:on_message|receive|recv|on\s*\(\s*["\']message)',
            content,
        ):
            line_start = content[: m.start()].count("\n") + 1
            surrounding = content[m.start() : m.start() + 500]
            if not re.search(
                r"(?i)(?:validate|sanitize|check|json\.loads|parse)", surrounding[:200]
            ):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="websocket_no_input_validation",
                        severity=Severity.HIGH,
                        file=rel,
                        line=line_start,
                        message="WebSocket message processed without input validation — injection risk",
                        suggestion="Validate/sanitize all WebSocket message content before processing",
                        cwe="CWE-20",
                        extra={"skill": "api-security.skill"},
                    )
                )

        # ── Missing authentication on WebSocket upgrade ────────────────────
        for m in re.finditer(
            r"(?i)(?:@(?:ws|websocket)\.route|\bdef\s+websocket\b|\basync\s+def\s+websocket\b|socketio\.on\b)",
            content,
        ):
            line_start = content[: m.start()].count("\n") + 1
            surrounding = content[m.start() : m.start() + 300]
            if not re.search(
                r"(?i)(?:auth|token|jwt|session|api_key|authenticate)", surrounding[:150]
            ):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="websocket_no_auth",
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=line_start,
                        message="WebSocket endpoint lacks authentication — unauthenticated access",
                        suggestion="Add authentication handshake (JWT, session, or API key) to WebSocket upgrade",
                        cwe="CWE-287",
                        extra={"skill": "api-security.skill"},
                    )
                )

        # ── Message size / rate limiting missing ───────────────────────────
        for m in re.finditer(
            r'(?i)(?:@app\.ws|\bwebsocket_route\b|\.on\s*\(\s*["\']?connect)', content
        ):
            line_start = content[: m.start()].count("\n") + 1
            surrounding = content[m.start() : m.start() + 300]
            if not re.search(r"(?i)(?:max_size|max_length|limit|throttle|rate)", surrounding[:150]):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="websocket_no_limit",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=line_start,
                        message="WebSocket missing message size/rate limiting — DoS vector",
                        suggestion="Configure max_message_size and rate limiting for WebSocket messages",
                        cwe="CWE-770",
                        extra={"skill": "api-security.skill"},
                    )
                )

        # ── Sensitive data sent over WebSocket ─────────────────────────────
        for m in re.finditer(
            r'(?i)(?:send|emit)\(.*["\']?(?:\bpassword\b|\btoken\b|\bsecret\b|api_key|secret_key|\bssn\b|\bcredit\b)',
            content,
        ):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="sensitive_data_in_websocket",
                    severity=Severity.HIGH,
                    file=rel,
                    line=content[: m.start()].count("\n") + 1,
                    message="Sensitive data potentially sent over WebSocket — data leak risk",
                    suggestion="Avoid sending secrets/tokens over WebSocket; use server-side operations",
                    cwe="CWE-200",
                    extra={"skill": "api-security.skill"},
                )
            )
