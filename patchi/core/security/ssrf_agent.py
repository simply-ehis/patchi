"""
SSRFProtectionAgent — Server-Side Request Forgery protection analysis.

Scans for:
- Unvalidated URL/user-input passed to HTTP requests
- HTTP client calls with user-controlled URLs
- SSRF via redirect following
- Internal network access from user input
- File:// and other protocol handlers
- Missing URL validation/sanitization
- DNS rebinding potential
- Cloud metadata endpoint access (169.254.169.254)

Uses AST via ast_utils for HTTP client detection;
regex for literal text patterns (IPs, protocols, URL construction).
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
from ..brain.ast_utils import HTTP_CLIENTS, find_assignments, find_calls, get_call_arg
from ..brain.languages import DEFAULT_IGNORE_DIRS, Lang, detect_language
from ..brain.trace_log import trace_agent
from .pattern_loader import (
    get_ssrf_internal_network_patterns,
    get_ssrf_metadata_patterns,
    get_ssrf_protocol_patterns,
    load_patterns,
)

# Load YAML patterns once at module level
_SSRF_PATTERNS = load_patterns().get("ssrf", {})
_YAML_PROTOCOL = get_ssrf_protocol_patterns()
_YAML_METADATA = get_ssrf_metadata_patterns()
_YAML_INTERNAL = get_ssrf_internal_network_patterns()
_YAML_URL_VARS = set(_SSRF_PATTERNS.get("url_var_names", []))
_YAML_USER_INPUT = set(_SSRF_PATTERNS.get("user_input_markers", []))
_YAML_REDIRECT_SINKS = _SSRF_PATTERNS.get("redirect_sinks", {})


_log = logging.getLogger("patchi.security.ssrf_agent")


@register
class SSRFProtectionAgent(BaseAgent):
    """Agent for detecting SSRF vulnerabilities."""

    group = AgentGroup.SECURITY
    name = "SSRFProtectionAgent"
    description = (
        "SSRF protection: unvalidated URLs, internal network access, metadata endpoint exposure"
    )

    # ── Source patterns for multi-language scanning ─────────────────────────
    _SOURCE_PATTERNS = [
        "*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java",
        "*.php", "*.rb", "*.go", "*.rs", "*.cs",
    ]

    # ── Dangerous protocol handlers (merged from YAML + defaults) ────────────
    _PROTOCOL_PATTERNS = [
        (
            re.compile(r'["\']file://', re.I),
            Severity.HIGH,
            "file:// protocol handler — potential local file access via SSRF",
        ),
        (
            re.compile(r'["\']gopher://', re.I),
            Severity.HIGH,
            "gopher:// protocol handler — potential SSRF vector",
        ),
        (
            re.compile(r'["\']dict://', re.I),
            Severity.MEDIUM,
            "dict:// protocol handler — potential SSRF vector",
        ),
        (
            re.compile(r'["\']ldap://', re.I),
            Severity.MEDIUM,
            "ldap:// protocol handler — potential SSRF vector",
        ),
    ] + [(p, Severity(s), m) for p, s, m in _YAML_PROTOCOL]

    # ── Cloud metadata endpoints (merged from YAML + defaults) ──────────────
    _METADATA_PATTERNS = [
        (
            re.compile(r"169\.254\.169\.254", re.I),
            Severity.CRITICAL,
            "AWS/GCP cloud metadata endpoint access — potential SSRF to cloud credentials",
        ),
        (
            re.compile(r"metadata\.google\.internal", re.I),
            Severity.CRITICAL,
            "GCP metadata endpoint access — potential SSRF to cloud credentials",
        ),
    ] + [(p, Severity(s), m) for p, s, m in _YAML_METADATA]

    # ── Internal network patterns (merged from YAML + defaults) ─────────────
    _INTERNAL_NETWORK_PATTERNS = [
        (
            re.compile(r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+"),
            Severity.LOW,
            "Localhost URL — verify this isn't user-controlled",
        ),
        (
            re.compile(
                r"(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"
            ),
            Severity.MEDIUM,
            "Internal network IP — potential SSRF to internal services",
        ),
    ] + [(p, Severity(s), m) for p, s, m in _YAML_INTERNAL]

    # ── URL construction patterns (where user input flows to URL) ───────────
    _URL_VAR_NAMES = {
        "url", "endpoint", "target", "host", "base_url", "baseUri",
        "requestUrl", "fetchUrl", "request_url",
    } | _YAML_URL_VARS

    _USER_INPUT_MARKERS = {
        "request.", "req.", "params.", "args.", "input", "data[", "form[",
        "query.", "body.", "headers.", "c.Query", "r.URL",
    } | _YAML_USER_INPUT

    # ── Redirect/forward patterns (merged from YAML + defaults) ─────────────
    _REDIRECT_CALL_SINKS = {
        Lang.PYTHON: {"redirect", "redirect_url"},
        Lang.JAVASCRIPT: {"res.redirect", "response.redirect"},
        Lang.TYPESCRIPT: {"res.redirect", "response.redirect"},
        Lang.JAVA: {"sendRedirect"},
        Lang.PHP: {"header", "redirect"},
        Lang.RUBY: {"redirect_to"},
        Lang.GO: {"http.Redirect"},
        Lang.C_SHARP: {"Redirect"},
    }
    for _lk, _funcs in _YAML_REDIRECT_SINKS.items():
        try:
            _lang = Lang(_lk)
        except ValueError:
            continue
        _REDIRECT_CALL_SINKS.setdefault(_lang, set()).update(_funcs)

    _SKIP_DIRS = DEFAULT_IGNORE_DIRS | {"test", "tests", "vendor"}

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        files_scanned = 0

        with trace_agent(self.name, inp.root) as trace:
            for pattern in self._SOURCE_PATTERNS:
                for p in self._safe_rglob(inp.root, pattern):
                    rel = str(p.relative_to(inp.root))
                    if self._should_skip(rel):
                        continue
                    files_scanned += 1
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                    except Exception as e:
                        _log.warning("SSRFProtectionAgent._run failed: %s", e)
                        continue

                    lang = detect_language(p)
                    findings.extend(self._check_http_clients(content, lang, rel))
                    findings.extend(self._check_protocols(content, rel))
                    findings.extend(self._check_metadata(content, rel))
                    findings.extend(self._check_internal_network(content, rel))
                    findings.extend(self._check_url_construction(content, lang, rel))
                    findings.extend(self._check_redirects(content, lang, rel))
            trace.findings = len(findings)
            trace.files_scanned = files_scanned

        result.status = AgentStatus.DONE
        result.findings = findings
        result.files_scanned = files_scanned
        result.data.update({"files_scanned": files_scanned, "finding_count": len(findings)})
        return

    def _check_http_clients(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        findings = []
        for call in find_calls(content, lang, HTTP_CLIENTS):
            findings.append(
                make_finding(
                    self.name,
                    "ssrf_http_client",
                    Severity.MEDIUM,
                    rel_path,
                    f"HTTP client call ({call['name']}) — verify URL is not user-controlled",
                    line=call["line"],
                    code_snippet=call["full_text"][:120],
                    suggestion="Validate and whitelist URLs before making HTTP requests. Use URL parsing and allowlist.",
                )
            )
        return findings

    def _check_protocols(self, content: str, rel_path: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, severity, message in self._PROTOCOL_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        make_finding(
                            self.name,
                            "ssrf_dangerous_protocol",
                            severity,
                            rel_path,
                            message,
                            line=line_num,
                            code_snippet=stripped[:120],
                            suggestion="Block non-HTTP/HTTPS protocols in URL handling.",
                        )
                    )
        return findings

    def _check_metadata(self, content: str, rel_path: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, severity, message in self._METADATA_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        make_finding(
                            self.name,
                            "ssrf_metadata_access",
                            severity,
                            rel_path,
                            message,
                            line=line_num,
                            code_snippet=stripped[:120],
                            suggestion="Block access to cloud metadata endpoints. Use IMDSv2 if metadata access is required.",
                        )
                    )
        return findings

    def _check_internal_network(self, content: str, rel_path: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, severity, message in self._INTERNAL_NETWORK_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        make_finding(
                            self.name,
                            "ssrf_internal_network",
                            severity,
                            rel_path,
                            message,
                            line=line_num,
                            code_snippet=stripped[:120],
                            suggestion="Restrict outbound HTTP requests to prevent access to internal services.",
                        )
                    )
        return findings

    def _check_url_construction(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        findings = []
        for assign in find_assignments(content, lang):
            target = assign["target"].lower()
            if not any(v in target for v in self._URL_VAR_NAMES):
                continue
            value = assign["value"]
            if not any(marker in value.lower() for marker in self._USER_INPUT_MARKERS):
                continue
            findings.append(
                make_finding(
                    self.name,
                    "ssrf_url_construction",
                    Severity.HIGH,
                    rel_path,
                    f"URL variable '{assign['target']}' constructed from user input — validate and sanitize before use",
                    line=assign["line"],
                    code_snippet=assign["full_text"][:120],
                    suggestion="Parse URLs with urllib.parse and validate against an allowlist before use.",
                )
            )
        return findings

    def _check_redirects(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        findings = []
        sinks = self._REDIRECT_CALL_SINKS.get(lang, set())
        if sinks:
            for call in find_calls(content, lang, sinks):
                arg = get_call_arg(call["full_text"])
                if arg and any(marker in arg.lower() for marker in self._USER_INPUT_MARKERS):
                    findings.append(
                        make_finding(
                            self.name,
                            "ssrf_redirect",
                            Severity.HIGH,
                            rel_path,
                            "Redirect with user-controlled URL — potential open redirect/SSRF",
                            line=call["line"],
                            code_snippet=call["full_text"][:120],
                            suggestion="Validate redirect targets against an allowlist. Never redirect to user-supplied URLs.",
                        )
                    )
        return findings

    def _should_skip(self, rel_path: str) -> bool:
        parts = rel_path.replace("\\", "/").split("/")
        return any(p in self._SKIP_DIRS for p in parts)

    def _safe_rglob(self, root: Path, pattern: str):
        """Directory-walking with pruning."""
        suffix = pattern.replace("*.", ".")
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self._SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(suffix):
                    yield Path(dirpath) / fn
