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

import ipaddress
import logging
import os
from pathlib import Path
from urllib.parse import urlsplit

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
from ..brain.ast_utils import HTTP_CLIENTS, find_assignments, find_calls, get_call_arg
from ..brain.code_query import string_literals
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
    domain = AgentDomain.SECURITY
    name = "SSRFProtectionAgent"
    description = "SSRF protection: unvalidated URLs, internal network access, metadata endpoint exposure"

    # ── Source patterns for multi-language scanning ─────────────────────────
    _SOURCE_PATTERNS = [
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
        "*.cs",
    ]

    # ── Dangerous protocol handlers (merged from YAML + defaults) ────────────
    # Dangerous schemes / hosts, matched against parsed string literals
    # (urllib.parse + ipaddress — comments and formatting can't misfire).
    # User-supplied YAML customs stay pattern-based (see _YAML_* below).
    _DANGEROUS_SCHEMES = {
        "file": (
            Severity.HIGH,
            "file:// protocol handler — potential local file access via SSRF",
        ),
        "gopher": (
            Severity.HIGH,
            "gopher:// protocol handler — potential SSRF vector",
        ),
        "dict": (
            Severity.MEDIUM,
            "dict:// protocol handler — potential SSRF vector",
        ),
        "ldap": (
            Severity.MEDIUM,
            "ldap:// protocol handler — potential SSRF vector",
        ),
    }
    _METADATA_HOSTS = frozenset({"169.254.169.254", "metadata.google.internal"})

    # ── Cloud metadata endpoints (merged from YAML + defaults) ──────────────
    _METADATA_MESSAGES = {
        "169.254.169.254": "AWS/GCP cloud metadata endpoint access — potential SSRF to cloud credentials",
        "metadata.google.internal": "GCP metadata endpoint access — potential SSRF to cloud credentials",
    }

    # ── Internal network patterns (merged from YAML + defaults) ─────────────
    _LOCALHOST_MESSAGE = "Localhost URL — verify this isn't user-controlled"
    _INTERNAL_MESSAGE = "Internal network IP — potential SSRF to internal services"

    # ── URL construction patterns (where user input flows to URL) ───────────
    _URL_VAR_NAMES = {
        "url",
        "endpoint",
        "target",
        "host",
        "base_url",
        "baseUri",
        "requestUrl",
        "fetchUrl",
        "request_url",
    } | _YAML_URL_VARS

    _USER_INPUT_MARKERS = {
        "request.",
        "req.",
        "params.",
        "args.",
        "input",
        "data[",
        "form[",
        "query.",
        "body.",
        "headers.",
        "c.Query",
        "r.URL",
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
                    findings.extend(self._check_url_literals(content, lang, rel))
                    findings.extend(self._check_custom_patterns(content, rel))
                    findings.extend(self._check_url_construction(content, lang, rel))
                    findings.extend(self._check_redirects(content, lang, rel))
            # Dedupe: structural checks and YAML customs can flag the same
            # literal with slightly different messages — same place+type is one issue
            seen: set[tuple] = set()
            unique: list = []
            for finding in findings:
                key = (finding.file, finding.type, finding.line)
                if key not in seen:
                    seen.add(key)
                    unique.append(finding)
            findings = unique
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
            # LOW, not MEDIUM: a bare client call is a review reminder, not
            # evidence — exploitability needs user-controlled input reaching
            # the URL (see _check_url_construction, which carries the weight).
            # Every httpx.get in a codebase is not a MEDIUM finding.
            findings.append(
                make_finding(
                    self.name,
                    "ssrf_http_client",
                    Severity.LOW,
                    rel_path,
                    f"HTTP client call ({call['name']}) — verify URL is not user-controlled",
                    line=call["line"],
                    code_snippet=call["full_text"][:120],
                    suggestion="Validate and whitelist URLs before making HTTP requests. Use URL parsing and"
                    " allowlist.",
                )
            )
        return findings

    @staticmethod
    def _split_host(value: str) -> tuple[str, str]:
        """(scheme, host) from a literal; bare hostnames work without scheme."""
        text = value.strip()
        if "://" in text:
            try:
                parsed = urlsplit(text)
                return parsed.scheme.lower(), parsed.hostname or ""
            except ValueError:
                return "", ""
        return "", text

    def _check_url_literals(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        """Dangerous URLs via parsed string literals (urllib.parse + ipaddress)."""
        findings = []
        lines = content.splitlines()

        def _snippet(line_num: int) -> str:
            if 0 < line_num <= len(lines):
                return lines[line_num - 1].strip()[:120]
            return ""

        for value, line_num in string_literals(content, lang):
            if "://" not in value and "." not in value and ":" not in value:
                continue
            scheme, host = self._split_host(value)
            if scheme in self._DANGEROUS_SCHEMES:
                severity, message = self._DANGEROUS_SCHEMES[scheme]
                findings.append(
                    make_finding(
                        self.name,
                        "ssrf_dangerous_protocol",
                        severity,
                        rel_path,
                        message,
                        line=line_num,
                        code_snippet=_snippet(line_num),
                        suggestion="Block non-HTTP/HTTPS protocols in URL handling.",
                    )
                )
                continue
            host = (host or "").lower().split("@")[-1].split(":")[0].strip("[]")
            if not host:
                continue
            if host in self._METADATA_MESSAGES:
                findings.append(
                    make_finding(
                        self.name,
                        "ssrf_metadata_access",
                        Severity.CRITICAL,
                        rel_path,
                        self._METADATA_MESSAGES[host],
                        line=line_num,
                        code_snippet=_snippet(line_num),
                        suggestion="Block access to cloud metadata endpoints. Use IMDSv2 if metadata access is"
                        " required.",
                    )
                )
                continue
            if host == "localhost":
                findings.append(
                    make_finding(
                        self.name,
                        "ssrf_internal_network",
                        Severity.LOW,
                        rel_path,
                        self._LOCALHOST_MESSAGE,
                        line=line_num,
                        code_snippet=_snippet(line_num),
                        suggestion="Restrict outbound HTTP requests to prevent access to internal services.",
                    )
                )
                continue
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                if addr.is_loopback:
                    severity, message = Severity.LOW, self._LOCALHOST_MESSAGE
                else:
                    severity, message = Severity.MEDIUM, self._INTERNAL_MESSAGE
                findings.append(
                    make_finding(
                        self.name,
                        "ssrf_internal_network",
                        severity,
                        rel_path,
                        message,
                        line=line_num,
                        code_snippet=_snippet(line_num),
                        suggestion="Restrict outbound HTTP requests to prevent access to internal services.",
                    )
                )
        return findings

    @staticmethod
    def _as_severity(value) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return Severity(str(value).lower())
        except ValueError:
            return Severity.MEDIUM

    def _check_custom_patterns(self, content: str, rel_path: str) -> list[Finding]:
        """User-supplied YAML customs stay pattern-based (configuration, not logic)."""
        findings = []
        customs: list[tuple] = []
        customs.extend((p, s, m, "ssrf_dangerous_protocol") for p, s, m in _YAML_PROTOCOL)
        customs.extend((p, s, m, "ssrf_metadata_access") for p, s, m in _YAML_METADATA)
        customs.extend((p, s, m, "ssrf_internal_network") for p, s, m in _YAML_INTERNAL)
        if not customs:
            return findings
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, severity, message, finding_type in customs:
                try:
                    matched = pattern.search(line)
                except Exception:
                    continue
                if matched:
                    findings.append(
                        make_finding(
                            self.name,
                            finding_type,
                            self._as_severity(severity),
                            rel_path,
                            message,
                            line=line_num,
                            code_snippet=stripped[:120],
                            suggestion="Review against SSRF guidance.",
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
                            suggestion="Validate redirect targets against an allowlist. Never redirect to"
                            " user-supplied URLs.",
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
