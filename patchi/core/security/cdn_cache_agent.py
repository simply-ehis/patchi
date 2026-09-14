"""
CDNCacheSecurityAgent — CDN/edge cache security issues.

Detects CDN-related security issues:
- Cache poisoning via unvalidated headers
- Origin bypass (missing origin access controls)
- Cache-key normalization flaws
- Missing cache-control directives
- CDN configuration misconfigurations (CloudFront, Fastly, etc.)

Uses static file analysis and optional external tools (curl).
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
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
from ..brain.trace_log import trace_agent

_SOURCE_EXTENSIONS = {
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
    "*.yaml",
    "*.yml",
    "*.toml",
    "*.json",
    "*.conf",
    "*.cfg",
    "*.nginx",
}

_CDN_CONFIG_NAMES = {
    "cloudfront.yaml",
    "cloudfront.yml",
    "cloudfront.json",
    "fastly.toml",
    "fastly.yaml",
    "fastly.yml",
    "cloudflare.toml",
    "cloudflare.yaml",
    "cloudflare.yml",
    "akamai.json",
    "akamai.yaml",
    "cloudfront-properties.json",
}

_CACHE_CONTROL_PATTERNS = [
    re.compile(r"cache-control", re.IGNORECASE),
    re.compile(r"surrogate-control", re.IGNORECASE),
    re.compile(r"x-cache", re.IGNORECASE),
    re.compile(r"cdn-cache", re.IGNORECASE),
]

_ORIGIN_BYPASS_PATTERNS = [
    (re.compile(r"X-Forwarded-Host", re.IGNORECASE), "X-Forwarded-Host header manipulation"),
    (re.compile(r"X-Original-URL", re.IGNORECASE), "X-Original-URL header injection"),
    (re.compile(r"X-Rewrite-URL", re.IGNORECASE), "X-Rewrite-URL header injection"),
    (re.compile(r"X-Real-IP", re.IGNORECASE), "X-Real-IP header spoofing"),
]

_CACHE_KEY_INJECTION_PATTERNS = [
    (
        re.compile(r"(?:cache.?key|cacheKey|cache_key)\s*[=:]\s*.*\+|f['\"].*\{.*\}", re.IGNORECASE),
        "Dynamic cache key construction via string concatenation",
    ),
    (re.compile(r"Vary\s*:\s*\*", re.IGNORECASE), "Wildcard Vary header may cause cache poisoning"),
]


_log = logging.getLogger("patchi.security.cdn_cache_agent")


@register
class CDNCacheSecurityAgent(BaseAgent):
    """Agent for detecting CDN and edge cache security issues."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "CDNCacheSecurityAgent"
    description = "CDN/edge cache security: cache poisoning, origin bypass, cache-key normalization"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings: list[Finding] = []
        files_scanned = 0

        with trace_agent(self.name, inp.root) as trace:
            # ── Static analysis ────────────────────────────────────────────
            findings.extend(self._scan_cdn_configs(inp))
            findings.extend(self._scan_cache_headers(inp))
            findings.extend(self._scan_origin_bypass(inp))
            findings.extend(self._scan_cache_key_issues(inp))

            for pattern in _SOURCE_EXTENSIONS:
                for fp in safe_rglob(inp.root, pattern):
                    if fp.is_file():
                        files_scanned += 1
                        findings.extend(self._scan_file(fp, inp.root))

            # ── External tool: curl ────────────────────────────────────────
            if shutil.which("curl"):
                findings.extend(self._run_curl_check(inp))

            trace.findings = len(findings)
            trace.files_scanned = files_scanned

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "cdn_findings": len(findings),
                "curl_available": shutil.which("curl") is not None,
            }
        )
        return

    # ── CDN config file scan ───────────────────────────────────────────────

    def _scan_cdn_configs(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for fp in safe_rglob(inp.root, "*"):
            if fp.name in _CDN_CONFIG_NAMES:
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    if "OriginAccessControl" not in content and "origin_access" not in content.lower():
                        findings.append(
                            make_finding(
                                severity=Severity.HIGH,
                                file=rel,
                                line_start=0,
                                title="CDN-01: Missing Origin Access Control",
                                description=(
                                    "CDN configuration file found without origin access control "
                                    "settings. This may allow direct origin bypass."
                                ),
                                evidence=content[:200],
                                suggestion="Enable Origin Access Identity (CloudFront) or Shield Origin (Fastly).",
                            )
                        )
                    if "signed" not in content.lower() and "token" not in content.lower():
                        findings.append(
                            make_finding(
                                severity=Severity.MEDIUM,
                                file=rel,
                                line_start=0,
                                title="CDN-02: No Signed URLs/Cookies Configured",
                                description="CDN distribution has no signed URL or signed cookie configuration.",
                                suggestion="Enable signed URLs or signed cookies for authenticated content.",
                            )
                        )
                except Exception as e:
                    _log.warning("CDNCacheSecurityAgent._scan_cdn_configs failed: %s", e)
        return findings

    # ── Cache header analysis ──────────────────────────────────────────────

    def _scan_cache_headers(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        header_patterns = [
            ("*.conf", ["nginx", "apache", "httpd"]),
            ("*.cfg", ["nginx", "apache"]),
            ("*.yaml", ["proxy", "upstream", "cache"]),
            ("*.yml", ["proxy", "upstream", "cache"]),
        ]
        for pattern, _context_words in header_patterns:
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                    for i, line in enumerate(lines, 1):
                        for rx in _CACHE_CONTROL_PATTERNS:
                            if rx.search(line):
                                if "no-store" not in line.lower() and "private" not in line.lower():
                                    findings.append(
                                        make_finding(
                                            severity=Severity.MEDIUM,
                                            file=rel,
                                            line_start=i,
                                            title="CDN-03: Cache-Control May Allow Sensitive Data Caching",
                                            description=(
                                                "Cache header found without no-store/private directive. "
                                                "Sensitive data may be cached at the edge."
                                            ),
                                            evidence=line.strip(),
                                            suggestion="Add 'no-store' or 'private' for sensitive endpoints.",
                                        )
                                    )
                                break
                except Exception as e:
                    _log.warning("CDNCacheSecurityAgent._scan_cache_headers failed: %s", e)
        return findings

    # ── Origin bypass patterns ─────────────────────────────────────────────

    def _scan_origin_bypass(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.py", "*.js", "*.ts", "*.java", "*.go", "*.rb", "*.php"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                    for i, line in enumerate(lines, 1):
                        for rx, desc in _ORIGIN_BYPASS_PATTERNS:
                            if rx.search(line) and "test" not in rel.lower():
                                findings.append(
                                    make_finding(
                                        severity=Severity.HIGH,
                                        file=rel,
                                        line_start=i,
                                        title="CDN-04: Origin Bypass via Header Injection",
                                        description=desc,
                                        evidence=line.strip(),
                                        suggestion="Validate and strip CDN-injected headers at the origin.",
                                    )
                                )
                except Exception as e:
                    _log.warning("CDNCacheSecurityAgent._scan_origin_bypass failed: %s", e)
        return findings

    # ── Cache-key normalization ────────────────────────────────────────────

    def _scan_cache_key_issues(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.py", "*.js", "*.ts", "*.go", "*.rb", "*.php", "*.conf"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                    for i, line in enumerate(lines, 1):
                        for rx, desc in _CACHE_KEY_INJECTION_PATTERNS:
                            if rx.search(line):
                                findings.append(
                                    make_finding(
                                        severity=Severity.MEDIUM,
                                        file=rel,
                                        line_start=i,
                                        title="CDN-05: Cache Key Injection Risk",
                                        description=desc,
                                        evidence=line.strip(),
                                        suggestion="Normalize cache keys to prevent injection via headers.",
                                    )
                                )
                except Exception as e:
                    _log.warning("CDNCacheSecurityAgent._scan_cache_key_issues failed: %s", e)
        return findings

    # ── General source file scan ───────────────────────────────────────────

    def _scan_file(self, fp: Path, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = fp.relative_to(root).as_posix()
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            # CDN-specific secrets
            secret_patterns = [
                (
                    re.compile(
                        r"(?:cloudfront|fastly|cloudflare)[_-]?(?:key|token|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                        re.IGNORECASE,
                    ),
                    "CDN-06: Hardcoded CDN Credential",
                ),
            ]
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                for rx, title in secret_patterns:
                    if rx.search(line):
                        findings.append(
                            make_finding(
                                severity=Severity.CRITICAL,
                                file=rel,
                                line_start=i,
                                title=title,
                                description="Hardcoded CDN credential found in source code.",
                                evidence=line.strip()[:120],
                                suggestion="Move CDN credentials to environment variables or a secrets manager.",
                            )
                        )
        except Exception as e:
            _log.warning("CDNCacheSecurityAgent._scan_file failed: %s", e)
        return findings

    # ── External tool: curl ────────────────────────────────────────────────

    def _run_curl_check(self, inp: AgentInput) -> list[Finding]:
        """Use curl to probe cache headers if a URL is provided in config."""
        findings: list[Finding] = []
        url = inp.config.get("cdn_probe_url")
        if not url or not isinstance(url, str):
            return findings

        try:
            proc = subprocess.run(
                ["curl", "-sI", "-m", "10", url],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode == 0:
                headers_lower = proc.stdout.lower()
                if "x-cache:" in headers_lower and "hit" in headers_lower:
                    findings.append(
                        make_finding(
                            severity=Severity.LOW,
                            file="(cdn_probe)",
                            line_start=0,
                            title="CDN-03: Cache Hit Detected on Probe URL",
                            description="The probed URL returned a cache HIT. Verify sensitive data is not cached.",
                            evidence=proc.stdout[:300],
                        )
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return findings
