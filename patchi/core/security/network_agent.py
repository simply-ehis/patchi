"""
NetworkAgent — network security configuration issues.

Detects network-related security issues:
- Insecure SSL/TLS configurations
- Missing HTTPS redirects
- Weak cipher suites
- Open ports/services
- Missing security headers
- Improper firewall rules
- Unencrypted communication

Uses pattern matching and configuration analysis.
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

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


@register
class NetworkAgent(BaseAgent):
    """Agent for detecting network security issues."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "NetworkAgent"
    description = "Network security: SSL/TLS, HTTPS redirects, cipher suites, security headers"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run network security configuration detection."""
        findings = []

        # Define configuration and source file patterns to scan
        patterns = [
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
            "*.json",
            "*.yml",
            "*.yaml",
            "*.toml",
            "*.config",
            "*.conf",
            "*.ini",
            "*.xml",
            "Dockerfile*",
            "docker-compose*.yml",
            "**/config/**",
            "**/nginx/**",
            "**/apache/**",
            "**/ssl/**",
            "**/tls/**",
        ]

        # Search for files
        for pattern in patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_file_network_security(file_path, rel_path))

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "network_findings": len(
                    [
                        f
                        for f in findings
                        if any(
                            word in f.title.lower()
                            for word in [
                                "ssl",
                                "tls",
                                "https",
                                "cipher",
                                "header",
                                "redirect",
                                "encryption",
                            ]
                        )
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

    def _scan_file_network_security(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan a file for network security issues."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")

            # Check for SSL/TLS issues
            findings.extend(self._scan_ssl_tls_issues(content, rel_path))

            # Check for HTTPS redirect issues
            findings.extend(self._scan_https_redirects(content, rel_path))

            # Check for weak cipher suites
            findings.extend(self._scan_cipher_suites(content, rel_path))

            # Check for missing security headers
            findings.extend(self._scan_security_headers(content, rel_path))

            # Check for other network security issues
            findings.extend(self._scan_other_network_issues(content, rel_path))

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Network security scanner file read error",
                    description=f"Could not analyze {file_path.name} for network security issues: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_ssl_tls_issues(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for SSL/TLS configuration issues."""
        findings = []

        # Look for weak SSL/TLS protocol versions. Part 7: bare `TLSv1`
        # as a substring matches TLSv1.2/TLSv1.3 — anchor to 1.0 exactly.
        # SSLv2/SSLv3 configured is CRITICAL; TLS 1.0 is HIGH.
        ssl_patterns = [
            (r"SSLv2|SSLv3", "Broken SSL Protocol", Severity.CRITICAL),
            (r"(?<![\w.])TLSv1\.0(?![\d.])|TLSv1(?![\d._])", "Weak TLS Protocol (1.0)", Severity.HIGH),
            (r"ssl_version.*TLSv1(\.0|_0)?(?![\d._])", "Weak TLS Version", Severity.HIGH),
            (r"tls_min_version.*TLSv1(\.0|_0)?(?![\d._])", "Weak TLS Minimum Version", Severity.HIGH),
            (
                r"protocol.*SSLv2|protocol.*SSLv3",
                "Weak Protocol Configuration",
                Severity.CRITICAL,
            ),
            (
                r"protocol.*TLSv1\.0(?![\d._])|protocol.*TLSv1(?![\d._])",
                "Weak Protocol Configuration (TLS 1.0)",
                Severity.HIGH,
            ),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in ssl_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description=f"Weak SSL/TLS protocol configuration found: {match.group(0)}",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_https_redirects(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for HTTPS redirect issues."""
        findings = []

        has_https_enforcement = bool(
            re.search(
                r"redirect.*https|enable.*https|hsts|strict-transport-security",
                content,
                re.IGNORECASE,
            )
        )
        has_plain_http = bool(
            re.search(
                r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
                content,
            )
        )

        if has_plain_http and not has_https_enforcement:
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                if re.search(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)", line):
                    findings.append(
                        make_finding(
                            severity=Severity.MEDIUM,
                            file=rel_path,
                            line_start=i,
                            title="Plain HTTP without HTTPS enforcement",
                            description="Plain HTTP URL found without HTTPS redirect/enforcement",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_cipher_suites(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for weak cipher suite configurations."""
        findings = []

        # Look for weak cipher suites. Part 7: bare tokens ("DES" in
        # "description") need cipher/TLS context on the line; AES-128 is
        # not weak and is dropped outright.
        _CIPHER_CTX = re.compile(r"cipher|tls|ssl|protocol|suite|openssl|schannel", re.IGNORECASE)
        weak_cipher_patterns = [
            (r"\bRC4\b|\bDES\b|\b3DES\b|\bMD5\b|\bSHA1\b", "Weak Cipher Suite", Severity.HIGH),
            (
                r"cipher.*\bRC4\b|cipher.*\bDES\b|cipher.*\b3DES\b|cipher.*\bMD5\b",
                "Weak Cipher Configuration",
                Severity.HIGH,
            ),
            (r"\bdes-cbc\b", "Potentially Weak Cipher", Severity.MEDIUM),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in weak_cipher_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    if not _CIPHER_CTX.search(line):
                        continue
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description=f"Weak cipher suite configuration found: {match.group(0)}",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_security_headers(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for missing security headers."""
        findings = []

        # Look for missing security headers
        security_headers = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Content-Security-Policy",
        ]

        # Check if security headers are set
        lines = content.splitlines()
        for _i, line in enumerate(lines, 1):
            # Look for response header setting
            if any(header.lower() in line.lower() for header in security_headers):
                continue  # Header is being set, no issue here
            elif any(
                setting_pattern in line.lower() for setting_pattern in ["header(", "setheader", "response.header"]
            ):
                # Check if it's setting a security header
                has_security_header = False
                for header in security_headers:
                    if header.lower() in line.lower():
                        has_security_header = True
                        break
                if not has_security_header:
                    # This line sets a header but not a security header
                    # This alone isn't necessarily bad, but let's check for missing headers in context
                    pass

        # Look for common web frameworks where security headers should be set
        framework_indicators = ["express", "django", "flask", "fastapi", "spring", "laravel"]
        if any(indicator in content.lower() for indicator in framework_indicators):
            # Check if security headers are configured
            has_hsts = any(hsts_pattern in content.lower() for hsts_pattern in ["strict-transport-security", "hsts"])
            has_xfo = any(xfo_pattern in content.lower() for xfo_pattern in ["x-frame-options", "frame-options"])
            has_xcto = any(xcto_pattern in content.lower() for xcto_pattern in ["x-content-type-options", "nosniff"])

            missing_headers = []
            if not has_hsts:
                missing_headers.append("HSTS")
            if not has_xfo:
                missing_headers.append("X-Frame-Options")
            if not has_xcto:
                missing_headers.append("X-Content-Type-Options")

            if missing_headers:
                findings.append(
                    make_finding(
                        severity=Severity.MEDIUM,
                        file=rel_path,
                        line_start=0,
                        title=f"Missing Security Headers: {', '.join(missing_headers)}",
                        description=f"No {', '.join(missing_headers)} found in this file"
                        " — verify middleware/proxy sets them",
                        evidence=f"Detected web framework but missing security headers: {', '.join(missing_headers)}",
                    )
                )

        return findings

    def _scan_other_network_issues(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for other network security issues."""
        findings = []

        # Part 7: the per-line http check duplicates _scan_https_redirects
        # (which additionally excludes localhost and checks enforcement).
        # This block now only covers http:// references in non-URL contexts
        # the redirect check misses (docs/comments excluded by callers).
        http_patterns = [
            (r'"http://(?!localhost|127\.0\.0\.1)', "Plain HTTP Reference", Severity.MEDIUM),
            (r"'http://(?!localhost|127\.0\.0\.1)", "Plain HTTP Reference", Severity.MEDIUM),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in http_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description=f"Plain HTTP URL found in potentially secure context: {match.group(0)}",
                            evidence=line.strip(),
                        )
                    )

        return findings
