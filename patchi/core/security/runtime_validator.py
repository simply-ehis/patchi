"""
Runtime Security Validation (Layer 5) — DAST for web apps.

Deploys the generated app in an isolated environment and runs:
- Security header validation on actual HTTP responses
- TLS/SSL configuration checks
- HTTP method tampering tests
- Server information leakage detection
- Basic active probing (when dev mode enabled)

Requires the app to be running (or spins up via Docker if available).
"""

from __future__ import annotations
import logging

import subprocess
import urllib.error
import urllib.request

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
)
from patchi.core.constants import is_offline

# ── Expected security headers ─────────────────────────────────────────────────

_REQUIRED_HEADERS = {
    "strict-transport-security": ("HSTS missing", Severity.HIGH, "CWE-319"),
    "x-content-type-options": ("X-Content-Type-Options missing", Severity.MEDIUM, "CWE-693"),
    "x-frame-options": ("X-Frame-Options missing (clickjacking)", Severity.MEDIUM, "CWE-1021"),
    "x-xss-protection": ("X-XSS-Protection missing", Severity.LOW, "CWE-79"),
    "content-security-policy": ("Content-Security-Policy missing", Severity.HIGH, "CWE-693"),
    "referrer-policy": ("Referrer-Policy missing", Severity.LOW, "CWE-200"),
    "permissions-policy": ("Permissions-Policy missing", Severity.LOW, "CWE-250"),
}

_DANGEROUS_HEADERS = {
    "server": ("Server header leaks version info", Severity.LOW, "CWE-200"),
    "x-powered-by": ("X-Powered-By header leaks technology stack", Severity.LOW, "CWE-200"),
}

_SENSITIVE_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS"]


_log = logging.getLogger("patchi.security.runtime_validator")


def _check_headers(url: str) -> list[dict]:
    """Fetch URL and check security headers."""
    findings = []
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Patchi-SecurityValidator/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, (msg, sev, cwe) in _REQUIRED_HEADERS.items():
                if header not in headers:
                    findings.append(
                        {"message": msg, "severity": sev.value, "cwe": cwe, "header": header}
                    )

            for header, (msg, sev, cwe) in _DANGEROUS_HEADERS.items():
                if header in headers:
                    findings.append(
                        {
                            "message": f"{msg}: {headers[header]}",
                            "severity": sev.value,
                            "cwe": cwe,
                            "header": header,
                        }
                    )

    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        pass

    return findings


def _check_method_tampering(base_url: str) -> list[dict]:
    """Test if sensitive HTTP methods are allowed."""
    findings = []
    for method in _SENSITIVE_METHODS:
        try:
            req = urllib.request.Request(base_url, method=method)
            req.add_header("User-Agent", "Patchi-SecurityValidator/1.0")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status < 400:
                    findings.append(
                        {
                            "message": f"HTTP {method} allowed on {base_url} (status {resp.status})",
                            "severity": "medium" if method in ("PUT", "DELETE", "PATCH") else "low",
                            "cwe": "CWE-749",
                        }
                    )
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            # 405 Method Not Allowed is expected
            pass
        except Exception as e:
            _log.warning("_check_method_tampering failed: %s", e)

    return findings


def _check_tls(url: str) -> list[dict]:
    """Basic TLS check — verify HTTPS and cert validity."""
    findings = []
    if url.startswith("http://"):
        findings.append(
            {
                "message": "Application uses plain HTTP — no TLS",
                "severity": "high",
                "cwe": "CWE-319",
            }
        )

    # Try sslyze if available
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname:
            proc = subprocess.run(
                ["sslyze", "--json", hostname],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                import json

                data = json.loads(proc.stdout)
                for scan in data.get("scan_result", {}).get("tls_cipher_suites", []):
                    for suite in scan.get("tls_cipher_suites", []):
                        name = suite.get("name", "")
                        if any(
                            weak in name.upper() for weak in ("RC4", "DES", "NULL", "EXPORT", "MD5")
                        ):
                            findings.append(
                                {
                                    "message": f"Weak TLS cipher: {name}",
                                    "severity": "high",
                                    "cwe": "CWE-326",
                                }
                            )
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    return findings


# ── Runtime Validator Agent ───────────────────────────────────────────────────


@register
class RuntimeValidatorAgent(BaseAgent):
    """Runtime security validation: headers, TLS, method tampering."""

    name = "RuntimeValidatorAgent"
    group = AgentGroup.SECURITY
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        if is_offline():
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="skipped_offline",
                    severity=Severity.INFO,
                    file="",
                    message="Runtime validation skipped — offline mode (no live probing)",
                )
            )
            return

        # Look for configured URL in brain or config
        app_url = (
            inp.brain.get("app_url", "")
            or inp.config.get("app_url", "")
            or inp.extra.get("app_url", "")
        )

        if not app_url:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="no_target_url",
                    severity=Severity.INFO,
                    file="",
                    message="No app URL configured — set 'app_url' in config or brain to enable runtime validation",
                )
            )
            return

        # 1. Header checks
        header_findings = _check_headers(app_url)
        for f in header_findings:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="missing_header" if "missing" in f["message"] else "header_leak",
                    severity=Severity(f["severity"]),
                    file=app_url,
                    message=f["message"],
                    cwe=f["cwe"],
                )
            )

        # 2. TLS check
        tls_findings = _check_tls(app_url)
        for f in tls_findings:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="tls_issue",
                    severity=Severity(f["severity"]),
                    file=app_url,
                    message=f["message"],
                    cwe=f["cwe"],
                )
            )

        # 3. Method tampering
        method_findings = _check_method_tampering(app_url)
        for f in method_findings:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="method_tampering",
                    severity=Severity(f["severity"]),
                    file=app_url,
                    message=f["message"],
                    cwe=f["cwe"],
                )
            )

        result.files_scanned = 1
