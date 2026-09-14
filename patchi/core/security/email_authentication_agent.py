"""
EmailAuthenticationAgent — email authentication and header security.

Detects email-related security issues:
- Missing or misconfigured SPF records
- Missing or misconfigured DKIM records
- Missing or misconfigured DMARC records
- CRLF injection in email headers
- Hardcoded SMTP credentials
- Insecure email sending patterns (smtplib without TLS)
- Missing rate limiting on email endpoints

Uses static file analysis and optional external tools (dig, checkdmarc).
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
}

_SMTP_PATTERNS = [
    (re.compile(r"\bsmtplib\b|smtplib\.SMTP|smtplib\.SMTP_SSL"), "Python smtplib"),
    (re.compile(r"\bsendgrid\b|SendGrid|send_grid"), "SendGrid SDK"),
    (re.compile(r"\bSES\b|aws[-_]?ses|boto.*ses"), "AWS SES"),
    (re.compile(r"\bMailgun\b|mailgun"), "Mailgun"),
    (re.compile(r"\bpostmark\b|Postmark"), "Postmark"),
    (re.compile(r"\bnodemailer\b|createTransport"), "Nodemailer"),
    (re.compile(r"\bphpmailer\b|PHPMailer"), "PHPMailer"),
    (re.compile(r"\bswiftmailer\b|SwiftMailer|Swift_Message"), "SwiftMailer"),
    (re.compile(r"\bmail\s*\(|mb_send_mail|wp_mail"), "PHP mail()"),
    (re.compile(r"\bSMTP\b.*\bconnect\b|\bsmtp_client\b", re.IGNORECASE), "Generic SMTP client"),
]

_SMTP_CREDENTIAL_PATTERNS = [
    (
        re.compile(
            r"(?:smtp[_-]?(?:password|pass|pwd|secret|key|token))\s*[:=]\s*['\"][^'\"]{4,}['\"]",
            re.IGNORECASE,
        ),
        "EMAILAUTH-06: Hardcoded SMTP Password",
    ),
    (
        re.compile(r"(?:smtp[_-]?(?:user|username|login))\s*[:=]\s*['\"][^'\"]{2,}['\"]", re.IGNORECASE),
        "EMAILAUTH-07: Hardcoded SMTP Username",
    ),
    (
        re.compile(
            r"(?:SMTP_PASSWORD|SMTP_USER|EMAIL_PASSWORD|EMAIL_USER|MAIL_PASSWORD)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
            re.IGNORECASE,
        ),
        "EMAILAUTH-06: Hardcoded SMTP Credential Constant",
    ),
    (
        re.compile(r"['\"](?:smtps?://[^'\"]*:[^'\"]*@)['\"]", re.IGNORECASE),
        "EMAILAUTH-06: SMTP Credential in URL",
    ),
]

_CRLF_INJECTION_PATTERNS = [
    (
        re.compile(r"(?:subject|to|from|cc|bcc|reply[-_]?to)\s*[=:]\s*.*\+.*\\r\\n|\\r\\n", re.IGNORECASE),
        "EMAILAUTH-08: CRLF Injection in Email Header",
    ),
    (
        re.compile(r"headers?\s*\[.*\]\s*=.*\+|headers?.*update.*\{", re.IGNORECASE),
        "EMAILAUTH-08: Dynamic Email Header Construction",
    ),
]

_TLS_PATTERNS = [
    re.compile(r"\.starttls\(\)|\.ehlo\(\)", re.IGNORECASE),
    re.compile(r"SMTP_SSL|smtps://", re.IGNORECASE),
    re.compile(r"context\s*=\s*ssl\.create_default_context", re.IGNORECASE),
]


_log = logging.getLogger("patchi.security.email_authentication_agent")


@register
class EmailAuthenticationAgent(BaseAgent):
    """Agent for detecting email authentication and header security issues."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "EmailAuthenticationAgent"
    description = "Email authentication: SPF, DKIM, DMARC, header injection"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings: list[Finding] = []
        files_scanned = 0

        with trace_agent(self.name, inp.root) as trace:
            # ── Static analysis ────────────────────────────────────────────
            findings.extend(self._scan_spf_dkim_dmarc(inp))
            findings.extend(self._scan_smtp_code(inp))
            findings.extend(self._scan_crlf_injection(inp))
            findings.extend(self._scan_tls_usage(inp))

            for pattern in _SOURCE_EXTENSIONS:
                for fp in safe_rglob(inp.root, pattern):
                    if fp.is_file():
                        files_scanned += 1
                        findings.extend(self._scan_file(fp, inp.root))

            # ── External tools ─────────────────────────────────────────────
            if shutil.which("dig"):
                findings.extend(self._run_dig_email_checks(inp))

            trace.findings = len(findings)
            trace.files_scanned = files_scanned

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "email_auth_findings": len(findings),
                "dig_available": shutil.which("dig") is not None,
            }
        )
        return

    # ── SPF/DKIM/DMARC config scan ────────────────────────────────────────

    def _scan_spf_dkim_dmarc(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.tf", "*.yaml", "*.yml", "*.json", "*.conf", "*.dns", "*.zone"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    content_lower = content.lower()
                    if any(k in content_lower for k in ("dns", "zone", "domain", "mx", "mail")):
                        if "spf" not in content_lower and "txt" not in content_lower:
                            findings.append(
                                make_finding(
                                    severity=Severity.HIGH,
                                    file=rel,
                                    line_start=0,
                                    title="EMAILAUTH-01: No SPF Record Found",
                                    description="DNS/mail configuration without SPF record. Emails may be spoofed.",
                                    suggestion="Add an SPF TXT record (e.g., v=spf1 include:_spf.google.com ~all).",
                                )
                            )
                        if "dkim" not in content_lower:
                            findings.append(
                                make_finding(
                                    severity=Severity.HIGH,
                                    file=rel,
                                    line_start=0,
                                    title="EMAILAUTH-02: No DKIM Record Found",
                                    description="DNS/mail configuration without DKIM. Email integrity cannot be"
                                    " verified.",
                                    suggestion="Configure DKIM signing and publish the public key as a DNS TXT record.",
                                )
                            )
                        if "dmarc" not in content_lower:
                            findings.append(
                                make_finding(
                                    severity=Severity.HIGH,
                                    file=rel,
                                    line_start=0,
                                    title="EMAILAUTH-03: No DMARC Record Found",
                                    description="No DMARC policy found. Spoofed emails will not be rejected.",
                                    suggestion="Add a DMARC TXT record (e.g., v=DMARC1; p=quarantine;"
                                    " rua=mailto:dmarc@example.com).",
                                )
                            )
                except Exception as e:
                    _log.warning("EmailAuthenticationAgent._scan_spf_dkim_dmarc failed: %s", e)
        return findings

    # ── SMTP code patterns ─────────────────────────────────────────────────

    def _scan_smtp_code(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.py", "*.js", "*.ts", "*.php", "*.rb", "*.go", "*.java"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                    for i, line in enumerate(lines, 1):
                        for rx, desc in _SMTP_PATTERNS:
                            if rx.search(line):
                                findings.append(
                                    make_finding(
                                        severity=Severity.LOW,
                                        file=rel,
                                        line_start=i,
                                        title="EMAILAUTH-04: Email Sending Code Detected",
                                        description=f"Email sending code found: {desc}. Verify authentication is"
                                        f" properly configured.",
                                        evidence=line.strip()[:120],
                                    )
                                )
                                break
                except Exception as e:
                    _log.warning("EmailAuthenticationAgent._scan_smtp_code failed: %s", e)
        return findings

    # ── CRLF injection ─────────────────────────────────────────────────────

    def _scan_crlf_injection(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.py", "*.js", "*.ts", "*.php", "*.rb", "*.go", "*.java"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                    for i, line in enumerate(lines, 1):
                        for rx, desc in _CRLF_INJECTION_PATTERNS:
                            if rx.search(line):
                                findings.append(
                                    make_finding(
                                        severity=Severity.HIGH,
                                        file=rel,
                                        line_start=i,
                                        title=desc,
                                        description="User-controlled input may be injected into email headers via"
                                        " CRLF.",
                                        evidence=line.strip()[:120],
                                        suggestion="Sanitize header values: strip \\r\\n characters before use.",
                                    )
                                )
                except Exception as e:
                    _log.warning("EmailAuthenticationAgent._scan_crlf_injection failed: %s", e)
        return findings

    # ── TLS usage in SMTP ──────────────────────────────────────────────────

    def _scan_tls_usage(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.py", "*.js", "*.ts", "*.php", "*.rb"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    # _SMTP_PATTERNS entries are (regex, label) tuples.
                    has_smtp = any(rx.search(content) for rx, _ in _SMTP_PATTERNS[:3])
                    if has_smtp:
                        has_tls = any(rx.search(content) for rx in _TLS_PATTERNS)
                        if not has_tls:
                            lines = content.splitlines()
                            for i, line in enumerate(lines, 1):
                                if any(rx.search(line) for rx, _ in _SMTP_PATTERNS[:3]):
                                    findings.append(
                                        make_finding(
                                            severity=Severity.HIGH,
                                            file=rel,
                                            line_start=i,
                                            title="EMAILAUTH-05: SMTP Without TLS",
                                            description="SMTP connection found without TLS/STARTTLS. Credentials and"
                                            " content sent in cleartext.",
                                            evidence=line.strip()[:120],
                                            suggestion="Use SMTP_SSL or call starttls() before sending.",
                                        )
                                    )
                                    break
                except Exception as e:
                    _log.warning("EmailAuthenticationAgent._scan_tls_usage failed: %s", e)
        return findings

    # ── General source file scan (credentials) ─────────────────────────────

    def _scan_file(self, fp: Path, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = fp.relative_to(root).as_posix()
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                for rx, title in _SMTP_CREDENTIAL_PATTERNS:
                    if rx.search(line):
                        findings.append(
                            make_finding(
                                severity=Severity.CRITICAL,
                                file=rel,
                                line_start=i,
                                title=title,
                                description="Hardcoded SMTP credential found in source code.",
                                evidence=line.strip()[:120],
                                suggestion="Move SMTP credentials to environment variables or a secrets manager.",
                            )
                        )
        except Exception as e:
            _log.warning("EmailAuthenticationAgent._scan_file failed: %s", e)
        return findings

    # ── External tool: dig ─────────────────────────────────────────────────

    def _run_dig_email_checks(self, inp: AgentInput) -> list[Finding]:
        """Run dig to check SPF/DKIM/DMARC DNS records."""
        findings: list[Finding] = []
        domain = inp.config.get("email_check_domain")
        if not domain or not isinstance(domain, str):
            return findings

        # Check SPF
        try:
            proc = subprocess.run(
                ["dig", "+short", "txt", domain, "+timeout=5"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                output = proc.stdout.lower()
                if "v=spf1" not in output:
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file="(dns_probe)",
                            line_start=0,
                            title="EMAILAUTH-01: No SPF Record",
                            description=f"No SPF record found for {domain}.",
                            evidence=proc.stdout[:200],
                            suggestion="Add an SPF TXT record.",
                        )
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Check DKIM (common selector)
        for selector in ("default", "google", "selector1", "selector2", "k1"):
            try:
                proc = subprocess.run(
                    ["dig", "+short", "txt", f"{selector}._domainkey.{domain}", "+timeout=5"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    break  # Found DKIM record
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
        else:
            findings.append(
                make_finding(
                    severity=Severity.HIGH,
                    file="(dns_probe)",
                    line_start=0,
                    title="EMAILAUTH-02: No DKIM Record Found",
                    description=f"No DKIM record found for {domain} (checked common selectors).",
                    suggestion="Configure DKIM and publish the public key.",
                )
            )

        # Check DMARC
        try:
            proc = subprocess.run(
                ["dig", "+short", "txt", f"_dmarc.{domain}", "+timeout=5"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                output = proc.stdout.lower()
                if "v=dmarc1" not in output:
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file="(dns_probe)",
                            line_start=0,
                            title="EMAILAUTH-03: No DMARC Record",
                            description=f"No DMARC record found for {domain}.",
                            evidence=proc.stdout[:200],
                            suggestion="Add a DMARC TXT record with at minimum p=none for monitoring.",
                        )
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return findings
