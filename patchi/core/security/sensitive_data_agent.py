"""
SensitiveDataAgent — PII and credential exposure detection.

Scans source code for:
- Hardcoded API keys, tokens, passwords, secrets
- PII patterns (emails, SSNs, credit cards, phone numbers, IPs)
- Connection strings with embedded credentials
- Private keys and certificates in source
- AWS/GCP/Azure credentials
- Database URLs with passwords

Uses regex pattern matching. Does NOT call AI.
Does NOT write to disk. Does NOT touch the queue.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

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

_log = logging.getLogger("patchi.security.sensitive_data_agent")


@register
class SensitiveDataAgent(BaseAgent):
    """Agent for detecting PII and credential exposure in source code."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "SensitiveDataAgent"
    description = (
        "PII/credential exposure: API keys, passwords, emails, SSNs, connection strings in code"
    )

    # ── Credential patterns ─────────────────────────────────────────────────
    _CREDENTIAL_PATTERNS = [
        # Generic API keys / secrets
        (
            re.compile(
                r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{16,}["\']',
                re.I,
            ),
            Severity.CRITICAL,
            "Hardcoded API key/token in source code",
        ),
        (
            re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', re.I),
            Severity.CRITICAL,
            "Hardcoded password in source code",
        ),
        (
            re.compile(
                r'(?:secret|client[_-]?secret)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{8,}["\']', re.I
            ),
            Severity.CRITICAL,
            "Hardcoded secret in source code",
        ),
        # AWS
        (
            re.compile(r"AKIA[0-9A-Z]{16}", re.I),
            Severity.CRITICAL,
            "AWS Access Key ID found in source code",
        ),
        (
            re.compile(
                r'(?:aws[_-]?secret|aws[_-]?access[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']', re.I
            ),
            Severity.CRITICAL,
            "AWS credential in source code",
        ),
        # GCP
        (
            re.compile(r'["\']AIza[0-9A-Za-z_-]{35}["\']', re.I),
            Severity.CRITICAL,
            "GCP API key found in source code",
        ),
        (
            re.compile(
                r'(?:gcp[_-]?key|google[_-]?api[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']', re.I
            ),
            Severity.CRITICAL,
            "GCP credential in source code",
        ),
        # Azure
        (
            re.compile(
                r'(?:azure|az)[_-]?(?:key|secret|token)\s*[:=]\s*["\'][^"\']{8,}["\']', re.I
            ),
            Severity.CRITICAL,
            "Azure credential in source code",
        ),
        # Private keys
        (
            re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.I),
            Severity.CRITICAL,
            "Private key embedded in source code",
        ),
        (
            re.compile(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", re.I),
            Severity.CRITICAL,
            "SSH private key embedded in source code",
        ),
        # Connection strings with passwords
        (
            re.compile(r"(?:mongodb|mysql|postgres|redis|amqp|smtp)://[^:]+:[^@]+@", re.I),
            Severity.HIGH,
            "Connection string with embedded credentials",
        ),
        (
            re.compile(r'DATABASE_URL\s*[:=]\s*["\'][^"\']+:.*@', re.I),
            Severity.HIGH,
            "DATABASE_URL with embedded password",
        ),
        # Generic high-entropy strings that look like secrets
        (
            re.compile(r'(?:token|bearer)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{32,}["\']', re.I),
            Severity.HIGH,
            "Long bearer/token string — possible hardcoded credential",
        ),
    ]

    # ── PII patterns ────────────────────────────────────────────────────────
    _PII_PATTERNS = [
        # Email addresses
        (
            re.compile(r'["\'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\']', re.I),
            Severity.MEDIUM,
            "Email address hardcoded in source",
        ),
        # SSN patterns (US)
        (
            re.compile(r'["\']?\d{3}-\d{2}-\d{4}["\']?'),
            Severity.HIGH,
            "Possible Social Security Number in source",
        ),
        # Credit card numbers
        (
            re.compile(r'["\']?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}["\']?'),
            Severity.HIGH,
            "Possible credit card number in source",
        ),
        # Phone numbers (US format)
        (
            re.compile(r'["\']?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}["\']?'),
            Severity.LOW,
            "Phone number in source — verify if intentional",
        ),
        # IP addresses with ports (possible internal infra exposure)
        (
            re.compile(r'["\']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+["\']?'),
            Severity.MEDIUM,
            "IP:port pair in source — verify if intentional",
        ),
    ]

    _SKIP_DIRS = DEFAULT_IGNORE_DIRS | {"test", "tests", "test_*"}

    # Test files are excluded from PII checks (may contain test data)
    _SKIP_DIRS_PII = DEFAULT_IGNORE_DIRS | {"test", "tests"}

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        files_scanned = 0

        for p in self._safe_rglob(inp.root, "*.py"):
            rel = str(p.relative_to(inp.root))
            if self._should_skip(rel):
                continue
            files_scanned += 1
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                _log.warning("SensitiveDataAgent._run failed: %s", e)
                continue

            findings.extend(self._check_credentials(content, rel))
            findings.extend(self._check_pii(content, rel))

        result.status = AgentStatus.DONE
        result.findings = findings
        result.files_scanned = files_scanned
        result.data.update({"files_scanned": files_scanned, "finding_count": len(findings)})
        return

    def _check_credentials(self, content: str, rel_path: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            # Skip obvious test/mock patterns (but not in the key value itself)
            line_lower = stripped.lower()
            if any(
                kw in line_lower.split('"')[0] or kw in line_lower.split("'")[0]
                for kw in ("placeholder", "xxx", "fake_", "mock_")
            ):
                continue

            for pattern, severity, message in self._CREDENTIAL_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        make_finding(
                            self.name,
                            "credential_exposure",
                            severity,
                            rel_path,
                            message,
                            line=line_num,
                            code_snippet=stripped[:120],
                            suggestion="Move credentials to .env file or secret manager. Never commit secrets.",
                        )
                    )
        return findings

    def _check_pii(self, content: str, rel_path: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            # Skip test files for PII (they use dummy data)
            if "test" in rel_path.lower():
                continue

            for pattern, severity, message in self._PII_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        make_finding(
                            self.name,
                            "pii_exposure",
                            severity,
                            rel_path,
                            message,
                            line=line_num,
                            code_snippet=stripped[:120],
                            suggestion="Remove PII from source code. Use environment variables or test fixtures.",
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
