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
    description = "PII/credential exposure: API keys, passwords, emails, SSNs, connection strings in code"

    # ── Credential patterns ─────────────────────────────────────────────────
    # (compiled, severity, message, kind, value_group). kind="keyword" means
    # the NAME suggests secrecy and the VALUE must independently pass
    # looks_like_secret (Part 7) — keyword findings cap at HIGH, never
    # CRITICAL. kind="structural" tokens keep CRITICAL subject to the same
    # placeholder/entropy/fixture gates. Provider prefixes are
    # case-SENSITIVE (akia != AKIA).
    _CREDENTIAL_PATTERNS = [
        # Generic API keys / secrets
        (
            re.compile(
                r'(?i:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9+/=_-]{16,})["\']'
            ),
            Severity.HIGH,
            "Hardcoded API key/token in source code",
            "keyword",
            1,
        ),
        (
            re.compile(r'(?i:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']'),
            Severity.HIGH,
            "Hardcoded password in source code",
            "keyword",
            1,
        ),
        (
            re.compile(r'(?i:secret|client[_-]?secret)\s*[:=]\s*["\']([^"\']+)["\']'),
            Severity.HIGH,
            "Hardcoded secret in source code",
            "keyword",
            1,
        ),
        # AWS (case-sensitive)
        (
            re.compile(r"AKIA[0-9A-Z]{16}"),
            Severity.CRITICAL,
            "AWS Access Key ID found in source code",
            "structural",
            0,
        ),
        (
            re.compile(r'(?i:aws[_-]?secret|aws[_-]?access[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']'),
            Severity.HIGH,
            "AWS credential in source code",
            "keyword",
            1,
        ),
        # GCP
        (
            re.compile(r'["\']AIza[0-9A-Za-z_-]{35}["\']'),
            Severity.CRITICAL,
            "GCP API key found in source code",
            "structural",
            0,
        ),
        (
            re.compile(r'(?i:gcp[_-]?key|google[_-]?api[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']'),
            Severity.HIGH,
            "GCP credential in source code",
            "keyword",
            1,
        ),
        # Azure (az requires a separator — bare "az" is far too broad)
        (
            re.compile(r'(?i:azure[_-]?(?:key|secret|token)|az[_-](?:key|secret|token))\s*[:=]\s*["\']([^"\']+)["\']'),
            Severity.HIGH,
            "Azure credential in source code",
            "keyword",
            1,
        ),
        # Private keys (body required — header alone may be a doc snippet)
        (
            re.compile(r"-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
            Severity.CRITICAL,
            "Private key embedded in source code",
            "pem",
            0,
        ),
        # Connection strings with passwords (placeholder passwords rejected)
        (
            re.compile(r"(?:mongodb|mysql|postgres|redis|amqp|smtp)://([^/\s]+)@"),
            Severity.HIGH,
            "Connection string with embedded credentials",
            "uri",
            1,
        ),
        (
            re.compile(r'(?i:database_url)\s*[:=]\s*["\']([^"\']+)["\']'),
            Severity.HIGH,
            "DATABASE_URL with embedded password",
            "uri_value",
            1,
        ),
        # Generic high-entropy strings that look like secrets
        (
            re.compile(r'(?i:token|bearer)\s*[:=]\s*["\']([A-Za-z0-9+/=_-]{32,})["\']'),
            Severity.HIGH,
            "Long bearer/token string — possible hardcoded credential",
            "keyword",
            1,
        ),
    ]

    # ── PII patterns ────────────────────────────────────────────────────────
    # Shapes are structural, but shape alone is not identity: SSN/CC carry
    # validity checks (area-number rules, Luhn), examples/tests are excluded,
    # and fixture paths never verdict. (pattern, severity, message, validator)
    _PII_PATTERNS = [
        # Email addresses
        (
            re.compile(r'["\']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?'),
            Severity.MEDIUM,
            "Email address hardcoded in source",
            "email",
        ),
        # SSN patterns (US)
        (
            re.compile(r'["\']?(\d{3}-\d{2}-\d{4})["\']?'),
            Severity.HIGH,
            "Possible Social Security Number in source",
            "ssn",
        ),
        # Credit card numbers
        (
            re.compile(r'["\']?(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})["\']?'),
            Severity.HIGH,
            "Possible credit card number in source",
            "cc",
        ),
        # Phone numbers (US format)
        (
            re.compile(r'["\']?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}["\']?'),
            Severity.LOW,
            "Phone number in source — verify if intentional",
            "none",
        ),
        # IP addresses with ports (possible internal infra exposure)
        (
            re.compile(r'["\']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+["\']?'),
            Severity.MEDIUM,
            "IP:port pair in source — verify if intentional",
            "none",
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
        from patchi.core.security.secret_evidence import (
            is_fixture_path,
            is_placeholder,
            looks_like_secret,
            private_key_body_present,
        )

        findings = []
        fixture_file = is_fixture_path(rel_path)
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

            for pattern, severity, message, kind, group in self._CREDENTIAL_PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                if fixture_file:
                    continue
                try:
                    value = m.group(group) if group else m.group(0)
                except IndexError:
                    value = m.group(0)
                if kind == "pem":
                    window = "\n".join(lines[line_num - 1:line_num + 15])
                    if not private_key_body_present(window):
                        continue  # doc snippet, not a key
                elif kind == "uri":
                    # userinfo must be a real credential, not user:xxx@.
                    # Regex metacharacters in the userinfo mean this is a
                    # PATTERN describing URIs (e.g. in scanner source), not
                    # a credential — skip.
                    import re as _re

                    userinfo = (value or "").split("@")[0] if "@" in value else value
                    pw = userinfo.rsplit(":", 1)[-1] if ":" in userinfo else ""
                    if not pw or is_placeholder(pw):
                        continue
                    if _re.search(r"[\[\]^$*+?.(){}\\|]", pw):
                        continue
                elif kind == "uri_value":
                    # DATABASE_URL value must actually embed credentials
                    if "@" not in value:
                        continue
                    userinfo = value.split("@")[0].rsplit("/", 1)[-1]
                    pw = userinfo.rsplit(":", 1)[-1] if ":" in userinfo else ""
                    if not pw or is_placeholder(pw):
                        continue
                elif kind == "keyword":
                    # Keyword-assigned values with spaces are descriptions
                    # ("secret": "Steal Credentials"), never credentials.
                    if not looks_like_secret(value, allow_spaces=False):
                        continue
                elif not looks_like_secret(value):
                    continue
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

    @staticmethod
    def _luhn_ok(digits: str) -> bool:
        """Luhn checksum for credit-card plausibility."""
        total = 0
        for i, ch in enumerate(reversed(digits)):
            d = ord(ch) - 48
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    @staticmethod
    def _valid_ssn(value: str) -> bool:
        """Reject SSA-invalid area numbers (000, 666, 900-999) and 000 groups."""
        area, group, _serial = value.split("-")
        if area in ("000", "666") or area.startswith("9"):
            return False
        return group != "00"

    _EXAMPLE_DOMAINS = frozenset({"example.com", "example.org", "example.net", "test.com", "invalid"})

    def _check_pii(self, content: str, rel_path: str) -> list[Finding]:
        from patchi.core.security.secret_evidence import is_fixture_path

        findings = []
        lines = content.splitlines()
        # Fixture/test/doc paths intentionally carry dummy PII.
        pii_dead = is_fixture_path(rel_path)
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if pii_dead:
                continue

            for pattern, severity, message, validator in self._PII_PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                if validator == "email" and "://" in line:
                    # userinfo@host inside a URI is the credential rule's
                    # jurisdiction, not email PII (avoids double-counting).
                    continue
                if validator == "email":
                    domain = (m.group(1).rsplit("@", 1)[-1] or "").lower()
                    if domain in self._EXAMPLE_DOMAINS or domain.startswith("test"):
                        continue
                elif validator == "ssn":
                    if not self._valid_ssn(m.group(1)):
                        continue
                elif validator == "cc":
                    digits = re.sub(r"\D", "", m.group(1))
                    if len(digits) < 13 or not self._luhn_ok(digits):
                        continue
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
