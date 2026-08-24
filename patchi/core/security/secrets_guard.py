"""
Secrets Guard — pre-apply gate and extended secrets scanning.

Scans for secrets in source, config, CI files. Blocks patches that
introduce new secrets. Enhanced scanning beyond SecretScanner.
"""

from __future__ import annotations

import re

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)

# ── Pre-apply secrets gate ────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    (
        re.compile(
            r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{16,}["\']',
            re.I,
        ),
        Severity.CRITICAL,
        "Hardcoded API key",
    ),
    (
        re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', re.I),
        Severity.CRITICAL,
        "Hardcoded password",
    ),
    (
        re.compile(r'(?:secret|client[_-]?secret)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{8,}["\']', re.I),
        Severity.CRITICAL,
        "Hardcoded secret",
    ),
    (re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL, "AWS Access Key ID"),
    (re.compile(r'["\']AIza[0-9A-Za-z_-]{35}["\']'), Severity.CRITICAL, "GCP API key"),
    (
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.I),
        Severity.CRITICAL,
        "Private key",
    ),
    (
        re.compile(r"(?:mongodb|mysql|postgres|redis|amqp|smtp)://[^:]+:[^@]+@", re.I),
        Severity.HIGH,
        "Connection string with credentials",
    ),
    (
        re.compile(r'DATABASE_URL\s*[:=]\s*["\'][^"\']+:.*@', re.I),
        Severity.HIGH,
        "DATABASE_URL with password",
    ),
]


def scan_code_for_secrets(code: str, file_path: str) -> list[dict]:
    """Scan a code string for secrets. Returns list of dicts with line, severity, message."""
    findings = []
    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        for pattern, severity, message in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "line": i,
                        "severity": severity.value,
                        "message": message,
                        "evidence": line.strip()[:100],
                        "file": file_path,
                    }
                )
    return findings


def gate_check_proposed_code(proposed_code: str, file_path: str) -> tuple[bool, list[dict]]:
    """Check if proposed code introduces new secrets. Returns (safe, findings)."""
    findings = scan_code_for_secrets(proposed_code, file_path)
    return len(findings) == 0, findings


# ── Extended secrets scanner (config/CI files) ───────────────────────────────


@register
class SecretsGuard(BaseAgent):
    """Extended secrets scanning: config, CI, Docker, K8s files."""

    name = "SecretsGuard"
    group = AgentGroup.SECURITY
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        config_patterns = [
            ".env*",
            "*.yml",
            "*.yaml",
            "*.toml",
            "*.ini",
            "*.cfg",
            "Dockerfile*",
            "docker-compose*.yml",
            "*.conf",
            "**/.github/**",
            "**/.gitlab-ci*",
            "**/Jenkinsfile*",
        ]

        scanned = 0
        for pattern in config_patterns:
            for fpath in safe_rglob(inp.root, pattern):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                scanned += 1
                secrets = scan_code_for_secrets(content, rel)
                for s in secrets:
                    result.add_finding(
                        Finding(
                            agent=self.name,
                            type="hardcoded_secret",
                            severity=Severity(s["severity"]),
                            file=s["file"],
                            line=s["line"],
                            message=s["message"],
                            code_snippet=s["evidence"],
                        )
                    )

        result.files_scanned = scanned
