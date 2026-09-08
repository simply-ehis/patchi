"""Secrets runtime management agent — validates secrets handling, rotation, and hardcoding."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

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

# Secrets provider detection patterns
SECRETS_PROVIDERS = {
    "hashicorp_vault": {
        "import": r"import\s+hvac|from\s+hvac\b|import\s+vault|from\s+vault\b|vault\.client|vault\.Vault",
        "config": r"VAULT_ADDR|VAULT_TOKEN|vault\.addr|vault\.token|VaultClient",
        "lease": r"lease|renew|revoke|ttl|max_ttl",
    },
    "aws_secrets_manager": {
        "import": r"import\s+boto3|from\s+boto3\b|aws.*secrets|secretsmanager",
        "client": r"boto3\.client.*secretsmanager|SecretsManagerClient|get_secret_value",
        "rotation": r"rotation|rotate.*secret|SecretRotation",
    },
    "aws_ssm": {
        "import": r"import\s+boto3|from\s+boto3\b",
        "client": r"ssm\.|SSM|get_parameter|ParameterStore",
    },
    "azure_key_vault": {
        "import": r"from\s+azure\.keyvault|import\s+azure\.keyvault|KeyVaultClient",
        "config": r"AZURE_KEYVAULT|KeyVaultSecret|vault_url",
    },
    "gcp_secret_manager": {
        "import": r"from\s+google\.cloud.*secretmanager|import\s+google\.cloud.*secretmanager",
        "client": r"SecretManagerServiceClient|access_secret_version",
    },
    "dotenv": {
        "import": r"from\s+dotenv|import\s+dotenv|load_dotenv|dotenv_values",
        "usage": r"os\.environ|os\.getenv|ENV\[|environ\[",
    },
}

# Hardcoded secret patterns (merged from SecretsGuard)
HARDCODED_SECRET_PATTERNS = [
    (r"(?:password|passwd|pwd)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded password", Severity.CRITICAL),
    (
        r"(?:api[_-]?key|apikey)\s*=\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
        "Hardcoded API key",
        Severity.CRITICAL,
    ),
    (
        r"(?:secret|token)\s*=\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
        "Hardcoded secret/token",
        Severity.CRITICAL,
    ),
    (
        r"(?:aws[_-]?access[_-]?key[_-]?id)\s*=\s*[\"']AKIA[0-9A-Z]{16}[\"']",
        "Hardcoded AWS access key",
        Severity.CRITICAL,
    ),
    (
        r"(?:aws[_-]?secret[_-]?access[_-]?key)\s*=\s*[\"'][0-9a-zA-Z/+=]{40}[\"']",
        "Hardcoded AWS secret key",
        Severity.CRITICAL,
    ),
    (r"(?:private[_-]?key)\s*=\s*[\"']-----BEGIN", "Hardcoded private key", Severity.CRITICAL),
    (
        r"(?:connection[_-]?string|dsn)\s*=\s*[\"'][^\"']*(?:password|pwd)=[^\"']+[\"']",
        "Hardcoded connection string with password",
        Severity.HIGH,
    ),
    # Extended patterns from SecretsGuard
    (
        re.compile(
            r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{16,}["\']',
            re.I,
        ),
        Severity.CRITICAL,
        "Hardcoded API key (extended)",
    ),
    (re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', re.I), Severity.CRITICAL, "Hardcoded password (extended)"),
    (re.compile(r'(?:secret|client[_-]?secret)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{8,}["\']', re.I), Severity.CRITICAL, "Hardcoded secret (extended)"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL, "AWS Access Key ID"),
    (re.compile(r'["\']AIza[0-9A-Za-z_-]{35}["\']'), Severity.CRITICAL, "GCP API key"),
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.I), Severity.CRITICAL, "Private key"),
    (re.compile(r"(?:mongodb|mysql|postgres|redis|amqp|smtp)://[^:]+:[^@]+@", re.I), Severity.HIGH, "Connection string with credentials"),
    (re.compile(r'DATABASE_URL\s*[:=]\s*["\'][^"\']+:.*@', re.I), Severity.HIGH, "DATABASE_URL with password"),
]

# Core dump and memory protection patterns
COREDUMP_PATTERNS = [
    (r"core.*dump|coredump|CORE_PATTERN", "Core dump configuration"),
    (r"ulimit.*-c|RLIMIT_CORE", "Core dump size limit"),
    (r"/proc/sys/kernel/core_pattern", "Core dump pattern"),
]

CONTROL_IDS = {
    "SECRETS-01": ("Hardcoded credentials in source", Severity.CRITICAL),
    "SECRETS-02": ("Secrets in environment variables", Severity.MEDIUM),
    "SECRETS-03": ("Missing lease renewal", Severity.HIGH),
    "SECRETS-04": ("Secrets provider detected", Severity.INFO),
    "SECRETS-05": ("Core dump exposure risk", Severity.HIGH),
    "SECRETS-06": ("Secrets caching TTL misconfigured", Severity.MEDIUM),
}

# Config/CI file patterns from SecretsGuard
CONFIG_CI_PATTERNS = [
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


def scan_code_for_secrets(code: str, file_path: str) -> list[dict]:
    """Scan a code string for secrets. Returns list of dicts with line, severity, message."""
    findings = []
    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        for pattern in HARDCODED_SECRET_PATTERNS:
            if isinstance(pattern, tuple):
                # Handle two formats: (regex, desc, severity) and (regex, severity, desc)
                if len(pattern) == 3:
                    p0, p1, p2 = pattern
                    # If p1 is Severity enum, format is (regex, severity, desc)
                    if isinstance(p1, Severity):
                        regex, severity, desc = p0, p1, p2
                    else:
                        # Format is (regex, desc, severity)
                        regex, desc, severity = p0, p1, p2
                else:
                    continue

                if isinstance(regex, str):
                    regex = re.compile(regex, re.I)
                if regex.search(line):
                    findings.append(
                        {
                            "line": i,
                            "severity": severity.value,
                            "message": desc,
                            "evidence": line.strip()[:100],
                            "file": file_path,
                        }
                    )
    return findings


def gate_check_proposed_code(proposed_code: str, file_path: str) -> tuple[bool, list[dict]]:
    """Check if proposed code introduces new secrets. Returns (safe, findings)."""
    findings = scan_code_for_secrets(proposed_code, file_path)
    return len(findings) == 0, findings


_log = logging.getLogger("patchi.security.secrets_runtime_agent")


@register
class SecretsRuntimeAgent(BaseAgent):
    name = "SecretsRuntimeAgent"
    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    description = "Secrets runtime management: lease renewal, file-mount vs env var, dynamic secrets, caching TTL"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        with trace_agent(self.name, inp.root) as trace:
            findings: list[Finding] = []
            files_scanned = 0

            # Phase 1: Static analysis of source code
            for fpath in safe_rglob(inp.root, "*.py"):
                files_scanned += 1
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    _log.warning("SecretsRuntimeAgent._run failed: %s", e)
                    continue

                rel = str(fpath.relative_to(inp.root))

                # Detect hardcoded secrets
                for pattern, desc, severity in HARDCODED_SECRET_PATTERNS:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        line_no = content[: m.start()].count("\n") + 1
                        # Skip if it's in a test file or comment
                        if re.search(
                            r"#.*" + re.escape(m.group()),
                            content.split("\n")[line_no - 1 : line_no][0],
                        ):
                            continue
                        findings.append(
                            make_finding(
                                severity,
                                rel,
                                line_no,
                                f"SECRETS-01: {desc}",
                                f"Found {desc.lower()} in source code. Secrets should never be hardcoded.",
                                code_snippet=m.group()[:80]
                                + ("..." if len(m.group()) > 80 else ""),
                                suggestion="Use a secrets manager or environment variables with proper secret rotation",
                                cwe="CWE-798",
                                control_id="SECRETS-01",
                            )
                        )

                # Detect secrets provider usage
                provider_found = None
                for provider_name, provider_patterns in SECRETS_PROVIDERS.items():
                    for _pattern_key, pattern in provider_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            provider_found = provider_name
                            break
                    if provider_found:
                        break

                if provider_found:
                    findings.append(
                        make_finding(
                            Severity.INFO,
                            rel,
                            0,
                            f"SECRETS-04: Secrets provider detected: {provider_found}",
                            f"Code uses {provider_found} for secrets management. Verify proper configuration.",
                            suggestion=f"Review {provider_name} configuration for security best practices",
                            control_id="SECRETS-04",
                        )
                    )

                # Check for secrets in environment variables (os.environ usage)
                env_usage = re.findall(r"os\.environ(?:\.get|\.pop|\[)|os\.getenv\(", content)
                if env_usage:
                    # Check if secrets-related env vars are accessed
                    for m in re.finditer(r"os\.environ(?:\.get|\.pop|\[)|os\.getenv\(", content):
                        line_no = content[: m.start()].count("\n") + 1
                        line_text = content.split("\n")[line_no - 1 : line_no][0]
                        # Check if the env var name contains secret-related keywords
                        secret_keywords = [
                            "password",
                            "secret",
                            "token",
                            "key",
                            "credential",
                            "auth",
                        ]
                        if any(kw in line_text.lower() for kw in secret_keywords):
                            findings.append(
                                make_finding(
                                    Severity.MEDIUM,
                                    rel,
                                    line_no,
                                    "SECRETS-02: Secret accessed via environment variable",
                                    "Secrets in environment variables may be exposed via /proc, logs, or crash dumps. Consider file mounts.",
                                    code_snippet=line_text.strip()[:100],
                                    suggestion="Use file-mounted secrets (e.g., Kubernetes secrets, Vault file backend) instead of env vars for sensitive values",
                                    control_id="SECRETS-02",
                                )
                            )

                # Check for lease renewal / TTL handling
                has_vault = re.search(
                    r"hvac|vault\.client|VAULT_ADDR|VaultClient", content, re.IGNORECASE
                )
                if has_vault:
                    has_lease = re.search(r"lease|renew|revoke|ttl|max_ttl", content, re.IGNORECASE)
                    if not has_lease:
                        findings.append(
                            make_finding(
                                Severity.HIGH,
                                rel,
                                0,
                                "SECRETS-03: Missing Vault lease renewal",
                                "Vault client detected without lease renewal logic. Secrets may expire and cause outages.",
                                suggestion="Implement lease renewal and automatic re-authentication",
                                control_id="SECRETS-03",
                            )
                        )

                # Check for caching TTL
                has_cache = re.search(
                    r"cache|lru_cache|functools\.cache|TTLCache|cachetools", content, re.IGNORECASE
                )
                if has_cache and has_vault:
                    has_ttl = re.search(
                        r"ttl|expire|timeout|max_age|maxsize", content, re.IGNORECASE
                    )
                    if not has_ttl:
                        findings.append(
                            make_finding(
                                Severity.MEDIUM,
                                rel,
                                0,
                                "SECRETS-06: Secret caching without TTL",
                                "Secrets may be cached without expiration. Stale secrets could be used after rotation.",
                                suggestion="Set appropriate TTL on cached secrets and invalidate on rotation events",
                                control_id="SECRETS-06",
                            )
                        )

                # Check for core dump exposure
                for pattern, desc in COREDUMP_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Check if secrets exist in the same file
                        has_secrets = re.search(
                            r"password|secret|token|key|credential",
                            content,
                            re.IGNORECASE,
                        )
                        if has_secrets:
                            findings.append(
                                make_finding(
                                    Severity.HIGH,
                                    rel,
                                    0,
                                    "SECRETS-05: Core dump may expose secrets",
                                    f"Core dump configuration found ({desc}) in code that handles secrets. Secrets may leak in core dumps.",
                                    suggestion="Disable core dumps or ensure secrets are not in memory during crash-prone operations",
                                    cwe="CWE-244",
                                    control_id="SECRETS-05",
                                )
                            )

            # Phase 2: Check configuration files (extended from SecretsGuard)
            scanned = 0
            for pattern in CONFIG_CI_PATTERNS:
                for fpath in safe_rglob(inp.root, pattern):
                    if not fpath.is_file():
                        continue
                    files_scanned += 1
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    rel = fpath.relative_to(inp.root).as_posix()
                    scanned += 1
                    secrets = scan_code_for_secrets(content, rel)
                    for s in secrets:
                        findings.append(
                            make_finding(
                                Severity(s["severity"]),
                                s["file"],
                                s["line"],
                                s["message"],
                                code_snippet=s["evidence"],
                                cwe="CWE-798",
                                control_id="SECRETS-01",
                            )
                        )

            # Phase 3: Try gitleaks for hardcoded secrets detection
            gitleaks_path = shutil.which("gitleaks")
            if gitleaks_path:
                try:
                    proc = subprocess.run(
                        [
                            gitleaks_path,
                            "detect",
                            "--source",
                            str(inp.root),
                            "--report-format",
                            "json",
                            "--no-banner",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if proc.stdout:
                        import json

                        try:
                            data = json.loads(proc.stdout)
                            for item in data:
                                findings.append(
                                    make_finding(
                                        Severity.CRITICAL,
                                        item.get("File", ""),
                                        item.get("StartLine", 0),
                                        "SECRETS-01: Hardcoded secret (gitleaks)",
                                        f"Gitleaks detected: {item.get('Description', 'Unknown secret')}",
                                        code_snippet=item.get("Match", "")[:100],
                                        suggestion="Remove hardcoded secret and use secrets manager",
                                        cwe="CWE-798",
                                        control_id="SECRETS-01",
                                    )
                                )
                        except json.JSONDecodeError:
                            pass
                except (subprocess.TimeoutExpired, Exception):
                    pass

            # Phase 4: Try semgrep for secrets patterns
            semgrep_path = shutil.which("semgrep")
            if semgrep_path:
                from .security_config import _semgrep_config_value
                semgrep_config = _semgrep_config_value(inp.root)
                if not semgrep_config:
                    semgrep_path = None  # offline + no local pack -> skip
            if semgrep_path:
                try:
                    proc = subprocess.run(
                        [
                            semgrep_path,
                            "--config",
                            semgrep_config,
                            "--include",
                            "*.py",
                            "--json",
                            "--quiet",
                            "--max-target-bytes",
                            "100000",
                            str(inp.root),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if proc.returncode == 0 and proc.stdout:
                        import json

                        try:
                            data = json.loads(proc.stdout)
                            for r in data.get("results", []):
                                rule_id = r.get("check_id", "")
                                if any(
                                    kw in rule_id.lower()
                                    for kw in [
                                        "secret",
                                        "password",
                                        "credential",
                                        "hardcoded",
                                        "key",
                                    ]
                                ):
                                    findings.append(
                                        make_finding(
                                            Severity.HIGH,
                                            r.get("path", ""),
                                            r.get("start", {}).get("line", 0),
                                            f"Semgrep: {rule_id}",
                                            r.get("extra", {}).get("message", ""),
                                            code_snippet=r.get("extra", {}).get("lines", ""),
                                            suggestion="Review semgrep finding for secrets security impact",
                                        )
                                    )
                        except json.JSONDecodeError:
                            pass
                except (subprocess.TimeoutExpired, Exception):
                    pass

            result.findings = findings
            result.files_scanned = files_scanned
            result.status = AgentStatus.DONE
            trace.findings = len(findings)
            trace.files_scanned = files_scanned

            return
