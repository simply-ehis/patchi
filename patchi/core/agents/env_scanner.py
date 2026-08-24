"""
EnvScanner — secret/credential pattern detection.

Scans for potentially sensitive information in:
- Environment files (.env, .env.local, .env.production, etc.)
- Configuration files (json, yaml, toml)
- Source code (hardcoded secrets, API keys, passwords)
- Build files and scripts

Looks for patterns like:
- AWS keys (AKIA..., AGPA..., AIDA..., etc.)
- GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
- Slack tokens (xox[a-z]-...)
- Password fields in configs
- Database URLs with credentials
- Private key headers

Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import re
from pathlib import Path

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

from .base import (
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


import logging
_log = logging.getLogger("patchi.agents.env_scanner")

@register
class EnvScanner(BaseAgent):
    """Scanner for environment variables and secrets."""

    group = AgentGroup.SCANNER
    name = "EnvScanner"
    description = "Secret/credential pattern detection"

    # Common secret patterns
    SECRET_PATTERNS = [
        # AWS keys
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"AGPA[0-9A-Z]{16}", "AWS Access Key"),
        (r"AIDA[0-9A-Z]{16}", "AWS Access Key"),
        (r"AROA[0-9A-Z]{16}", "AWS Access Key"),
        (r"ASIA[0-9A-Z]{16}", "AWS Access Key"),
        # AWS secret keys
        (r"[0-9a-zA-Z/+]{40}(?=\s|$)", "AWS Secret Key"),
        # GitHub tokens
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
        (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Access Token"),
        (r"ghu_[0-9a-zA-Z]{36}", "GitHub User-to-server Token"),
        (r"ghs_[0-9a-zA-Z]{36}", "GitHub Server-to-Server Token"),
        (r"ghr_[0-9a-zA-Z]{76}", "GitHub Refresh Token"),
        # Slack tokens
        (r"xox[a-zA-Z]-[0-9A-Za-z-]+", "Slack Token"),
        # Slack webhooks
        (
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}",
            "Slack Webhook",
        ),
        # Google API keys
        (r"AIza[0-9A-Za-z\\-_]{35}", "Google API Key"),
        # Google OAuth
        (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID"),
        # Facebook access tokens
        (r"EAACEdEose0cBA[0-9A-Za-z]+", "Facebook Access Token"),
        # Passwords in various formats
        (r'password\s*[=:]\s*["\'][^"\']+["\']', "Password in config"),
        (r'pwd\s*[=:]\s*["\'][^"\']+["\']', "Password in config"),
        (r'passwd\s*[=:]\s*["\'][^"\']+["\']', "Password in config"),
        # Database connection strings with credentials
        (r"postgres://[a-zA-Z0-9_%]+:[^@]+@", "PostgreSQL Connection String"),
        (r"mysql://[a-zA-Z0-9_%]+:[^@]+@", "MySQL Connection String"),
        (r"mongodb://[a-zA-Z0-9_%]+:[^@]+@", "MongoDB Connection String"),
        # Private key headers
        (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
        (r"-----BEGIN DSA PRIVATE KEY-----", "DSA Private Key"),
        (r"-----BEGIN EC PRIVATE KEY-----", "EC Private Key"),
        (r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key"),
        (r"-----BEGIN PRIVATE KEY-----", "Private Key"),
        # SSH keys
        (r"ssh-rsa [A-Za-z0-9+/\s]+={0,2}", "SSH Public Key"),
        (r"ssh-ed25519 [A-Za-z0-9+/\s]+={0,2}", "SSH Ed25519 Key"),
        # Generic API keys
        (r'api[_-]?key["\']?\s*[=:]\s*["\'][^"\']+["\']', "Generic API Key"),
        (r'api[_-]?token["\']?\s*[=:]\s*["\'][^"\']+["\']', "Generic API Token"),
        (r'secret["\']?\s*[=:]\s*["\'][^"\']+["\']', "Generic Secret"),
        (r'token["\']?\s*[=:]\s*["\'][^"\']+["\']', "Generic Token"),
    ]

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan for environment variables and secrets."""
        findings = []

        # Define environment file patterns
        env_patterns = [
            ".env",
            ".env.*",
            ".envrc",
            "*.env",
            "*.config",
            "*.conf",
            "*.ini",
            "*.properties",
            "*.json",
            "*.yaml",
            "*.yml",
            "*.toml",
            "*.py",
            "*.js",
            "*.ts",
            "*.jsx",
            "*.tsx",
            "*.sh",
            "*.bash",
            "*.zsh",
            "*.ps1",
            "*.bat",
            "Dockerfile*",
            "docker-compose*.yml",
            "docker-compose*.yaml",
            "package.json",
            "requirements.txt",
            "Pipfile",
            "Gemfile",
            "composer.json",
        ]

        # Search for environment/config files
        for pattern in env_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_env_file(file_path, rel_path))

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update({
            "secrets_found": len(
                [
                    f
                    for f in findings
                    if "Secret" in f.title or "Token" in f.title or "Key" in f.title
        ]
            ),
            "passwords_found": len([f for f in findings if "Password" in f.title]),
            "needs_ai": False,
        })
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        # Skip ignored directories (node_modules, .venv, etc.)
        from pathlib import PurePosixPath

        if any(p in DEFAULT_IGNORE_DIRS for p in PurePosixPath(file_path).parts):
            return True

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

    def _scan_env_file(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan an environment/config file for secrets."""
        findings = []

        if file_path.name == "package-lock.json":
            return findings

        try:
            content = file_path.read_text(encoding="utf-8")
            lines = content.splitlines()

            # Check each line for secret patterns
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                # Skip comment lines and pattern/regex definitions (not real secrets)
                if stripped.startswith(("#", "//", "*", "/*")):
                    continue
                _fp_markers = (
                    "re.compile",
                    "re.search",
                    "re.match",
                    "re.finditer",
                    "SECRET_PATTERNS",
                    "_PATTERN",
                    "REGEX",
                    "RE_",
                )
                if any(m in line for m in _fp_markers):
                    continue
                for pattern, description in self.SECRET_PATTERNS:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        masked_match = self._mask_sensitive_info(match.group(0))
                        findings.append(
                            make_finding(
                                severity=Severity.CRITICAL,
                                finding_type="hardcoded_secret",
                                file=rel_path,
                                line_start=line_num,
                                title=f"Potential {description}",
                                description=f"Found potential {description} in {file_path.name}",
                                evidence=f"Match: {masked_match}",
                            )
                        )

            # Special check for .env files - look for common environment variable patterns
            if ".env" in file_path.name.lower():
                findings.extend(self._scan_dotenv_file(file_path, rel_path, lines))

        except UnicodeDecodeError:
            # If it's a binary file, try to read as binary and decode what we can
            try:
                content = file_path.read_bytes()
                # Try to decode as UTF-8, ignoring errors
                text_content = content.decode("utf-8", errors="ignore")
                lines = text_content.splitlines()

                for line_num, line in enumerate(lines, 1):
                    for pattern, description in self.SECRET_PATTERNS:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            masked_match = self._mask_sensitive_info(match.group(0))

                            findings.append(
                                make_finding(
                                    severity=Severity.CRITICAL,
                                    finding_type="hardcoded_secret",
                                    file=rel_path,
                                    line_start=line_num,
                                    title=f"Potential {description}",
                                    description=f"Found potential {description} in {file_path.name}",
                                    evidence=f"Match: {masked_match}",
                                )
                            )
            except Exception as e:
                _log.warning("EnvScanner._scan_env_file failed: %s", e)
                findings.append(
                    make_finding(
                        severity=Severity.LOW,
                        file=rel_path,
                        line_start=0,
                        title="File read error",
                        description=f"Could not read {file_path.name} for environment variable scanning",
                        evidence="Binary or corrupted file",
                    )
                )
        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Environment file read error",
                    description=f"Could not read environment file {file_path.name}: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_dotenv_file(self, file_path: Path, rel_path: str, lines: list[str]) -> list[Finding]:
        """Special scanning for .env files."""
        findings = []

        # Look for common environment variable patterns that might contain secrets
        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            if line.strip().startswith("#") or not line.strip():
                continue

            # Look for assignment patterns
            if "=" in line:
                var_name, var_value = line.split("=", 1)
                var_name = var_name.strip()
                var_value = var_value.strip().strip("\"'")  # Remove quotes

                # Check if the variable name suggests it might be sensitive
                sensitive_keywords = [
                    "KEY",
                    "SECRET",
                    "TOKEN",
                    "PASSWORD",
                    "PWD",
                    "PASSPHRASE",
                    "API",
                    "AUTH",
                    "CREDENTIAL",
                    "ACCESS",
                    "CLIENT_ID",
                    "CLIENT_SECRET",
                    "DATABASE_URL",
                    "DB_URL",
                    "REDIS_URL",
                    "MONGO_URL",
                ]

                if any(keyword in var_name.upper() for keyword in sensitive_keywords):
                    # Check if the value looks like a secret
                    if self._looks_like_secret(var_value):
                        findings.append(
                            make_finding(
                                severity=Severity.HIGH,
                                finding_type="hardcoded_secret",
                                file=rel_path,
                                line_start=line_num,
                                title=f"Potential secret in environment variable: {var_name}",
                                description=f"Environment variable '{var_name}' may contain sensitive information",
                                evidence=f"Variable: {var_name}, Value (masked): {self._mask_sensitive_info(var_value)}",
                            )
                        )

        return findings

    def _looks_like_secret(self, value: str) -> bool:
        """Check if a value looks like it might be a secret."""
        # Check for common secret characteristics
        if len(value) < 6:  # Too short to be a secret
            return False

        # Check for randomness - if it has high entropy it might be a secret
        if self._has_high_entropy(value):
            return True

        # Check against our known patterns
        for pattern, _ in self.SECRET_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True

        return False

    def _has_high_entropy(self, text: str) -> bool:
        """Check if text has high entropy (suggesting it might be a key/token)."""
        if len(text) < 10:  # Too short to reliably determine entropy
            return False

        # Calculate character diversity
        unique_chars = len(set(text))
        total_chars = len(text)

        # If more than 50% of characters are unique, it might be high entropy
        if unique_chars / total_chars > 0.5:
            return True

        return False

    def _mask_sensitive_info(self, text: str) -> str:
        """Mask sensitive information for display."""
        if not text:
            return ""

        # For API keys and tokens, show first 4 and last 4 characters
        if len(text) > 8:
            return f"{text[:4]}...{text[-4:]}"

        # For shorter texts, mask the middle
        if len(text) > 4:
            return f"{text[:2]}...{text[-2:]}"

        # For very short texts, mask completely
        return "***"
