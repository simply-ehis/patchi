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

import logging
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
    get_shard_files,
    make_finding,
    register,
    scope_allows,
)

# Directories holding intentional fake secrets (attacker fixtures, test
# data) — scanning them only produces false positives.
_FIXTURE_DIRS = ("attack_scenarios/", "tests/fixtures/", "fixtures/")

_log = logging.getLogger("patchi.agents.env_scanner")


@register
class EnvScanner(BaseAgent):
    """Scanner for environment variables and secrets."""

    group = AgentGroup.SCANNER
    name = "EnvScanner"
    description = "Secret/credential pattern detection"
    shardable = True
    supported_languages = None

    # Common secret patterns — tiered (Part 7).
    # kind="structural": the token SHAPE is the evidence (prefix + charset +
    # length). Still gated on placeholder/entropy/fixture via secret_evidence.
    # kind="keyword": a NAME suggests secrecy; the VALUE must independently
    # pass looks_like_secret or nothing is emitted (never CRITICAL).
    # kind="public": public key material — inventory INFO, never a secret.
    # kind="pem": header alone proves nothing without a base64 body.
    # Flags are per-pattern: provider prefixes are case-SENSITIVE (akia !=
    # AKIA); only the keyword names match case-insensitively.
    SECRET_PATTERNS = [
        # AWS keys (case-sensitive by design)
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "structural", ""),
        (r"AGPA[0-9A-Z]{16}", "AWS Access Key", "structural", ""),
        (r"AIDA[0-9A-Z]{16}", "AWS Access Key", "structural", ""),
        (r"AROA[0-9A-Z]{16}", "AWS Access Key", "structural", ""),
        (r"ASIA[0-9A-Z]{16}", "AWS Access Key", "structural", ""),
        # AWS secret keys. Part 7: exactly 40 base64 chars AND at least
        # one digit — prose with slashes ("a/b/c...") has no digits and
        # longer hashes (sha512 blobs) don't boundary-match.
        (
            r"(?<![0-9a-zA-Z/+_])(?=[0-9a-zA-Z/+]{0,39}[0-9])[0-9a-zA-Z/+]{40}(?![0-9a-zA-Z/+_])",
            "AWS Secret Key",
            "structural",
            "",
        ),
        # GitHub tokens
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", "structural", ""),
        (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Access Token", "structural", ""),
        (r"ghu_[0-9a-zA-Z]{36}", "GitHub User-to-server Token", "structural", ""),
        (r"ghs_[0-9a-zA-Z]{36}", "GitHub Server-to-Server Token", "structural", ""),
        (r"ghr_[0-9a-zA-Z]{76}", "GitHub Refresh Token", "structural", ""),
        # Slack tokens
        (r"xox[a-zA-Z]-[0-9A-Za-z-]+", "Slack Token", "structural", ""),
        # Slack webhooks
        (
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}",
            "Slack Webhook",
            "structural",
            "",
        ),
        # Google API keys
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "structural", ""),
        # Google OAuth
        (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID", "structural", ""),
        # Facebook access tokens
        (r"EAACEdEose0cBA[0-9A-Za-z]+", "Facebook Access Token", "structural", ""),
        # Passwords in various formats (keyword tier: value must prove itself)
        (r'(?i:password)\s*[=:]\s*["\']([^"\']+)["\']', "Password in config", "keyword", ""),
        (r'(?i:pwd)\s*[=:]\s*["\']([^"\']+)["\']', "Password in config", "keyword", ""),
        (r'(?i:passwd)\s*[=:]\s*["\']([^"\']+)["\']', "Password in config", "keyword", ""),
        # Database connection strings with credentials
        (r"postgres://[a-zA-Z0-9_%]+:[^@]+@", "PostgreSQL Connection String", "structural", ""),
        (r"mysql://[a-zA-Z0-9_%]+:[^@]+@", "MySQL Connection String", "structural", ""),
        (r"mongodb://[a-zA-Z0-9_%]+:[^@]+@", "MongoDB Connection String", "structural", ""),
        # Private key headers (body required — see scan loop)
        (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key", "pem", ""),
        # SSH keys — PUBLIC material, inventory only
        (r"ssh-rsa [A-Za-z0-9+/\s]+={0,2}", "SSH Public Key", "public", ""),
        (r"ssh-ed25519 [A-Za-z0-9+/\s]+={0,2}", "SSH Ed25519 Key", "public", ""),
        # Generic API keys (keyword tier)
        (r'(?i:api[_-]?key)["\']?\s*[=:]\s*["\']([^"\']+)["\']', "Generic API Key", "keyword", ""),
        (r'(?i:api[_-]?token)["\']?\s*[=:]\s*["\']([^"\']+)["\']', "Generic API Token", "keyword", ""),
        (r'(?i:secret)["\']?\s*[=:]\s*["\']([^"\']+)["\']', "Generic Secret", "keyword", ""),
        (r'(?i:token)["\']?\s*[=:]\s*["\']([^"\']+)["\']', "Generic Token", "keyword", ""),
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

        # Search for environment/config files — use corpus if available
        corpus = inp.extra.get("file_corpus")
        _MAX_FILES = 100
        if corpus and corpus.entries:
            env_exts = {
                ".env",
                ".envrc",
                ".config",
                ".conf",
                ".ini",
                ".properties",
                ".json",
                ".yaml",
                ".yml",
                ".toml",
                ".py",
                ".js",
                ".ts",
                ".jsx",
                ".tsx",
                ".sh",
                ".bash",
                ".zsh",
                ".ps1",
                ".bat",
            }
            count = 0
            for rel_key in corpus.entries:
                if count >= _MAX_FILES:
                    break
                p = Path(rel_key)
                ext = p.suffix.lower()
                name = p.name.lower()
                if ext in env_exts or name.startswith("dockerfile") or name.startswith("docker-compose"):
                    if not scope_allows(inp, rel_key):
                        continue
                    if not self._should_skip_file(rel_key, inp):
                        findings.extend(self._scan_env_file(inp.root / rel_key, rel_key))
                        count += 1
        else:
            for pattern in env_patterns:
                for file_path in get_shard_files(inp, pattern):
                    if file_path.is_file():
                        rel_path = file_path.relative_to(inp.root).as_posix()
                        if not scope_allows(inp, rel_path):
                            continue
                        if not self._should_skip_file(rel_path, inp):
                            findings.extend(self._scan_env_file(file_path, rel_path))

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "secrets_found": len(
                    [f for f in findings if "Secret" in f.title or "Token" in f.title or "Key" in f.title]
                ),
                "passwords_found": len([f for f in findings if "Password" in f.title]),
                "needs_ai": False,
            }
        )
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        # Skip ignored directories (node_modules, .venv, etc.)
        from pathlib import PurePosixPath

        if any(p in DEFAULT_IGNORE_DIRS for p in PurePosixPath(file_path).parts):
            return True

        # Skip intentional-secret fixtures (attacker scenarios, test data),
        # wherever nested in the tree
        parts = PurePosixPath(file_path).parts
        if any(d.strip("/") in parts for d in _FIXTURE_DIRS):
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

        # Fixture/test/doc paths intentionally look dangerous — verdicts
        # from them are noise by construction, not findings.
        from patchi.core.security.secret_evidence import (
            is_fixture_path,
            looks_like_secret,
            private_key_body_present,
        )

        _is_fixture = is_fixture_path(rel_path)

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
                # Self-detection guard: regex pattern strings that LOOK like
                # secrets (e.g. "-----BEGIN RSA PRIVATE KEY-----" inside
                # this file) must not be flagged.
                if "PRIVATE KEY" in line and ('r"' in line or "r'" in line):
                    continue
                if any(m in line for m in _fp_markers):
                    continue
                for pattern, description, kind, _flags in self.SECRET_PATTERNS:
                    for match in re.finditer(pattern, line):
                        if _is_fixture and kind != "public":
                            continue
                        verdict = self._verdict_for_match(
                            kind,
                            match,
                            description,
                            rel_path,
                            line_num,
                            file_path.name,
                            lines,
                            looks_like_secret,
                            private_key_body_present,
                        )
                        if verdict is not None:
                            findings.append(verdict)

            # Special check for .env files - look for common environment variable patterns
            if ".env" in file_path.name.lower():
                findings.extend(self._scan_dotenv_file(file_path, rel_path, lines))

        except UnicodeDecodeError:
            # If it's a binary file, try to read as binary and decode what we can
            try:
                from patchi.core.security.secret_evidence import (
                    looks_like_secret as _lls,
                )
                from patchi.core.security.secret_evidence import (
                    private_key_body_present as _pkb,
                )

                content = file_path.read_bytes()
                # Try to decode as UTF-8, ignoring errors
                text_content = content.decode("utf-8", errors="ignore")
                lines = text_content.splitlines()

                for line_num, line in enumerate(lines, 1):
                    for pattern, description, kind, _flags in self.SECRET_PATTERNS:
                        for match in re.finditer(pattern, line):
                            if _is_fixture and kind != "public":
                                continue
                            verdict = self._verdict_for_match(
                                kind,
                                match,
                                description,
                                rel_path,
                                line_num,
                                file_path.name,
                                lines,
                                _lls,
                                _pkb,
                            )
                            if verdict is not None:
                                findings.append(verdict)
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

    @staticmethod
    def _verdict_for_match(
        kind: str,
        match,
        description: str,
        rel_path: str,
        line_num: int,
        file_name: str,
        lines: list[str],
        looks_like_secret,
        private_key_body_present,
    ):
        """One match → finding or None (Part 7 verdict policy).

        structural: token shape is evidence, but the VALUE must still pass
        looks_like_secret (placeholders/examples/low-entropy rejected).
        keyword: the name suggests secrecy; value must prove it. Max HIGH.
        public: inventory INFO — public keys are published by design.
        pem: header + base64 body required, else a doc snippet (skipped).
        """
        from patchi.core.agents.base import Severity, make_finding

        matched = match.group(0)
        # Keyword patterns capture the value in group 1; structural patterns
        # are matched on the token itself.
        try:
            value = match.group(1)
        except IndexError:
            value = matched

        if kind == "public":
            return make_finding(
                severity=Severity.INFO,
                finding_type="public_key_material",
                file=rel_path,
                line_start=line_num,
                title=f"Public key material ({description}) — not a secret",
                description=f"Published-by-design key in {file_name}; no action needed",
                evidence=f"Match: {matched[:60]}",
            )
        if kind == "pem":
            window = "\n".join(lines[max(0, line_num - 1):line_num + 15])
            if not private_key_body_present(window):
                return None
            return make_finding(
                severity=Severity.CRITICAL,
                finding_type="hardcoded_secret",
                file=rel_path,
                line_start=line_num,
                title=f"Potential {description}",
                description=f"Private key block with key material in {file_name}",
                evidence="Match: -----BEGIN ... PRIVATE KEY----- (body verified)",
            )
        if kind == "keyword":
            if not looks_like_secret(value, allow_spaces=False):
                return None
            return make_finding(
                severity=Severity.HIGH,
                finding_type="hardcoded_secret",
                file=rel_path,
                line_start=line_num,
                title=f"Potential {description}",
                description=f"Secret-shaped value assigned to a sensitive name in {file_name}",
                evidence=f"Match: {matched[:4]}...{matched[-4:] if len(matched) > 8 else ''}",
            )
        # structural
        if not looks_like_secret(matched):
            return None
        return make_finding(
            severity=Severity.CRITICAL,
            finding_type="hardcoded_secret",
            file=rel_path,
            line_start=line_num,
            title=f"Potential {description}",
            description=f"Found potential {description} in {file_name}",
            evidence=f"Match: {matched[:4]}...{matched[-4:] if len(matched) > 8 else ''}",
        )

    def _scan_dotenv_file(self, file_path: Path, rel_path: str, lines: list[str]) -> list[Finding]:
        """Special scanning for .env files."""
        from patchi.core.security.secret_evidence import is_fixture_path as _is_fx
        from patchi.core.security.secret_evidence import looks_like_secret as _lls

        findings = []
        _dotenv_fixture = _is_fx(rel_path)

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
                    # Check if the value looks like a secret (shared Shannon
                    # gate; fixture .env files are intentional by construction)
                    if not _dotenv_fixture and _lls(var_value):
                        findings.append(
                            make_finding(
                                severity=Severity.HIGH,
                                finding_type="hardcoded_secret",
                                file=rel_path,
                                line_start=line_num,
                                title=f"Potential secret in environment variable: {var_name}",
                                description=f"Environment variable '{var_name}' may contain sensitive information",
                                evidence=f"Variable: {var_name}, Value (masked):"
                                f" {self._mask_sensitive_info(var_value)}",
                            )
                        )

        return findings

    def _looks_like_secret(self, value: str) -> bool:
        """Shared secret gate (Part 7): length + Shannon entropy + no
        placeholder. Kept as a method for backward compatibility."""
        from patchi.core.security.secret_evidence import looks_like_secret

        return looks_like_secret(value)

    def _has_high_entropy(self, text: str) -> bool:
        """Real Shannon entropy (Part 7). Kept as a method for compatibility."""
        from patchi.core.security.secret_evidence import shannon_entropy

        return len(text or "") >= 10 and shannon_entropy(text) >= 3.5

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
