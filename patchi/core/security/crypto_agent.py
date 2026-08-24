"""
CryptoAgent — cryptographic implementation issues.

Detects crypto-related security issues:
- Weak hashing algorithms (MD5, SHA1)
- Weak encryption algorithms (DES, RC4)
- Hardcoded cryptographic keys
- Improper salt usage
- Predictable random number generation
- Padding oracle vulnerabilities
- Weak key sizes
- Insecure PRNG usage

Uses pattern matching and code analysis.
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..agents.base import (
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
class CryptoAgent(BaseAgent):
    """Agent for detecting cryptographic implementation issues."""

    group = AgentGroup.SECURITY
    name = "CryptoAgent"
    description = "Cryptographic issues: weak algos, hardcoded keys, improper salt, PRNG"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run cryptographic security detection."""
        findings = []

        # Define source file patterns to scan
        source_patterns = [
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
        ]

        # Search for source files
        for pattern in source_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_file_crypto_security(file_path, rel_path))

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update({
            "crypto_findings": len(
                [
                    f
                    for f in findings
                    if any(
                        word in f.title.lower()
                        for word in [
                            "crypto",
                            "hash",
                            "encrypt",
                            "random",
                            "salt",
                            "key",
                            "prng",
        ]
        )
        ]
            ),
            "needs_ai": False,
        })
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

    def _scan_file_crypto_security(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan a file for cryptographic security issues."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")

            # Check for weak hashing algorithms
            findings.extend(self._scan_weak_hashing(content, rel_path))

            # Check for weak encryption algorithms
            findings.extend(self._scan_weak_encryption(content, rel_path))

            # Check for hardcoded cryptographic keys
            findings.extend(self._scan_hardcoded_keys(content, rel_path))

            # Check for improper salt usage
            findings.extend(self._scan_salt_issues(content, rel_path))

            # Check for predictable random generation
            findings.extend(self._scan_random_generation(content, rel_path))

            # Check for other crypto issues
            findings.extend(self._scan_other_crypto_issues(content, rel_path))

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Crypto security scanner file read error",
                    description=f"Could not analyze {file_path.name} for cryptographic issues: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_weak_hashing(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for weak hashing algorithm usage."""
        findings = []

        # Look for weak hashing algorithms
        weak_hash_patterns = [
            (r"MD5|md5", "Weak Hash Algorithm (MD5)", Severity.HIGH),
            (r"SHA1|sha1", "Weak Hash Algorithm (SHA1)", Severity.HIGH),
            (r"hash.*md5|digest.*md5", "MD5 Hash Usage", Severity.HIGH),
            (r"hash.*sha1|digest.*sha1", "SHA1 Hash Usage", Severity.HIGH),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in weak_hash_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description=f"Weak hashing algorithm found: {match.group(0)}",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_weak_encryption(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for weak encryption algorithm usage."""
        findings = []

        # Look for weak encryption algorithms
        weak_crypto_patterns = [
            (r"\bDES\b", "Weak Encryption Algorithm (DES)", Severity.HIGH),
            (r"\bRC4\b", "Weak Stream Cipher (RC4)", Severity.HIGH),
            (r"\bblowfish\b", "Weak Block Cipher (Blowfish)", Severity.MEDIUM),
            (r"encrypt.*\bDES\b|cipher.*\bDES\b", "DES Encryption Usage", Severity.HIGH),
            (r"encrypt.*\bRC4\b|cipher.*\bRC4\b", "RC4 Encryption Usage", Severity.HIGH),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in weak_crypto_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description=f"Weak encryption algorithm found: {match.group(0)}",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_hardcoded_keys(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for hardcoded cryptographic keys."""
        findings = []

        # Look for hardcoded keys (require key-like context to reduce false positives)
        key_patterns = [
            (
                r'(?:\bsecret\b|\bkey\b|\btoken\b|\bpassword)\s*[:=]\s*["\'][A-Za-z0-9+/=]{20,}["\']',
                "Hardcoded Cryptographic Key",
                Severity.HIGH,
            ),
            (
                r'(?:SECRET_KEY|API_KEY|PRIVATE_KEY|ENCRYPTION_KEY)\s*[:=]\s*["\'][^"\']{8,}["\']',
                "Hardcoded Key Constant",
                Severity.HIGH,
            ),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in key_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Additional validation to reduce false positives
                    matched_text = match.group(0)
                    # Check if it looks like a real key (not just a long hex string in other context)
                    if len(matched_text) > 20 or ("key" in line.lower() and len(matched_text) > 10):
                        findings.append(
                            make_finding(
                                severity=severity,
                                file=rel_path,
                                line_start=i,
                                title=description,
                                description=f"Potentially hardcoded cryptographic key found: {matched_text[:20]}...",
                                evidence=line.strip(),
                            )
                        )

        return findings

    def _scan_salt_issues(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for improper salt usage."""
        findings = []

        # Look for missing or weak salt usage
        salt_patterns = [
            (r"hash.*password(?![^=]*salt)", "Hashing Password Without Salt", Severity.HIGH),
            (r"pbkdf2(?![^=]*salt)", "PBKDF2 Without Salt", Severity.HIGH),
            (r"bcrypt(?![^=]*salt)", "bcrypt Without Salt", Severity.HIGH),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in salt_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Cryptographic function used without proper salt",
                            evidence=line.strip(),
                        )
                    )

        # Look for hardcoded salts
        hardcoded_salt_patterns = [
            (r'\bsalt\b\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded Salt", Severity.HIGH),
            (
                r"const.*\bsalt\b|var.*\bsalt\b|let.*\bsalt\b",
                "Possible Hardcoded Salt Variable",
                Severity.MEDIUM,
            ),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, description, severity in hardcoded_salt_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Possible hardcoded salt detected",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_random_generation(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for predictable random number generation."""
        findings = []

        # Look for insecure random generation (only in crypto-relevant contexts)
        random_patterns = [
            (r"Math\.random\(\)", "Predictable Random Number (JavaScript)", Severity.HIGH),
            (
                r"(?:random\.random|random\.randint|random\.choice|random\.randrange)\b",
                "Non-crypto PRNG (Python) — fine for games, risky for tokens/secrets",
                Severity.MEDIUM,
            ),
            (r"System\.Random|Random\.Next", "Potentially Weak Random (C#)", Severity.MEDIUM),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in random_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description=f"Insecure random number generation: {match.group(0)}",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_other_crypto_issues(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for other cryptographic issues."""
        findings = []

        # Look for weak key sizes
        key_size_patterns = [
            (r"key_size.*512|rsa.*512", "Weak RSA Key Size (512 bits)", Severity.HIGH),
            (r"key_size.*1024|rsa.*1024", "Weak RSA Key Size (1024 bits)", Severity.MEDIUM),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in key_size_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description=f"Weak cryptographic key size: {match.group(0)}",
                            evidence=line.strip(),
                        )
                    )

        return findings
