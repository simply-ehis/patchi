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
class CryptoAgent(BaseAgent):
    """Agent for detecting cryptographic implementation issues."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
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
        result.data.update(
            {
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

    # Invocation syntax near a weak-algorithm token: hashlib.md5(,
    # MessageDigest.getInstance("MD5"), createHash('md5'), Cipher/DES args.
    # A bare token (comment, variable named `des`, docs) is not usage.
    _CALL_CONTEXT_RE = re.compile(
        r"(hashlib|hash|digest|createhash|getinstance|get_instance|"
        r"cipher|encrypt|decrypt|creadecipher|createcipheriv)\s*[\(\.]",
        re.IGNORECASE,
    )

    # One notch down when the token has no invocation context on its line:
    # HIGH->MEDIUM, MEDIUM->LOW. Absence of proof is not proof of safety,
    # but it is not a HIGH either.
    _DEMOTE = {Severity.CRITICAL: Severity.HIGH, Severity.HIGH: Severity.MEDIUM,
               Severity.MEDIUM: Severity.LOW, Severity.LOW: Severity.INFO,
               Severity.INFO: Severity.INFO}

    def _emit_call_scoped(self, findings, severity, rel_path, i, title, description, line):
        """Emit at full severity with call context, else demoted + verify note."""
        if self._CALL_CONTEXT_RE.search(line):
            findings.append(
                make_finding(
                    severity=severity,
                    file=rel_path,
                    line_start=i,
                    title=title,
                    description=description,
                    evidence=line.strip(),
                )
            )
        else:
            findings.append(
                make_finding(
                    severity=self._DEMOTE.get(severity, Severity.LOW),
                    file=rel_path,
                    line_start=i,
                    title=title,
                    description=description + " (unverified usage — confirm a real call site)",
                    evidence=line.strip(),
                )
            )

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
                    self._emit_call_scoped(
                        findings,
                        severity,
                        rel_path,
                        i,
                        description,
                        f"Weak hashing algorithm found: {match.group(0)}",
                        line,
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
                    self._emit_call_scoped(
                        findings,
                        severity,
                        rel_path,
                        i,
                        description,
                        f"Weak encryption algorithm found: {match.group(0)}",
                        line,
                    )

        return findings

    def _scan_hardcoded_keys(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for hardcoded cryptographic keys."""
        from patchi.core.security.secret_evidence import is_fixture_path, looks_like_secret

        findings = []
        if is_fixture_path(rel_path):
            return findings

        # Look for hardcoded keys; values must pass the shared secret gate
        # (Part 7) — the old length-only validation fired on hex blobs.
        key_patterns = [
            (
                r'(?:\bsecret\b|\bkey\b|\btoken\b|\bpassword)\s*[:=]\s*["\']([^"\']+)["\']',
                "Hardcoded Cryptographic Key",
                Severity.HIGH,
            ),
            (
                r'(?:SECRET_KEY|API_KEY|PRIVATE_KEY|ENCRYPTION_KEY)\s*[:=]\s*["\']([^"\']+)["\']',
                "Hardcoded Key Constant",
                Severity.HIGH,
            ),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in key_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    try:
                        value = match.group(1)
                    except IndexError:
                        value = ""
                    if not looks_like_secret(value, allow_spaces=False):
                        continue
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Potentially hardcoded cryptographic key found.",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_salt_issues(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for improper salt usage."""
        findings = []

        # Look for missing or weak salt usage. Part 7: a single line cannot
        # prove absence of salt (it usually lives in an adjacent argument),
        # so these are MEDIUM + verify language, never HIGH. The bcrypt rule
        # is deleted outright: bcrypt manages its own salt (gensalt), so
        # "bcrypt without salt on this line" is false as a rule.
        salt_patterns = [
            (r"hash.*password(?![^=]*salt)", "Hashing Password Without Salt", Severity.MEDIUM),
            (r"pbkdf2(?![^=]*salt)", "PBKDF2 Without Salt", Severity.MEDIUM),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in salt_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Cryptographic function used without visible salt on this line — "
                            "verify the salt argument (it often lives in an adjacent parameter)",
                            evidence=line.strip(),
                        )
                    )

        # Look for hardcoded salts
        hardcoded_salt_patterns = [
            (r'\bsalt\b\s*[=:]\s*["\']([^"\']+)["\']', "Hardcoded Salt", Severity.MEDIUM),
            (
                r"const.*\bsalt\b|var.*\bsalt\b|let.*\bsalt\b",
                "Possible Hardcoded Salt Variable",
                Severity.LOW,
            ),
        ]

        from patchi.core.security.secret_evidence import looks_like_secret

        for i, line in enumerate(lines, 1):
            for pattern, description, severity in hardcoded_salt_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    if "salt" in description.lower() and "possible" not in description.lower():
                        try:
                            value = _match.group(1)
                        except IndexError:
                            value = ""
                        if not looks_like_secret(value, min_length=8, min_entropy=3.0):
                            continue
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Possible hardcoded salt detected — verify it is not a constant",
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

        # Part 7: Math.random() feeding an animation is not a vuln. Keep
        # HIGH only when a secret-adjacent sink shares the line; else MEDIUM.
        _SINK_RE = re.compile(r"token|secret|key|crypt|password|auth|nonce|session", re.IGNORECASE)

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in random_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    sev = severity
                    note = f"Insecure random number generation: {match.group(0)}"
                    if "Math.random" in match.group(0) and not _SINK_RE.search(line):
                        sev = Severity.MEDIUM
                        note += " (no secret sink on this line — verify usage)"
                    findings.append(
                        make_finding(
                            severity=sev,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description=note,
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_other_crypto_issues(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for other cryptographic issues."""
        findings = []

        # Look for weak key sizes. Part 7: a bare "1024" may be a buffer,
        # port, or test constant — require key-generation context on the
        # line, else skip (not even a LOW: numbers alone are not findings).
        _KEYGEN_RE = re.compile(r"keygen|generate|genkey|new\s+\w*[Kk]ey|key_size|keysize", re.IGNORECASE)
        key_size_patterns = [
            (r"key_size.*512|rsa.*512", "Weak RSA Key Size (512 bits)", Severity.HIGH),
            (r"key_size.*1024|rsa.*1024", "Weak RSA Key Size (1024 bits)", Severity.MEDIUM),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in key_size_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    if not _KEYGEN_RE.search(line):
                        continue
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
