"""
InsecureRandomnessAgent — Predictable random number generation.

Detects use of non-cryptographic random number generators in security-sensitive
contexts (tokens, passwords, keys, sessions, CSRF, etc.) and recommends
cryptographically secure alternatives.

Covers all 11 languages:
  - JS/TS: Math.random(), Math.floor(Math.random()
  - Python: random.random(), random.randint(), random.choice(), random.choices()
  - Java: java.util.Random, Math.random()
  - Go: math/rand
  - Rust: rand::random, rand::thread_rng
  - C/C++: rand(), srand()
  - Ruby: rand, Random.new
  - Swift: Int.random, Double.random, GKRandomSource

Uses tree-sitter AST + Python `ast` for call/import detection (no regex).
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

from pathlib import Path

from patchi.core.brain.ast_utils import find_calls, find_imports
from patchi.core.brain.languages import EXTENSION_MAP, Lang

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
class InsecureRandomnessAgent(BaseAgent):
    """Agent for detecting insecure random number generation."""

    group = AgentGroup.SECURITY
    name = "InsecureRandomnessAgent"
    description = "Predictable RNG in security-sensitive contexts (tokens, passwords, keys)"

    # Security-sensitive keywords that elevate RNG usage from INFO to HIGH
    SENSITIVE_CONTEXT_KEYWORDS = [
        "token", "password", "secret", "key", "session", "csrf",
        "nonce", "otp", "auth", "reset", "salt", "iv", "challenge",
        "jwt", "api_key", "apikey", "access_token", "refresh_token",
        "verification", "recovery", "mfa", "2fa", "tfa",
    ]

    # Per-language insecure RNG call sets (matched by leaf name)
    RNG_CALLS: dict[Lang, set[str]] = {
        Lang.JAVASCRIPT: {"Math.random", "Math.floor"},
        Lang.TYPESCRIPT: {"Math.random", "Math.floor"},
        Lang.PYTHON: {
            "random.random", "random.randint", "random.choice", "random.choices",
            "random.uniform", "random.shuffle", "random.sample", "random.randrange",
            "random.getrandbits", "random.getstate", "random.seed",
        },
        Lang.JAVA: {"Random", "Math.random"},
        Lang.GO: {"rand.Intn", "rand.Int", "rand.Float64", "rand.Perm", "rand.Shuffle", "rand.Seed"},
        Lang.RUST: {"rand::random", "rand::thread_rng", "rand::Rng.gen", "rand::Rng.gen_range"},
        Lang.C: {"rand", "srand"},
        Lang.CPP: {"rand", "srand"},
        Lang.RUBY: {"rand", "Random.new", "Random.rand"},
        Lang.SWIFT: {"Int.random", "Double.random", "CGFloat.random", "randomElement", "GKRandomSource"},
        Lang.PHP: {"mt_rand", "rand", "array_rand"},
        Lang.KOTLIN: {"Random.nextInt", "Random.nextDouble", "Random.nextBoolean"},
        Lang.C_SHARP: {"Random.Next", "Random.NextDouble", "Random.NextBytes"},
    }

    # Import / module patterns that indicate insecure RNG usage
    RNG_IMPORTS: dict[Lang, set[str]] = {
        Lang.PYTHON: {"random"},
        Lang.JAVA: {"java.util.Random"},
        Lang.GO: {"math/rand"},
        Lang.RUST: {"rand"},
        Lang.KOTLIN: {"kotlin.random.Random"},
    }

    # Secure alternative suggestions per language
    SECURE_ALTERNATIVES: dict[str, str] = {
        "JavaScript": "crypto.randomBytes() or crypto.randomUUID() (Node.js) / window.crypto.getRandomValues() (browser)",
        "Python": "secrets.token_bytes(), secrets.token_hex(), secrets.choice(), or os.urandom()",
        "Java": "java.security.SecureRandom",
        "Go": "crypto/rand.Read()",
        "Rust": "rand::rngs::OsRng or getrandom::getrandom()",
        "C/C++": "getrandom() (Linux) / BCryptGenRandom() (Windows) / arc4random() (BSD)",
        "Ruby": "SecureRandom.hex(), SecureRandom.urlsafe_base64(), or SecureRandom.random_bytes()",
        "Swift": "SecRandomCopyBytes() or CryptoKit's SecureRandom",
    }

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []

        source_patterns = [
            "*.py", "*.js", "*.jsx", "*.ts", "*.tsx",
            "*.java", "*.go", "*.rs", "*.c", "*.h",
            "*.cpp", "*.cxx", "*.cc", "*.hpp", "*.rb",
            "*.swift", "*.php", "*.kt", "*.cs",
        ]

        for pattern in source_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_file_rng(file_path, rel_path))

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update({
            "rng_findings": len(findings),
            "needs_ai": False,
        })
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        from pathlib import PurePosixPath
        restrictions = inp.config.get("restrictions", [])
        for r in restrictions:
            if r.get("enabled", True):
                path = r["path"]
                if file_path.startswith(path) or PurePosixPath(file_path).match(path):
                    if r["type"] == "NO_TOUCH":
                        return True
                    if r["type"] == "SCAN_ONLY" and self.__class__.__name__ == "FixAgent":
                        return True
        return False

    def _scan_file_rng(self, file_path: Path, rel_path: str) -> list[Finding]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            lang = EXTENSION_MAP.get(file_path.suffix.lower())
            if lang is None:
                return findings

            lines = content.splitlines()
            call_set = self.RNG_CALLS.get(lang, set())
            import_set = self.RNG_IMPORTS.get(lang, set())

            # 1. Call-based detection (imports of the rand module count as INFO)
            if call_set:
                for call in find_calls(content, lang, call_set):
                    line_num = call["line"] or 1
                    line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                    self._add_call_finding(findings, rel_path, line_num, line, lang, call["name"])

            # 2. Import-based detection (e.g. `import random`, `math/rand`)
            if import_set:
                for imp in find_imports(content, lang, import_set):
                    line_num = imp["line"] or 1
                    line = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                    is_sensitive = any(kw in line.lower() for kw in self.SENSITIVE_CONTEXT_KEYWORDS)
                    secure_alt = self.SECURE_ALTERNATIVES.get(
                        lang.value if hasattr(lang, "value") else str(lang),
                        "a cryptographically secure alternative",
                    )
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH if is_sensitive else Severity.INFO,
                            file=rel_path,
                            line_start=line_num,
                            title=f"Insecure RNG import ({str(lang)})",
                            description=(
                                f"Non-cryptographic random module imported"
                                f"{' in a security-sensitive context' if is_sensitive else ''}. "
                                f"Use {secure_alt} instead."
                            ),
                            evidence=line.strip(),
                            cwe="CWE-338" if is_sensitive else "CWE-330",
                        )
                    )

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="RNG scanner file read error",
                    description=f"Could not analyze {file_path.name}: {e}",
                    evidence=str(e),
                )
            )

        return findings

    def _add_call_finding(
        self, findings: list[Finding], rel_path: str, line_num: int, line: str,
        lang: Lang, rng_name: str,
    ) -> None:
        is_sensitive = any(kw in line.lower() for kw in self.SENSITIVE_CONTEXT_KEYWORDS)
        secure_alt = self.SECURE_ALTERNATIVES.get(
            lang.value if hasattr(lang, "value") else str(lang),
            "a cryptographically secure alternative",
        )
        findings.append(
            make_finding(
                severity=Severity.HIGH if is_sensitive else Severity.MEDIUM,
                file=rel_path,
                line_start=line_num,
                title=f"Insecure RNG in {'security-sensitive' if is_sensitive else ''} context ({str(lang)})",
                description=(
                    f"Non-cryptographic random generator {rng_name} detected"
                    f"{' in a security-sensitive context' if is_sensitive else ''}. "
                    f"Use {secure_alt} instead."
                ),
                evidence=line.strip(),
                cwe="CWE-338" if is_sensitive else "CWE-330",
            )
        )
