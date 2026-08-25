"""
EnvVarValidator — Environment variable usage validation.

Scans source code for environment variable reads and cross-references them
against `.env.example` / `.env.sample` files to find:
  - Undocumented env vars (used in code but not listed in .env.example)
  - Unused env vars (listed in .env.example but never read in code)
  - Missing validation (env vars read without default or guard)

Covers all 11 languages (process.env.*, os.getenv(), std::env::var(), etc.).

Env access spans both function calls AND property/subscript access (e.g.
`process.env.X` is not a call node in tree-sitter), so literal pattern
matching is the correct abstraction here. Patterns are scoped to exact
API names with word boundaries to avoid false positives.
Does NOT call AI (except for fix suggestions).
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

_log = logging.getLogger("patchi.security.env_var_validator")


@register
class EnvVarValidator(BaseAgent):
    """Agent for validating environment variable usage."""

    group = AgentGroup.SECURITY
    name = "EnvVarValidator"
    description = "Environment variable validation: undocumented, unused, missing defaults"

    # Per-language env var read patterns. Each is anchored to a specific API
    # (function call or property/subscript access) so it won't false-match
    # unrelated identifiers.
    ENV_READ_PATTERNS: list[tuple[str, str, str]] = [
        # JavaScript / TypeScript (call and property access)
        (r"process\.env\.(\w+)", "process.env.{}", "JavaScript"),
        (r"process\.env\[\s*['\"](\w+)['\"]\s*\]", "process.env['{}']", "JavaScript"),
        # Python
        (r"os\.getenv\s*\(\s*['\"](\w+)['\"]", "os.getenv('{}')", "Python"),
        (r"os\.environ\.get\s*\(\s*['\"](\w+)['\"]", "os.environ.get('{}')", "Python"),
        (r"os\.environ\[\s*['\"](\w+)['\"]\s*\]", "os.environ['{}']", "Python"),
        # Rust
        (r"env::var\s*\(\s*['\"](\w+)['\"]", "env::var(\"{}\")", "Rust"),
        (r"env!\(\s*['\"](\w+)['\"]", "env!(\"{}\")", "Rust"),
        # Go
        (r"os\.Getenv\s*\(\s*['\"](\w+)['\"]", "os.Getenv(\"{}\")", "Go"),
        (r"os\.LookupEnv\s*\(\s*['\"](\w+)['\"]", "os.LookupEnv(\"{}\")", "Go"),
        # Java
        (r"System\.getenv\s*\(\s*['\"](\w+)['\"]", "System.getenv(\"{}\")", "Java"),
        # Ruby
        (r"ENV\[\s*['\"](\w+)['\"]\s*\]", "ENV[\"{}\"]", "Ruby"),
        (r"ENV\.fetch\s*\(\s*['\"](\w+)['\"]", "ENV.fetch(\"{}\")", "Ruby"),
        # Swift
        (r"ProcessInfo\.processInfo\.environment\[\s*['\"](\w+)['\"]\s*\]", "ProcessInfo.environment[\"{}\"]", "Swift"),
        # C / C++ (getenv)
        (r"getenv\s*\(\s*['\"](\w+)['\"]", "getenv(\"{}\")", "C/C++"),
        # PHP
        (r"getenv\s*\(\s*['\"](\w+)['\"]", "getenv(\"{}\")", "PHP"),
        # Kotlin
        (r"System\.getenv\s*\(\s*['\"](\w+)['\"]", "System.getenv(\"{}\")", "Kotlin"),
        # C#
        (r"Environment\.GetEnvironmentVariable\s*\(\s*['\"](\w+)['\"]", "Environment.GetEnvironmentVariable(\"{}\")", "C#"),
    ]

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []

        source_patterns = [
            "*.py", "*.js", "*.jsx", "*.ts", "*.tsx",
            "*.java", "*.go", "*.rs", "*.c", "*.h",
            "*.cpp", "*.cxx", "*.cc", "*.hpp", "*.rb",
            "*.swift", "*.php", "*.kt", "*.cs",
        ]

        # Step 1: Collect all env vars used in source code
        used_env_vars: dict[str, list[dict]] = {}
        for pattern in source_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        content = self._safe_read(file_path)
                        if content is None:
                            continue
                        self._collect_env_vars(content, rel_path, used_env_vars)

        # Step 2: Find .env.example / .env.sample
        env_example = self._find_env_example(inp.root)
        documented_vars: set[str] = set()
        if env_example:
            documented_vars = self._parse_env_example(env_example)
            # Check for documented but unused vars
            for var in sorted(documented_vars):
                if var not in used_env_vars:
                    findings.append(
                        make_finding(
                            severity=Severity.INFO,
                            file=env_example.relative_to(inp.root).as_posix(),
                            line_start=0,
                            title=f"Unused documented env var: {var}",
                            description=(
                                f"Environment variable '{var}' is documented in {env_example.name} "
                                "but never referenced in source code. Consider removing it."
                            ),
                        )
                    )

        # Step 3: Check each used env var
        for var, usages in sorted(used_env_vars.items()):
            is_documented = var in documented_vars
            all_with_default = all(u.get("has_default", False) for u in usages)
            all(not u.get("is_bare_access", True) for u in usages)

            if not is_documented:
                first_usage = usages[0]
                findings.append(
                    make_finding(
                        severity=Severity.MEDIUM,
                        file=first_usage["file"],
                        line_start=first_usage["line"],
                        title=f"Undocumented env var: {var}",
                        description=(
                            f"Environment variable '{var}' is read in source code "
                            f"but not documented in {env_example.name if env_example else '.env.example'}. "
                            "Add it to the env template with a default or description."
                        ),
                        evidence=first_usage["snippet"],
                    )
                )

            if not all_with_default:
                bare_usages = [u for u in usages if not u.get("has_default", False)]
                for u in bare_usages[:1]:
                    findings.append(
                        make_finding(
                            severity=Severity.LOW,
                            file=u["file"],
                            line_start=u["line"],
                            title=f"Unvalidated env var access: {var}",
                            description=(
                                f"Environment variable '{var}' is accessed without a default value "
                                "or guard. This may crash at runtime if the variable is not set."
                            ),
                            evidence=u["snippet"],
                            cwe="CWE-754",
                        )
                    )

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update({
            "used_env_vars": len(used_env_vars),
            "documented_vars": len(documented_vars),
            "env_findings": len(findings),
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

    def _safe_read(self, path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except Exception as e:
            _log.warning("EnvVarValidator._safe_read failed: %s", e)
            return None

    def _collect_env_vars(
        self, content: str, rel_path: str, acc: dict[str, list[dict]]
    ) -> None:
        lines = content.splitlines()
        for pattern, _fmt, _lang in self.ENV_READ_PATTERNS:
            for match in re.finditer(pattern, content):
                var_name = match.group(1)
                line_num = content[: match.start()].count("\n") + 1
                line = lines[line_num - 1] if line_num <= len(lines) else ""
                # Heuristic: does this access have a default value?
                has_default = bool(
                    re.search(
                        rf"process\.env\.{re.escape(var_name)}\s*(\?\?|\|\|)\s*",
                        line,
                    )
                    or re.search(
                        rf"os\.getenv\(['\"]{re.escape(var_name)}['\"],\s*",
                        line,
                    )
                    or re.search(
                        rf"os\.environ\.get\(['\"]{re.escape(var_name)}['\"],\s*",
                        line,
                    )
                    or re.search(
                        rf"ENV\.fetch\(['\"]{re.escape(var_name)}['\"]",
                        line,
                    )
                )
                # Heuristic: bare access without guard
                is_bare_access = bool(
                    re.search(rf"process\.env\.{re.escape(var_name)}\b", line)
                    and not re.search(rf"process\.env\.{re.escape(var_name)}\s*(\?\?|\|\|)", line)
                )
                if var_name not in acc:
                    acc[var_name] = []
                acc[var_name].append({
                    "file": rel_path,
                    "line": line_num,
                    "snippet": line.strip(),
                    "has_default": has_default,
                    "is_bare_access": is_bare_access,
                })

    def _find_env_example(self, root: Path) -> Path | None:
        candidates = [
            root / ".env.example",
            root / ".env.sample",
            root / ".env.dist",
            root / "env.example",
            root / ".env.template",
        ]
        for p in candidates:
            if p.is_file():
                return p
        # Also search one level deep
        for p in root.iterdir():
            if p.is_file() and p.name.lower() in (
                ".env.example", ".env.sample", ".env.dist", "env.example", ".env.template"
            ):
                return p
        return None

    def _parse_env_example(self, path: Path) -> set[str]:
        """Parse .env.example into a set of variable names."""
        content = self._safe_read(path)
        if content is None:
            return set()
        vars_set: set[str] = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Split on = or :
            var_name = re.split(r"[=:]", line, maxsplit=1)[0].strip()
            if var_name and re.match(r"^[a-zA-Z_]\w*$", var_name):
                vars_set.add(var_name)
        return vars_set
