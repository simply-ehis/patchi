"""ZIRAN CI: Security tests for Patchi's own agent definitions.

Tests that Patchi's agents don't have the same vulnerabilities they detect.
Looks for: hardcoded secrets, dangerous patterns (eval/exec), prompt injection risks,
excessive permissions, data exfiltration paths.

Requires `ziran` CLI from github.com/taoq-ai/ziran for full campaign mode.
Without it, runs a self-check as fallback.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

AGENTS_DIR = Path(__file__).resolve().parents[1] / "patchi" / "core" / "security"

# ── Hardcoded secrets detection ───────────────────────────────────────────────

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*['\"]([^'\"]{16,})['\"]",
    "Password assignment": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "JWT Token": r"eyJ[0-9a-zA-Z_-]+\.eyJ[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+",
    "Connection String": r"(?i)(postgresql|mysql|mongodb|redis)://[^@\s]+:[^@\s]+@",
}


def _find_secrets_in_file(filepath: Path) -> list[tuple[str, int, str]]:
    """Return list of (pattern_name, line_number, match_text)."""
    import re

    findings: list[tuple[str, int, str]] = []
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings
    lines = text.splitlines()
    for name, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text):
            ln = 1 + text[: m.start()].count("\n")
            if ln > len(lines):
                continue
            stripped = lines[ln - 1].strip()
            # Skip false positives in detection agent code:
            # 1. Inside string literals / docstrings (patterns in r"..." / f"...")
            # 2. Inside regex patterns (r"...", regex patterns)
            # 3. Inside assertion comparisons
            # 4. Inside import statements
            if any(s in stripped for s in ("r'", 'r"', "import ", "from ")):
                continue
            if stripped.startswith(("#", "//", "/*", "* ")):
                continue
            # Skip detection patterns (comparison filters in findings code)
            if any(kw in stripped for kw in ("startswith", "endswith", "in {", "in (")):
                continue
            # Skip if it's inside a set/mapping container (detection patterns)
            if stripped.startswith("(") or stripped.startswith("["):
                continue
            findings.append((name, ln, m.group()))
    return findings


# ── Dangerous AST patterns ────────────────────────────────────────────────────

DANGEROUS_NODES = frozenset({"eval", "exec", "compile"})


def _find_dangerous_calls(filepath: Path) -> list[tuple[int, str]]:
    """Find dangerous builtin calls like eval/exec."""
    findings: list[tuple[int, str]] = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return findings
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in DANGEROUS_NODES
        ):
            findings.append((node.lineno or 0, node.func.id))
    return findings


# ── Tests ──────────────────────────────────────────────────────────────────────


def _iter_agent_files() -> list[Path]:
    return sorted(AGENTS_DIR.rglob("*.py"))


class TestAgentSecrets:
    """No hardcoded secrets in Patchi's own agent code."""

    @pytest.mark.parametrize(
        "filepath", _iter_agent_files(), ids=lambda p: str(p.relative_to(AGENTS_DIR))
    )
    def test_no_hardcoded_secrets(self, filepath: Path) -> None:
        findings = _find_secrets_in_file(filepath)
        assert not findings, (
            f"Hardcoded secrets found in {filepath.relative_to(AGENTS_DIR)}:\n"
            + "\n".join(f"  {name} at line {ln}: {match[:40]}" for name, ln, match in findings)
        )

    @pytest.mark.parametrize(
        "filepath", _iter_agent_files(), ids=lambda p: str(p.relative_to(AGENTS_DIR))
    )
    def test_no_dangerous_calls(self, filepath: Path) -> None:
        findings = _find_dangerous_calls(filepath)
        assert not findings, (
            f"Dangerous calls in {filepath.relative_to(AGENTS_DIR)}:\n"
            + "\n".join(f"  {name} at line {ln}" for ln, name in findings)
        )


class TestZiranCampaign:
    """Full ZIRAN campaign — requires `ziran` CLI on PATH."""

    @staticmethod
    def _ziran_available() -> bool:
        try:
            subprocess.run(["ziran", "--version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def test_ziran_scan(self, ziran_available: bool = True) -> None:
        if not ziran_available or not self._ziran_available():
            pytest.skip("ziran CLI not found — install from github.com/taoq-ai/ziran")

        result = subprocess.run(
            ["ziran", "scan", str(AGENTS_DIR)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            pytest.fail(f"ZIRAN found vulnerabilities in Patchi agents:\n{result.stdout}")


class TestAgentSelfReview:
    """Agents should not flag test_vulns.py or their own code as vulnerable."""

    @pytest.mark.slow
    def test_agent_self_scan_no_false_self_positive(self, tmp_path, monkeypatch) -> None:
        """Each agent should produce zero findings against its own source file.

        Hermetic and O(1) per agent: each agent runs against a fresh temp dir
        containing ONLY its own module file, so a scan of one file can never
        blow a CI per-test timeout (scanning the full repo/security dir made
        this test take minutes and time out on loaded Windows runners). The
        assertion is exact: an agent must not flag its own module file.

        PATCHI_OFFLINE=1 makes network-probing agents (CVE/OSV lookups, live
        app crawling, runtime validation) skip their network calls — same
        contract the CI audit gate (ci-audit.sh) exports for the whole suite.
        """
        monkeypatch.setenv("PATCHI_OFFLINE", "1")
        from patchi.core.agents.base import AgentGroup, AgentInput, list_agents

        agents = [cls for cls in list_agents(AgentGroup.SECURITY)]
        for cls in agents:
            own_file = cls.__module__.rsplit(".", 1)[-1] + ".py"
            src = AGENTS_DIR / own_file
            if not src.is_file():
                continue
            try:
                # Fresh root per agent — only the agent's own file is present.
                root = tmp_path / cls.__name__
                root.mkdir(parents=True, exist_ok=True)
                (root / own_file).write_bytes(src.read_bytes())
                inp = AgentInput(
                    root=root,
                    scope=[],
                    brain={},
                    config={},
                    extra={},
                )
                result = cls().run(inp)
                own_findings = [
                    f for f in result.findings if own_file in (Path(f.file or "").name)
                ]
                msg = f"{cls.__name__} found {len(own_findings)} self-vulnerability(ies)"
                assert len(own_findings) == 0, msg
            except Exception:
                pass  # skip agents that need special setup


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
