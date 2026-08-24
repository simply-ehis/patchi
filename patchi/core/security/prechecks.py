"""
Cheap Pre-Checks (Layer 0) — instant gate before expensive scans.

Pure deterministic checks that run in <1 second:
- patchi_pattern_count: count pattern occurrences (banned APIs, refactor verification)
- patchi_lint_check: wrap ruff/eslint for fast style/bug detection
- patchi_diff_stat: before/after line counts on a change
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

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

# ── Banned API patterns (zero tolerance) ──────────────────────────────────────

_BANNED_APIS = [
    (re.compile(r"\beval\s*\("), "eval() — code injection risk"),
    (re.compile(r"\bexec\s*\("), "exec() — code injection risk"),
    (re.compile(r"\bpickle\.loads?\s*\("), "pickle deserialization — RCE risk"),
    (re.compile(r"\bmarshal\.loads?\s*\("), "marshal deserialization — RCE risk"),
    (re.compile(r"\b__import__\s*\("), "dynamic import — verify necessity"),
]


def patchi_pattern_count(root: Path, pattern: str, path_filter: str = "*.py") -> int:
    """Count occurrences of a regex pattern across files. Returns total count."""
    count = 0
    for fpath in safe_rglob(root, path_filter):
        if not fpath.is_file():
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        count += len(re.findall(pattern, content))
    return count


def patchi_lint_check(root: Path, language: str = "python") -> list[dict]:
    """Run ruff (Python) or eslint (JS/TS) and return parsed violations."""
    violations = []

    if language == "python":
        try:
            proc = subprocess.run(
                ["ruff", "check", "--output-format=json", str(root)],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(root),
            )
            import json

            data = json.loads(proc.stdout) if proc.stdout.strip() else []
            for item in data:
                violations.append(
                    {
                        "file": item.get("filename", ""),
                        "line": item.get("location", {}).get("row", 0),
                        "code": item.get("code", ""),
                        "message": item.get("message", ""),
                    }
                )
        except FileNotFoundError:
            import logging

            logging.getLogger("patchi.prechecks").warning(
                "ruff not installed — skipping Python lint check"
            )
        except (subprocess.TimeoutExpired, Exception):
            pass

    elif language in ("javascript", "typescript"):
        try:
            proc = subprocess.run(
                ["npx", "eslint", "--format=json", str(root)],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(root),
            )
            import json

            data = json.loads(proc.stdout) if proc.stdout.strip() else []
            for item in data:
                for msg in item.get("messages", []):
                    violations.append(
                        {
                            "file": item.get("filePath", ""),
                            "line": msg.get("line", 0),
                            "code": msg.get("ruleId", ""),
                            "message": msg.get("message", ""),
                        }
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

    return violations


def patchi_diff_stat(original: str, proposed: str) -> dict:
    """Compare before/after line counts. Returns add/delete/total stats."""
    orig_lines = original.splitlines()
    prop_lines = proposed.splitlines()
    orig_set = set(orig_lines)
    prop_set = set(prop_lines)
    added = prop_set - orig_set
    deleted = orig_set - prop_set
    return {
        "orig_lines": len(orig_lines),
        "new_lines": len(prop_lines),
        "lines_added": len(added),
        "lines_deleted": len(deleted),
        "net_change": len(prop_lines) - len(orig_lines),
    }


# ── Pre-checks Agent ──────────────────────────────────────────────────────────


@register
class PreCheckAgent(BaseAgent):
    """Layer 0: instant deterministic pre-checks before expensive scans."""

    name = "PreCheckAgent"
    group = AgentGroup.SECURITY
    timeout = 15

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # 1. Banned API checks
        for pattern, msg in _BANNED_APIS:
            count = patchi_pattern_count(inp.root, pattern.pattern)
            if count > 0:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="banned_api",
                        severity=Severity.CRITICAL,
                        file="",
                        message=f"{msg} — {count} occurrence(s) found",
                        cwe="CWE-94",
                    )
                )

        # 2. Quick lint check
        violations = patchi_lint_check(inp.root, "python")
        for v in violations[:20]:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="lint_violation",
                    severity=Severity.LOW,
                    file=v["file"],
                    line=v["line"],
                    message=f"[{v['code']}] {v['message']}",
                )
            )

        result.files_scanned = len(list(safe_rglob(inp.root, "*.py")))
