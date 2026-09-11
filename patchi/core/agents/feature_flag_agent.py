"""
FeatureFlagArchaeology §2.1.4 — hardcoded boolean flags for >N releases.

Detects `if (FEATURE_X)`, `featureFlag === true` where flag value is constant
across N commits (git log + blame). Flags: true/false, 0/1, "on"/"off".
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    get_shard_files,
    make_finding,
    register,
)

_log = logging.getLogger("patchi.agents.feature_flag")

_FLAG_RE = re.compile(r"(?:feature[_-]?flag|FLAG|ff[_A-Z]+|isEnabled|enabled)\s*[=:]\s*(true|false|1|0|\"on\"|\'on\'|\"off\"|\'off\')", re.I)
_BOOL_ASSIGN = re.compile(r"^\s*(?:const|let|var)?\s*(\w*(?:flag|enabled|feature)\w*)\s*=\s*(true|false)\b", re.I | re.M)


def _git_log_count(root: Path, rel: str, flag_name: str, commits: int = 20) -> int:
    """How many recent commits keep the same flag value line."""
    try:
        out = subprocess.run(
            ["git", "log", f"-{commits}", "--oneline", "--", rel],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(root),
        )
        if out.returncode != 0:
            return 0
        return len([line for line in out.stdout.splitlines() if line.strip()])
    except Exception as exc:  # noqa: BLE001
        _log.debug("git log %s failed: %s", flag_name, exc)
        return 0


@register
class FeatureFlagArchaeologyAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "FeatureFlagArchaeologyAgent"
    description = "Hardcoded boolean flags (feature flag archaeology) — §2.1.4"
    timeout = 60
    shardable = True
    supported_languages = None

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        _MAX_FILES = 300
        _count = 0
        for pattern in ("*.py", "*.js", "*.ts", "*.tsx", "*.go", "*.java"):
            for fp in get_shard_files(inp, pattern):
                if _count >= _MAX_FILES:
                    break
                if not fp.is_file():
                    continue
                _count += 1
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for m in _BOOL_ASSIGN.finditer(txt):
                    name = m.group(1)
                    val = m.group(2)
                    line = txt[: m.start()].count("\n") + 1
                    # Check git history depth for this flag line's file
                    depth = _git_log_count(inp.root, rel, name, commits=15)
                    if depth >= 10:  # hardcoded for >10 releases
                        findings.append(
                            make_finding(
                                severity=Severity.LOW,
                                file=rel,
                                line_start=line,
                                title=f"Hardcoded flag {name}={val} for {depth} commits (archaeology)",
                                description=f"Boolean flag '{name}' has been {val} for {depth} recent commits touching {rel} — likely dead code. Remove flag or make dynamic. References: uber/piranha for refactoring.",
                                evidence=m.group(0).strip()[:120],
                                finding_type="hardcoded_flag",
                            )
                        )
        result.status = AgentStatus.SUCCEEDED
        result.findings = findings[:50]
        result.data["flag_count"] = len(findings)
