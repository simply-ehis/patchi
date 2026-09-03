"""FormatAgent §p check — ruff / eslint / prettier --check."""

from __future__ import annotations

import logging
import shutil
import subprocess

from patchi.core.agents.base import AgentGroup, AgentInput, AgentResult, AgentStatus, BaseAgent, Severity, make_finding, register

_log = logging.getLogger("patchi.agents.side.format")

@register
class FormatAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "FormatAgent"
    description = "Format check before app run"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root
        findings = []
        checks = [
            (["ruff", "check", "."], "ruff"),
            (["npx", "eslint", ".", "--max-warnings", "0"], "eslint"),
            (["npx", "prettier", "--check", "."], "prettier"),
        ]
        for cmd, name in checks:
            if not shutil.which(cmd[0]):
                continue
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=str(root))
                if proc.returncode != 0 and proc.stdout.strip():
                    # only first 3 lines to avoid flood
                    snippet = "\n".join(proc.stdout.splitlines()[:3])[:400]
                    findings.append(make_finding(severity=Severity.LOW, file="", line_start=0, title=f"Format: {name} failed", description=snippet, finding_type="format_error"))
                    break  # one format failure enough
            except Exception as exc:  # noqa: BLE001
                _log.debug("format %s failed: %s", name, exc)
        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
