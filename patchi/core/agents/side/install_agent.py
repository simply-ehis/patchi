"""InstallAgent §p check — npm ci / pip install / go mod / cargo build."""

from __future__ import annotations

import logging
import shutil
import subprocess

from patchi.core.agents.base import AgentGroup, AgentInput, AgentResult, AgentStatus, BaseAgent, Severity, make_finding, register

_log = logging.getLogger("patchi.agents.side.install")

@register
class InstallAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "InstallAgent"
    description = "Install deps before app run — npm ci / pip install"
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root
        findings = []
        logs = []
        # Node
        if (root / "package.json").exists() and not (root / "node_modules").exists():
            cmd = ["npm", "ci"] if (root / "package-lock.json").exists() else ["npm", "install"]
            if shutil.which("npm"):
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=str(root))
                    logs.append(proc.stdout[:500] + proc.stderr[:500])
                    if proc.returncode != 0:
                        findings.append(make_finding(severity=Severity.HIGH, file="package.json", line_start=0, title="npm install failed", description=proc.stderr[:500], finding_type="install_failed"))
                except Exception as exc:  # noqa: BLE001
                    _log.debug("install npm failed: %s", exc)
        # Python
        if (root / "requirements.txt").exists():
            if shutil.which("pip"):
                try:
                    proc = subprocess.run([shutil.which("pip"), "install", "-r", "requirements.txt"], capture_output=True, text=True, timeout=120, cwd=str(root))
                    logs.append(proc.stdout[:500])
                    if proc.returncode != 0:
                        findings.append(make_finding(severity=Severity.HIGH, file="requirements.txt", line_start=0, title="pip install failed", description=proc.stderr[:500], finding_type="install_failed"))
                except Exception as exc:  # noqa: BLE001
                    _log.debug("pip install failed: %s", exc)
        # Go / Rust log only
        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data["install_logs"] = logs[:2]
        out = root / ".patchi" / "launcher" / "install.log"
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            out.write_text("\n".join(logs)[:8000], encoding="utf-8")
        except OSError:
            pass
