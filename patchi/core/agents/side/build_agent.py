"""BuildAgent §p check — npm run build / tsc --noEmit / cargo check."""

from __future__ import annotations

import logging
import shutil
import subprocess

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
)

_log = logging.getLogger("patchi.agents.side.build")

@register
class BuildAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "BuildAgent"
    description = "Build check before app run"
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root
        findings = []
        cmds = []
        if (root / "package.json").exists():
            try:
                import json

                pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
                if "build" in pkg.get("scripts", {}):
                    cmds.append((["npm", "run", "build"], "package.json"))
                if (root / "tsconfig.json").exists() and shutil.which("npx"):
                    cmds.append((["npx", "tsc", "--noEmit"], "tsconfig.json"))
            except Exception as exc:  # noqa: BLE001
                _log.debug("build pkg read failed: %s", exc)
        if (root / "Cargo.toml").exists() and shutil.which("cargo"):
            cmds.append((["cargo", "check"], "Cargo.toml"))
        for cmd, file in cmds:
            if not shutil.which(cmd[0]):
                continue
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=str(root))
                if proc.returncode != 0:
                    findings.append(make_finding(severity=Severity.HIGH, file=file, line_start=0, title=f"Build failed: {' '.join(cmd)}", description=(proc.stdout + proc.stderr)[:600], finding_type="build_failed"))
            except Exception as exc:  # noqa: BLE001
                _log.debug("build %s failed: %s", cmd, exc)
        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
