"""
RunAgent — starts the target app after P-Check green, for Test/Attack.

Chain: Check (Install/Build/Format) → green READY_TO_SERVE → Run (AppLauncher) → Test/Attack
Test/Attack agents rely on Run, Run relies on Check.

This agent is always run anytime a Test or Attack agent is queued.
"""

from __future__ import annotations

import logging

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

_log = logging.getLogger("patchi.agents.run")


@register
class RunAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "RunAgent"
    description = "Run — start app on free port after P-Check green (test/attack dependency)"
    timeout = 90

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Gate: Check must be green
        try:
            from patchi.core.testing.gate import require_ready

            ready, url, st = require_ready(inp.root)
            if not ready:
                from patchi.core.testing.gate import gate_message

                msg = gate_message(st)
                result.status = AgentStatus.SKIPPED
                result.data["gate_blocked"] = True
                result.data["gate_reason"] = msg
                result.add_finding(
                    make_finding(
                        severity=Severity.INFO,
                        file="",
                        line_start=0,
                        title="Run skipped — P-Check not READY_TO_SERVE",
                        description=msg,
                        finding_type="run_gate_blocked",
                    )
                )
                return
        except Exception as exc:  # noqa: BLE001
            _log.debug("run gate check failed: %s", exc)

        # Start app
        try:
            from patchi.core.testing.app_launcher import ensure_running

            # Reuse if already running
            url = ensure_running(inp.root, inp.config, inp.extra)
            if url:
                result.status = AgentStatus.SUCCEEDED
                result.data["base_url"] = url
                result.data["url"] = url
                result.add_finding(
                    make_finding(
                        severity=Severity.INFO,
                        file="",
                        line_start=0,
                        title=f"App running at {url}",
                        description=f"RunAgent started target app at {url} (P-Check was green)",
                        finding_type="app_running",
                    )
                )
            else:
                result.status = AgentStatus.FAILED
                result.add_finding(
                    make_finding(
                        severity=Severity.HIGH,
                        file="",
                        line_start=0,
                        title="Run failed — could not start app",
                        description="AppLauncher ensure_running returned None — check .patchi/launcher/app.log and start command",
                        finding_type="run_failed",
                    )
                )
        except Exception as exc:  # noqa: BLE001
            _log.warning("RunAgent failed: %s", exc)
            result.status = AgentStatus.FAILED
            result.add_finding(
                make_finding(
                    severity=Severity.HIGH,
                    file="",
                    line_start=0,
                    title="Run exception",
                    description=str(exc)[:300],
                    finding_type="run_exception",
                )
            )
