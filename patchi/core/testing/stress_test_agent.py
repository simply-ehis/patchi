"""
StressTestAgent — Load testing via StressOrchestrator.

Thin wrapper around StressOrchestrator that runs as a registered BaseAgent.
Supports load, spike, soak, and breakpoint testing scenarios.

Uses aiohttp for async HTTP requests (no external binary needed).
"""

from __future__ import annotations

import asyncio
import logging

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
)
from ..testing.live_v2.stress_orchestrator import (
    StressConfig,
    StressOrchestrator,
    StressTestReport,
)

_log = logging.getLogger("patchi.testing.stress_test_agent")


@register
class StressTestAgent(BaseAgent):
    """Load/stress testing agent using StressOrchestrator."""

    group = AgentGroup.TEST
    domain = AgentDomain.TESTING
    name = "StressTestAgent"
    description = "Stress testing: load, spike, soak, breakpoint scenarios via async HTTP"
    timeout = 600  # 10 minutes max for stress tests

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        target_url = self._detect_target(inp)
        if not target_url:
            self.skip(result, "No running web application detected. Start the web server first.")
            return

        _log.info("StressTestAgent: Testing %s with StressOrchestrator", target_url)

        # Get scenario from config (default: load)
        scenario = inp.config.get("stress_scenario", "load")
        users = inp.config.get("stress_users", 10)
        duration = inp.config.get("stress_duration", 60)

        # Build endpoints from route map
        route_map = inp.brain.get("route_map", {})
        endpoints = []
        for k, v in route_map.items():
            if isinstance(v, dict):
                path = v.get("path", k.split(" ", 1)[-1])
                endpoints.append({"method": "GET", "path": path})
        if not endpoints:
            endpoints = [{"method": "GET", "path": "/"}]

        # Run stress test
        try:
            report = asyncio.run(self._run_stress(target_url, scenario, users, duration, endpoints))
            self._process_report(report, result)
        except Exception as e:
            _log.error("StressTestAgent failed: %s", e)
            result.add_error(f"Stress test failed: {e}")
            result.status = AgentStatus.FAILED

    async def _run_stress(
        self,
        target_url: str,
        scenario: str,
        users: int,
        duration: int,
        endpoints: list[dict],
    ) -> StressTestReport:
        """Run the stress test via StressOrchestrator."""
        config = StressConfig(
            base_url=target_url,
            scenario=scenario,
            users=users,
            duration_seconds=duration,
            endpoints=endpoints,
        )
        orchestrator = StressOrchestrator(config)
        return await orchestrator.run()

    def _process_report(self, report: StressTestReport, result: AgentResult) -> None:
        """Process StressTestReport into AgentResult findings."""
        result.data["report"] = report.to_dict()
        result.data["scenario"] = report.config.scenario
        result.data["users"] = report.config.users
        result.data["duration_seconds"] = report.config.duration_seconds

        # Add latency findings
        latency = report.latency
        if latency:
            p95 = latency.get("p95", 0)
            p99 = latency.get("p99", 0)

            if p95 > 2000:
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="slow_p95",
                        severity=Severity.MEDIUM,
                        file="stress_test",
                        message=f"Slow p95 latency under load: {p95:.0f}ms",
                    )
                )
            if p99 > 5000:
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="slow_p99",
                        severity=Severity.HIGH,
                        file="stress_test",
                        message=f"Slow p99 latency under load: {p99:.0f}ms",
                    )
                )

        # Add error rate findings
        if report.total_requests > 0:
            error_rate = report.failed_requests / report.total_requests
            if error_rate > 0.05:  # 5%
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="high_error_rate",
                        severity=Severity.HIGH,
                        file="stress_test",
                        message=f"High load-test error rate: {error_rate:.1%}",
                    )
                )

        # Add breakpoint findings
        if report.breakpoint_found:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="breakpoint_found",
                    severity=Severity.HIGH,
                    file="stress_test",
                    message=f"Breakpoint found at {report.breakpoint_users} users",
                )
            )

        # Add soak stability findings
        if not report.soak_stability:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="soak_instability",
                    severity=Severity.MEDIUM,
                    file="stress_test",
                    message="System instability detected during soak test",
                )
            )

        result.status = AgentStatus.DONE
        result.files_scanned = 1

    def _detect_target(self, inp: AgentInput) -> str | None:
        """Detect the target URL for testing."""
        import socket

        # Check for explicit base_url in config
        if inp.config.get("base_url"):
            return inp.config["base_url"]

        # Try common ports
        ports = [1612, 8000, 3000, 8080, 80]

        for port in ports:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return f"http://127.0.0.1:{port}"
            except (ConnectionRefusedError, OSError):
                continue

        # Check config for web port
        try:
            from patchi.core import config as cfg

            config = cfg.load(inp.root)
            web_config = config.get("web", {})
            host = web_config.get("host", "127.0.0.1")
            port = web_config.get("port", 1612)
            return f"http://{host}:{port}"
        except Exception as _exc:
            _log.warning("_detect_target failed: %s", _exc)

        return None
