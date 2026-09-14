"""
LiveTestRunner — Orchestrates all test agents and streams results live.

Manages the full test lifecycle:
1. Discovers which agents to run based on test type
2. Executes agents sequentially (or parallel for independent ones)
3. Streams real-time results via WebSocket events
4. Generates summary report
5. Saves results to memory for historical tracking

This is the bridge between the CLI test command, web UI, and test agents.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..agents.base import AgentGroup, AgentInput, AgentResult, AgentStatus

_log = logging.getLogger("patchi.testing.live_test_runner")


@dataclass
class TestRunConfig:
    """Configuration for a test run."""

    test_types: list[str] = field(default_factory=lambda: ["unit", "regression"])
    area: str | None = None
    base_url: str | None = None
    parallel: bool = False
    timeout_per_agent: int = 120
    on_event: Callable | None = None  # async callback for live streaming


@dataclass
class TestRunResult:
    """Aggregated result of a full test run."""

    started_at: float = 0
    completed_at: float = 0
    total_duration_ms: int = 0
    agents_run: list[str] = field(default_factory=list)
    results: list[AgentResult] = field(default_factory=list)
    total_findings: int = 0
    total_passed: int = 0
    total_failed: int = 0
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_duration_ms": self.total_duration_ms,
            "agents_run": self.agents_run,
            "total_findings": self.total_findings,
            "total_passed": self.total_passed,
            "total_failed": self.total_failed,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }


# Map of test type names to agent class names
TEST_TYPE_MAP = {
    "unit": ["UnitTestAgent"],
    "regression": ["RegressionAgent"],
    "browser": ["BrowserTestAgent"],
    "stress": ["StressTestAgent"],
    "accessibility": ["UIAccessibilityAgent"],
    "api": ["APIContractAgent"],
    "buttons": ["UIButtonAgent"],
    "layout": ["UILayoutAgent"],
    "e2e": ["E2EFlowAgent"],
    "visual": ["VisualRegressionAgent"],
    "smoke": ["UIButtonAgent", "UILayoutAgent", "UIAccessibilityAgent"],
    "full": [
        "UnitTestAgent",
        "RegressionAgent",
        "UIButtonAgent",
        "UIAccessibilityAgent",
        "UILayoutAgent",
        "E2EFlowAgent",
        "VisualRegressionAgent",
    ],
}


class LiveTestRunner:
    """Orchestrates test execution and streams live results."""

    def __init__(self, root: Path):
        self.root = root
        self._event_queue: asyncio.Queue | None = None
        self._event_callback: Callable | None = None

    async def run(self, config: TestRunConfig) -> TestRunResult:
        """Execute a full test run with live event streaming."""
        # Import test agents to trigger registration
        import patchi.core.testing.test_agents  # noqa
        import patchi.core.testing.ui_button_agent  # noqa
        import patchi.core.testing.ui_accessibility_agent  # noqa
        import patchi.core.testing.ui_layout_agent  # noqa
        import patchi.core.testing.e2e_flow_agent  # noqa
        import patchi.core.testing.visual_regression_agent  # noqa

        from ..agents.base import get_agent

        result = TestRunResult(started_at=time.time())

        # Resolve which agents to run
        agent_names = self._resolve_agents(config.test_types)
        result.agents_run = agent_names

        # Load brain and config
        from .. import config as cfg
        from .. import memory as mem

        brain = mem.get_brain(self.root)
        try:
            app_config = cfg.load(self.root)
        except Exception as e:
            _log.warning("LiveTestRunner.run failed: %s", e)
            app_config = {}

        # Determine scope
        scope = []
        if config.area:
            area_path = self.root / config.area
            if area_path.is_dir():
                scope = [str(p.relative_to(self.root)) for p in area_path.rglob("*.py")]

        # Fire start event
        await self._emit(
            "test_run_started",
            {
                "agents": agent_names,
                "test_types": config.test_types,
                "area": config.area,
            },
        )

        # Run agents
        for agent_name in agent_names:
            agent_cls = get_agent(agent_name)
            if not agent_cls:
                continue

            await self._emit(
                "agent_started",
                {
                    "agent": agent_name,
                    "description": agent_cls.description if hasattr(agent_cls, "description") else "",
                },
            )

            t0 = time.monotonic()
            try:
                inp = AgentInput(
                    root=self.root,
                    scope=scope,
                    brain=brain,
                    config=app_config,
                    extra={"base_url": config.base_url} if config.base_url else {},
                )
                agent = agent_cls()
                agent_result = await asyncio.to_thread(agent.run, inp)
            except Exception as e:
                agent_result = AgentResult(
                    agent_name=agent_name,
                    agent_group=AgentGroup.TEST,
                    status=AgentStatus.FAILED,
                )
                agent_result.add_error(str(e))

            agent_result.duration_ms = int((time.monotonic() - t0) * 1000)
            result.results.append(agent_result)

            # Count findings
            result.total_findings += agent_result.finding_count

            # Count passed/failed from suite data
            suite = agent_result.data.get("suite", {})
            result.total_passed += suite.get("passed", 0)
            result.total_failed += suite.get("failed", 0)

            # Fire agent done event
            await self._emit(
                "agent_done",
                {
                    "agent": agent_name,
                    "status": agent_result.status.value,
                    "finding_count": agent_result.finding_count,
                    "duration_ms": agent_result.duration_ms,
                    "passed": suite.get("passed", 0),
                    "failed": suite.get("failed", 0),
                },
            )

            # Fire individual findings
            for finding in agent_result.findings:
                await self._emit(
                    "agent_finding",
                    {
                        "agent": agent_name,
                        "severity": finding.severity.value,
                        "type": finding.type,
                        "message": finding.message,
                        "file": finding.file,
                    },
                )

        result.completed_at = time.time()
        result.total_duration_ms = int((result.completed_at - result.started_at) * 1000)

        # Build summary
        result.summary = self._build_summary(result)

        # Fire completion event
        await self._emit("test_run_completed", result.summary)

        # Save to memory
        self._save_results(result)

        return result

    def _resolve_agents(self, test_types: list[str]) -> list[str]:
        """Resolve test type names to agent class names."""
        agents = []
        for t in test_types:
            t_lower = t.lower()
            if t_lower in TEST_TYPE_MAP:
                agents.extend(TEST_TYPE_MAP[t_lower])
            else:
                # Try direct agent name
                from ..agents.base import get_agent

                if get_agent(t):
                    agents.append(t)
        return list(dict.fromkeys(agents))  # dedupe preserving order

    def _build_summary(self, result: TestRunResult) -> dict:
        """Build a summary of the test run."""
        by_status = {}
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for r in result.results:
            status = r.status.value
            by_status[status] = by_status.get(status, 0) + 1
            for f in r.findings:
                sev = f.severity.value
                by_severity[sev] = by_severity.get(sev, 0) + 1

        all_passed = by_status.get("failed", 0) == 0 and by_status.get("skipped", 0) == 0

        return {
            "total_agents": len(result.results),
            "by_status": by_status,
            "by_severity": by_severity,
            "total_findings": result.total_findings,
            "total_passed": result.total_passed,
            "total_failed": result.total_failed,
            "all_passed": all_passed,
            "duration_ms": result.total_duration_ms,
        }

    def _save_results(self, result: TestRunResult) -> None:
        """Save test results to memory for historical tracking."""
        try:
            from .. import memory as mem

            scan_data = {
                "status": "done" if result.summary.get("all_passed") else "failed",
                "duration_ms": result.total_duration_ms,
                "finding_count": result.total_findings,
                "passed": result.total_passed,
                "failed": result.total_failed,
                "agents": result.agents_run,
                "summary": result.summary,
            }
            mem.save_scan_result("TestRunner", scan_data, self.root)
        except Exception as e:
            _log.warning("LiveTestRunner._save_results failed: %s", e)

    async def _emit(self, event: str, data: dict) -> None:
        """Emit a live event for WebSocket streaming."""
        if self._event_queue:
            await self._event_queue.put({"event": event, "data": data, "ts": time.time()})

        if self._event_callback:
            try:
                await self._event_callback(event, data)
            except Exception as e:
                _log.debug("LiveTestRunner._emit failed: %s", e)

    def set_event_callback(self, callback: Callable) -> None:
        """Set an async callback for live event streaming."""
        self._event_callback = callback
