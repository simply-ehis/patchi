"""
Live Test Runner v2 — Enhanced test orchestration with browser automation,
visual regression, stress testing, and video recording.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from patchi.core.agents.base import AgentGroup, AgentInput, AgentResult
from patchi.core.testing.live_test_runner import TestRunConfig, TestRunResult
from patchi.core.testing.live_v2.browser_pool import BrowserPool, BrowserConfig, get_browser_pool
from patchi.core.testing.live_v2.stress_orchestrator import StressOrchestrator, StressConfig, StressTestReport
from patchi.core.testing.live_v2.screenshot_manager import ScreenshotManager, ScreenshotConfig, VisualRegressionAgent
from patchi.core.testing.live_v2.video_recorder import VideoRecorder, RecordingConfig, TestRecording

_log = logging.getLogger("patchi.testing.live_test_runner_v2")


@dataclass
class LiveTestConfigV2:
    """Enhanced configuration for live test runs."""
    # Base config
    test_types: list[str] = field(default_factory=lambda: ["unit", "regression", "browser", "visual"])
    area: str | None = None
    base_url: str | None = None
    parallel: bool = False
    timeout_per_agent: int = 120

    # Browser config
    browser_config: BrowserConfig = field(default_factory=BrowserConfig)

    # Visual regression
    visual_threshold: float = 0.1
    update_baselines: bool = False

    # Stress testing
    stress_config: StressConfig | None = None

    # Video recording
    record_video: bool = False
    recording_config: RecordingConfig = field(default_factory=RecordingConfig)

    # Screenshot config
    screenshot_config: ScreenshotConfig = field(default_factory=ScreenshotConfig)


@dataclass
class LiveTestResultV2:
    """Enhanced test run result with live testing data."""
    # Base results
    base_result: TestRunResult

    # Live testing results
    browser_tests: list[dict] = field(default_factory=list)
    visual_regression: dict | None = None
    stress_test: StressTestReport | None = None
    recordings: list[TestRecording] = field(default_factory=list)
    screenshots: list[dict] = field(default_factory=list)

    # Summary
    live_test_summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        base = self.base_result.to_dict()
        base.update({
            "browser_tests": self.browser_tests,
            "visual_regression": self.visual_regression,
            "stress_test": self.stress_test.__dict__ if self.stress_test else None,
            "recordings": [r.__dict__ for r in self.recordings],
            "screenshots": self.screenshots,
            "live_test_summary": self.live_test_summary,
        })
        return base


class LiveTestRunnerV2:
    """
    Enhanced Live Test Runner with browser automation, visual regression,
    stress testing, and video recording.
    
    Usage:
        config = LiveTestConfigV2(
            test_types=["unit", "browser", "visual", "stress"],
            base_url="https://app.example.com",
            stress_config=StressConfig(base_url="https://api.example.com", users=50),
            record_video=True,
        )
        runner = LiveTestRunnerV2(project_root)
        result = await runner.run(config)
    """

    def __init__(
        self,
        root: Path,
        on_progress: Callable[[str], None] = None,
        on_event: Callable[[str, dict], None] = None,
    ):
        self.root = root
        self.on_progress = on_progress or (lambda _: None)
        self.on_event = on_event or (lambda e, d: None)

        # Components
        self.browser_pool: BrowserPool | None = None
        self.screenshot_manager: ScreenshotManager | None = None
        self.video_recorder: VideoRecorder | None = None

        # State
        self._run_id = ""
        self._start_time = 0
        self._config: LiveTestConfigV2 | None = None

    async def run(self, config: LiveTestConfigV2) -> LiveTestResultV2:
        """Run a complete live test suite."""
        self._run_id = f"live-{uuid.uuid4().hex[:8]}"
        self._start_time = time.time()
        self._config = config

        self.on_progress(f"🚀 Starting Live Test Run: {self._run_id}")
        self.on_event("test_run_started", {"run_id": self._run_id, "config": config.__dict__})

        # Initialize components
        await self._initialize_components(config)

        try:
            # Run base test agents
            base_result = await self._run_base_tests(config)

            # Run live tests
            browser_results = await self._run_browser_tests(config)
            visual_results = await self._run_visual_regression(config)
            stress_results = await self._run_stress_tests(config)

            # Capture screenshots
            screenshots = await self._capture_screenshots(config)

            # Build enhanced result
            result = LiveTestResultV2(
                base_result=base_result,
                browser_tests=browser_results,
                visual_regression=visual_results,
                stress_test=stress_results,
                recordings=[],  # Would be populated if video recording enabled
                screenshots=screenshots,
                live_test_summary=self._build_live_summary(
                    base_result, browser_results, visual_results, stress_results
                ),
            )

            return result

        finally:
            await self._cleanup_components()

    async def _initialize_components(self, config: LiveTestConfigV2):
        """Initialize browser pool, screenshot manager, video recorder."""
        self.on_progress("🔧 Initializing test components...")

        # Browser pool
        self.browser_pool = await get_browser_pool(config.browser_config)

        # Screenshot manager
        self.screenshot_manager = ScreenshotManager(
            baseline_dir=self.root / ".patchi" / "visual_baselines",
            threshold=config.visual_threshold,
            on_progress=self.on_progress,
        )

        # Video recorder (if enabled)
        if config.record_video:
            self.video_recorder = VideoRecorder(config.recording_config)

    async def _cleanup_components(self):
        """Clean up all components."""
        if self.video_recorder:
            await self.video_recorder.shutdown()

        # Browser pool is global, don't shutdown here
        # await shutdown_browser_pool()

    async def _run_base_tests(self, config: LiveTestConfigV2) -> TestRunResult:
        """Run base test agents (unit, regression, etc.)."""
        from patchi.core.testing.live_test_runner import LiveTestRunner

        base_config = TestRunConfig(
            test_types=[t for t in config.test_types if t not in ["browser", "visual", "stress"]],
            area=config.area,
            base_url=config.base_url,
            parallel=config.parallel,
            timeout_per_agent=config.timeout_per_agent,
            on_event=self.on_event,
        )

        base_runner = LiveTestRunner(self.root)
        return await base_runner.run(base_config)

    async def _run_browser_tests(self, config: LiveTestConfigV2) -> list[dict]:
        """Run browser automation tests."""
        if "browser" not in config.test_types or not config.base_url:
            return []

        self.on_progress("🌐 Running browser tests...")

        page = await self.browser_pool.get_page()
        results = []

        try:
            # Define browser test scenarios
            scenarios = self._get_browser_scenarios(config)

            for scenario in scenarios:
                self.on_progress(f"  ▶ {scenario['name']}")
                result = await self._run_browser_scenario(page, scenario, config)
                results.append(result)

                self.on_event("browser_test_completed", result)

        finally:
            await self.browser_pool.release_page(page)

        return results

    def _get_browser_scenarios(self, config: LiveTestConfigV2) -> list[dict]:
        """Get browser test scenarios based on config."""
        scenarios = [
            {
                "name": "Homepage Load",
                "url": config.base_url,
                "actions": [
                    {"action": "goto", "url": config.base_url},
                    {"action": "wait_for_load_state", "state": "networkidle"},
                    {"action": "assert_title", "contains": "Home"},
                ],
            },
        ]

        # Add more scenarios based on test_types
        if "e2e" in config.test_types:
            scenarios.append({
                "name": "User Login Flow",
                "url": f"{config.base_url}/login",
                "actions": [
                    {"action": "goto", "url": f"{config.base_url}/login"},
                    {"action": "fill", "selector": "#username", "value": "testuser"},
                    {"action": "fill", "selector": "#password", "value": "testpass"},
                    {"action": "click", "selector": "button[type=submit]"},
                    {"action": "wait_for_url", "url": "**/dashboard**"},
                    {"action": "assert_element", "selector": ".user-menu"},
                ],
            })

        return scenarios

    async def _run_browser_scenario(self, page: Any, scenario: dict, config: LiveTestConfigV2) -> dict:
        """Run a single browser test scenario."""
        start_time = time.time()
        result = {
            "name": scenario["name"],
            "url": scenario.get("url", config.base_url),
            "steps": [],
            "passed": True,
            "error": None,
            "duration_ms": 0,
            "screenshots": [],
        }

        try:
            for step in scenario.get("actions", []):
                step_result = await self._execute_browser_step(page, step)
                result["steps"].append(step_result)

                if not step_result.get("success", False):
                    result["passed"] = False
                    result["error"] = step_result.get("error")
                    break

            # Take final screenshot
            if config.screenshot_config:
                screenshot = await self.screenshot_manager.capture(
                    page,
                    scenario.get("url", config.base_url),
                    name=f"{scenario['name']}-final",
                    config=config.screenshot_config,
                )
                result["screenshots"].append({
                    "name": "final",
                    "base64": screenshot.image_base64[:100] + "...",  # Truncated for logging
                    "dimensions": screenshot.dimensions,
                })

        except Exception as e:
            result["passed"] = False
            result["error"] = str(e)
            _log.error(f"Browser scenario failed: {e}")

        result["duration_ms"] = int((time.time() - start_time) * 1000)
        return result

    async def _execute_browser_step(self, page: Any, step: dict) -> dict:
        """Execute a single browser test step."""
        action = step.get("action")
        step_result = {"action": action, "success": False}

        try:
            if action == "goto":
                await page.goto(step["url"], wait_until="networkidle")
                step_result["success"] = True

            elif action == "click":
                await page.click(step["selector"])
                step_result["success"] = True

            elif action == "fill":
                await page.fill(step["selector"], step["value"])
                step_result["success"] = True

            elif action == "wait_for_load_state":
                await page.wait_for_load_state(step.get("state", "networkidle"))
                step_result["success"] = True

            elif action == "wait_for_selector":
                await page.wait_for_selector(step["selector"], timeout=step.get("timeout", 10000))
                step_result["success"] = True

            elif action == "wait_for_url":
                await page.wait_for_url(step["url"], timeout=step.get("timeout", 10000))
                step_result["success"] = True

            elif action == "assert_title":
                title = await page.title()
                step_result["success"] = step["contains"] in title
                step_result["actual_title"] = title

            elif action == "assert_element":
                element = await page.query_selector(step["selector"])
                step_result["success"] = element is not None
                step_result["element_found"] = element is not None

            elif action == "assert_text":
                element = await page.query_selector(step["selector"])
                if element:
                    text = await element.text_content()
                    step_result["success"] = step["contains"] in text
                    step_result["actual_text"] = text
                else:
                    step_result["success"] = False

            elif action == "screenshot":
                screenshot = await self.screenshot_manager.capture(
                    page, page.url, name=step.get("name", "step"),
                    config=self._config.screenshot_config if self._config else None
                )
                step_result["success"] = True
                step_result["screenshot"] = screenshot.image_base64[:100] + "..."

            else:
                step_result["error"] = f"Unknown action: {action}"

        except Exception as e:
            step_result["error"] = str(e)

        return step_result

    async def _run_visual_regression(self, config: LiveTestConfigV2) -> dict | None:
        """Run visual regression tests."""
        if "visual" not in config.test_types or not config.base_url:
            return None

        self.on_progress("👁️ Running visual regression tests...")

        agent = VisualRegressionAgent(self.root, {
            "visual_threshold": config.visual_threshold,
        })

        # Define URLs to test
        urls = [
            config.base_url,
            f"{config.base_url}/login",
            f"{config.base_url}/dashboard",
        ]

        try:
            result = await agent.run(
                urls=urls,
                base_url=config.base_url,
                update_baselines=config.update_baselines,
            )

            self.on_progress(f"  Visual regression: {result['passed']} passed, {result['failed']} failed")
            self.on_event("visual_regression_completed", result)

            return result
        except Exception as e:
            _log.error(f"Visual regression failed: {e}")
            return {"error": str(e)}

    async def _run_stress_tests(self, config: LiveTestConfigV2) -> StressTestReport | None:
        """Run stress/load tests."""
        if "stress" not in config.test_types or not config.stress_config:
            return None

        self.on_progress("⚡ Running stress tests...")

        try:
            orchestrator = StressOrchestrator(config.stress_config, on_progress=self.on_progress)
            report = await orchestrator.run()

            self.on_progress(f"  Stress test: {report.requests_per_second:.1f} req/s, P95: {report.latency.get('p95', 0):.0f}ms")
            self.on_event("stress_test_completed", report.__dict__)

            return report
        except Exception as e:
            _log.error(f"Stress test failed: {e}")
            return None

    async def _capture_screenshots(self, config: LiveTestConfigV2) -> list[dict]:
        """Capture screenshots for key pages."""
        if not config.base_url:
            return []

        page = await self.browser_pool.get_page()
        screenshots = []

        try:
            urls = [
                config.base_url,
                f"{config.base_url}/login",
                f"{config.base_url}/dashboard",
            ]

            for url in urls:
                try:
                    result = await self.screenshot_manager.capture(
                        page, url, config=config.screenshot_config
                    )
                    screenshots.append({
                        "url": url,
                        "dimensions": result.dimensions,
                        "timestamp": result.timestamp,
                        "base64_preview": result.image_base64[:100] + "...",
                    })
                except Exception as e:
                    _log.warning(f"Screenshot failed for {url}: {e}")
                    screenshots.append({"url": url, "error": str(e)})

        finally:
            await self.browser_pool.release_page(page)

        return screenshots

    def _build_live_summary(
        self,
        base_result: TestRunResult,
        browser_tests: list[dict],
        visual_results: dict | None,
        stress_results: StressTestReport | None,
    ) -> dict:
        """Build live testing summary."""
        browser_passed = sum(1 for t in browser_tests if t.get("passed"))
        browser_total = len(browser_tests)

        visual_passed = visual_results.get("passed", 0) if visual_results else 0
        visual_total = visual_results.get("total", 0) if visual_results else 0

        return {
            "base_tests": {
                "total_agents": len(base_result.results),
                "total_findings": base_result.total_findings,
                "passed": base_result.total_passed,
                "failed": base_result.total_failed,
            },
            "browser_tests": {
                "total": browser_total,
                "passed": browser_passed,
                "failed": browser_total - browser_passed,
            },
            "visual_regression": {
                "total": visual_total,
                "passed": visual_passed,
                "failed": visual_total - visual_passed,
            },
            "stress_test": {
                "completed": stress_results is not None,
                "requests_per_second": stress_results.requests_per_second if stress_results else 0,
                "latency_p95_ms": stress_results.latency.get("p95", 0) if stress_results else 0,
                "error_rate": stress_results.failed_requests / stress_results.total_requests if stress_results and stress_results.total_requests > 0 else 0,
            },
            "overall_duration_ms": int((time.time() - self._start_time) * 1000),
        }


# Convenience function
async def run_live_tests_v2(
    root: Path,
    config: LiveTestConfigV2,
    on_progress: Callable[[str], None] = None,
) -> LiveTestResultV2:
    """Run enhanced live tests."""
    runner = LiveTestRunnerV2(root, on_progress=on_progress)
    return await runner.run(config)


# Agent wrapper for integration
from patchi.core.agents.base import BaseAgent, register, Finding, Severity


@register
class LiveTestRunnerV2Agent(BaseAgent):
    """Live Test Runner v2 as a Patchi agent."""

    name = "LiveTestRunnerV2Agent"
    group = AgentGroup.TEST
    timeout = 600

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Get config from extra
        config_data = inp.extra.get("live_test_config", {})

        config = LiveTestConfigV2(
            test_types=config_data.get("test_types", ["unit", "regression"]),
            area=inp.scope[0] if inp.scope else None,
            base_url=config_data.get("base_url"),
            parallel=config_data.get("parallel", False),
        )

        # Parse stress config if present
        if "stress" in config.test_types and config_data.get("stress_config"):
            sc = config_data["stress_config"]
            config.stress_config = StressConfig(
                base_url=sc.get("base_url", config.base_url),
                scenario=sc.get("scenario", "load"),
                users=sc.get("users", 10),
                duration_seconds=sc.get("duration_seconds", 60),
            )

        async def run():
            runner = LiveTestRunnerV2(inp.root, on_progress=lambda m: result.add_log(m))
            return await runner.run(config)

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        test_result = loop.run_until_complete(run())

        # Add findings from base result
        for agent_result in test_result.base_result.results:
            for finding in agent_result.findings:
                result.add_finding(finding)

        # Add live test findings
        if test_result.visual_regression and test_result.visual_regression.get("failed", 0) > 0:
            for diff in test_result.visual_regression.get("diffs", []):
                if not diff.get("passed", True):
                    result.add_finding(Finding(
                        agent="LiveTestRunnerV2Agent",
                        type="visual_regression",
                        severity=Severity.MEDIUM,
                        file="",
                        line=0,
                        message=f"Visual regression detected: {diff.get('difference_percent', 0):.1f}% difference",
                        detail="Baseline comparison failed for visual test",
                    ))

        if test_result.stress_test and test_result.stress_test.failed_requests > 0:
            result.add_finding(Finding(
                agent="LiveTestRunnerV2Agent",
                type="stress_test_failure",
                severity=Severity.HIGH,
                file="",
                line=0,
                message=f"Stress test failures: {test_result.stress_test.failed_requests}/{test_result.stress_test.total_requests} requests failed",
                detail=f"Error rate: {test_result.stress_test.failed_requests / test_result.stress_test.total_requests * 100:.1f}%",
            ))

        result.data["live_test_result"] = test_result.to_dict()
