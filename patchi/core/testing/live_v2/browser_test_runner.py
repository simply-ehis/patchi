"""
Browser Test Runner — Executes browser automation tests using BrowserPool.

Features:
- Parallel test execution across browser pool
- Screenshot capture at each step
- Video recording for full test sessions
- Visual regression detection
- Real-time progress reporting
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from patchi.core.agents.base import Finding, Severity
from patchi.core.testing.live_v2.browser_pool import BrowserPool, BrowserConfig, get_browser_pool
from patchi.core.testing.live_v2.screenshot_manager import ScreenshotManager, ScreenshotConfig

_log = logging.getLogger("patchi.testing.browser_runner")


@dataclass
class TestStep:
    """A single step in a browser test."""
    action: str  # navigate, click, fill, screenshot, assert
    target: str = ""  # URL, selector, or assertion
    value: str = ""  # input value for fill
    description: str = ""
    screenshot: bool = False  # capture screenshot after this step


@dataclass
class TestResult:
    """Result of a single test."""
    name: str
    passed: bool
    steps_completed: int = 0
    steps_total: int = 0
    duration_ms: int = 0
    screenshots: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class TestSuiteResult:
    """Result of a full test suite run."""
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    duration_ms: int = 0
    screenshots_dir: str = ""
    results: list[TestResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "duration_ms": self.duration_ms,
            "screenshots_dir": self.screenshots_dir,
            "findings": [f.to_dict() for f in self.findings],
        }


class BrowserTestRunner:
    """Runs browser automation tests using BrowserPool."""

    def __init__(
        self,
        root: Path,
        base_url: str = "http://127.0.0.1:1612",
        on_progress: Callable[[str], None] = None,
    ):
        self.root = root
        self.base_url = base_url
        self.on_progress = on_progress or (lambda _: None)
        self._evidence_dir = root / ".patchi" / "evidence" / "browser_tests"
        self._evidence_dir.mkdir(parents=True, exist_ok=True)

    async def run_test(
        self,
        name: str,
        steps: list[TestStep],
        browser_pool: BrowserPool | None = None,
    ) -> TestResult:
        """Run a single browser test with multiple steps."""
        start = time.monotonic()
        result = TestResult(
            name=name,
            passed=True,
            steps_total=len(steps),
        )
        screenshot_mgr = ScreenshotManager(self._evidence_dir)

        pool = browser_pool or await get_browser_pool()
        page = None

        try:
            page = await pool.get_page()
            self.on_progress(f"🧪 Running test: {name}")

            for i, step in enumerate(steps):
                try:
                    await self._execute_step(page, step, screenshot_mgr, result)
                    result.steps_completed = i + 1
                except Exception as e:
                    result.passed = False
                    result.errors.append(f"Step {i+1} ({step.action}): {e}")
                    _log.warning("Test step failed: %s", e)
                    # Capture error screenshot
                    try:
                        ss_path = await screenshot_mgr.capture(
                            page, f"{name}_error_step{i+1}"
                        )
                        if ss_path:
                            result.screenshots.append(str(ss_path))
                    except Exception:
                        pass
                    break

        except Exception as e:
            result.passed = False
            result.errors.append(f"Test setup failed: {e}")
        finally:
            if page and browser_pool is None:
                await pool.release_page(page)

        result.duration_ms = int((time.monotonic() - start) * 1000)
        self.on_progress(
            f"{'✅' if result.passed else '❌'} {name}: "
            f"{result.steps_completed}/{result.steps_total} steps "
            f"({result.duration_ms}ms)"
        )
        return result

    async def _execute_step(
        self,
        page: Any,
        step: TestStep,
        screenshot_mgr: ScreenshotManager,
        result: TestResult,
    ) -> None:
        """Execute a single test step."""
        if step.action == "navigate":
            url = step.target if step.target.startswith("http") else f"{self.base_url}{step.target}"
            await page.goto(url, wait_until="domcontentloaded")
            self.on_progress(f"  📍 Navigated to {url}")

        elif step.action == "click":
            await page.click(step.target)
            self.on_progress(f"  🖱️ Clicked {step.target}")

        elif step.action == "fill":
            await page.fill(step.target, step.value)
            self.on_progress(f"  ✏️ Filled {step.target}")

        elif step.action == "screenshot" or step.screenshot:
            label = step.description or f"step_{result.steps_completed + 1}"
            ss_path = await screenshot_mgr.capture(page, label)
            if ss_path:
                result.screenshots.append(str(ss_path))
                self.on_progress(f"  📸 Screenshot: {label}")

        elif step.action == "assert_text":
            text = await page.text_content(step.target)
            if step.value not in (text or ""):
                raise AssertionError(
                    f"Expected '{step.value}' in text, got: '{(text or '')[:100]}'"
                )
            self.on_progress(f"  ✅ Assert text passed")

        elif step.action == "assert_visible":
            visible = await page.is_visible(step.target)
            if not visible:
                raise AssertionError(f"Element {step.target} not visible")
            self.on_progress(f"  ✅ Assert visible passed")

        elif step.action == "wait":
            timeout = int(step.value) if step.value else 1000
            await page.wait_for_timeout(timeout)

    async def run_suite(
        self,
        tests: list[tuple[str, list[TestStep]]],
        max_parallel: int = 3,
    ) -> TestSuiteResult:
        """Run a suite of browser tests in parallel."""
        start = time.monotonic()
        suite = TestSuiteResult(
            total_tests=len(tests),
            screenshots_dir=str(self._evidence_dir),
        )

        pool = await get_browser_pool(BrowserConfig(max_browsers=max_parallel))

        try:
            # Run tests in parallel with semaphore
            sem = asyncio.Semaphore(max_parallel)

            async def run_one(name: str, steps: list[TestStep]) -> TestResult:
                async with sem:
                    return await self.run_test(name, steps, pool)

            tasks = [run_one(name, steps) for name, steps in tests]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, Exception):
                    suite.failed += 1
                    suite.results.append(TestResult(
                        name="unknown", passed=False, errors=[str(r)]
                    ))
                else:
                    if r.passed:
                        suite.passed += 1
                    else:
                        suite.failed += 1
                    suite.results.append(r)
                    suite.findings.extend(r.findings)

        finally:
            await pool.shutdown()

        suite.duration_ms = int((time.monotonic() - start) * 1000)
        self.on_progress(
            f"🏁 Test suite: {suite.passed}/{suite.total_tests} passed "
            f"({suite.duration_ms}ms)"
        )
        return suite

    async def run_smoke_test(self, url: str = None) -> TestSuiteResult:
        """Run a quick smoke test against the app."""
        target = url or self.base_url
        steps = [
            TestStep("navigate", target, description="Load homepage"),
            TestStep("assert_visible", "body", description="Page body visible"),
            TestStep("screenshot", description="Homepage screenshot"),
            TestStep("navigate", f"{target}/api/health", description="Health endpoint"),
            TestStep("screenshot", description="Health endpoint screenshot"),
        ]
        return await self.run_suite([("smoke_test", steps)])

    async def run_accessibility_check(self, url: str = None) -> TestSuiteResult:
        """Run basic accessibility checks."""
        target = url or self.base_url
        steps = [
            TestStep("navigate", target, description="Load page"),
            TestStep("assert_visible", "html[lang]", description="Has lang attribute"),
            TestStep("assert_visible", "title", description="Has title element"),
            TestStep("assert_visible", "main, [role=main]", description="Has main landmark"),
            TestStep("screenshot", description="Accessibility snapshot"),
        ]
        return await self.run_suite([("accessibility_check", steps)])
