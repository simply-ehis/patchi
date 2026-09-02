"""
BrowserTestAgent — Playwright tests for critical flows.

Runs Playwright tests for:
- Login flows
- Checkout processes
- Form submissions
- API calls through the UI
- Error states
- Navigation paths
- Responsive design checks

Can use existing Playwright tests or generate new ones based on the app contract.
Captures screenshots on failures and reports console/network errors.

Does NOT write to disk (unless creating new tests).
May call AI for generating new test scripts.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from pathlib import Path

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
)
from ..ai.client import call_ai
from ..ai.prompts import Skill, build_prompt, get_system_prompt

_log = logging.getLogger("patchi.testing.browser_test_agent")


@register
class BrowserTestAgent(BaseAgent):
    """Agent for running browser tests with Playwright."""

    group = AgentGroup.TEST
    name = "BrowserTestAgent"
    description = "Playwright tests for critical flows: login, checkout, forms, navigation"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run Playwright tests for critical user flows."""
        start_time = time.time()
        findings = []

        # Check if Playwright is available
        try:
            import playwright  # noqa: F401 — used to check availability
        except ImportError:
            findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file="__playwright__",
                    line_start=0,
                    title="Playwright not installed",
                    description="Playwright is required for browser tests. Install with: pip install playwright",
                    evidence="Playwright not found in environment",
                )
            )
            result.status = AgentStatus.SKIPPED
            result.findings = findings
            result.data.update({"playwright_available": False, "needs_ai": False})
            return

        # ── Live probe against a running app (opt-in) ─────────────────────────
        # Real navigation through the shared browser pool: captures console
        # errors, page crashes, 5xx responses and screenshots of failures.
        # Opt-in via extra["live_probe"]=True (web Live Tests tab sets it) so
        # plain test runs never launch a browser implicitly.
        base_url = (inp.extra or {}).get("base_url")
        wants_probe = bool((inp.extra or {}).get("live_probe"))
        if base_url and wants_probe:
            probe = self._live_probe(inp, base_url)
            if probe:
                result.data["live_probe"] = probe
                for pf in probe.get("findings", []):
                    findings.append(pf)

        # Check for existing Playwright tests
        existing_tests = self._find_existing_playwright_tests(inp.root)

        if existing_tests:
            # Run existing tests
            test_results = self._run_existing_tests(existing_tests, inp.root)
        else:
            # Check if we have an app contract to generate tests
            app_contract = self._get_app_contract(inp)
            if app_contract:
                # Generate new tests based on app contract
                generated_tests = self._generate_tests_from_contract(app_contract, inp.root)
                test_results = self._run_generated_tests(generated_tests, inp.root)
            else:
                findings.append(
                    make_finding(
                        severity=Severity.INFO,
                        file="__browser_tests__",
                        line_start=0,
                        title="No browser tests available",
                        description="No existing Playwright tests found and no app contract to generate tests",
                        evidence="Need either existing tests or confirmed app contract",
                    )
                )
                result.status = AgentStatus.SKIPPED
                result.findings = findings
                result.data.update({"tests_run": 0, "needs_ai": True})
                return

        # Process test results
        if test_results["success"]:
            findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file="__browser_summary__",
                    line_start=0,
                    title=f"Browser Tests Passed: {test_results['passed']}/{test_results['total']}",
                    description=f"Browser tests passed: {test_results['passed']}/{test_results['total']} tests",
                    evidence=f"Passed: {test_results['passed']}, Failed: {test_results['failed']}",
                )
            )
        else:
            findings.append(
                make_finding(
                    severity=Severity.HIGH,
                    file="__browser_summary__",
                    line_start=0,
                    title=f"Browser Tests Failed: {test_results['failed']}/{test_results['total']}",
                    description=f"Browser tests failed: {test_results['failed']}/{test_results['total']} tests",
                    evidence=f"Passed: {test_results['passed']}, Failed: {test_results['failed']}",
                )
            )

        # Add individual test results
        for test in test_results.get("test_details", []):
            if test.get("status") == "FAILED":
                findings.append(
                    make_finding(
                        severity=Severity.HIGH,
                        file=test.get("flow", "__unknown__"),
                        line_start=0,
                        title=f"Browser Test Failure: {test['name']}",
                        description=test.get("error", "Unknown error"),
                        evidence=f"Flow: {test['name']}\nError: {test.get('error', 'N/A')}\nScreenshot: {test.get('screenshot', 'N/A')}",
                    )
                )
            elif test.get("status") == "PASSED":
                findings.append(
                    make_finding(
                        severity=Severity.INFO,
                        file=test.get("flow", "__unknown__"),
                        line_start=0,
                        title=f"Browser Test Passed: {test['name']}",
                        description="Browser test passed successfully",
                        evidence=f"Flow: {test['name']}",
                    )
                )

        duration = time.time() - start_time

        result.status = AgentStatus.SUCCEEDED if test_results["success"] else AgentStatus.FAILED
        result.findings = findings
        result.data.update(
            {
                "total_tests": test_results["total"],
                "passed_tests": test_results["passed"],
                "failed_tests": test_results["failed"],
                "duration": round(duration, 2),
                "needs_ai": True,  # Generating new tests requires AI
            }
        )
        return

    # ── Live probe (shared browser pool) ──────────────────────────────────────

    def _live_probe(self, inp: AgentInput, base_url: str) -> dict | None:
        """Navigate the running app with a pooled browser.

        Collects per page: console errors, uncaught page errors, HTTP >= 500
        responses, and a screenshot whenever navigation or rendering fails.
        Findings are capped so one noisy app can't flood the report.
        """
        import asyncio

        try:
            return asyncio.run(self._probe_async(inp, base_url))
        except Exception as e:
            _log.warning("BrowserTestAgent live probe failed: %s", e)
            return None

    async def _probe_async(self, inp: AgentInput, base_url: str) -> dict:
        from .live_v2.browser_pool import get_browser_pool

        pool = await get_browser_pool()
        page = await pool.get_page()

        console_errors: list[dict] = []
        http_errors: list[dict] = []
        nav_failures: list[dict] = []
        screenshots: list[str] = []

        artifacts = inp.root / ".patchi" / "artifacts" / "browser"
        artifacts.mkdir(parents=True, exist_ok=True)

        def _on_console(msg):
            if msg.type == "error":
                console_errors.append({"page": page.url, "text": msg.text[:200]})

        def _on_pageerror(err):
            console_errors.append({"page": page.url, "text": f"pageerror: {err}"[:200]})

        def _on_response(resp):
            if resp.status >= 500:
                http_errors.append({"page": page.url, "status": resp.status, "url": resp.url[:200]})

        page.on("console", _on_console)
        page.on("pageerror", _on_pageerror)
        page.on("response", _on_response)

        urls = [base_url]
        for route in (inp.brain or {}).get("routes", [])[:6]:
            path = route.get("path") if isinstance(route, dict) else getattr(route, "path", "")
            method = (
                route.get("method") if isinstance(route, dict) else getattr(route, "method", "get")
            ) or "get"
            if (
                str(method).lower() in ("get", "")
                and path
                and not path.startswith(("api/", "/api"))
            ):
                urls.append(base_url.rstrip("/") + ("/" + path.lstrip("/")))
        seen = set()
        urls = [u for u in urls if not (u in seen or seen.add(u))][:5]

        findings_payload: list[dict] = []
        try:
            for url in urls:
                try:
                    await page.goto(url, wait_until="networkidle", timeout=15000)
                except Exception as e:
                    slug = "nav-failure"
                    shot = artifacts / f"{slug}-{len(screenshots)}.png"
                    try:
                        await page.screenshot(path=str(shot), full_page=False)
                        screenshots.append(shot.name)
                    except Exception as _exc:
                        _log.warning('_probe_async failed: %s', _exc)
                    nav_failures.append({"url": url, "error": str(e)[:160]})
                    continue
        finally:
            await pool.release_page(page)

        # Cap noise, convert to finding payloads (agent-level severity mapping)
        for ce in console_errors[:10]:
            findings_payload.append(
                {
                    "kind": "console_error",
                    "severity": "medium",
                    "page": ce["page"],
                    "detail": ce["text"],
                }
            )
        for he in http_errors[:10]:
            findings_payload.append(
                {
                    "kind": "http_5xx",
                    "severity": "high",
                    "page": he.get("page", ""),
                    "detail": f"{he['status']} on {he['url']}",
                }
            )
        for nf in nav_failures:
            findings_payload.append(
                {
                    "kind": "navigation_failure",
                    "severity": "high",
                    "page": nf["url"],
                    "detail": nf["error"],
                }
            )

        return {
            "base_url": base_url,
            "pages_probed": len(urls),
            "console_errors": len(console_errors),
            "http_errors": len(http_errors),
            "nav_failures": len(nav_failures),
            "screenshots": screenshots,
            "findings": findings_payload,
        }

    def _find_existing_playwright_tests(self, root: Path) -> list[Path]:
        """Find existing Playwright test files."""
        test_files = []

        # Look for common Playwright test locations
        playwright_patterns = [
            "tests/e2e/**/*.py",
            "tests/e2e/**/*.js",
            "tests/e2e/**/*.ts",
            "e2e/**/*.py",
            "e2e/**/*.js",
            "e2e/**/*.ts",
            "tests/playwright/**/*.py",
            "tests/playwright/**/*.js",
            "tests/playwright/**/*.ts",
            "**/playwright*.js",
            "**/playwright*.ts",
            "**/playwright*.py",
        ]

        for pattern in playwright_patterns:
            for test_file in root.rglob(pattern):
                if test_file.is_file():
                    test_files.append(test_file)

        return test_files

    def _get_app_contract(self, inp: AgentInput) -> list[dict] | None:
        """Get the app contract with critical flows."""
        try:
            from .. import memory as mem

            brain = mem.get_brain(inp.root)
            if brain and "confirmed_flows" in brain:
                return brain["confirmed_flows"]
            return None
        except Exception as e:
            _log.warning("BrowserTestAgent._get_app_contract failed: %s", e)
            return None

    def _generate_tests_from_contract(self, app_contract: list[dict], root: Path) -> list[Path]:
        """Generate Playwright tests based on the app contract using AI."""
        generated: list[Path] = []
        from .. import config as cfg

        config = cfg.load(root)
        if not config:
            return generated

        flows_text = "\n".join(
            f"- {f.get('name', '?')}: {f.get('description', '')}" for f in app_contract
        )

        system = get_system_prompt(Skill.TEST_GENERATE)
        user_prompt = build_prompt(
            Skill.TEST_GENERATE,
            {
                "file_path": "browser/critical_flows.py",
                "file_content": f"# App Contract Critical Flows\n{flows_text}",
                "existing_tests_section": "Generate Playwright (Python) end-to-end tests for each critical flow.",
                "language": "python",
            },
        )

        response = call_ai(config, system, user_prompt, max_tokens=4000)
        if not response:
            return generated

        import re

        blocks = re.findall(r"```(?:\w+)?\n(.*?)```", response, re.DOTALL)
        out_dir = root / ".patchi" / "tests" / "browser"
        out_dir.mkdir(parents=True, exist_ok=True)

        for i, block in enumerate(blocks):
            test_path = out_dir / f"generated_flow_{i}.py"
            test_path.write_text(block, encoding="utf-8")
            generated.append(test_path)

        return generated

    def _run_existing_tests(self, test_files: list[Path], root: Path) -> dict:
        """Run existing Playwright tests."""
        if not test_files:
            return {
                "success": True,
                "total": 0,
                "passed": 0,
                "failed": 0,
                "test_details": [],
            }

        try:
            # Try to run with pytest-playwright
            cmd = (
                [sys.executable, "-m", "pytest"]
                + [str(tf.relative_to(root)) for tf in test_files]
                + ["-v"]
            )
            result = subprocess.run(
                cmd, cwd=root, capture_output=True, text=True, timeout=300
            )  # 5 min timeout

            if result.returncode in [0, 1]:  # 0 = all passed, 1 = some failed
                return self._parse_pytest_playwright_output(result.stdout + result.stderr)
            else:
                return {
                    "success": False,
                    "error": f"Test execution failed: {result.stderr}",
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "test_details": [],
                }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Browser tests timed out after 300 seconds",
                "total": 0,
                "passed": 0,
                "failed": 0,
                "test_details": [],
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running existing tests: {str(e)}",
                "total": 0,
                "passed": 0,
                "failed": 0,
                "test_details": [],
            }

    def _run_generated_tests(self, test_files: list[Path], root: Path) -> dict:
        """Run generated Playwright tests."""
        if not test_files:
            return {"success": True, "total": 0, "passed": 0, "failed": 0, "test_details": []}
        try:
            import subprocess
            import sys

            targets = [str(tf.relative_to(root)) for tf in test_files]
            cmd = [sys.executable, "-m", "pytest"] + targets + ["-v", "--tb=short"]
            proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=300)
            output = f"{proc.stdout}\n{proc.stderr}"
            passed = failed = 0
            for line in output.splitlines():
                if "PASSED" in line:
                    passed += 1
                elif "FAILED" in line:
                    failed += 1
            return {
                "success": proc.returncode == 0,
                "total": passed + failed,
                "passed": passed,
                "failed": failed,
                "test_details": [],
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "total": 0, "passed": 0, "failed": 0, "error": "Timeout"}
        except Exception as e:
            return {"success": False, "total": 0, "passed": 0, "failed": 0, "error": str(e)}

    def _parse_pytest_playwright_output(self, output: str) -> dict:
        """Parse pytest output with Playwright tests."""
        lines = output.split("\n")
        total = 0
        passed = 0
        failed = 0
        test_details = []

        current_test = None
        in_failure_section = False

        for line in lines:
            if "PASSED" in line and "::" in line:
                # Example: "test_login.py::test_valid_login PASSED"
                test_name = line.split()[0]
                passed += 1
                test_details.append({"name": test_name, "status": "PASSED", "flow": test_name})
            elif "FAILED" in line and "::" in line:
                # Example: "test_login.py::test_invalid_login FAILED"
                test_name = line.split()[0]
                failed += 1
                in_failure_section = True
                current_test = test_name
                test_details.append(
                    {
                        "name": test_name,
                        "status": "FAILED",
                        "flow": test_name,
                        "error": "Test failed",
                    }
                )
            elif in_failure_section and line.strip().startswith("_"):
                in_failure_section = False
            elif in_failure_section and current_test:
                # Capture error details
                for detail in test_details:
                    if detail["name"] == current_test and detail["status"] == "FAILED":
                        if "error" in detail:
                            detail["error"] += f"\n{line.strip()}"
                        else:
                            detail["error"] = line.strip()

        total = passed + failed

        return {
            "success": failed == 0,
            "total": total or 1,  # Default to 1 if parsing failed
            "passed": passed,
            "failed": failed,
            "test_details": test_details,
        }
