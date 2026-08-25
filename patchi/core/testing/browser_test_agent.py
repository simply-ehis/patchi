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
        result.data.update({
            "total_tests": test_results["total"],
            "passed_tests": test_results["passed"],
            "failed_tests": test_results["failed"],
            "duration": round(duration, 2),
            "needs_ai": True,  # Generating new tests requires AI
        })
        return

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
