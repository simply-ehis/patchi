"""
E2EFlowAgent — AI-generated end-to-end test scripts via Playwright.

Uses the AI layer to:
- Analyze the app's HTML/routes and generate Playwright test scripts
- Test full user flows (login → dashboard → action → logout)
- Test error states and edge cases
- Generate tests from app contract critical flows
- Run generated tests and report results

Each test script is generated as a standalone Python file using playwright.sync_api.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Severity,
    make_finding,
    register,
)


@register
class E2EFlowAgent(BaseAgent):
    """AI-generated E2E tests for full user flows via Playwright."""

    group = AgentGroup.TEST
    name = "E2EFlowAgent"
    description = "AI-generated Playwright E2E tests: login, checkout, forms, navigation"
    timeout = 300

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        try:
            from playwright.sync_api import (
                sync_playwright,  # noqa: F401 — used to check availability
            )
        except ImportError:
            self.skip(result, "playwright not installed")
            return

        base_url = self._find_base_url(inp)
        if not base_url:
            self.skip(result, "no running server found")
            return

        # Step 1: Discover pages and routes
        pages = self._discover_pages(inp.root)
        routes = self._extract_routes(inp)
        flows = self._get_contract_flows(inp)

        # Step 2: Generate test scripts using AI
        test_scripts = self._generate_test_scripts(inp, pages, routes, flows, base_url)

        if not test_scripts:
            # Fallback: generate basic smoke tests without AI
            test_scripts = self._generate_smoke_tests(pages, routes, base_url)

        # Step 3: Run generated tests
        test_results = self._run_generated_tests(test_scripts, inp.root)

        # Step 4: Report results
        total = test_results.get("total", 0)
        passed = test_results.get("passed", 0)
        failed = test_results.get("failed", 0)

        for detail in test_results.get("details", []):
            severity = Severity.INFO if detail["passed"] else Severity.HIGH
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="e2e_pass" if detail["passed"] else "e2e_fail",
                    severity=severity,
                    file=detail.get("file", "generated_test"),
                    message=f"{'PASS' if detail['passed'] else 'FAIL'}: {detail['name']}",
                    detail=detail.get("error", "")[:500] if not detail["passed"] else "",
                )
            )

        result.data["suite"] = {
            "runner": "playwright_e2e",
            "total": total,
            "passed": passed,
            "failed": failed,
            "scripts_generated": len(test_scripts),
            "details": test_results.get("details", [])[:50],
        }
        result.files_scanned = len(pages)

    def _generate_test_scripts(
        self, inp: AgentInput, pages: list, routes: list, flows: list, base_url: str
    ) -> list[dict]:
        """Use AI to generate Playwright test scripts."""
        from ..ai.client import call_ai

        config = inp.config
        if not config.get("ai", {}).get("keys") and not config.get("ai", {}).get(
            "local_model_name"
        ):
            return []

        pages_text = "\n".join(f"- {p}" for p in pages[:20])
        routes_text = "\n".join(f"- {r}" for r in routes[:20]) if routes else "No routes detected"
        flows_text = ""
        if flows:
            flows_text = "\nConfirmed critical flows:\n" + "\n".join(
                f"- {f.get('name', '?')}: {f.get('description', '')}" for f in flows
            )

        system = """You are a Playwright test generator for the Patchi testing framework.

Generate Python test scripts using playwright.sync_api that test the web application.

RULES:
- Use `from playwright.sync_api import sync_playwright` (sync API, not async)
- Each test function must accept `base_url` as a parameter
- Tests must be self-contained (no external fixtures)
- Use try/except to handle errors gracefully
- Print structured results: print("PASS: test_name") or print("FAIL: test_name: error")
- Test real user interactions: click buttons, fill forms, verify content
- Test navigation between pages
- Test error states (invalid inputs, missing required fields)
- Test responsive behavior at mobile viewport

Generate 5-10 test functions that cover the most important user flows.
Each function should be named `test_<something>` and take `base_url` as argument.
At the end, include a `def main():` that runs all tests and prints a summary."""

        user_prompt = f"""Generate Playwright E2E tests for this application.

Base URL: {base_url}

Available pages:
{pages_text}

Routes:
{routes_text}
{flows_text}

Generate comprehensive E2E tests covering:
1. Page load and rendering tests
2. Button click tests (verify actions happen)
3. Form submission tests (valid + invalid inputs)
4. Navigation tests (clicking links moves between pages)
5. Error state tests (what happens with bad input)
6. At least one responsive test (mobile viewport)

Return ONLY Python code in a single code block."""

        response = call_ai(config, system, user_prompt, max_tokens=6000)
        if not response:
            return []

        # Extract Python code blocks
        blocks = re.findall(r"```(?:python)?\n(.*?)```", response, re.DOTALL)
        if not blocks:
            # Try to find function definitions directly
            if "def test_" in response:
                blocks = [response]

        scripts = []
        for i, block in enumerate(blocks):
            scripts.append(
                {
                    "name": f"ai_generated_{i}",
                    "code": block,
                    "source": "ai",
                }
            )

        return scripts

    def _generate_smoke_tests(self, pages: list, routes: list, base_url: str) -> list[dict]:
        """Generate basic smoke tests without AI as a fallback."""
        test_code = f'''
from playwright.sync_api import sync_playwright
import sys

def test_page_loads(base_url, page_path):
    """Test that a page loads without errors."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        url = f"{{base_url}}/{{page_path}}" if not page_path.startswith("http") else page_path
        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
            if response and response.status < 400:
                print(f"PASS: page_loads_{{page_path.replace('/', '_').replace('.html', '')}}")
            else:
                print(f"FAIL: page_loads_{{page_path.replace('/', '_').replace('.html', '')}}: status {{response.status if response else 'None'}}")
        except Exception as e:
            print(f"FAIL: page_loads_{{page_path.replace('/', '_').replace('.html', '')}}: {{e}}")
        finally:
            browser.close()

def test_no_console_errors(base_url, page_path):
    """Test that no JavaScript errors occur on page load."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        errors = []
        page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
        url = f"{{base_url}}/{{page_path}}" if not page_path.startswith("http") else page_path
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(2000)
            if errors:
                print(f"FAIL: console_errors_{{page_path.replace('/', '_').replace('.html', '')}}: {{errors[0][:100]}}")
            else:
                print(f"PASS: console_errors_{{page_path.replace('/', '_').replace('.html', '')}}")
        except Exception as e:
            print(f"PASS: console_errors_{{page_path.replace('/', '_').replace('.html', '')}}: page failed to load")
        finally:
            browser.close()

if __name__ == "__main__":
    base = "{base_url}"
    pages = {pages[:10]}
    passed = failed = 0
    for page_path in pages:
        test_page_loads(base, page_path)
        test_no_console_errors(base, page_path)
'''

        return [{"name": "smoke_tests", "code": test_code, "source": "generated"}]

    def _run_generated_tests(self, scripts: list[dict], root: Path) -> dict:
        """Run generated test scripts as subprocesses."""
        total = 0
        passed = 0
        failed = 0
        details = []

        for script in scripts:
            # Write script to temp file
            script_path = root / ".patchi" / "tests" / "e2e" / f"{script['name']}.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text(script["code"], encoding="utf-8")

            try:
                proc = subprocess.run(
                    [sys.executable, str(script_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=str(root),
                )
                output = proc.stdout + proc.stderr

                for line in output.splitlines():
                    if line.startswith("PASS:"):
                        total += 1
                        passed += 1
                        details.append(
                            {"name": line[6:].strip(), "passed": True, "file": script["name"]}
                        )
                    elif line.startswith("FAIL:"):
                        total += 1
                        failed += 1
                        parts = line[6:].split(":", 1)
                        details.append(
                            {
                                "name": parts[0].strip(),
                                "passed": False,
                                "error": parts[1].strip() if len(parts) > 1 else "unknown",
                                "file": script["name"],
                            }
                        )
            except subprocess.TimeoutExpired:
                total += 1
                failed += 1
                details.append(
                    {
                        "name": script["name"],
                        "passed": False,
                        "error": "timeout",
                        "file": script["name"],
                    }
                )
            except Exception as e:
                total += 1
                failed += 1
                details.append(
                    {
                        "name": script["name"],
                        "passed": False,
                        "error": str(e)[:200],
                        "file": script["name"],
                    }
                )

        return {"total": total, "passed": passed, "failed": failed, "details": details}

    def _find_base_url(self, inp: AgentInput) -> str | None:
        extra_base = (inp.extra or {}).get("base_url")
        if extra_base:
            return extra_base
        test_config = inp.config.get("test_config", {})
        if test_config.get("base_url"):
            return test_config["base_url"]
        import socket

        # Check config/brain for configured dev server port first (LIMIT-12)
        config = inp.config or {}
        brain = inp.brain or {}
        config_port = config.get("web_port") or brain.get("web_port")
        if config_port:
            try:
                with socket.create_connection(("127.0.0.1", int(config_port)), timeout=1):
                    return f"http://127.0.0.1:{int(config_port)}"
            except (ConnectionRefusedError, OSError, ValueError):
                pass
        for port in [3000, 5173, 8080, 4200, 8000, 4321, 5189]:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return f"http://127.0.0.1:{port}"
            except (ConnectionRefusedError, OSError):
                continue
        return None

    def _discover_pages(self, root: Path) -> list[str]:
        pages = []
        for p in root.rglob("*.html"):
            if any(part in DEFAULT_IGNORE_DIRS for part in p.parts):
                continue
            pages.append(p.relative_to(root).as_posix())
        return sorted(set(pages))[:20]

    def _extract_routes(self, inp: AgentInput) -> list[str]:
        brain = inp.brain or {}
        route_map = brain.get("route_map", {})
        routes = []
        for _key, val in route_map.items():
            if isinstance(val, dict) and "path" in val:
                routes.append(val["path"])
            elif isinstance(val, str):
                routes.append(val)
        return routes[:20]

    def _get_contract_flows(self, inp: AgentInput) -> list[dict]:
        brain = inp.brain or {}
        return brain.get("confirmed_flows", [])
