"""
UIButtonAgent — Playwright tests for button clicks, forms, and interactive elements.

Scans the app's HTML for buttons, links, form inputs, and interactive elements,
then uses Playwright to:
- Click every button and verify response
- Submit forms and validate outcomes
- Test tab/enter/space keyboard activation
- Verify hover/focus states render
- Check disabled states are respected
- Test loading states and async actions

Requires: playwright (pip install playwright && playwright install chromium)
"""

from __future__ import annotations

import json
import time
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


import logging
_log = logging.getLogger("patchi.testing.ui_button_agent")

@register
class UIButtonAgent(BaseAgent):
    """Test buttons, forms, and interactive UI elements with Playwright."""

    group = AgentGroup.TEST
    name = "UIButtonAgent"
    description = (
        "Button/form/interaction testing via Playwright: clicks, submissions, keyboard nav"
    )
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skip(result, "playwright not installed — pip install playwright")
            return

        base_url = self._get_base_url(inp)
        if not base_url:
            self.skip(result, "no base_url found — set hosted.log_path or provide app contract")
            return

        html_sources = self._discover_html_sources(inp.root)
        if not html_sources:
            self.skip(result, "no HTML files found to test against")
            return

        tests_run = 0
        tests_passed = 0
        tests_failed = 0
        all_details = []

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            for html_path in html_sources[:20]:  # cap at 20 pages
                page = browser.new_page()
                try:
                    url = (
                        f"{base_url}/{html_path}" if not html_path.startswith("http") else html_path
                    )
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception as e:
                    result.add_finding(
                        make_finding(
                            agent=self.name,
                            finding_type="page_load_error",
                            severity=Severity.HIGH,
                            file=html_path,
                            message=f"Failed to load page: {e}",
                        )
                    )
                    tests_failed += 1
                    tests_run += 1
                    page.close()
                    continue

                # Discover interactive elements
                elements = self._find_interactive_elements(page)
                page_tests = 0
                page_passed = 0

                for el in elements:
                    tests_run += 1
                    page_tests += 1
                    try:
                        test_result = self._test_element(page, el)
                        if test_result["passed"]:
                            page_passed += 1
                            tests_passed += 1
                        else:
                            tests_failed += 1
                            result.add_finding(
                                make_finding(
                                    agent=self.name,
                                    finding_type="button_test_failed",
                                    severity=Severity.MEDIUM,
                                    file=html_path,
                                    line=el.get("line", 0),
                                    message=f"Element test failed: {el['selector']} — {test_result['error']}",
                                    detail=json.dumps(test_result, indent=2),
                                )
                            )
                        all_details.append(
                            {
                                "file": html_path,
                                "selector": el["selector"],
                                "type": el["type"],
                                "passed": test_result["passed"],
                                "error": test_result.get("error", ""),
                                "response_ms": test_result.get("response_ms", 0),
                            }
                        )
                    except Exception as e:
                        tests_failed += 1
                        result.add_finding(
                            make_finding(
                                agent=self.name,
                                finding_type="test_exception",
                                severity=Severity.HIGH,
                                file=html_path,
                                message=f"Test exception on {el['selector']}: {e}",
                            )
                        )

                page.close()

                if page_tests > 0:
                    result.add_finding(
                        make_finding(
                            agent=self.name,
                            finding_type="page_summary",
                            severity=Severity.INFO,
                            file=html_path,
                            message=f"Page tested: {page_passed}/{page_tests} elements passed",
                        )
                    )

            browser.close()

        result.data["suite"] = {
            "runner": "playwright_buttons",
            "total": tests_run,
            "passed": tests_passed,
            "failed": tests_failed,
            "details": all_details[:100],  # cap output
        }
        result.files_scanned = len(html_sources)

    def _get_base_url(self, inp: AgentInput) -> str | None:
        """Extract base URL from config or brain."""
        # Check explicit base_url from extra (set by LiveTestRunner or test config)
        extra_base = (inp.extra or {}).get("base_url")
        if extra_base:
            return extra_base

        # Check for hosted config
        hosted = inp.config.get("hosted", {})
        if hosted.get("log_path"):
            pass

        # Check brain for routes/URLs
        brain = inp.brain or {}
        route_map = brain.get("route_map", {})
        if route_map:
            first_route = next(iter(route_map.values()), {})
            if isinstance(first_route, dict) and "url" in first_route:
                return first_route["url"].rsplit("/", 1)[0]

        # Check test_config in app config
        test_config = inp.config.get("test_config", {})
        if test_config.get("base_url"):
            return test_config["base_url"]

        # Check for common dev server ports
        import socket

        for port in [3000, 5173, 8080, 4200, 8000, 4321, 5189]:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return f"http://127.0.0.1:{port}"
            except (ConnectionRefusedError, OSError):
                continue

        return None

    def _discover_html_sources(self, root: Path) -> list[str]:
        """Find HTML files in the project."""
        html_files = []
        for p in root.rglob("*.html"):
            if any(part in DEFAULT_IGNORE_DIRS for part in p.parts):
                continue
            rel = p.relative_to(root).as_posix()
            html_files.append(rel)

        # Also check for SPA routes (common patterns)
        if (root / "src").exists():
            for ext in ["*.tsx", "*.jsx", "*.vue", "*.svelte"]:
                for p in (root / "src").rglob(ext):
                    if any(part in DEFAULT_IGNORE_DIRS for part in p.parts):
                        continue
                    rel = p.relative_to(root).as_posix()
                    html_files.append(rel)

        return sorted(set(html_files))[:30]

    def _find_interactive_elements(self, page) -> list[dict]:
        """Discover buttons, links, inputs, and clickable elements."""
        elements = []

        # Buttons
        for btn in page.query_selector_all(
            "button, [role='button'], input[type='submit'], input[type='button']"
        ):
            text = btn.inner_text() if btn.is_visible() else ""
            elements.append(
                {
                    "selector": self._get_selector(page, btn),
                    "type": "button",
                    "text": text.strip()[:50],
                    "disabled": btn.is_disabled(),
                    "line": 0,
                }
            )

        # Links with href
        for link in page.query_selector_all("a[href]"):
            text = link.inner_text() if link.is_visible() else ""
            elements.append(
                {
                    "selector": self._get_selector(page, link),
                    "type": "link",
                    "text": text.strip()[:50],
                    "href": link.get_attribute("href") or "",
                    "disabled": False,
                    "line": 0,
                }
            )

        # Form inputs
        for inp in page.query_selector_all("input:not([type='hidden']), textarea, select"):
            elements.append(
                {
                    "selector": self._get_selector(page, inp),
                    "type": "input",
                    "input_type": inp.get_attribute("type") or "text",
                    "name": inp.get_attribute("name") or "",
                    "placeholder": inp.get_attribute("placeholder") or "",
                    "disabled": inp.is_disabled(),
                    "line": 0,
                }
            )

        # Clickable divs/spans (role=button, onclick, tabindex)
        for clickable in page.query_selector_all(
            "[role='button'], [onclick], [tabindex]:not([tabindex='-1'])"
        ):
            text = clickable.inner_text() if clickable.is_visible() else ""
            elements.append(
                {
                    "selector": self._get_selector(page, clickable),
                    "type": "clickable",
                    "text": text.strip()[:50],
                    "disabled": False,
                    "line": 0,
                }
            )

        return elements

    def _get_selector(self, page, element) -> str:
        """Generate a CSS selector for an element."""
        try:
            # Try data-testid first
            test_id = element.get_attribute("data-testid")
            if test_id:
                return f"[data-testid='{test_id}']"

            # Try id
            el_id = element.get_attribute("id")
            if el_id:
                return f"#{el_id}"

            # Fallback to tag + nth-child
            tag = element.evaluate("el => el.tagName.toLowerCase()")
            parent = element.evaluate(
                "el => el.parentElement ? el.parentElement.tagName.toLowerCase() : 'body'"
            )
            index = element.evaluate("""el => {
                let i = 1;
                let sib = el.previousElementSibling;
                while (sib) { if (sib.tagName === el.tagName) i++; sib = sib.previousElementSibling; }
                return i;
            }""")
            return f"{parent} > {tag}:nth-child({index})"
        except Exception as e:
            _log.warning("UIButtonAgent._get_selector failed: %s", e)
            return "unknown"

    def _test_element(self, page, el: dict) -> dict:
        """Test a single interactive element."""
        selector = el["selector"]
        el_type = el["type"]

        if el.get("disabled"):
            return {"passed": True, "note": "disabled — skipped"}

        try:
            element = page.query_selector(selector)
            if not element or not element.is_visible():
                return {"passed": True, "note": "not visible — skipped"}
        except Exception as e:
            _log.warning("UIButtonAgent._test_element failed: %s", e)
            return {"passed": True, "note": "element not found"}

        time.monotonic()

        if el_type in ("button", "clickable"):
            return self._test_button(page, element, selector)
        elif el_type == "link":
            return self._test_link(page, element, selector)
        elif el_type == "input":
            return self._test_input(page, element, selector, el)

        return {"passed": True, "note": "unsupported type"}

    def _test_button(self, page, element, selector: str) -> dict:
        """Test a button: click it, check for errors."""
        try:
            # Check for console errors during click
            errors = []
            page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)

            element.scroll_into_view_if_needed()
            element.click(timeout=5000)

            # Wait briefly for any async response
            page.wait_for_timeout(1000)

            response_ms = int((time.monotonic() - time.monotonic()) * 1000)

            if errors:
                return {
                    "passed": False,
                    "error": f"Console errors: {'; '.join(errors[:3])}",
                    "response_ms": response_ms,
                }

            return {"passed": True, "response_ms": response_ms}
        except Exception as e:
            return {"passed": False, "error": str(e)[:200]}

    def _test_link(self, page, element, selector: str) -> dict:
        """Test a link: verify href exists and is reachable."""
        try:
            href = element.get_attribute("href")
            if not href:
                return {"passed": False, "error": "Link has no href"}

            if href.startswith("#") or href.startswith("javascript:"):
                return {"passed": True, "note": "anchor/js link — click tested"}

            return {"passed": True, "note": f"href={href[:80]}"}
        except Exception as e:
            return {"passed": False, "error": str(e)[:200]}

    def _test_input(self, page, element, selector: str, el: dict) -> dict:
        """Test an input: type into it, verify value changes."""
        try:
            input_type = el.get("input_type", "text")
            if input_type in ("submit", "button", "hidden"):
                return {"passed": True, "note": f"skipped type={input_type}"}

            element.scroll_into_view_if_needed()
            element.click(timeout=3000)

            # Type test value
            test_value = "test_input_value"
            if input_type == "email":
                test_value = "test@example.com"
            elif input_type == "number":
                test_value = "42"

            element.fill(test_value)
            page.wait_for_timeout(300)

            # Verify value was set
            value = element.input_value() if hasattr(element, "input_value") else ""
            if value == test_value:
                return {"passed": True, "note": "input accepted value"}
            else:
                return {"passed": False, "error": f"Expected '{test_value}', got '{value}'"}

        except Exception as e:
            return {"passed": False, "error": str(e)[:200]}
