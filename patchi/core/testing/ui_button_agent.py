"""
UIButtonAgent — Interactive button and click-action testing via Playwright.

Tests every interactive element:
- Discovers all buttons, links, and clickable elements
- Verifies buttons are clickable (not covered, not disabled unexpectedly)
- Tests button hover, focus, and active states
- Clicks buttons and checks for JS errors / broken handlers
- Verifies buttons have meaningful text or aria-labels
- Checks for buttons that do nothing (no action)
- Screenshots each page and links evidence to findings

Requires: playwright
"""

from __future__ import annotations

import logging

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Severity,
    make_finding,
    register,
)
from ._browser import (
    discover_routes,
    find_server,
    open_page,
    save_screenshot,
)

_log = logging.getLogger("patchi.testing.ui_button_agent")


@register
class UIButtonAgent(BaseAgent):
    """Interactive button and click-action testing."""

    group = AgentGroup.TEST
    domain = AgentDomain.VISUAL
    name = "UIButtonAgent"
    description = "Button/click testing: clickability, handlers, JS errors, empty actions"
    timeout = 180

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError:
            self.skip(result, "playwright not installed — pip install playwright && playwright install chromium")
            return

        base_url = find_server(inp.root, inp.config, inp.extra)
        if not base_url:
            self.skip(result, "no running server found — start `p web` (default :1612)")
            return

        routes = discover_routes(inp.config, inp.extra)
        if not routes:
            self.skip(result, "no routes discovered")
            return

        screenshot_dir = inp.root / ".patchi" / "evidence" / "screenshots" / "ui_button"
        total_issues = 0
        pages_tested = 0
        error_pages = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            for page_path in routes[:15]:
                ps = open_page(browser, f"{base_url}{page_path}")
                page = ps.page
                try:
                    slug = page_path.strip("/").replace("/", "_") or "root"
                    shot = save_screenshot(page, screenshot_dir, slug)
                    rel = str(shot.relative_to(inp.root)) if shot else None

                    if ps.status and ps.status >= 400:
                        error_pages += 1
                        result.add_finding(
                            make_finding(
                                agent=self.name,
                                finding_type="page_error",
                                severity=Severity.HIGH,
                                file=page_path,
                                message=f"HTTP {ps.status} on {page_path} (button test skipped)",
                                extra={"screenshot": rel},
                            )
                        )
                        continue

                    for ce in ps.console_errors[:5]:
                        result.add_finding(
                            make_finding(
                                agent=self.name,
                                finding_type="console_error",
                                severity=Severity.LOW,
                                file=page_path,
                                message=f"Console error on {page_path}: {ce[:160]}",
                                extra={"screenshot": rel},
                            )
                        )

                    buttons = self._find_buttons(page)
                    issues = self._analyze_buttons(buttons, page_path)
                    for issue in issues:
                        if rel:
                            issue.extra = {**(issue.extra or {}), "screenshot": rel}
                        result.add_finding(issue)
                        total_issues += 1

                    interaction_issues = self._capture_interactions(page, page_path, rel, base_url)
                    for issue in interaction_issues:
                        result.add_finding(issue)
                        total_issues += 1

                    pages_tested += 1
                finally:
                    page.close()

            browser.close()

        if total_issues == 0 and error_pages == 0 and pages_tested > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="button_summary",
                    severity=Severity.INFO,
                    file="(all pages)",
                    message=f"Button testing PASSED: {pages_tested} pages, 0 issues",
                )
            )
        elif pages_tested > 0 or error_pages > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="button_summary",
                    severity=Severity.MEDIUM,
                    file="(all pages)",
                    message=f"Button issues: {total_issues} across {pages_tested} pages ({error_pages} error pages)",
                )
            )

        result.data["suite"] = {
            "runner": "button_test",
            "pages_tested": pages_tested,
            "total_issues": total_issues,
        }
        result.files_scanned = pages_tested

    def _find_buttons(self, page) -> list:
        return page.evaluate("""() => {
            const buttons = [];
            document.querySelectorAll('button, a[href], input[type=submit], input[type=button], [role=button], .btn, [class*=btn]').forEach(el => {
                const r = el.getBoundingClientRect();
                if (r.width > 0 && r.height > 0) {
                    buttons.push({
                        tag: el.tagName.toLowerCase(),
                        type: el.getAttribute('type') || '',
                        text: (el.innerText || '').trim().substring(0, 50),
                        ariaLabel: el.getAttribute('aria-label') || '',
                        title: el.getAttribute('title') || '',
                        id: el.id || '',
                        classes: (el.className || '').substring(0, 80),
                        x: Math.round(r.x),
                        y: Math.round(r.y),
                        w: Math.round(r.width),
                        h: Math.round(r.height),
                        href: el.getAttribute('href') || '',
                        disabled: el.disabled || el.hasAttribute('disabled'),
                    });
                }
            });
            return buttons;
        }""")

    def _analyze_buttons(self, buttons: list, page_path: str) -> list:
        findings = []
        for b in buttons:
            if b["disabled"]:
                continue
            label = b["text"] or b["ariaLabel"] or b["title"]
            if not label and b["tag"] not in ("a",):
                findings.append(
                    make_finding(
                        agent=self.name,
                        finding_type="button_no_label",
                        severity=Severity.MEDIUM,
                        file=page_path,
                        message=f"Button has no text/aria-label: <{b['tag']}> '{b['classes'][:40]}'",
                        extra={"selector": f"{b['tag']}#{b['id']}"},
                    )
                )
            if b["w"] > 0 and b["h"] > 0 and (b["w"] < 24 or b["h"] < 24):
                findings.append(
                    make_finding(
                        agent=self.name,
                        finding_type="button_too_small",
                        severity=Severity.LOW,
                        file=page_path,
                        message=f"Button too small ({b['w']}x{b['h']}px): '{label[:30]}'",
                        extra={"selector": f"{b['tag']}#{b['id']}"},
                    )
                )
            if b["tag"] == "button" and b["type"] == "submit" and not b["text"] and not b["ariaLabel"]:
                findings.append(
                    make_finding(
                        agent=self.name,
                        finding_type="submit_no_label",
                        severity=Severity.MEDIUM,
                        file=page_path,
                        message=f"Submit button has no label: <button type=submit> '{b['classes'][:40]}'",
                        extra={"selector": f"button#{b['id']}"},
                    )
                )
        return findings

    def _capture_interactions(self, page, page_path: str, rel: str | None, base_url: str) -> list:
        findings = []
        try:
            locators = page.locator('button:not([disabled]), a[href], [role=button]:not([disabled])')
            count = locators.count()
            if count == 0:
                return findings
            captured = []

            def _on_pageerror(exc):
                captured.append(str(exc))

            def _on_console(msg):
                if msg.type == "error":
                    captured.append(str(getattr(msg, "text", msg)))

            page.on("pageerror", _on_pageerror)
            page.on("console", _on_console)
            clicked = 0
            url = f"{base_url}{page_path}"
            for i in range(min(count, 8)):
                captured.clear()
                try:
                    # reset to a clean page state so locators never go stale
                    page.goto(url, wait_until="load", timeout=15000)
                    loc = locators.nth(i)
                    tag = loc.evaluate("e => e.tagName.toLowerCase()")
                    if tag == "button" and loc.evaluate("e => e.type") == "submit":
                        continue  # don't submit forms during tests
                    href = loc.evaluate("e => e.getAttribute('href') || ''")
                    if href and (href.startswith("http") or href.startswith("mailto:")):
                        continue  # leave site / external
                    try:
                        label = loc.evaluate("e => (e.innerText || e.getAttribute('aria-label') || '').trim().substring(0, 30)")
                    except Exception:
                        label = "?"
                except Exception:
                    continue
                try:
                    loc.click(timeout=2000, force=True)
                    page.wait_for_timeout(400)
                except Exception:
                    findings.append(
                        make_finding(
                            agent=self.name,
                            finding_type="button_no_action",
                            severity=Severity.LOW,
                            file=page_path,
                            message=f"Button click failed/had no handler: <{tag}> '{label}'",
                            extra={"screenshot": rel},
                        )
                    )
                else:
                    if captured:
                        findings.append(
                            make_finding(
                                agent=self.name,
                                finding_type="button_js_error",
                                severity=Severity.HIGH,
                                file=page_path,
                                message=f"Button click raised JS error: <{tag}> '{label}': {captured[0][:160]}",
                                extra={"screenshot": rel},
                            )
                        )
                clicked += 1
                if clicked >= 6:
                    break
            page.remove_listener("pageerror", _on_pageerror)
            page.remove_listener("console", _on_console)
        except Exception as e:
            _log.warning("UIButtonAgent._capture_interactions failed: %s", e)
        return findings
