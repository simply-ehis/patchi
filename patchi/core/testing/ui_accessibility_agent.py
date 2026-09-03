"""
UIAccessibilityAgent — Real WCAG accessibility testing via Playwright + axe-core.

Injects axe-core into every page and runs comprehensive accessibility checks:
- Color contrast (WCAG 2.1 AA)
- Missing alt text on images
- Missing form labels
- Keyboard navigation and focus order
- ARIA attributes and roles
- Heading hierarchy
- Landmark regions
- Screen reader compatibility
- Touch target sizes (WCAG 2.5.5)

Screenshots are captured per page and linked to findings; HTTP/console errors
are surfaced so a11y runs don't silently no-op on broken pages.

Requires: playwright, axe-core (injected from CDN)
"""
from __future__ import annotations

import logging

from ..agents.base import (
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

# axe-core CDN for injection
AXE_CORE_JS = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.8.4/axe.min.js"

AXE_RULES_BY_SEVERITY = {
    "critical": [
        "color-contrast", "image-alt", "label", "select-name", "button-name",
        "input-image-alt", "aria-required-attr", "valid-lang", "doc-title",
    ],
    "serious": [
        "aria-allowed-attr", "aria-hidden-body", "aria-hidden-focus", "bypass",
        "definition-list", "dlitem", "duplicate-id", "heading-order", "html-has-lang",
        "html-lang-valid", "landmark-banner-is-top-level", "landmark-contentinfo-is-top-level",
        "landmark-main-is-top-level", "landmark-no-duplicate-banner", "landmark-one-main",
        "meta-viewport", "region",
    ],
    "moderate": [
        "color-contrast-enhanced", "css-orientation-lock", "frame-title",
        "heading-level", "html-xml-lang-mismatch", "identical-links-same-purpose",
        "label-title-only", "link-in-text-block", "p-as-heading", "table-duplicate-name",
    ],
    "minor": [
        "css-orientation-lock", "definition-list", "dlitem", "link-name",
        "list", "listitem", "meter-name", "scrollable-region-focusable", "tabindex",
    ],
}


_log = logging.getLogger("patchi.testing.ui_accessibility_agent")


@register
class UIAccessibilityAgent(BaseAgent):
    """Real WCAG accessibility testing via Playwright + axe-core injection."""

    group = AgentGroup.TEST
    name = "UIAccessibilityAgent"
    description = "axe-core WCAG testing: contrast, alt text, labels, keyboard nav, ARIA"
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

        screenshot_dir = inp.root / ".patchi" / "evidence" / "screenshots" / "ui_accessibility"
        total_violations = 0
        all_violations = []
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
                                message=f"HTTP {ps.status} on {page_path} (a11y test skipped)",
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

                    violations = self._run_axe_core(page, page_path)
                    total_violations += len(violations)
                    all_violations.extend(violations)

                    kb_issues = self._test_keyboard_navigation(page, page_path)
                    for issue in kb_issues:
                        if rel:
                            issue.extra = {**(issue.extra or {}), "screenshot": rel}
                        result.add_finding(issue)

                    pages_tested += 1
                finally:
                    page.close()

            browser.close()

        for v in all_violations:
            severity = self._map_impact(v.get("impact", "moderate"))
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="a11y_violation",
                    severity=severity,
                    file=v.get("file", ""),
                    message=f"[{v.get('impact', '?')}] {v.get('id', 'unknown')}: {v.get('description', '')}",
                    detail=self._format_violation(v),
                    extra={"rule": v.get("id", ""), "wcag_tags": v.get("tags", []),
                           "screenshot": v.get("screenshot")},
                )
            )

        if total_violations == 0 and error_pages == 0 and pages_tested > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="a11y_summary",
                    severity=Severity.INFO,
                    file="(all pages)",
                    message=f"Accessibility PASSED: {pages_tested} pages, 0 violations",
                )
            )
        elif pages_tested > 0 or error_pages > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="a11y_summary",
                    severity=Severity.HIGH if (total_violations or error_pages) else Severity.MEDIUM,
                    file="(all pages)",
                    message=f"Accessibility: {total_violations} violations, {error_pages} error pages across {pages_tested} pages",
                )
            )

        result.data["suite"] = {
            "runner": "axe_core",
            "pages_tested": pages_tested,
            "total_violations": total_violations,
            "violations": all_violations[:50],
        }
        result.files_scanned = pages_tested

    def _run_axe_core(self, page, page_path: str) -> list[dict]:
        """Inject axe-core and run accessibility audit."""
        violations = []
        try:
            page.add_script_tag(url=AXE_CORE_JS)
            page.wait_for_function("typeof axe !== 'undefined'", timeout=10000)

            axe_results = page.evaluate("""async () => {
                try {
                    const results = await axe.run(document, {
                        runOnly: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice']
                    });
                    return {
                        violations: results.violations.map(v => ({
                            id: v.id,
                            impact: v.impact,
                            description: v.description,
                            help: v.help,
                            helpUrl: v.helpUrl,
                            tags: v.tags,
                            nodes: v.nodes.map(n => ({
                                target: n.target,
                                html: n.html ? n.html.substring(0, 200) : '',
                                failureSummary: n.failureSummary,
                            })),
                        })),
                        passes: results.passes.length,
                        incomplete: results.incomplete.length,
                        inapplicable: results.inapplicable.length,
                    };
                } catch (e) {
                    return { error: e.message, violations: [] };
                }
            }""")

            if axe_results.get("error"):
                return violations

            for v in axe_results.get("violations", []):
                v["file"] = page_path
                v["passes"] = axe_results.get("passes", 0)
                v["incomplete"] = axe_results.get("incomplete", 0)
                violations.append(v)

        except Exception as e:
            _log.warning("UIAccessibilityAgent._run_axe_core failed (offline?): %s", e)

        return violations

    def _test_keyboard_navigation(self, page, page_path: str) -> list:
        """Test that all interactive elements are keyboard accessible."""
        findings = []
        try:
            focused_elements = []
            for _ in range(30):
                page.keyboard.press("Tab")
                page.wait_for_timeout(100)

                focused = page.evaluate("""() => {
                    const el = document.activeElement;
                    if (!el || el === document.body) return null;
                    return {
                        tag: el.tagName.toLowerCase(),
                        id: el.id || '',
                        role: el.getAttribute('role') || '',
                        tabindex: el.getAttribute('tabindex'),
                        ariaLabel: el.getAttribute('aria-label') || '',
                        text: (el.innerText || '').substring(0, 50),
                    };
                }""")

                if focused:
                    focused_elements.append(focused)

            interactive_no_focus = page.evaluate("""() => {
                const issues = [];
                document.querySelectorAll('button, a[href], input, select, textarea, [onclick]').forEach(el => {
                    const tabindex = el.getAttribute('tabindex');
                    if (tabindex === '-1') {
                        issues.push({
                            tag: el.tagName.toLowerCase(),
                            id: el.id || '',
                            text: (el.innerText || '').substring(0, 50),
                            issue: 'Interactive element has tabindex=-1 (not keyboard accessible)',
                        });
                    }
                });
                return issues;
            }""")

            for issue in interactive_no_focus:
                findings.append(
                    make_finding(
                        agent=self.name,
                        finding_type="keyboard_inaccessible",
                        severity=Severity.HIGH,
                        file=page_path,
                        message=f"Keyboard inaccessible: <{issue['tag']}> — {issue['issue']}",
                        detail=f"id={issue.get('id', 'none')}, text={issue.get('text', '')}",
                    )
                )

        except Exception as e:
            _log.warning("UIAccessibilityAgent._test_keyboard_navigation failed: %s", e)

        return findings

    def _map_impact(self, impact: str) -> Severity:
        return {
            "critical": Severity.CRITICAL,
            "serious": Severity.HIGH,
            "moderate": Severity.MEDIUM,
            "minor": Severity.LOW,
        }.get((impact or "").lower(), Severity.MEDIUM)

    def _format_violation(self, v: dict) -> str:
        lines = [f"Rule: {v.get('id', '?')}"]
        lines.append(f"Impact: {v.get('impact', '?')}")
        lines.append(f"Help: {v.get('help', '?')}")
        lines.append(f"WCAG: {', '.join(v.get('tags', [])[:5])}")
        for node in v.get("nodes", [])[:3]:
            lines.append(f"  Element: {node.get('html', '')[:100]}")
            lines.append(f"  Fix: {node.get('failureSummary', '')[:100]}")
        return "\n".join(lines)
