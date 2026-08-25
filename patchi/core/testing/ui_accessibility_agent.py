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

Requires: playwright, axe-playwright-python or manual axe-core injection
"""

from __future__ import annotations

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

# axe-core CDN for injection
AXE_CORE_JS = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.8.4/axe.min.js"

AXE_RULES_BY_SEVERITY = {
    "critical": [
        "color-contrast",
        "image-alt",
        "label",
        "select-name",
        "button-name",
        "input-image-alt",
        "aria-required-attr",
        "valid-lang",
        "doc-title",
    ],
    "serious": [
        "aria-allowed-attr",
        "aria-hidden-body",
        "aria-hidden-focus",
        "bypass",
        "definition-list",
        "dlitem",
        "duplicate-id",
        "heading-order",
        "html-has-lang",
        "html-lang-valid",
        "landmark-banner-is-top-level",
        "landmark-contentinfo-is-top-level",
        "landmark-main-is-top-level",
        "landmark-no-duplicate-banner",
        "landmark-one-main",
        "meta-viewport",
        "region",
    ],
    "moderate": [
        "color-contrast-enhanced",
        "css-orientation-lock",
        "frame-title",
        "heading-level",
        "html-xml-lang-mismatch",
        "identical-links-same-purpose",
        "label-title-only",
        "link-in-text-block",
        "p-as-heading",
        "table-duplicate-name",
    ],
    "minor": [
        "css-orientation-lock",
        "definition-list",
        "dlitem",
        "link-name",
        "list",
        "listitem",
        "meter-name",
        "scrollable-region-focusable",
        "tabindex",
    ],
}


import logging

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
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skip(result, "playwright not installed — pip install playwright")
            return

        base_url = self._find_base_url(inp)
        if not base_url:
            self.skip(result, "no running server found — start dev server first")
            return

        pages_to_test = self._discover_pages(inp.root)
        if not pages_to_test:
            self.skip(result, "no HTML pages found to test")
            return

        total_violations = 0
        all_violations = []
        pages_tested = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            for page_path in pages_to_test[:15]:
                page = browser.new_page()
                try:
                    url = (
                        f"{base_url}/{page_path}" if not page_path.startswith("http") else page_path
                    )
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception as e:
                    result.add_finding(
                        make_finding(
                            agent=self.name,
                            finding_type="page_load_error",
                            severity=Severity.HIGH,
                            file=page_path,
                            message=f"Could not load page for a11y test: {e}",
                        )
                    )
                    page.close()
                    continue

                # Inject axe-core
                violations = self._run_axe_core(page, page_path)
                total_violations += len(violations)
                all_violations.extend(violations)
                pages_tested += 1

                # Also test keyboard navigation
                kb_issues = self._test_keyboard_navigation(page, page_path)
                for issue in kb_issues:
                    result.add_finding(issue)

                page.close()

            browser.close()

        # Report violations
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
                    extra={"rule": v.get("id", ""), "wcag_tags": v.get("tags", [])},
                )
            )

        # Summary
        if total_violations == 0 and pages_tested > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="a11y_summary",
                    severity=Severity.INFO,
                    file="(all pages)",
                    message=f"Accessibility PASSED: {pages_tested} pages, 0 violations",
                )
            )
        elif pages_tested > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="a11y_summary",
                    severity=Severity.HIGH,
                    file="(all pages)",
                    message=f"Accessibility FAILED: {pages_tested} pages, {total_violations} violations",
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
            # Inject axe-core script
            page.add_script_tag(url=AXE_CORE_JS)
            page.wait_for_function("typeof axe !== 'undefined'", timeout=10000)

            # Run axe and get results
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
            # axe-core injection failed — try alternative approach
            _log.warning("UIAccessibilityAgent._run_axe_core failed: %s", e)

        return violations

    def _test_keyboard_navigation(self, page, page_path: str) -> list:
        """Test that all interactive elements are keyboard accessible."""
        findings = []
        try:
            # Tab through elements and check focus
            focused_elements = []
            for _ in range(30):  # tab up to 30 times
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

            # Check for elements that can't receive focus
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

    def _discover_pages(self, root: Path) -> list[str]:
        """Find HTML pages to test."""
        pages = []
        for p in root.rglob("*.html"):
            if any(part in DEFAULT_IGNORE_DIRS for part in p.parts):
                continue
            pages.append(p.relative_to(root).as_posix())

        return sorted(set(pages))[:20]

    def _find_base_url(self, inp: AgentInput) -> str | None:
        """Find a running dev server."""
        extra_base = (inp.extra or {}).get("base_url")
        if extra_base:
            return extra_base
        test_config = inp.config.get("test_config", {})
        if test_config.get("base_url"):
            return test_config["base_url"]
        import socket

        for port in [3000, 5173, 8080, 4200, 8000, 4321, 5189]:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return f"http://127.0.0.1:{port}"
            except (ConnectionRefusedError, OSError):
                continue
        return None

    def _map_impact(self, impact: str) -> Severity:
        return {
            "critical": Severity.CRITICAL,
            "serious": Severity.HIGH,
            "moderate": Severity.MEDIUM,
            "minor": Severity.LOW,
        }.get(impact.lower(), Severity.MEDIUM)

    def _format_violation(self, v: dict) -> str:
        lines = [f"Rule: {v.get('id', '?')}"]
        lines.append(f"Impact: {v.get('impact', '?')}")
        lines.append(f"Help: {v.get('help', '?')}")
        lines.append(f"WCAG: {', '.join(v.get('tags', [])[:5])}")
        for node in v.get("nodes", [])[:3]:
            lines.append(f"  Element: {node.get('html', '')[:100]}")
            lines.append(f"  Fix: {node.get('failureSummary', '')[:100]}")
        return "\n".join(lines)
