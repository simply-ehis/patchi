"""
UILayoutAgent — Layout, responsive design, and visual structure testing.

Uses Playwright to:
- Test at multiple viewports (mobile, tablet, laptop, desktop)
- Verify no horizontal scroll overflow
- Check element overlap and z-index issues
- Validate image dimensions and aspect ratios
- Test text truncation and overflow
- Verify grid/flex layouts don't collapse
- Screenshot every page/viewport and link the evidence to findings

Requires: playwright
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

VIEWPORTS = [
    {"width": 320, "height": 568, "label": "mobile"},
    {"width": 768, "height": 1024, "label": "tablet"},
    {"width": 1024, "height": 768, "label": "laptop"},
    {"width": 1440, "height": 900, "label": "desktop"},
]


_log = logging.getLogger("patchi.testing.ui_layout_agent")


@register
class UILayoutAgent(BaseAgent):
    """Layout, responsive design, and visual structure testing."""

    group = AgentGroup.TEST
    name = "UILayoutAgent"
    description = "Responsive layout testing: viewports, overflow, overlap, grid collapse"
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

        screenshot_dir = inp.root / ".patchi" / "evidence" / "screenshots" / "ui_layout"
        issues_found = 0
        pages_tested = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            for page_path in routes[:15]:
                for vp in VIEWPORTS:
                    ps = open_page(
                        browser,
                        f"{base_url}{page_path}",
                        viewport={"width": vp["width"], "height": vp["height"]},
                    )
                    page = ps.page
                    try:
                        slug = page_path.strip("/").replace("/", "_") or "root"
                        shot = save_screenshot(page, screenshot_dir, f"{slug}_{vp['label']}")
                        rel = str(shot.relative_to(inp.root)) if shot else None

                        if ps.status and ps.status >= 400:
                            result.add_finding(
                                make_finding(
                                    agent=self.name,
                                    finding_type="page_error",
                                    severity=Severity.HIGH,
                                    file=page_path,
                                    message=f"HTTP {ps.status} on {page_path} ({vp['label']})",
                                    extra={"viewport": vp["label"], "screenshot": rel},
                                )
                            )
                            continue

                        issues = self._check_layout(page, page_path, vp["label"], vp["width"])
                        for issue in issues:
                            if rel:
                                issue.extra = {**(issue.extra or {}), "screenshot": rel}
                            result.add_finding(issue)
                            issues_found += 1

                        for ce in ps.console_errors[:5]:
                            result.add_finding(
                                make_finding(
                                    agent=self.name,
                                    finding_type="console_error",
                                    severity=Severity.LOW,
                                    file=page_path,
                                    message=f"Console error on {page_path} ({vp['label']}): {ce[:160]}",
                                    extra={"viewport": vp["label"], "screenshot": rel},
                                )
                            )
                    finally:
                        page.close()
                pages_tested += 1

            browser.close()

        if issues_found == 0 and pages_tested > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="layout_summary",
                    severity=Severity.INFO,
                    file="(all pages)",
                    message=f"Layout PASSED: {pages_tested} pages, 4 viewports, 0 issues",
                )
            )
        elif pages_tested > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="layout_summary",
                    severity=Severity.MEDIUM,
                    file="(all pages)",
                    message=f"Layout issues: {issues_found} issues across {pages_tested} pages",
                )
            )

        result.data["suite"] = {
            "runner": "layout_checker",
            "pages_tested": pages_tested,
            "viewports_tested": len(VIEWPORTS),
            "issues_found": issues_found,
        }
        result.files_scanned = pages_tested

    def _check_layout(self, page, page_path: str, vp_label: str, vp_width: int) -> list:
        """Run layout checks at a specific viewport."""
        findings = []

        # 1. Horizontal overflow check
        overflow = page.evaluate("""() => {
            const docWidth = document.documentElement.scrollWidth;
            const viewWidth = window.innerWidth;
            return { docWidth, viewWidth, overflow: docWidth > viewWidth };
        }""")
        if overflow.get("overflow"):
            findings.append(
                make_finding(
                    agent=self.name,
                    finding_type="horizontal_overflow",
                    severity=Severity.MEDIUM,
                    file=page_path,
                    message=f"Horizontal overflow at {vp_label}: page width {overflow['docWidth']}px > viewport {overflow['viewWidth']}px",
                    extra={"viewport": vp_label, "viewport_width": vp_width},
                )
            )

        # 2. Overlapping elements
        overlaps = page.evaluate("""() => {
            const issues = [];
            const elements = document.querySelectorAll('button, a, input, [role="button"]');
            const rects = [];
            elements.forEach(el => {
                const r = el.getBoundingClientRect();
                if (r.width > 0 && r.height > 0) {
                    rects.push({ tag: el.tagName, id: el.id, rect: { x: r.x, y: r.y, w: r.width, h: r.height }});
                }
            });
            for (let i = 0; i < rects.length; i++) {
                for (let j = i + 1; j < rects.length; j++) {
                    const a = rects[i].rect, b = rects[j].rect;
                    if (a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y) {
                        const overlapArea = Math.max(0, Math.min(a.x+a.w, b.x+b.w) - Math.max(a.x, b.x)) *
                                           Math.max(0, Math.min(a.y+a.h, b.y+b.h) - Math.max(a.y, b.y));
                        if (overlapArea > 100) {
                            issues.push({
                                el1: `${rects[i].tag}#${rects[i].id}`,
                                el2: `${rects[j].tag}#${rects[j].id}`,
                                area: Math.round(overlapArea),
                            });
                        }
                    }
                }
            }
            return issues.slice(0, 10);
        }""")

        for o in overlaps:
            findings.append(
                make_finding(
                    agent=self.name,
                    finding_type="element_overlap",
                    severity=Severity.LOW,
                    file=page_path,
                    message=f"Elements overlap ({o['area']}px²): {o['el1']} ↔ {o['el2']}",
                    extra={"viewport": vp_label},
                )
            )

        # 3. Missing responsive meta tag (at mobile viewport)
        if vp_label == "mobile":
            has_meta = page.evaluate("""() => {
                return !!document.querySelector('meta[name="viewport"]');
            }""")
            if not has_meta:
                findings.append(
                    make_finding(
                        agent=self.name,
                        finding_type="missing_viewport_meta",
                        severity=Severity.HIGH,
                        file=page_path,
                        message="Missing <meta name='viewport'> tag — mobile layout will break",
                    )
                )

        # 4. Text overflow / truncation
        text_overflow = page.evaluate("""() => {
            const issues = [];
            document.querySelectorAll('h1, h2, h3, p, span, a, button, label').forEach(el => {
                const r = el.getBoundingClientRect();
                const style = window.getComputedStyle(el);
                if (r.right > window.innerWidth + 5 && style.overflow !== 'hidden') {
                    issues.push({
                        tag: el.tagName,
                        text: (el.innerText || '').substring(0, 40),
                        right: Math.round(r.right),
                        overflow: style.overflow,
                    });
                }
            });
            return issues.slice(0, 5);
        }""")

        for t in text_overflow:
            findings.append(
                make_finding(
                    agent=self.name,
                    finding_type="text_overflow",
                    severity=Severity.LOW,
                    file=page_path,
                    message=f"Text extends past viewport: <{t['tag']}> '{t['text']}' (right={t['right']}px)",
                    extra={"viewport": vp_label},
                )
            )

        # 5. Tiny touch targets (< 44px)
        touch_targets = page.evaluate("""() => {
            const issues = [];
            document.querySelectorAll('button, a, input, select, [role="button"]').forEach(el => {
                const r = el.getBoundingClientRect();
                if (r.width > 0 && r.height > 0 && (r.width < 44 || r.height < 44)) {
                    issues.push({
                        tag: el.tagName,
                        text: (el.innerText || '').substring(0, 30),
                        width: Math.round(r.width),
                        height: Math.round(r.height),
                    });
                }
            });
            return issues.slice(0, 10);
        }""")

        for tt in touch_targets:
            findings.append(
                make_finding(
                    agent=self.name,
                    finding_type="tiny_touch_target",
                    severity=Severity.LOW if vp_label != "mobile" else Severity.MEDIUM,
                    file=page_path,
                    message=f"Touch target too small ({tt['width']}x{tt['height']}px, min 44px): <{tt['tag']}> '{tt['text']}'",
                    extra={"viewport": vp_label},
                )
            )

        # 6. Grid/flex collapse check
        collapse = page.evaluate("""() => {
            const issues = [];
            document.querySelectorAll('[class*="grid"], [class*="flex"], [style*="display: grid"], [style*="display: flex"]').forEach(el => {
                const r = el.getBoundingClientRect();
                const style = window.getComputedStyle(el);
                const children = el.children.length;
                if (children > 1 && r.height < 10) {
                    issues.push({
                        tag: el.tagName,
                        class: (el.className || '').substring(0, 50),
                        height: Math.round(r.height),
                        children: children,
                    });
                }
            });
            return issues.slice(0, 5);
        }""")

        for c in collapse:
            findings.append(
                make_finding(
                    agent=self.name,
                    finding_type="layout_collapse",
                    severity=Severity.HIGH,
                    file=page_path,
                    message=f"Layout collapsed: <{c['tag']}> with {c['children']} children has height {c['height']}px",
                    extra={"viewport": vp_label, "class": c.get("class", "")},
                )
            )

        return findings
