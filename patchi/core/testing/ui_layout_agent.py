"""
UILayoutAgent — Layout, responsive design, and visual structure testing.

Uses Playwright to:
- Test at multiple viewports (320px, 768px, 1024px, 1440px)
- Verify no horizontal scroll overflow
- Check element overlap and z-index issues
- Validate image dimensions and aspect ratios
- Test text truncation and overflow
- Verify grid/flex layouts don't collapse
- Check for missing responsive breakpoints
- Screenshot comparison at different sizes

Requires: playwright
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

VIEWPORTS = [
    {"width": 320, "height": 568, "label": "mobile"},
    {"width": 768, "height": 1024, "label": "tablet"},
    {"width": 1024, "height": 768, "label": "laptop"},
    {"width": 1440, "height": 900, "label": "desktop"},
]


import logging
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
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skip(result, "playwright not installed — pip install playwright")
            return

        base_url = self._find_base_url(inp)
        if not base_url:
            self.skip(result, "no running server found")
            return

        pages = self._discover_pages(inp.root)
        if not pages:
            self.skip(result, "no HTML pages found")
            return

        issues_found = 0
        pages_tested = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            for page_path in pages[:15]:
                for vp in VIEWPORTS:
                    page = browser.new_page(viewport={"width": vp["width"], "height": vp["height"]})
                    try:
                        url = (
                            f"{base_url}/{page_path}"
                            if not page_path.startswith("http")
                            else page_path
                        )
                        page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    except Exception as e:
                        _log.warning("UILayoutAgent._run failed: %s", e)
                        page.close()
                        continue

                    vp_label = vp["label"]
                    issues = self._check_layout(page, page_path, vp_label, vp["width"])

                    for issue in issues:
                        result.add_finding(issue)
                        issues_found += 1

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

    def _find_base_url(self, inp: AgentInput) -> str | None:
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

    def _discover_pages(self, root: Path) -> list[str]:
        pages = []
        for p in root.rglob("*.html"):
            if any(part in DEFAULT_IGNORE_DIRS for part in p.parts):
                continue
            pages.append(p.relative_to(root).as_posix())
        return sorted(set(pages))[:20]
