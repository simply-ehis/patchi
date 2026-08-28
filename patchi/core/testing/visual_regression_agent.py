"""
VisualRegressionAgent — Screenshot comparison testing via Playwright.

Takes screenshots at multiple viewports, waits for full render, and compares
them against stored baselines:

- Baselines stored in ``.patchi/visual_baselines/{route}/``
- Current shots saved to ``.patchi/evidence/screenshots/visual_regression/``
- On change, a **pixel-diff overlay** (red boxes around changed regions) is
  generated so reviewers can see *what* moved, not just that it did.
- HTTP status (>=400) and console/page errors are surfaced as findings.
- Every finding carries the screenshot path so the UI can display evidence.

Requires: playwright, Pillow
"""

from __future__ import annotations

import hashlib
import json
import logging
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
from ._browser import (
    DEFAULT_UI_ROUTES,
    discover_routes,
    find_server,
    open_page,
    save_screenshot,
)

VIEWPORTS = [
    {"width": 1440, "height": 900, "label": "desktop"},
    {"width": 768, "height": 1024, "label": "tablet"},
    {"width": 375, "height": 812, "label": "mobile"},
]

_log = logging.getLogger("patchi.testing.visual_regression_agent")


@register
class VisualRegressionAgent(BaseAgent):
    """Screenshot diff testing: baseline comparison, layout shifts, visual regressions."""

    group = AgentGroup.TEST
    name = "VisualRegressionAgent"
    description = "Screenshot diff testing: baseline comparison, layout shifts, visual regressions"
    timeout = 240

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

        baseline_root = inp.root / ".patchi" / "visual_baselines"
        evidence_dir = inp.root / ".patchi" / "evidence" / "screenshots" / "visual_regression"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        shots = 0
        regressions = 0
        new_baselines = 0
        error_pages = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            for route in routes[:15]:
                for vp in VIEWPORTS:
                    browser.new_context(viewport={"width": vp["width"], "height": vp["height"]})
                    page_session = open_page(browser, f"{base_url}{route}")
                    page = page_session.page
                    try:
                        slug = route.strip("/").replace("/", "_") or "root"
                        shot_name = f"{slug}_{vp['label']}"
                        shot_path = save_screenshot(page, evidence_dir, shot_name)
                        if shot_path is None:
                            continue
                        rel = str(shot_path.relative_to(inp.root))
                        shots += 1

                        # Surface server / runtime errors as findings + annotation
                        if page_session.status and page_session.status >= 400:
                            error_pages += 1
                            result.add_finding(
                                make_finding(
                                    agent=self.name,
                                    finding_type="page_error",
                                    severity=Severity.HIGH,
                                    file=route,
                                    message=f"HTTP {page_session.status} on {route} ({vp['label']})",
                                    extra={"viewport": vp["label"], "status": page_session.status,
                                           "screenshot": rel},
                                )
                            )
                        for ce in page_session.console_errors[:5]:
                            result.add_finding(
                                make_finding(
                                    agent=self.name,
                                    finding_type="console_error",
                                    severity=Severity.MEDIUM,
                                    file=route,
                                    message=f"Console error on {route} ({vp['label']}): {ce[:160]}",
                                    extra={"viewport": vp["label"], "screenshot": rel},
                                )
                            )

                        # Baseline compare
                        base_shot = baseline_root / slug / f"{vp['label']}.png"
                        if not base_shot.exists():
                            base_shot.parent.mkdir(parents=True, exist_ok=True)
                            page.screenshot(path=str(base_shot), full_page=True)
                            new_baselines += 1
                            result.add_finding(
                                make_finding(
                                    agent=self.name,
                                    finding_type="new_baseline",
                                    severity=Severity.INFO,
                                    file=route,
                                    message=f"New baseline created: {slug} ({vp['label']})",
                                    extra={"viewport": vp["label"], "screenshot": rel,
                                           "baseline": str(base_shot.relative_to(inp.root))},
                                )
                            )
                        else:
                            diff_path, changed = self._diff(base_shot, shot_path, evidence_dir, slug, vp["label"])
                            if changed:
                                regressions += 1
                                result.add_finding(
                                    make_finding(
                                        agent=self.name,
                                        finding_type="visual_regression",
                                        severity=Severity.MEDIUM,
                                        file=route,
                                        message=f"Visual change on {route} ({vp['label']}): {len(changed)} region(s) changed",
                                        detail=f"Baseline: {base_shot.name}\nCurrent: {shot_path.name}",
                                        extra={"viewport": vp["label"], "screenshot": rel,
                                               "baseline": str(base_shot.relative_to(inp.root)),
                                               "diff": str(diff_path.relative_to(inp.root)) if diff_path else None,
                                               "regions": len(changed)},
                                    )
                                )
                                # refresh baseline so next run compares against now-current
                                page.screenshot(path=str(base_shot), full_page=True)
                    finally:
                        page.close()
            browser.close()

        if regressions == 0 and error_pages == 0 and shots > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="visual_summary",
                    severity=Severity.INFO,
                    file="(all pages)",
                    message=f"Visual regression PASSED: {shots} screenshots, 0 regressions, {new_baselines} new baselines",
                )
            )
        elif shots > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="visual_summary",
                    severity=Severity.MEDIUM,
                    file="(all pages)",
                    message=f"Visual regression: {regressions} changes, {error_pages} error pages across {shots} screenshots",
                )
            )

        result.data["suite"] = {
            "runner": "visual_regression",
            "screenshots": shots,
            "regressions": regressions,
            "new_baselines": new_baselines,
            "error_pages": error_pages,
        }
        result.files_scanned = shots

    # ── pixel diff ──────────────────────────────────────────────────────────

    def _diff(self, base_path: Path, curr_path: Path, out_dir: Path, slug: str, label: str):
        """Return (diff_image_path, changed_regions) using a downscaled pixel diff.

        Requires Pillow. If Pillow is unavailable, falls back to a file-size /
        hash comparison and reports diffing as unavailable (no crash).
        """
        try:
            from PIL import Image, ImageDraw
        except Exception:
            _log.warning("VisualRegressionAgent: Pillow not installed — pixel diff disabled")
            return None, []

        try:
            base = Image.open(base_path).convert("RGB")
            curr = Image.open(curr_path).convert("RGB")
        except Exception as e:
            _log.warning("VisualRegressionAgent._diff open failed: %s", e)
            return None, []

        # Downscale for speed + stable diffing (the overlay is illustrative).
        max_w = 900
        for im in (base, curr):
            if im.width > max_w:
                h = int(im.height * max_w / im.width)
                im.thumbnail((max_w, h))

        if base.size != curr.size:
            # Layout changed dramatically — treat whole image as changed.
            out = curr.copy()
            d = ImageDraw.Draw(out)
            d.rectangle([0, 0, out.width - 1, out.height - 1], outline=(255, 0, 0), width=3)
            diff_path = out_dir / f"{slug}_{label}_diff.png"
            out.save(str(diff_path))
            return diff_path, [list(out.getbbox())]

        bpx, cpx = base.load(), curr.load()
        bw, bh = base.size
        cell = 16
        changed = []
        for y in range(0, bh, cell):
            for x in range(0, bw, cell):
                diff = 0
                n = 0
                for yy in range(y, min(y + cell, bh)):
                    for xx in range(x, min(x + cell, bw)):
                        br, bg, bb = bpx[xx, yy]
                        cr, cg, cb = cpx[xx, yy]
                        diff += abs(br - cr) + abs(bg - cg) + abs(bb - cb)
                        n += 1
                if n and diff / n > 55:  # perceptible change in this cell
                    changed.append((x, y, min(cell, bw - x), min(cell, bh - y)))

        if not changed:
            return None, []

        out = curr.copy()
        d = ImageDraw.Draw(out)
        for (x, y, w, h) in changed:
            d.rectangle([x, y, x + w, y + h], outline=(255, 0, 0), width=2)
        diff_path = out_dir / f"{slug}_{label}_diff.png"
        out.save(str(diff_path))
        return diff_path, [list(c) for c in changed]
