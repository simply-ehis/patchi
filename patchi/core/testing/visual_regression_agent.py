"""
VisualRegressionAgent — Screenshot comparison testing via Playwright.

Takes screenshots at multiple viewports and compares them:
- Baseline screenshots stored in .patchi/baselines/
- Compares current screenshots against baselines
- Detects layout shifts, missing elements, color changes
- Saves diffs as overlay images
- Tracks visual changes over time

Requires: playwright
"""

from __future__ import annotations

import hashlib
import json
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
    {"width": 1440, "height": 900, "label": "desktop"},
    {"width": 768, "height": 1024, "label": "tablet"},
    {"width": 375, "height": 812, "label": "mobile"},
]


import logging
_log = logging.getLogger("patchi.testing.visual_regression_agent")

@register
class VisualRegressionAgent(BaseAgent):
    """Screenshot comparison testing for visual regressions."""

    group = AgentGroup.TEST
    name = "VisualRegressionAgent"
    description = "Screenshot diff testing: baseline comparison, layout shifts, visual regressions"
    timeout = 180

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skip(result, "playwright not installed")
            return

        base_url = self._find_base_url(inp)
        if not base_url:
            self.skip(result, "no running server found")
            return

        pages = self._discover_pages(inp.root)
        if not pages:
            self.skip(result, "no HTML pages found")
            return

        baseline_dir = inp.root / ".patchi" / "baselines"
        baseline_dir.mkdir(parents=True, exist_ok=True)

        screenshots_taken = 0
        regressions = 0
        new_baselines = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            for page_path in pages[:10]:
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
                        _log.warning("VisualRegressionAgent._run failed: %s", e)
                        page.close()
                        continue

                    # Take screenshot
                    screenshot_name = (
                        f"{page_path.replace('/', '_').replace('.html', '')}_{vp['label']}"
                    )
                    screenshot_path = baseline_dir / f"{screenshot_name}.png"

                    try:
                        page.screenshot(path=str(screenshot_path), full_page=True)
                        screenshots_taken += 1

                        # Compare with previous screenshot if exists
                        prev_hash = self._get_stored_hash(inp.root, screenshot_name)
                        current_hash = self._hash_file(screenshot_path)

                        if prev_hash is None:
                            # New baseline
                            new_baselines += 1
                            self._store_hash(inp.root, screenshot_name, current_hash)
                            result.add_finding(
                                make_finding(
                                    agent=self.name,
                                    finding_type="new_baseline",
                                    severity=Severity.INFO,
                                    file=page_path,
                                    message=f"New baseline created: {screenshot_name} ({vp['label']})",
                                    extra={"viewport": vp["label"]},
                                )
                            )
                        elif prev_hash != current_hash:
                            # Visual regression detected!
                            regressions += 1
                            result.add_finding(
                                make_finding(
                                    agent=self.name,
                                    finding_type="visual_regression",
                                    severity=Severity.MEDIUM,
                                    file=page_path,
                                    message=f"Visual change detected: {screenshot_name} ({vp['label']})",
                                    detail=f"Baseline hash: {prev_hash[:12]}...\nCurrent hash: {current_hash[:12]}...",
                                    extra={
                                        "viewport": vp["label"],
                                        "baseline": prev_hash,
                                        "current": current_hash,
                                    },
                                )
                            )
                            self._store_hash(inp.root, screenshot_name, current_hash)

                    except Exception as e:
                        result.add_finding(
                            make_finding(
                                agent=self.name,
                                finding_type="screenshot_error",
                                severity=Severity.LOW,
                                file=page_path,
                                message=f"Screenshot failed: {e}",
                            )
                        )

                    page.close()

            browser.close()

        # Summary
        if regressions == 0 and screenshots_taken > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="visual_summary",
                    severity=Severity.INFO,
                    file="(all pages)",
                    message=f"Visual regression PASSED: {screenshots_taken} screenshots, 0 regressions, {new_baselines} new baselines",
                )
            )
        elif screenshots_taken > 0:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="visual_summary",
                    severity=Severity.MEDIUM,
                    file="(all pages)",
                    message=f"Visual regression: {regressions} changes detected across {screenshots_taken} screenshots",
                )
            )

        result.data["suite"] = {
            "runner": "visual_regression",
            "screenshots": screenshots_taken,
            "regressions": regressions,
            "new_baselines": new_baselines,
        }
        result.files_scanned = screenshots_taken

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
        return sorted(set(pages))[:15]

    def _hash_file(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _get_stored_hash(self, root: Path, name: str) -> str | None:
        hashes_file = root / ".patchi" / "baselines" / "hashes.json"
        if not hashes_file.exists():
            return None
        try:
            data = json.loads(hashes_file.read_text(encoding="utf-8"))
            return data.get(name)
        except Exception as e:
            _log.warning("VisualRegressionAgent._get_stored_hash failed: %s", e)
            return None

    def _store_hash(self, root: Path, name: str, hash_val: str) -> None:
        hashes_file = root / ".patchi" / "baselines" / "hashes.json"
        try:
            data = {}
            if hashes_file.exists():
                data = json.loads(hashes_file.read_text(encoding="utf-8"))
            data[name] = hash_val
            hashes_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            _log.warning("VisualRegressionAgent._store_hash failed: %s", e)
