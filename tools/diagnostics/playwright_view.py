"""
Playwright viewer for Patchi HTML reports (audit / plan).

Renders a self-contained HTML report in a headless Chromium browser, asserts
that the report actually painted (an <h1> is present), and optionally writes a
full-page screenshot. This is the "make it viewable" layer from the spec —
Playwright is *only* an attack/view surface here, not part of the CLI logic.

Usage:
    python tools/playwright_view.py report.html [screenshot.png]
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


def view(html_path: Path, screenshot: Path | None = None) -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1100, "height": 900})
        page.goto(html_path.as_uri())
        page.wait_for_selector("h1", timeout=5000)
        title = page.locator("h1").inner_text()
        assert title.strip(), "report did not render a heading"
        # Want at least one data row in the table if present.
        rows = page.locator("table tr").count()
        print(f"[playwright] rendered: {title!r}  ({rows} table rows)")
        if screenshot:
            page.screenshot(path=str(screenshot), full_page=True)
            print(f"[playwright] screenshot -> {screenshot}")
        browser.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: playwright_view.py <report.html> [screenshot.png]")
        raise SystemExit(2)
    html_file = Path(sys.argv[1])
    shot_file = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    if not html_file.exists():
        print(f"no such file: {html_file}")
        raise SystemExit(1)
    view(html_file, shot_file)
