"""AdsAgent §p test — marketing gallery captures (screenshots + short video).

Viewports 1440/768/375 against the marketing surfaces (story + pricing hero),
networkidle settle + 1500ms, into .patchi/evidence/ads/ for imagegen use.
Fail-open: skips without playwright or a running server.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Severity,
    make_finding,
    register,
)
from ._browser import discover_routes, find_server, save_screenshot

_log = logging.getLogger("patchi.testing.ads_agent")

VIEWPORTS = [(1440, 900), (768, 1024), (375, 812)]
GALLERY_ROUTES = ["/landing", "/"]


@register
class AdsAgent(BaseAgent):
    """Marketing gallery: hero/story/pricing captures per viewport + 5s video."""

    group = AgentGroup.TEST
    name = "AdsAgent"
    description = "Marketing captures: screenshots + short video per viewport"
    timeout = 300

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError:
            self.skip(result, "playwright not installed — pip install playwright")
            return

        base_url = find_server(inp.root, inp.config, inp.extra)
        if not base_url:
            self.skip(result, "no running server found — start `p web` (default :1612)")
            return

        gallery = inp.root / ".patchi" / "evidence" / "ads"
        routes = [r for r in discover_routes(inp.config, inp.extra) if r in GALLERY_ROUTES]
        if not routes:
            routes = list(GALLERY_ROUTES)

        shots: list[str] = []
        videos: list[str] = []
        error_pages = 0

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                for width, height in VIEWPORTS:
                    vdir = gallery / f"{width}x{height}"
                    vdir.mkdir(parents=True, exist_ok=True)
                    for route in routes:
                        slug = (route.strip("/").replace("/", "_") or "root") + f"_{width}"
                        ctx = browser.new_context(
                            viewport={"width": width, "height": height},
                            record_video_dir=str(vdir),
                            record_video_size={"width": width, "height": height},
                        )
                        page = ctx.new_page()
                        try:
                            try:
                                page.goto(
                                    f"{base_url}{route}",
                                    wait_until="networkidle",
                                    timeout=20000,
                                )
                            except Exception:
                                page.goto(f"{base_url}{route}", timeout=20000)
                            page.wait_for_timeout(1500)
                            shot = save_screenshot(page, vdir, slug)
                            if shot:
                                shots.append(str(shot.relative_to(inp.root)))
                            # ~5s hero video: let the page live, then close
                            page.wait_for_timeout(5000)
                        except Exception as exc:  # noqa: BLE001
                            _log.debug("ads capture failed %s @%s: %s", route, width, exc)
                            error_pages += 1
                        finally:
                            try:
                                vid = page.video.path() if page.video else None
                            except Exception:
                                vid = None
                            page.close()
                            ctx.close()
                            if vid:
                                try:
                                    videos.append(str(Path(vid).relative_to(inp.root)))
                                except ValueError:
                                    videos.append(str(vid))
            finally:
                browser.close()

        if shots or videos:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="ads_gallery",
                    severity=Severity.INFO,
                    file="(gallery)",
                    message=(f"Marketing gallery: {len(shots)} shots + {len(videos)} videos (.patchi/evidence/ads/)"),
                )
            )
        if error_pages:
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="ads_error_pages",
                    severity=Severity.MEDIUM,
                    file="(gallery)",
                    message=f"{error_pages} gallery capture(s) failed",
                )
            )
        if not shots and not videos and not error_pages:
            self.skip(result, "nothing captured")
            return

        result.data["suite"] = {
            "runner": "ads_gallery",
            "viewports": [f"{w}x{h}" for w, h in VIEWPORTS],
            "screenshots": shots[:12],
            "videos": videos[:6],
            "error_pages": error_pages,
        }
        result.files_scanned = len(shots) + len(videos)
