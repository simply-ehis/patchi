"""Live Testing API — browser tests, screenshots, stress tests."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

_log = logging.getLogger("patchi.web.api.live_testing")


router = APIRouter(prefix="/api/live-testing")


class StressTestRequest(BaseModel):
    url: str = "http://127.0.0.1:1612"
    users: int = 10
    duration_seconds: int = 30
    ramp_up_seconds: int = 5


class SmokeTestRequest(BaseModel):
    url: str = "http://127.0.0.1:1612"


# ── State ────────────────────────────────────────────────────────────────────

_stress_state = {"running": False, "last_result": None, "task": None, "cancelled": False}
_install_state = {"running": False, "last_result": None, "log": []}
_audit_state = {
    "running": False,
    "progress": {"current": 0, "total": 0, "route": ""},
    "last_result": None,
}
_dast_state = {"running": False, "task": None, "cancelled": False}
_smoke_state = {"running": False, "task": None, "cancelled": False}


def _run_audit_sync(base_url: str, root: Path, routes: list[str] | None = None) -> dict:
    """Run full-page browser audit synchronously (called via to_thread)."""
    from playwright.sync_api import sync_playwright

    from patchi.core.testing._browser import (
        discover_routes,
        open_page,
        save_screenshot,
    )

    if routes is None:
        routes = discover_routes({}, {})

    evidence_dir = root / ".patchi" / "evidence" / "browser_audit"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    results = []
    total = len(routes)
    _audit_state["progress"] = {"current": 0, "total": total, "route": ""}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            for i, route in enumerate(routes):
                url = f"{base_url}{route}"
                _audit_state["progress"] = {
                    "current": i + 1,
                    "total": total,
                    "route": route,
                }

                page_session = open_page(browser, url)
                page = page_session.page
                load_time_ms = 0

                try:
                    slug = route.strip("/").replace("/", "_") or "root"

                    # Re-measure load time with a fresh goto
                    perf_start = page.evaluate("() => performance.now()")
                    try:
                        page.reload(wait_until="load", timeout=15000)
                        page.wait_for_timeout(500)
                    except Exception as _exc:
                        _log.warning("_run_audit_sync failed: %s", _exc)
                    perf_end = page.evaluate("() => performance.now()")
                    load_time_ms = round(perf_end - perf_start, 1)

                    # Screenshot
                    shot_name = f"audit_{slug}"
                    shot_path = save_screenshot(page, evidence_dir, shot_name)
                    screenshot_file = shot_path.name if shot_path else None

                    # Collect page metrics
                    metrics = page.evaluate(
                        "() => ({dom_nodes: document.querySelectorAll('*').length, "
                        "images: document.querySelectorAll('img').length, "
                        "links: document.querySelectorAll('a').length, "
                        "scripts: document.querySelectorAll('script').length, "
                        "stylesheets: document.querySelectorAll('link[rel=stylesheet]').length, "
                        "title: document.title || '', "
                        "has_viewport_meta: !!document.querySelector('meta[name=viewport]'), "
                        "has_h1: !!document.querySelector('h1')})"
                    )

                    # Check for broken images
                    broken_images = page.evaluate(
                        "() => Array.from(document.querySelectorAll('img'))"
                        ".filter(img => !img.complete || img.naturalWidth === 0)"
                        ".map(img => img.src)"
                    )

                    # Check for empty links
                    empty_links = page.evaluate(
                        "() => Array.from(document.querySelectorAll('a[href]'))"
                        ".filter(a => !a.textContent.trim() && !a.querySelector('img'))"
                        ".length"
                    )

                    results.append(
                        {
                            "route": route,
                            "status": page_session.status,
                            "status_label": _status_label(page_session.status),
                            "load_time_ms": load_time_ms,
                            "console_errors": page_session.console_errors,
                            "console_error_count": len(page_session.console_errors),
                            "page_errors": page_session.page_errors,
                            "page_error_count": len(page_session.page_errors),
                            "screenshot": screenshot_file,
                            "metrics": metrics,
                            "broken_images": broken_images,
                            "broken_image_count": len(broken_images),
                            "empty_links": empty_links,
                            "severity": _severity_for_page(page_session, broken_images, empty_links),
                        }
                    )
                except Exception as e:
                    results.append(
                        {
                            "route": route,
                            "status": -1,
                            "status_label": "ERROR",
                            "load_time_ms": 0,
                            "console_errors": [str(e)],
                            "console_error_count": 1,
                            "page_errors": [],
                            "page_error_count": 0,
                            "screenshot": None,
                            "metrics": {},
                            "broken_images": [],
                            "broken_image_count": 0,
                            "empty_links": 0,
                            "severity": "critical",
                        }
                    )
                finally:
                    try:
                        page.close()
                    except Exception as _exc:
                        _log.warning("_run_audit_sync failed: %s", _exc)
        finally:
            browser.close()

    # Summary
    statuses = [r["status"] for r in results]
    errors_4xx = sum(1 for s in statuses if 400 <= s < 500)
    errors_5xx = sum(1 for s in statuses if s >= 500)
    ok_count = sum(1 for s in statuses if 200 <= s < 400)
    total_console = sum(r["console_error_count"] for r in results)
    total_page_err = sum(r["page_error_count"] for r in results)
    total_broken = sum(r["broken_image_count"] for r in results)
    avg_load = round(sum(r["load_time_ms"] for r in results) / max(len(results), 1), 1)
    critical = sum(1 for r in results if r["severity"] == "critical")
    warnings = sum(1 for r in results if r["severity"] == "warning")
    passed = sum(1 for r in results if r["severity"] == "pass")

    # Save results JSON
    result_data = {
        "ok": True,
        "base_url": base_url,
        "total_routes": len(results),
        "summary": {
            "passed": passed,
            "warnings": warnings,
            "critical": critical,
            "ok_2xx": ok_count,
            "errors_4xx": errors_4xx,
            "errors_5xx": errors_5xx,
            "total_console_errors": total_console,
            "total_page_errors": total_page_err,
            "total_broken_images": total_broken,
            "avg_load_time_ms": avg_load,
        },
        "pages": results,
    }

    # Persist to disk
    audit_file = evidence_dir / "audit_results.json"
    audit_file.write_text(json.dumps(result_data, indent=2, default=str), encoding="utf-8")

    _audit_state["last_result"] = result_data
    return result_data


def _status_label(status: int) -> str:
    if status == 200:
        return "OK"
    if status == 301:
        return "Redirect"
    if status == 304:
        return "Cached"
    if status == 404:
        return "Not Found"
    if status == 500:
        return "Server Error"
    if status < 0:
        return "Failed"
    return str(status)


def _severity_for_page(session, broken_images: list, empty_links: int) -> str:
    if session.status >= 500 or session.status < 0:
        return "critical"
    if session.status >= 400:
        return "warning"
    if session.page_errors:
        return "critical"
    if len(session.console_errors) > 3 or broken_images or empty_links > 2:
        return "warning"
    if session.console_errors:
        return "info"
    return "pass"


# ── Endpoints ────────────────────────────────────────────────────────────────


def _playwright_error_message(exc: Exception) -> str:
    """Human-readable hint when Playwright or its browsers are missing."""
    msg = str(exc)
    if "No module named 'playwright'" in msg or 'No module named "playwright"' in msg:
        return "Playwright not installed — run: pip install playwright && playwright install chromium"
    if "Executable doesn't exist" in msg or "playwright install" in msg.lower():
        return "Playwright browsers not installed — run: playwright install chromium"
    if "Host system is missing dependencies" in msg:
        return "Playwright OS deps missing — run: playwright install-deps chromium"
    return msg


@router.get("/status")
async def status(request: Request):
    """Get live testing status."""
    root: Path = request.app.state.root
    has_pool = True
    pool_hint = ""
    try:
        from patchi.core.testing.live_v2.browser_pool import _browser_pool

        has_pool = bool(_browser_pool and _browser_pool._initialized)
    except Exception as exc:
        has_pool = False
        pool_hint = str(exc)
    return {
        "stress_running": _stress_state["running"],
        "evidence_dir": str(root / ".patchi" / "evidence"),
        "has_browser_pool": has_pool,
        "pool_hint": pool_hint,
    }


@router.post("/smoke-test")
async def smoke_test(req: SmokeTestRequest, request: Request):
    """Run a quick smoke test against the app."""
    root: Path = request.app.state.root
    try:
        from patchi.core.testing.live_v2.browser_test_runner import BrowserTestRunner

        runner = BrowserTestRunner(root, base_url=req.url)
        result = await runner.run_smoke_test(req.url)
        data = result.to_dict()
        data.setdefault("ok", data.get("failed", 1) == 0)
        return data
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": _playwright_error_message(e)},
        )


@router.post("/stress-test")
async def stress_test(req: StressTestRequest, request: Request):
    """Start a stress test against the app."""
    if _stress_state["running"]:
        return JSONResponse(
            status_code=409,
            content={"error": "Stress test already running"},
        )

    _stress_state["running"] = True
    _stress_state["cancelled"] = False

    try:
        from patchi.core.testing.live_v2.stress_orchestrator import (
            StressConfig,
            StressOrchestrator,
        )

        config = StressConfig(
            base_url=req.url,
            users=req.users,
            duration_seconds=req.duration_seconds,
            ramp_up_seconds=req.ramp_up_seconds,
        )
        orchestrator = StressOrchestrator(config)
        _stress_state["task"] = asyncio.current_task()
        report = await orchestrator.run()
        if _stress_state["cancelled"]:
            return JSONResponse({"ok": False, "message": "Stress test was cancelled"})
        _stress_state["last_result"] = report.to_dict()
        data = report.to_dict()
        data.setdefault("ok", True)
        return data
    except asyncio.CancelledError:
        return JSONResponse({"ok": False, "message": "Stress test was cancelled"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": _playwright_error_message(e)})
    finally:
        _stress_state["running"] = False
        _stress_state["task"] = None


@router.get("/stress-result")
async def stress_result():
    """Get the last stress test result."""
    return _stress_state["last_result"] or {"message": "No stress test results yet"}


@router.post("/stress-cancel")
async def cancel_stress() -> JSONResponse:
    """Cancel a running stress test."""
    if not _stress_state["running"]:
        return JSONResponse({"ok": True, "message": "No stress test running"})
    _stress_state["cancelled"] = True
    task = _stress_state.get("task")
    if task and not task.done():
        task.cancel()
    return JSONResponse({"ok": True, "message": "Stress test cancellation requested"})


@router.post("/dast-cancel")
async def cancel_dast() -> JSONResponse:
    """Cancel a running DAST scan."""
    if not _dast_state["running"]:
        return JSONResponse({"ok": True, "message": "No DAST scan running"})
    _dast_state["cancelled"] = True
    task = _dast_state.get("task")
    if task and not task.done():
        task.cancel()
    return JSONResponse({"ok": True, "message": "DAST scan cancellation requested"})


@router.post("/smoke-cancel")
async def cancel_smoke() -> JSONResponse:
    """Cancel a running smoke test."""
    if not _smoke_state["running"]:
        return JSONResponse({"ok": True, "message": "No smoke test running"})
    _smoke_state["cancelled"] = True
    task = _smoke_state.get("task")
    if task and not task.done():
        task.cancel()
    return JSONResponse({"ok": True, "message": "Smoke test cancellation requested"})


@router.get("/operations")
async def list_operations():
    """List all currently running operations across the system."""
    ops = []
    # Check scan state
    try:
        from patchi.web.api.scan import _scan_state

        if _scan_state.get("running"):
            ops.append({"type": "scan", "label": "Security Scan", "cancel_url": "/api/scan/cancel"})
    except Exception as _exc:
        _log.warning("list_operations failed: %s", _exc)
    if _stress_state["running"]:
        ops.append(
            {
                "type": "stress",
                "label": "Stress Test",
                "cancel_url": "/api/live-testing/stress-cancel",
            }
        )
    if _dast_state["running"]:
        ops.append({"type": "dast", "label": "DAST Scan", "cancel_url": "/api/live-testing/dast-cancel"})
    if _smoke_state["running"]:
        ops.append({"type": "smoke", "label": "Smoke Test", "cancel_url": "/api/live-testing/smoke-cancel"})
    if _audit_state["running"]:
        ops.append({"type": "audit", "label": "Browser Audit", "cancel_url": ""})
    try:
        from patchi.web.api.smart import _current_task

        if _current_task and not _current_task.done():
            ops.append({"type": "smart", "label": "Smart Agent", "cancel_url": "/api/smart/cancel"})
    except Exception as _exc:
        _log.warning("list_operations failed: %s", _exc)
    return JSONResponse({"ok": True, "operations": ops, "count": len(ops)})


@router.post("/screenshot")
async def capture_screenshot(req: SmokeTestRequest, request: Request):
    """Capture a screenshot of the app."""
    root: Path = request.app.state.root
    try:
        from patchi.core.testing.live_v2.browser_pool import get_browser_pool
        from patchi.core.testing.live_v2.screenshot_manager import ScreenshotManager

        evidence_dir = root / ".patchi" / "evidence" / "screenshots"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        screenshot_mgr = ScreenshotManager(evidence_dir)
        pool = await get_browser_pool()

        page = await pool.get_page()
        try:
            await page.goto(req.url, wait_until="domcontentloaded")
            ss_result = await screenshot_mgr.capture(page, req.url, name="manual_screenshot")
            # image_path is absolute; expose the servable filename + relative path
            from pathlib import Path as _P

            p = _P(str(ss_result.image_path))
            try:
                rel = str(p.relative_to(root))
            except ValueError:
                rel = p.name
            return {
                "success": True,
                "ok": True,
                "path": rel,
                "filename": p.name,
                "size": ss_result.file_size,
            }
        finally:
            await pool.release_page(page)
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": _playwright_error_message(e)})


@router.get("/browser-pool-stats")
async def browser_pool_stats():
    """Get browser pool statistics."""
    try:
        from patchi.core.testing.live_v2.browser_pool import get_browser_pool

        pool = await get_browser_pool()
        stats = pool.get_stats()
        # Back-compat alias: frontend expects `active_browsers`
        stats.setdefault("active_browsers", stats.get("current_active", 0))
        stats["playwright_installed"] = True
        return stats
    except Exception as e:
        return {
            "error": _playwright_error_message(e),
            "active_browsers": 0,
            "playwright_installed": False,
            "install_url": "/api/live-testing/install-browsers",
        }


def _run_playwright_install() -> dict:
    """Run `playwright install chromium` synchronously (called via to_thread)."""
    import subprocess
    import sys

    _install_state["log"].append("Running: playwright install chromium")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True,
            text=True,
            timeout=600,
        )
        tail = (proc.stdout + "\n" + proc.stderr).strip().splitlines()
        _install_state["log"].extend(tail[-20:])
        ok = proc.returncode == 0
        result = {
            "ok": ok,
            "returncode": proc.returncode,
            "log": _install_state["log"][-20:],
        }
        if not ok:
            result["error"] = f"playwright install exited {proc.returncode}"
        # Reset the global pool so the next call re-initializes with browsers
        try:
            import patchi.core.testing.live_v2.browser_pool as _bp

            _bp._browser_pool = None
        except Exception:
            pass
        return result
    except Exception as e:
        _install_state["log"].append(f"FAILED: {e}")
        return {"ok": False, "error": str(e), "log": _install_state["log"][-20:]}


@router.post("/install-browsers")
async def install_browsers():
    """One-click Playwright browser install (chromium). Long-running."""
    if _install_state["running"]:
        return JSONResponse(
            status_code=409,
            content={
                "ok": False,
                "message": "Install already running",
                "log": _install_state["log"][-20:],
            },
        )
    _install_state["running"] = True
    _install_state["log"] = []
    try:
        result = await asyncio.to_thread(_run_playwright_install)
        _install_state["last_result"] = result
        if result.get("ok"):
            return result
        return JSONResponse(status_code=500, content=result)
    finally:
        _install_state["running"] = False


@router.get("/install-browsers")
async def install_browsers_status():
    """Install status: running flag + last result + log tail."""
    return {
        "ok": True,
        "running": _install_state["running"],
        "last_result": _install_state["last_result"],
        "log": _install_state["log"][-20:],
    }


def _ads_dirs(root: Path) -> list[Path]:
    """Ads gallery viewport subdirs (evidence/ads/<WxH>/), if present."""
    base = root / ".patchi" / "evidence" / "ads"
    if not base.is_dir():
        return []
    try:
        return [d for d in sorted(base.iterdir()) if d.is_dir()]
    except OSError:
        return []


@router.get("/videos")
async def list_videos(request: Request):
    """List all recorded video evidence files."""
    root: Path = request.app.state.root
    video_dirs = [
        root / ".patchi" / "evidence" / "video",
        root / ".patchi" / "evidence" / "browser_tests" / "video",
        *_ads_dirs(root),
    ]

    videos = []
    seen_names: set[str] = set()
    for video_dir in video_dirs:
        if not video_dir.is_dir():
            continue
        for f in sorted(video_dir.glob("*.webm"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                stat = f.stat()
                # Deduplicate by filename across directories
                if f.name in seen_names:
                    continue
                seen_names.add(f.name)
                videos.append(
                    {
                        "name": f.stem,
                        "filename": f.name,
                        "path": str(f.relative_to(root)),
                        "size_bytes": stat.st_size,
                        "size_kb": round(stat.st_size / 1024, 1),
                        "timestamp": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                    }
                )
            except Exception as _exc:
                _log.warning("list_videos failed: %s", _exc)
    # Sort all videos by mtime descending
    videos.sort(key=lambda v: v["timestamp"], reverse=True)

    return JSONResponse(
        {
            "ok": True,
            "videos": videos[:50],
            "total": len(videos),
            "total_size_kb": sum(v["size_kb"] for v in videos),
        }
    )


@router.get("/video/{filename}")
async def serve_video(filename: str, request: Request):
    """Serve a video recording file for playback."""
    root: Path = request.app.state.root
    # Check multiple video directories
    video_dirs = [
        root / ".patchi" / "evidence" / "video",
        root / ".patchi" / "evidence" / "browser_tests" / "video",
        *_ads_dirs(root),
    ]

    # Security: only allow .webm files
    import re as _re

    if not _re.match(r"^[a-zA-Z0-9_@.\-]+\.webm$", filename):
        return JSONResponse({"error": "Invalid filename"}, status_code=403)

    for video_dir in video_dirs:
        file_path = video_dir / filename
        if file_path.exists() and file_path.is_file():
            try:
                file_path.resolve().relative_to(root.resolve())
            except ValueError:
                return JSONResponse({"error": "Access denied"}, status_code=403)
            from starlette.responses import FileResponse

            return FileResponse(file_path, media_type="video/webm")

    return JSONResponse({"error": "Video not found"}, status_code=404)


@router.post("/visual-regression")
async def run_visual_regression(request: Request):
    """Run visual regression agent — captures screenshots of all pages,
    compares against baselines, and generates pixel-diff overlays."""
    root: Path = request.app.state.root
    try:
        import asyncio

        from patchi.core import config as cfg
        from patchi.core import memory as mem
        from patchi.core.agents.base import AgentInput, AgentResult
        from patchi.core.testing.visual_regression_agent import VisualRegressionAgent

        config = cfg.load(root) if root.exists() else {}
        brain = mem.get_brain(root)
        inp = AgentInput(root=root, scope=[], brain=brain, config=config)
        result = AgentResult(agent_name="VisualRegressionAgent")

        agent = VisualRegressionAgent()
        # Run sync agent in thread pool so we don't block the event loop
        await asyncio.to_thread(agent._run, inp, result)

        return {
            "ok": True,
            "screenshots": result.data.get("suite", {}).get("screenshots", 0),
            "regressions": result.data.get("suite", {}).get("regressions", 0),
            "new_baselines": result.data.get("suite", {}).get("new_baselines", 0),
            "error_pages": result.data.get("suite", {}).get("error_pages", 0),
            "findings": [f.to_dict() for f in result.findings],
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@router.get("/screenshots")
async def list_screenshots(request: Request):
    """List visual regression screenshots and diff images."""
    root: Path = request.app.state.root
    shot_base = root / ".patchi" / "evidence" / "screenshots"
    evidence_dirs = [
        shot_base / "visual_regression",
        shot_base / "current",
        shot_base,
    ]
    baseline_dir = root / ".patchi" / "visual_baselines"

    screenshots = []
    seen: set[str] = set()
    for evidence_dir in evidence_dirs:
        if not evidence_dir.is_dir():
            continue
        for f in sorted(evidence_dir.glob("*.png"), key=lambda x: x.stat().st_mtime, reverse=True):
            if f.name in seen:
                continue
            seen.add(f.name)
            try:
                stat = f.stat()
                is_diff = "_diff" in f.stem
                screenshots.append(
                    {
                        "name": f.stem,
                        "filename": f.name,
                        "path": str(f.relative_to(root)),
                        "size_kb": round(stat.st_size / 1024, 1),
                        "timestamp": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                        "is_diff": is_diff,
                    }
                )
            except Exception as _exc:
                _log.warning("list_screenshots failed: %s", _exc)

    baseline_count = 0
    if baseline_dir.is_dir():
        baseline_count = len(list(baseline_dir.rglob("*.png")))

    return JSONResponse(
        {
            "ok": True,
            "screenshots": screenshots[:100],
            "total": len(screenshots),
            "baselines": baseline_count,
            "total_size_kb": round(sum(s["size_kb"] for s in screenshots), 1),
        }
    )


@router.get("/screenshot/{filename}")
async def serve_screenshot(filename: str, request: Request):
    """Serve a screenshot file."""
    root: Path = request.app.state.root
    evidence_dir = root / ".patchi" / "evidence" / "screenshots"
    candidates = [
        evidence_dir / filename,
        evidence_dir / "current" / filename,
        evidence_dir / "visual_regression" / filename,
    ]

    if not filename.endswith(".png"):
        return JSONResponse({"error": "Only .png files allowed"}, status_code=403)

    for file_path in candidates:
        try:
            file_path.resolve().relative_to(evidence_dir.resolve())
        except ValueError:
            return JSONResponse({"error": "Access denied"}, status_code=403)
        if file_path.is_file():
            from starlette.responses import FileResponse

            return FileResponse(file_path, media_type="image/png")

    # Fall back to ads gallery viewport subdirs
    for ads_dir in _ads_dirs(root):
        cand = ads_dir / filename
        try:
            cand.resolve().relative_to(ads_dir.resolve())
        except ValueError:
            return JSONResponse({"error": "Access denied"}, status_code=403)
        if cand.is_file():
            from starlette.responses import FileResponse

            return FileResponse(cand, media_type="image/png")
    return JSONResponse({"error": "Screenshot not found"}, status_code=404)


@router.get("/ads-gallery")
async def ads_gallery(request: Request):
    """Marketing gallery groups (viewport → screenshots + videos)."""
    root: Path = request.app.state.root
    groups: list[dict] = []
    for vdir in _ads_dirs(root):
        try:
            shots = sorted(
                (p.name for p in vdir.glob("*.png") if p.is_file()),
                key=lambda n: (vdir / n).stat().st_mtime,
                reverse=True,
            )
            vids = sorted(
                (p.name for p in vdir.glob("*.webm") if p.is_file()),
                key=lambda n: (vdir / n).stat().st_mtime,
                reverse=True,
            )
        except OSError:
            shots, vids = [], []
        if shots or vids:
            groups.append({"viewport": vdir.name, "screenshots": shots, "videos": vids})
    return JSONResponse({"ok": True, "groups": groups})


# ── Full-Page Browser Audit ───────────────────────────────────────────────


class FullAuditRequest(BaseModel):
    url: str = "http://127.0.0.1:1612"
    routes: list[str] | None = None


@router.post("/full-audit")
async def run_full_audit(req: FullAuditRequest, request: Request):
    """Run full-page browser audit — navigates every page, captures
    HTTP status, console errors, page errors, load time, screenshots,
    broken images, empty links, and page metrics."""
    root: Path = request.app.state.root

    if _audit_state["running"]:
        return JSONResponse(status_code=409, content={"error": "Audit already running"})

    _audit_state["running"] = True
    try:
        import asyncio

        result = await asyncio.to_thread(
            _run_audit_sync,
            req.url,
            root,
            req.routes,
        )
        return result
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})
    finally:
        _audit_state["running"] = False


@router.get("/full-audit")
async def get_full_audit(request: Request):
    """Get the last full-page audit results, or current progress if running."""
    if _audit_state["running"]:
        return {"running": True, "progress": _audit_state["progress"]}

    # Try to load persisted results
    if _audit_state["last_result"]:
        return _audit_state["last_result"]

    root: Path = request.app.state.root
    audit_file = root / ".patchi" / "evidence" / "browser_audit" / "audit_results.json"
    if audit_file.exists():
        try:
            return json.loads(audit_file.read_text(encoding="utf-8"))
        except Exception as _exc:
            _log.warning("get_full_audit failed: %s", _exc)

    return {"ok": False, "message": "No audit results yet. Run a full-page audit first."}


@router.get("/full-audit/progress")
async def full_audit_progress():
    """Poll audit progress while running."""
    if not _audit_state["running"]:
        return {"running": False}
    return {"running": True, "progress": _audit_state["progress"]}


@router.get("/full-audit/screenshot/{filename}")
async def serve_audit_screenshot(filename: str, request: Request):
    """Serve a full-page audit screenshot."""
    root: Path = request.app.state.root
    evidence_dir = root / ".patchi" / "evidence" / "browser_audit"
    file_path = evidence_dir / filename

    if not file_path.suffix == ".png":
        return JSONResponse({"error": "Only .png files allowed"}, status_code=403)
    try:
        file_path.resolve().relative_to(evidence_dir.resolve())
    except ValueError:
        return JSONResponse({"error": "Access denied"}, status_code=403)

    if not file_path.exists():
        return JSONResponse({"error": "Screenshot not found"}, status_code=404)

    from starlette.responses import FileResponse

    return FileResponse(file_path, media_type="image/png")
