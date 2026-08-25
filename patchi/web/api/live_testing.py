"""Live Testing API — browser tests, screenshots, stress tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/live-testing")


class StressTestRequest(BaseModel):
    url: str = "http://127.0.0.1:1612"
    users: int = 10
    duration_seconds: int = 30
    ramp_up_seconds: int = 5


class SmokeTestRequest(BaseModel):
    url: str = "http://127.0.0.1:1612"


# ── State ────────────────────────────────────────────────────────────────────

_stress_state = {"running": False, "last_result": None}


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/status")
async def status(request: Request):
    """Get live testing status."""
    root: Path = request.app.state.root
    return {
        "stress_running": _stress_state["running"],
        "evidence_dir": str(root / ".patchi" / "evidence"),
        "has_browser_pool": True,
    }


@router.post("/smoke-test")
async def smoke_test(req: SmokeTestRequest, request: Request):
    """Run a quick smoke test against the app."""
    root: Path = request.app.state.root
    try:
        from patchi.core.testing.live_v2.browser_test_runner import BrowserTestRunner
        runner = BrowserTestRunner(root, base_url=req.url)
        result = await runner.run_smoke_test(req.url)
        return result.to_dict()
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)},
        )


@router.post("/stress-test")
async def stress_test(req: StressTestRequest, request: Request):
    """Start a stress test against the app."""
    if _stress_state["running"]:
        return JSONResponse(
            status_code=409,
            content={"error": "Stress test already running"},
        )

    root: Path = request.app.state.root
    _stress_state["running"] = True

    try:
        from patchi.core.testing.live_v2.stress_orchestrator import (
            StressOrchestrator,
            StressConfig,
        )
        config = StressConfig(
            target_url=req.url,
            concurrent_users=req.users,
            duration_seconds=req.duration_seconds,
            ramp_up_seconds=req.ramp_up_seconds,
        )
        orchestrator = StressOrchestrator(root, config)
        report = await orchestrator.run()
        _stress_state["last_result"] = report.to_dict()
        return report.to_dict()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        _stress_state["running"] = False


@router.get("/stress-result")
async def stress_result():
    """Get the last stress test result."""
    return _stress_state["last_result"] or {"message": "No stress test results yet"}


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
            ss_path = await screenshot_mgr.capture(page, "manual_screenshot")
            return {"success": True, "path": str(ss_path)}
        finally:
            await pool.release_page(page)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/browser-pool-stats")
async def browser_pool_stats():
    """Get browser pool statistics."""
    try:
        from patchi.core.testing.live_v2.browser_pool import get_browser_pool
        pool = await get_browser_pool()
        return pool.get_stats()
    except Exception as e:
        return {"error": str(e)}
