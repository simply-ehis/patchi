"""Live Testing API — browser tests, screenshots, stress tests."""

from __future__ import annotations

from datetime import UTC, datetime
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

    _stress_state["running"] = True

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
            ss_result = await screenshot_mgr.capture(page, req.url, name="manual_screenshot")
            return {"success": True, "path": ss_result.image_path, "size": ss_result.file_size}
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


@router.get("/videos")
async def list_videos(request: Request):
    """List all recorded video evidence files."""
    root: Path = request.app.state.root
    video_dir = root / ".patchi" / "evidence" / "video"

    videos = []
    if video_dir.is_dir():
        for f in sorted(video_dir.glob("*.webm"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                stat = f.stat()
                videos.append({
                    "name": f.stem,
                    "filename": f.name,
                    "path": str(f.relative_to(root)),
                    "size_bytes": stat.st_size,
                    "size_kb": round(stat.st_size / 1024, 1),
                    "timestamp": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                })
            except Exception:
                pass

    return JSONResponse({
        "ok": True,
        "videos": videos[:50],
        "total": len(videos),
        "total_size_kb": sum(v["size_kb"] for v in videos),
    })


@router.get("/video/{filename}")
async def serve_video(filename: str, request: Request):
    """Serve a video recording file for playback."""
    root: Path = request.app.state.root
    video_dir = root / ".patchi" / "evidence" / "video"
    file_path = video_dir / filename

    # Security: only allow .webm files from the video directory
    if not file_path.suffix == ".webm":
        return JSONResponse({"error": "Only .webm files allowed"}, status_code=403)
    try:
        file_path.resolve().relative_to(video_dir.resolve())
    except ValueError:
        return JSONResponse({"error": "Access denied"}, status_code=403)

    if not file_path.exists():
        return JSONResponse({"error": "Video not found"}, status_code=404)

    from starlette.responses import FileResponse
    return FileResponse(file_path, media_type="video/webm")


@router.post("/visual-regression")
async def run_visual_regression(request: Request):
    """Run visual regression agent — captures screenshots of all pages,
    compares against baselines, and generates pixel-diff overlays."""
    root: Path = request.app.state.root
    try:
        import asyncio
        from patchi.core.testing.visual_regression_agent import VisualRegressionAgent
        from patchi.core.agents.base import AgentInput, AgentResult
        from patchi.core import config as cfg, memory as mem

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
    evidence_dir = root / ".patchi" / "evidence" / "screenshots" / "visual_regression"
    baseline_dir = root / ".patchi" / "visual_baselines"

    screenshots = []
    if evidence_dir.is_dir():
        for f in sorted(evidence_dir.glob("*.png"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                stat = f.stat()
                is_diff = "_diff" in f.stem
                screenshots.append({
                    "name": f.stem,
                    "filename": f.name,
                    "path": str(f.relative_to(root)),
                    "size_kb": round(stat.st_size / 1024, 1),
                    "timestamp": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                    "is_diff": is_diff,
                })
            except Exception:
                pass

    baseline_count = 0
    if baseline_dir.is_dir():
        baseline_count = len(list(baseline_dir.rglob("*.png")))

    return JSONResponse({
        "ok": True,
        "screenshots": screenshots[:100],
        "total": len(screenshots),
        "baselines": baseline_count,
        "total_size_kb": round(sum(s["size_kb"] for s in screenshots), 1),
    })


@router.get("/screenshot/{filename}")
async def serve_screenshot(filename: str, request: Request):
    """Serve a screenshot file."""
    root: Path = request.app.state.root
    evidence_dir = root / ".patchi" / "evidence" / "screenshots"
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
