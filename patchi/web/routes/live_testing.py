"""Live Testing page — browser automation, screenshots, stress tests."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from starlette.templating import Jinja2Templates

router = APIRouter()
_templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/live-tests", include_in_schema=False)
async def live_tests_page(request: Request):
    """Render the live testing dashboard (canonical; dashboard.py duplicate removed)."""
    root = request.app.state.root
    try:
        from patchi.core import memory as mem

        test_data = (mem.get_scan_results(root) or {}).get("TestRunner", {})
    except Exception:
        test_data = {}
    return _templates.TemplateResponse(
        request, "live_testing.html", {"request": request, "test_data": test_data}
    )


@router.get("/live-testing")
async def live_testing_redirect():
    """Legacy path — forwards to the unified live tests page."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/live-tests", status_code=307)
