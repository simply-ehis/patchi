"""Live Testing page — browser automation, screenshots, stress tests."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from starlette.templating import Jinja2Templates

router = APIRouter()
_templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/live-tests")
async def live_tests_page(request: Request):
    """Render the live testing dashboard."""
    return _templates.TemplateResponse("live_testing.html", {"request": request})


@router.get("/live-testing")
async def live_testing_redirect():
    """Legacy path — forwards to the unified live tests page."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/live-tests", status_code=307)
