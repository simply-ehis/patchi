"""Live Testing page — browser automation, screenshots, stress testing."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
_templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/live-testing", response_class=HTMLResponse)
async def live_testing_page(request: Request):
    """Render the live testing dashboard."""
    return _templates.TemplateResponse(
        "live_testing.html", {"request": request, "page": "live-testing"}
    )
