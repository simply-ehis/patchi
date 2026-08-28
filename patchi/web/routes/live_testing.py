"""Live Testing page — merged into the unified UI.

The live testing monitor lives at /live-tests (templates_v2). This legacy
path redirects there so old links keep working.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/live-testing")
async def live_testing_page():
    """Legacy path — forwards to the unified live tests page."""
    return RedirectResponse(url="/live-tests", status_code=307)
