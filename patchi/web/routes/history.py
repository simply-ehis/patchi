"""History route — scan and fix history."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

logger = logging.getLogger("patchi.web.history")

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    patches = mem.list_patches(root)

    scan_history = []
    try:
        from patchi.core.security.history import patchi_get_history

        scan_history = patchi_get_history(root, limit=30)
    except Exception as e:
        logger.warning("Failed to fetch scan history: %s", e)

    return templates.TemplateResponse(
        request,
        "history.html",
        {
            "request": request,
            "patches": patches,
            "scan_history": scan_history,
            "file_count": brain.get("file_count", 0),
            "route_count": brain.get("route_count", 0),
            "framework": brain.get("framework", "Unknown"),
        },
    )
