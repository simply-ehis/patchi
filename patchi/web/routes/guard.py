"""Guard route — hosted guard monitoring."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/guard", response_class=HTMLResponse)
async def guard(request: Request):
    root = request.app.state.root
    from patchi.core import config as cfg

    try:
        config = cfg.load(root)
    except Exception:
        config = {}

    hosted = config.get("hosted", {})

    return templates.TemplateResponse(
        request,
        "guard.html",
        {
            "request": request,
            "enabled": hosted.get("enabled", False),
            "log_path": hosted.get("log_path", ""),
        },
    )
