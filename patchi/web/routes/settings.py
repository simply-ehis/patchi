"""Settings route — web UI configuration panel."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    root = request.app.state.root
    from patchi.core import config as cfg
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    config = cfg.load(root)

    safe_keys = {
        "mode",
        "theme",
        "device_tier",
        "scan_depth",
        "risk_threshold",
        "queue_mode",
        "quiet_hours_start",
        "quiet_hours_end",
        "max_parallel_agents",
        "max_queue_depth",
        "websocket_timeout",
    }
    safe_config = {k: v for k, v in config.items() if k in safe_keys}

    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "request": request,
            "config": safe_config,
            "framework": brain.get("framework", "Unknown"),
            "health_score": brain.get("health_score", {}).get("total", 0),
            "ai_keys": len(config.get("ai", {}).get("keys", [])),
        },
    )
