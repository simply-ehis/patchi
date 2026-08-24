"""Dashboard route — Brain Map + security overview."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates as _Jinja2Templates

router = APIRouter()

templates = _Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
templates.env.filters["tojson"] = lambda v: json.dumps(v)


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    health = brain.get("health_score", {})

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "request": request,
            "health_score": health.get("total", 0),
            "health_grade": health.get("grade", "?"),
            "health_components": health.get("components", {}),
            "file_count": brain.get("file_count", 0),
            "route_count": brain.get("route_count", 0),
            "framework": brain.get("framework", "Unknown"),
            "languages": brain.get("languages", {}),
            "dead_files": brain.get("dead_files", []),
            "scan_time": brain.get("last_scan", "Never"),
        },
    )
