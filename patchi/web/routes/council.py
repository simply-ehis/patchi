"""Routes for council, attack timeline, and hosted pages.

Migrated from dashboard_v2.py to use v1 templates (extending base.html).
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates

router = APIRouter()

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
templates.env.filters["tojson"] = lambda v: json.dumps(v)


@router.get("/council", response_class=HTMLResponse)
async def council_page(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    council_sessions = mem.read(mem.MemoryCategory.ISSUES, root)
    council_sessions = [s for s in council_sessions if s.get("type") == "council_session"]

    return templates.TemplateResponse(
        request,
        "council.html",
        {"request": request, "council_sessions": council_sessions[-20:]},
    )


@router.get("/attacks", response_class=HTMLResponse)
async def attacks_page(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    scan_results = mem.get_scan_results(root)
    attack_data = scan_results.get("RedTeamEngineAgent", {})

    return templates.TemplateResponse(
        request,
        "attacks.html",
        {"request": request, "attack_data": attack_data},
    )


@router.get("/hosted", response_class=HTMLResponse)
async def hosted_page(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    scan_results = mem.get_scan_results(root)
    attack_data = scan_results.get("RedTeamEngineAgent", {})

    return templates.TemplateResponse(
        request,
        "hosted.html",
        {
            "request": request,
            "active_domains": brain.get("active_security_domains", []),
            "attack_data": attack_data,
        },
    )
