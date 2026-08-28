"""Public marketing landing — Snyk × Linear style, standalone.

Not the localhost app dashboard (/). This is the external-facing
story: hero + 3-up + Brain + Council + Live Tests + CLI parity + freemium.
Shares tokens with the app but is a separate band layout for marketing.
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


@router.get("/landing", response_class=HTMLResponse)
@router.get("/welcome", response_class=HTMLResponse)
async def landing(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem
    from patchi.core.health import compute as compute_health

    brain = mem.get_brain(root)
    hs = compute_health(root)

    # Stats for hero proof + metrics
    scan_results = mem.get_scan_results(root)
    total_findings = sum(len(v.get("findings", [])) for v in scan_results.values() if isinstance(v, dict))

    return templates.TemplateResponse(
        request,
        "landing.html",
        {
            "request": request,
            "health_score": hs.total,
            "health_grade": hs.grade,
            "file_count": brain.get("file_count", 0),
            "route_count": brain.get("route_count", 0),
            "framework": brain.get("framework", "Unknown"),
            "languages": brain.get("languages", {}),
            "recent_findings": total_findings,
            "active_domains": brain.get("active_security_domains", [])[:6],
            "project_purpose": brain.get("project_purpose", "AI-powered code security & quality agent colony"),
        },
    )
