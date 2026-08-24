"""Findings route — findings list with filters."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/findings", response_class=HTMLResponse)
async def findings(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    mem.get_brain(root)
    scan_results = mem.get_scan_results(root)

    # Flatten findings from all agents
    all_findings = []
    for agent_name, data in scan_results.items():
        for f in data.get("findings", []):
            f["agent"] = agent_name
            all_findings.append(f)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "request": request,
            "findings": all_findings,
            "total": len(all_findings),
        },
    )
