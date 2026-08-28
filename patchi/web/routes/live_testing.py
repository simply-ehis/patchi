"""Live Testing page — renders using v1 template (base.html)."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates

router = APIRouter()

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
templates.env.filters["tojson"] = lambda v: json.dumps(v)


@router.get("/live-testing", response_class=HTMLResponse)
async def live_testing_page(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    scan_results = mem.get_scan_results(root)
    test_data = scan_results.get("TestRunner", {})

    return templates.TemplateResponse(
        request,
        "live_testing.html",
        {"request": request, "test_data": test_data},
    )
