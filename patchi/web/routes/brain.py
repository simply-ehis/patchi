"""Brain route — brain knowledge viewer."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/brain", response_class=HTMLResponse)
async def brain(request: Request):
    root = request.app.state.root
    brain_md_path = root / ".patchi" / "BRAIN.md"

    import re

    content = ""
    if brain_md_path.exists():
        raw = brain_md_path.read_text(encoding="utf-8")
        content = re.sub(r"<[^>]*>", "", raw)
    else:
        content = "*No brain data yet. Run `p scan` first.*"

    return templates.TemplateResponse(
        request,
        "brain.html",
        {
            "request": request,
            "brain_content": content,
        },
    )
