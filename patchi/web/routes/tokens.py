"""Tokens route — admin token management page."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/tokens", response_class=HTMLResponse)
async def tokens_page(request: Request):
    root = request.app.state.root
    from patchi.core.hosted import tokens as tokens_mod

    token_list = tokens_mod.list_tokens(root)

    return templates.TemplateResponse(
        request,
        "tokens.html",
        {
            "request": request,
            "tokens": token_list,
        },
    )
