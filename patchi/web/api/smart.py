"""
Web API + page for the Smart Agent ("live view + control").

POST /api/smart/run  — kicks off a SmartAgent run; every tool event is streamed
                       live to all connected WebSocket clients (the "see it work
                       as it happens" view).
GET  /smart          — the control console page (type a goal, watch it run).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

_log = logging.getLogger("patchi.web.smart")

router = APIRouter()


class SmartRunRequest(BaseModel):
    goal: str
    max_steps: int = 6


@router.post("/api/smart/run")
async def smart_run(req: SmartRunRequest, request: Request):
    root = request.app.state.root
    loop = asyncio.get_event_loop()
    from patchi.web.ws import manager

    def on_event(payload: dict) -> None:
        try:
            asyncio.run_coroutine_threadsafe(
                manager.broadcast(payload["event"], payload["data"]), loop
            )
        except Exception as e:
            _log.debug("ws broadcast failed: %s", e)

    async def _run() -> None:
        from patchi.core.ai.smart import SmartAgent

        agent = SmartAgent(root, on_event=on_event, on_progress=lambda s: None)
        try:
            await agent.run(req.goal, max_steps=req.max_steps)
        except Exception as e:
            _log.error("SmartAgent run failed: %s", e)

    asyncio.create_task(_run())
    return {
        "success": True,
        "message": "SmartAgent started — events stream over /ws",
        "goal": req.goal,
    }


_SMART_HTML = None


@router.get("/smart", response_class=HTMLResponse)
async def smart_page(request: Request):
    global _SMART_HTML
    if _SMART_HTML is None:
        p = Path(__file__).resolve().parent.parent / "templates" / "smart.html"
        _SMART_HTML = p.read_text(encoding="utf-8")
    return HTMLResponse(_SMART_HTML)
