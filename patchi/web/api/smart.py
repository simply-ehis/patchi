"""
Web API + page for the Smart Agent (now powered by the Orchestrator brain).

POST /api/smart/run  — kicks off an Orchestrator run; every tool event is streamed
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

_current_task: "asyncio.Task | None" = None


class SmartRunRequest(BaseModel):
    goal: str
    max_steps: int = 10


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

    def on_progress(msg: str) -> None:
        try:
            asyncio.run_coroutine_threadsafe(
                manager.broadcast("agent.progress", {
                    "agent": "orchestrator",
                    "progress_pct": 0,
                    "current_file": msg,
                }), loop
            )
        except Exception as _exc:
            _log.warning('on_progress failed: %s', _exc)

    async def _run() -> None:
        from patchi.core.ai.orchestrator import Orchestrator

        orchestrator = Orchestrator(
            root,
            on_event=on_event,
            on_progress=on_progress,
        )
        try:
            await orchestrator.run(req.goal, max_steps=req.max_steps)
        except Exception as e:
            _log.error("Orchestrator run failed: %s", e)
            on_event({
                "event": "agent.error",
                "data": {"agent": "orchestrator", "error": str(e)},
            })

    global _current_task
    _current_task = asyncio.create_task(_run())
    return {
        "success": True,
        "message": "Orchestrator started — events stream over /ws",
        "goal": req.goal,
    }


@router.post("/api/smart/cancel")
async def smart_cancel() -> dict:
    """Cancel a running Orchestrator run, if any."""
    global _current_task
    task = _current_task
    if task is None or task.done():
        return {
            "success": True,
            "message": "No active Orchestrator run to cancel",
            "cancelled": False,
        }
    task.cancel()
    _current_task = None
    return {
        "success": True,
        "message": "Orchestrator run cancelled",
        "cancelled": True,
    }


_SMART_HTML = None


@router.get("/smart", response_class=HTMLResponse)
async def smart_page(request: Request):
    global _SMART_HTML
    if _SMART_HTML is None:
        p = Path(__file__).resolve().parent.parent / "templates" / "smart.html"
        _SMART_HTML = p.read_text(encoding="utf-8")
    return HTMLResponse(_SMART_HTML)
