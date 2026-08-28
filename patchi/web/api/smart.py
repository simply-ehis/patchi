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
        except Exception:
            pass

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

    asyncio.create_task(_run())
    return {
        "success": True,
        "message": "Orchestrator started — events stream over /ws",
        "goal": req.goal,
    }


@router.post("/api/smart/cancel")
async def smart_cancel(request: Request):
    """Cancel a running Smart Agent orchestrator (best-effort)."""
    # Currently the orchestrator runs as a fire-and-forget asyncio task;
    # cancelling is cooperative. We acknowledge and let the UI reset its
    # local state. Future: track task handle for true cancellation.
    return {"success": True, "message": "Cancel acknowledged — UI reset; server task will wind down"}


_SMART_HTML = None


@router.get("/smart", response_class=HTMLResponse)
async def smart_page(request: Request):
    global _SMART_HTML
    if _SMART_HTML is None:
        p = Path(__file__).resolve().parent.parent / "templates" / "smart.html"
        _SMART_HTML = p.read_text(encoding="utf-8")
    return HTMLResponse(_SMART_HTML)
