"""Guard API — HTMX fragments for hosted guard monitoring."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

logger = logging.getLogger("patchi.web.api.guard")

router = APIRouter(prefix="/api/guard")


@router.get("/threats", response_class=HTMLResponse)
async def get_threats(request: Request) -> str:
    root = request.app.state.root
    lines = [
        "<table style='width:100%;font-size:12px;'>",
        "<tr><th>IP</th><th>Score</th><th>Reason</th></tr>",
    ]
    try:
        from patchi.core.hosted.watchlist import WatchlistTracker

        tracker = WatchlistTracker(root)
        for t in tracker.top(10):
            ip = t.get("ip", "?")
            score = t.get("score", 0)
            reason = (t.get("reason", "") or "")[:60]
            lines.append(
                f"<tr><td style='font-family:var(--font-mono)'>{ip}</td><td>{score}</td><td>{reason}</td></tr>"
            )
    except Exception:
        lines.append("<tr><td colspan='3'>No threats</td></tr>")
    lines.append("</table>")
    return "".join(lines)


@router.get("/live", response_class=HTMLResponse)
async def get_live(request: Request) -> str:
    root = request.app.state.root
    lines: list[str] = []
    try:
        import time

        from patchi.core.hosted.audit_log import read_recent

        raw = read_recent(root, 10)
        for e in reversed(raw):
            ts = e.get("timestamp", 0)
            tstr = time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "--:--:--"
            data = e.get("data", {})
            msg = data.get("title", data.get("message", e.get("event", "")))
            lines.append(
                f"<div style='margin-bottom:3px'>"
                f"<span style='color:var(--text-dim)'>{tstr}</span> "
                f"<span>{msg}</span>"
                f"</div>"
            )
    except Exception as e:
        logger.warning("Failed to load recent audit events: %s", e)
    if not lines:
        lines.append("<div style='color:var(--text-dim)'>No recent events</div>")
    return "".join(lines)
