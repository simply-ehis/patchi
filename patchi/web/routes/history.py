"""History route — scan and fix history with filtering/sorting."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

logger = logging.getLogger("patchi.web.history")

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    patches = mem.list_patches(root)

    scan_history = []
    try:
        from patchi.core.security.history import patchi_get_history

        scan_history = patchi_get_history(root, limit=100)
    except Exception as e:
        logger.warning("Failed to fetch scan history: %s", e)

    # Extract unique tools for filter dropdown
    tools = sorted({s.get("tool", "unknown") for s in scan_history})

    return templates.TemplateResponse(
        request,
        "history.html",
        {
            "request": request,
            "patches": patches,
            "scan_history": scan_history,
            "scan_history_json": json.dumps(scan_history),
            "tools": tools,
            "file_count": brain.get("file_count", 0),
            "route_count": brain.get("route_count", 0),
            "framework": brain.get("framework", "Unknown"),
        },
    )


@router.get("/api/history/filter")
async def filter_history(
    request: Request,
    date_from: str | None = Query(None, description="Start date (YYYY-MM-DD)"),
    date_to: str | None = Query(None, description="End date (YYYY-MM-DD)"),
    severity: str | None = Query(None, description="Comma-separated severities"),
    tool: str | None = Query(None, description="Filter by tool name"),
    sort_by: str = Query("timestamp", description="Sort field"),
    sort_dir: str = Query("desc", description="Sort direction (asc/desc)"),
    limit: int = Query(50, description="Max results"),
):
    """Filter and sort scan history."""
    root = request.app.state.root

    try:
        from patchi.core.security.history import patchi_get_history

        all_history = patchi_get_history(root, limit=200)
    except Exception as e:
        logger.warning("Failed to fetch scan history: %s", e)
        all_history = []

    # Apply filters
    filtered = all_history

    # Date range filter
    if date_from:
        filtered = [s for s in filtered if s.get("timestamp", "") >= date_from]
    if date_to:
        # Include the full end day
        filtered = [s for s in filtered if s.get("timestamp", "") <= date_to + "T23:59:59"]

    # Severity filter (check if any matching severity has count > 0)
    if severity:
        sev_list = [s.strip() for s in severity.split(",") if s.strip()]
        if sev_list:
            filtered = [s for s in filtered if any(s.get("severity_breakdown", {}).get(sev, 0) > 0 for sev in sev_list)]

    # Tool filter
    if tool and tool != "all":
        filtered = [s for s in filtered if s.get("tool", "") == tool]

    # Sorting
    reverse = sort_dir == "desc"
    if sort_by == "timestamp":
        filtered.sort(key=lambda s: s.get("timestamp", ""), reverse=reverse)
    elif sort_by == "findings":
        filtered.sort(key=lambda s: s.get("findings_count", 0), reverse=reverse)
    elif sort_by == "health":
        filtered.sort(key=lambda s: s.get("health_score", 0), reverse=reverse)
    elif sort_by == "duration":
        filtered.sort(key=lambda s: s.get("duration_ms", 0), reverse=reverse)
    elif sort_by == "severity":
        # Sort by total critical+high findings
        def _sev_score(s):
            sb = s.get("severity_breakdown", {})
            return sb.get("critical", 0) * 100 + sb.get("high", 0) * 10

        filtered.sort(key=_sev_score, reverse=reverse)

    # Limit
    filtered = filtered[:limit]

    return JSONResponse(
        {
            "total": len(all_history),
            "filtered": len(filtered),
            "results": filtered,
        }
    )
