"""Scan API — trigger security scans."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

router = APIRouter(prefix="/api")


@router.post("/scan")
async def trigger_scan(request: Request, scan_type: str = "all") -> JSONResponse:
    """Trigger a security scan. Runs in background, sends progress via WebSocket."""
    root = request.app.state.root
    import patchi.core.security.security_agents  # noqa: F401
    from patchi.core import config as cfg
    from patchi.core import memory as mem
    from patchi.core.agents.base import AgentGroup, AgentInput, list_agents
    from patchi.web.ws import evt_scan_complete, evt_scan_progress, evt_scan_started

    try:
        config = cfg.load(root)
    except Exception:
        config = {}

    brain = mem.get_brain(root)

    # Determine agents to run — use dynamic registry, not hardcoded list
    all_agents = {a.name: a for a in list_agents(AgentGroup.SECURITY)}

    if scan_type == "all":
        # Run all registered security agents (excludes offensive/dev-only agents)
        _SKIP = {"SecurityProber", "RedTeamAgent"}  # offensive — dev mode only
        to_run = [a for a in list_agents(AgentGroup.SECURITY) if a.name not in _SKIP]
    elif scan_type in all_agents:
        to_run = [all_agents[scan_type]]
    else:
        return JSONResponse({"ok": False, "error": f"Unknown scan type: {scan_type}"})

    # Run scan in background
    async def _run():
        await evt_scan_started(len(to_run))

        results = []
        for i, agent_cls in enumerate(to_run):
            await evt_scan_progress(agent_cls.name, "scanning", i, len(to_run))

            inp = AgentInput(root=root, scope=[], brain=brain, config=config)
            result = await asyncio.to_thread(agent_cls().run, inp)
            results.append(result)

            await evt_scan_progress(agent_cls.name, "done", i + 1, len(to_run))

        total_findings = sum(r.finding_count for r in results)

        # Deduplicate + correlate via SecurityOrchestrator (WIRE-01)
        try:
            from patchi.core.security.orchestrator import SecurityOrchestrator

            security_report = SecurityOrchestrator().correlate(results)
            deduped_count = security_report.total_findings
        except Exception:
            deduped_count = total_findings

        await evt_scan_complete(deduped_count, 0)

    asyncio.create_task(_run())

    return JSONResponse({"ok": True, "message": f"Scan started with {len(to_run)} agents"})


@router.get("/findings-table")
async def get_findings(request: Request, limit: int = 20) -> HTMLResponse:
    """Get recent findings as HTML fragment."""
    root = request.app.state.root
    from fastapi.templating import Jinja2Templates

    from patchi.core import memory as mem

    templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

    scan_results = mem.get_scan_results(root)
    all_findings = []
    for agent_name, data in scan_results.items():
        for f in data.get("findings", [])[:limit]:
            f["agent"] = agent_name
            all_findings.append(f)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    return templates.TemplateResponse(
        request,
        "partials/findings_list.html",
        {
            "request": request,
            "findings": all_findings[:limit],
        },
    )


@router.get("/agents/status")
async def get_agents_status(request: Request) -> HTMLResponse:
    """Get agent status as HTML fragment."""
    root = request.app.state.root
    from fastapi.templating import Jinja2Templates

    from patchi.core import memory as mem

    templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

    scan_results = mem.get_scan_results(root)
    agents = []
    for agent_name, data in scan_results.items():
        agents.append(
            {
                "name": agent_name,
                "status": data.get("status", "unknown"),
                "findings": data.get("finding_count", 0),
                "duration_ms": data.get("duration_ms", 0),
            }
        )

    return templates.TemplateResponse(
        request,
        "partials/agent_grid.html",
        {
            "request": request,
            "agents": agents,
        },
    )
