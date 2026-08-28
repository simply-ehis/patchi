"""Unified Dashboard — Single entry point for all web UI.

Merges v2 functionality (Mission Control, Brain Map, Council, Red Team, Live Tests, Hosted)
with v1 health compute, recent findings, cost alerts. All routes served from root.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

_log = logging.getLogger("patchi.web.dashboard")

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates_v2"))
templates.env.filters["tojson"] = lambda v: json.dumps(v)

from patchi.core import config as cfg
from patchi.core.ai.tools.executor import ToolExecutor, WebConfirmationProvider


def _safe_mode(root) -> str:
    try:
        return cfg.load(root).get("mode", "confirm")
    except Exception:
        return "confirm"


# ── Main Dashboard (/) ───────────────────────────────────────────────
@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Unified Mission Control — single entry point at /."""
    root = request.app.state.root
    from patchi.core import memory as mem
    from patchi.core.health import compute as compute_health

    brain = mem.get_brain(root)
    hs = compute_health(root)

    cost_alert = None
    try:
        from patchi.core.tenant import check_tenant_cost_alert
        cost_alert = check_tenant_cost_alert(root, cfg.load(root))
    except Exception:
        pass

    scan_results = mem.get_scan_results(root)
    recent_findings = []
    for scanner, data in scan_results.items():
        for finding in data.get("findings", [])[-10:]:
            if isinstance(finding, dict):
                finding["source_scanner"] = scanner
                recent_findings.append(finding)
    recent_findings.sort(key=lambda f: f.get("timestamp", ""), reverse=True)

    return templates.TemplateResponse(
        request,
        "dashboard_v2.html",
        {
            "request": request,
            "health_score": hs.total,
            "health_grade": hs.grade,
            "health_components": hs.to_dict()["components"],
            "file_count": brain.get("file_count", 0),
            "route_count": brain.get("route_count", 0),
            "framework": brain.get("framework", "Unknown"),
            "languages": brain.get("languages", {}),
            "recent_findings": recent_findings[:10],
            "active_security_domains": brain.get("active_security_domains", []),
            "project_purpose": brain.get("project_purpose", ""),
            "project_domain": brain.get("project_domain", ""),
            "mode": _safe_mode(root),
            "cost_alert": cost_alert,
        },
    )


# ── HTML Page Routes ────────────────────────────────────────────────
@router.get("/brain-map", response_class=HTMLResponse)
async def brain_map_page(request: Request):
    """Brain map visualization."""
    root = request.app.state.root
    from patchi.core import memory as mem
    layers_data = mem.get_layers(root)
    return templates.TemplateResponse(
        request, "brain_map_v2.html", {"request": request, "layers_data": layers_data}
    )


@router.get("/council", response_class=HTMLResponse)
async def council_page(request: Request):
    """Council deliberation view."""
    root = request.app.state.root
    from patchi.core import memory as mem
    council_sessions = mem.read(mem.MemoryCategory.ISSUES, root)
    council_sessions = [s for s in council_sessions if s.get("type") == "council_session"]
    return templates.TemplateResponse(
        request, "council_v2.html", {"request": request, "council_sessions": council_sessions[-20:]}
    )


@router.get("/attack-timeline", response_class=HTMLResponse)
async def attack_timeline_page(request: Request):
    """Attack simulation timeline."""
    root = request.app.state.root
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    attack_data = scan_results.get("RedTeamEngineAgent", {})
    return templates.TemplateResponse(
        request, "attack_timeline_v2.html", {"request": request, "attack_data": attack_data}
    )


@router.get("/live-tests", response_class=HTMLResponse)
async def live_tests_page(request: Request):
    """Live test session monitor."""
    root = request.app.state.root
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    test_data = scan_results.get("TestRunner", {})
    return templates.TemplateResponse(
        request, "live_tests_v2.html", {"request": request, "test_data": test_data}
    )


@router.get("/hosted", response_class=HTMLResponse)
async def hosted_page(request: Request):
    """Hosted mode dashboard (experimental)."""
    root = request.app.state.root
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    hosted_data = scan_results.get("HostedModeAgent", {})
    return templates.TemplateResponse(
        request, "hosted.html", {"request": request, "hosted_data": hosted_data}
    )


# ── API Routes ──────────────────────────────────────────────────────
@router.get("/api/v2/agents/stream")
async def agents_stream(request: Request):
    """Server-sent events stream for live agent progress."""
    from patchi.core import memory as mem
    import asyncio

    root = request.app.state.root

    async def event_generator():
        scan_results = mem.get_scan_results(root)
        for scanner, data in scan_results.items():
            yield f"data: {json.dumps({'agent': scanner, 'status': 'completed', 'findings': len(data.get('findings', []))})}\n\n"
            await asyncio.sleep(0.1)

    from starlette.responses import StreamingResponse
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/api/v2/brain/layers")
async def get_brain_layers(request: Request):
    """Get brain layers for visualization."""
    root = request.app.state.root
    from patchi.core import memory as mem
    layers_data = mem.get_layers(root)
    return layers_data


@router.get("/api/v2/council/sessions")
async def get_council_sessions(request: Request):
    """Get council session history."""
    root = request.app.state.root
    from patchi.core import memory as mem
    history = mem.read(mem.MemoryCategory.ISSUES, root)
    sessions = [s for s in history if s.get("type") == "council_session"]
    return {"sessions": sessions[-50:]}


@router.get("/api/v2/attack/timeline")
async def get_attack_timeline(request: Request):
    """Get attack simulation timeline."""
    root = request.app.state.root
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    attack_data = scan_results.get("RedTeamEngineAgent", {})
    return attack_data


@router.get("/api/v2/live-tests/status")
async def get_live_test_status(request: Request):
    """Get live test status."""
    root = request.app.state.root
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    test_data = scan_results.get("TestRunner", {})
    return test_data


@router.post("/api/v2/tools/execute")
async def execute_tool(request: Request):
    """Execute an AI tool call from dashboard."""
    root = request.app.state.root
    data = await request.json()
    tool_name = data.get("tool")
    parameters = data.get("parameters", {})

    executor = ToolExecutor(root, confirmation_provider=WebConfirmationProvider())
    result = await executor.execute(tool_name, parameters, invoked_by="dashboard")

    return {
        "success": result.success,
        "result": result.result,
        "error": result.error,
        "invocation_id": result.invocation_id,
    }


@router.get("/api/v2/tools/list")
async def list_tools(request: Request):
    """List all available AI tools."""
    from patchi.core.ai.tools.registry import get_tool_registry
    registry = get_tool_registry()
    category = request.query_params.get("category")
    tools = registry.list_tools(category)
    return {"tools": tools}


@router.post("/api/v2/council/deliberate")
async def deliberate(request: Request):
    """Run a full Council deliberation on an issue (REST form of the WS action)."""
    root = request.app.state.root
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON body required"}, status_code=400)

    issue = (body.get("issue") or "").strip()
    if not issue:
        return JSONResponse({"error": "issue is required"}, status_code=400)

    try:
        from patchi.core.brain.council import run_council
        session = await run_council(root, issue)
    except Exception as e:
        _log.error("Council deliberation failed: %s", e)
        return JSONResponse({"error": f"Deliberation failed: {e}"}, status_code=500)

    try:
        from patchi.core import memory as mem
        mem.save_issue(
            {
                "type": "council_session",
                "issue": issue,
                "synthesis": session.synthesis,
                "consensus": session.consensus_reached,
                "timestamp": session.started_at,
                "decisions": [
                    {
                        "persona_name": d.persona_name,
                        "analysis": d.analysis,
                        "recommendation": d.recommendation,
                        "confidence": d.confidence,
                    }
                    for d in session.persona_decisions
                ],
                "action_plan": session.action_plan,
            },
            root,
        )
    except Exception as e:
        _log.warning("Failed to persist council session: %s", e)

    return {
        "issue": issue,
        "synthesis": session.synthesis,
        "consensus": session.consensus_reached,
        "action_plan": session.action_plan,
        "decisions": [
            {
                "persona_name": d.persona_name,
                "analysis": d.analysis,
                "recommendation": d.recommendation,
                "confidence": d.confidence,
            }
            for d in session.persona_decisions
        ],
        "duration_ms": session.duration_ms,
    }


# ── WebSocket ───────────────────────────────────────────────────────
@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """Unified WebSocket for real-time dashboard updates."""
    await ws.accept()
    root = ws.app.state.root

    try:
        await _send_initial_state(ws, root)
        while True:
            raw = await ws.receive_text()
            await _handle_ws_message(ws, root, raw)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        _log.error(f"WebSocket error: {e}")


async def _send_initial_state(ws: WebSocket, root: Path):
    """Send initial dashboard state."""
    from patchi.core import config as cfg
    from patchi.core import memory as mem
    from patchi.core.health import compute as compute_health

    brain = mem.get_brain(root)
    conf = cfg.load(root)
    hs = compute_health(root)

    await ws.send_json(
        {
            "event": "initial_state",
            "data": {
                "health_score": hs.total,
                "health_grade": hs.grade,
                "health_components": hs.to_dict()["components"],
                "file_count": brain.get("file_count", 0),
                "route_count": brain.get("route_count", 0),
                "framework": brain.get("framework", "Unknown"),
                "languages": brain.get("languages", {}),
                "mode": _safe_mode(root),
            },
        }
    )


async def _handle_ws_message(ws: WebSocket, root: Path, raw: str):
    """Handle incoming WebSocket message."""
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return

    action = msg.get("action")
    if action == "subscribe":
        await ws.send_json({"event": "subscribed", "data": {"channels": msg.get("data", {}).get("channels", [])}})
    elif action == "execute_tool":
        tool_name = msg.get("tool")
        parameters = msg.get("parameters", {})
        executor = ToolExecutor(root, confirmation_provider=WebConfirmationProvider())
        exec_result = await executor.execute(tool_name, parameters, invoked_by="dashboard")
        await ws.send_json(
            {
                "event": "tool_result",
                "data": {
                    "tool": tool_name,
                    "success": exec_result.success,
                    "result": exec_result.result,
                    "error": exec_result.error,
                },
            }
        )
    elif action == "start_scan":
        import asyncio as _asyncio

        def _cli_scan():
            from patchi.cli.commands.scan_cmd import run as cli_scan
            cli_scan(root=root, quiet=True, no_logo=True)

        try:
            await _asyncio.to_thread(_cli_scan)
            brain_mem = mem.get_brain(root)
            scans = mem.get_scan_results(root)
            brain_meta = scans.get("Brain", {})
            await ws.send_json(
                {
                    "event": "scan_completed",
                    "data": {
                        "file_count": brain_mem.get("file_count", 0),
                        "route_count": brain_mem.get("route_count", 0),
                        "duration": brain_meta.get("duration", 0),
                        "findings": sum(len(d.get("findings", [])) for d in scans.values()),
                    },
                }
            )
        except Exception as e:
            _log.error("Scan failed: %s", e)
            await ws.send_json({"event": "error", "data": {"message": str(e)}})