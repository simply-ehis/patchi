"""
Enhanced Web Dashboard v2 — Real-time monitoring and control interface.

Features:
- Live agent execution stream
- Council deliberation viewer
- Brain map visualization
- Attack timeline
- Test session monitoring
- Command palette for AI tool calls
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates

router = APIRouter()

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates_v2"))
templates.env.filters["tojson"] = lambda v: json.dumps(v)

_log = logging.getLogger("patchi.web.dashboard_v2")


@router.get("/", response_class=HTMLResponse)
async def dashboard_v2(request: Request):
    """Unified landing page — Mission Control."""
    root = request.app.state.root
    from patchi.core import memory as mem
    
    brain = mem.get_brain(root)
    health = brain.get("health_score", {})
    
    # Get recent scan results for live feed
    scan_results = mem.get_scan_results(root)
    recent_findings = []
    for scanner, data in scan_results.items():
        for finding in data.get("findings", [])[-10:]:
            if isinstance(finding, dict):
                finding["source_scanner"] = scanner
                recent_findings.append(finding)
    
    # Sort by timestamp
    recent_findings.sort(key=lambda f: f.get("timestamp", ""), reverse=True)
    
    return templates.TemplateResponse(
        request,
        "dashboard_v2.html",
        {
            "request": request,
            "health_score": health.get("total", 0),
            "health_grade": health.get("grade", "?"),
            "health_components": health.get("components", {}),
            "file_count": brain.get("file_count", 0),
            "route_count": brain.get("route_count", 0),
            "framework": brain.get("framework", "Unknown"),
            "languages": brain.get("languages", {}),
            "recent_findings": recent_findings[:20],
            "active_security_domains": brain.get("active_security_domains", []),
            "project_purpose": brain.get("project_purpose", ""),
            "project_domain": brain.get("project_domain", ""),
            "mode": _safe_mode(root),
        },
    )


@router.get("/v2", response_class=HTMLResponse)
async def dashboard_v2_alias(request: Request):
    """Backward-compat alias — /v2 forwards to the unified /."""
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/", status_code=307)


def _safe_mode(root) -> str:
    try:
        from patchi.core import config as cfg

        return cfg.load(root).get("mode", "confirm")
    except Exception:
        return "confirm"


@router.get("/brain-map", response_class=HTMLResponse)
async def brain_map_v2(request: Request):
    """Interactive brain map visualization."""
    root = request.app.state.root
    from patchi.core import memory as mem
    
    layers_data = mem.get_layers(root)
    
    return templates.TemplateResponse(
        request,
        "brain_map_v2.html",
        {
            "request": request,
            "layers_data": layers_data,
        },
    )


@router.get("/council", response_class=HTMLResponse)
async def council_view(request: Request):
    """Council deliberation viewer."""
    root = request.app.state.root
    from patchi.core import memory as mem
    
    # Get council session history
    council_history = mem.read(mem.MemoryCategory.ISSUES, root)
    council_sessions = [s for s in council_history if s.get("type") == "council_session"]
    
    return templates.TemplateResponse(
        request,
        "council_v2.html",
        {
            "request": request,
            "council_sessions": council_sessions[-20:],
        },
    )


@router.get("/attack-timeline", response_class=HTMLResponse)
async def attack_timeline(request: Request):
    """Attack simulation timeline."""
    root = request.app.state.root
    from patchi.core import memory as mem
    
    scan_results = mem.get_scan_results(root)
    attack_data = scan_results.get("RedTeamEngineAgent", {})
    
    return templates.TemplateResponse(
        request,
        "attack_timeline_v2.html",
        {
            "request": request,
            "attack_data": attack_data,
        },
    )


@router.get("/live-tests", response_class=HTMLResponse)
async def live_tests_view(request: Request):
    """Live test session monitor."""
    root = request.app.state.root
    from patchi.core import memory as mem
    
    scan_results = mem.get_scan_results(root)
    test_data = scan_results.get("TestRunner", {})
    
    return templates.TemplateResponse(
        request,
        "live_tests_v2.html",
        {
            "request": request,
            "test_data": test_data,
        },
    )


@router.get("/hosted", response_class=HTMLResponse)
async def hosted_view(request: Request):
    """Unified hosted control plane — guard status, compliance, webhooks."""
    root = request.app.state.root
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    scan_results = mem.get_scan_results(root)
    attack_data = scan_results.get("RedTeamEngineAgent", {})

    return templates.TemplateResponse(
        request,
        "hosted.html",
        {
            "request": request,
            "active_domains": brain.get("active_security_domains", []),
            "attack_data": attack_data,
        },
    )


# WebSocket endpoints for real-time updates
@router.websocket("/ws/v2")
async def websocket_v2(ws: WebSocket):
    """Enhanced WebSocket for real-time dashboard updates."""
    await ws.accept()
    
    root = ws.app.state.root
    
    try:
        # Send initial state
        await _send_initial_state(ws, root)
        
        # Listen for messages
        while True:
            raw = await ws.receive_text()
            await _handle_ws_message(ws, root, raw)
            
    except WebSocketDisconnect:
        pass
    except Exception as e:
        _log.error(f"WebSocket error: {e}")


async def _send_initial_state(ws: WebSocket, root: Path):
    """Send initial dashboard state."""
    from patchi.core import memory as mem
    from patchi.core import config as cfg
    from patchi.core.health import compute as compute_health
    
    brain = mem.get_brain(root)
    conf = cfg.load(root)
    hs = compute_health(root)
    
    await ws.send_json({
        "event": "initial_state",
        "data": {
            "health_score": hs.total,
            "health_grade": hs.grade,
            "health_components": hs.to_dict()["components"],
            "file_count": brain.get("file_count", 0),
            "route_count": brain.get("route_count", 0),
            "framework": brain.get("framework", "Unknown"),
            "mode": conf.get("mode", "confirm"),
            "active_domains": brain.get("active_security_domains", []),
            "project_purpose": brain.get("project_purpose", ""),
        },
    })


async def _handle_ws_message(ws: WebSocket, root: Path, raw: str):
    """Handle incoming WebSocket messages."""
    try:
        import json
        msg = json.loads(raw)
        action = msg.get("action", "")
        data = msg.get("data", {})
        
        if action == "ping":
            await ws.send_json({"event": "pong", "data": {}})
        
        elif action == "subscribe":
            # Subscribe to event streams
            channels = data.get("channels", [])
            await ws.send_json({"event": "subscribed", "data": {"channels": channels}})
        
        elif action == "council_query":
            # Query council for analysis
            from patchi.core.brain.council import run_council
            issue = data.get("issue", "")
            session = await run_council(root, issue)
            await ws.send_json({
                "event": "council_result",
                "data": {
                    "issue": issue,
                    "synthesis": session.synthesis,
                    "action_plan": session.action_plan,
                    "consensus": session.consensus_reached,
                },
            })
        
        elif action == "tool_call":
            # Execute AI tool call
            from patchi.core.ai.tool_executor import ToolExecutor
            tool_name = data.get("tool")
            parameters = data.get("parameters", {})
            
            executor = ToolExecutor(root)
            exec_result = await executor.execute(tool_name, parameters, invoked_by="dashboard")
            
            await ws.send_json({
                "event": "tool_result",
                "data": {
                    "tool": tool_name,
                    "success": exec_result.success,
                    "result": exec_result.result,
                    "error": exec_result.error,
                },
            })
        
        elif action == "start_scan":
            # Trigger a scan
            from patchi.core.brain.brain import Brain
            brain = Brain(root)
            report = brain.scan()
            await ws.send_json({
                "event": "scan_completed",
                "data": {
                    "file_count": report.file_count,
                    "route_count": report.route_count,
                    "duration": report.duration_seconds,
                },
            })
        
        elif action == "start_red_team":
            # Trigger red team assessment
            from patchi.core.security.red_team_engine import run_red_team
            report = await run_red_team(root, safe_mode=data.get("safe_mode", True))
            await ws.send_json({
                "event": "red_team_completed",
                "data": {
                    "assessment_id": report.assessment_id,
                    "findings": report.total_findings,
                    "by_severity": report.by_severity,
                },
            })
        
        elif action == "start_live_test":
            # Trigger live test
            from patchi.core.testing.live_v2.runner import run_live_tests_v2, LiveTestConfigV2
            from patchi.core.testing.live_v2.stress_orchestrator import StressConfig
            
            test_config = LiveTestConfigV2(
                test_types=data.get("test_types", ["browser", "visual"]),
                base_url=data.get("base_url"),
            )
            
            if data.get("stress"):
                test_config.stress_config = StressConfig(
                    base_url=data.get("base_url"),
                    scenario=data.get("stress_scenario", "load"),
                    users=data.get("stress_users", 10),
                )
            
            result = await run_live_tests_v2(root, test_config)
            await ws.send_json({
                "event": "live_test_completed",
                "data": result.to_dict(),
            })
        
    except Exception as e:
        _log.error(f"WebSocket message handling failed: {e}")
        await ws.send_json({"event": "error", "data": {"message": str(e)}})


# API endpoints for dashboard data
@router.get("/api/v2/agents/stream")
async def agents_stream(request: Request):
    """Stream agent execution events."""
    # This would return Server-Sent Events
    from fastapi.responses import StreamingResponse
    
    async def event_generator():
        # Stream agent events from memory
        from patchi.core import memory as mem
        root = request.app.state.root
        scan_results = mem.get_scan_results(root)
        
        for scanner, data in scan_results.items():
            yield f"data: {json.dumps({'agent': scanner, 'status': 'completed', 'findings': len(data.get('findings', []))})}\n\n"
            await asyncio.sleep(0.1)
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/api/v2/brain/layers")
async def get_brain_layers(request: Request):
    """Get layered brain data for visualization."""
    from patchi.core import memory as mem
    root = request.app.state.root
    layers_data = mem.get_layers(root)
    return layers_data


@router.get("/api/v2/council/sessions")
async def get_council_sessions(request: Request):
    """Get council session history."""
    from patchi.core import memory as mem
    root = request.app.state.root
    history = mem.read(mem.MemoryCategory.ISSUES, root)
    sessions = [s for s in history if s.get("type") == "council_session"]
    return {"sessions": sessions[-50:]}


@router.get("/api/v2/attack/timeline")
async def get_attack_timeline(request: Request):
    """Get attack simulation timeline."""
    from patchi.core import memory as mem
    root = request.app.state.root
    scan_results = mem.get_scan_results(root)
    attack_data = scan_results.get("RedTeamEngineAgent", {})
    return attack_data


@router.get("/api/v2/live-tests/status")
async def get_live_test_status(request: Request):
    """Get live test status."""
    from patchi.core import memory as mem
    root = request.app.state.root
    scan_results = mem.get_scan_results(root)
    test_data = scan_results.get("TestRunner", {})
    return test_data


@router.post("/api/v2/tools/execute")
async def execute_tool(request: Request):
    """Execute an AI tool call from dashboard."""
    from patchi.core.ai.tool_executor import ToolExecutor
    root = request.app.state.root
    
    data = await request.json()
    tool_name = data.get("tool")
    parameters = data.get("parameters", {})
    
    executor = ToolExecutor(root)
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
    
    return {
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "requires_confirmation": t.requires_confirmation,
                "side_effects": t.side_effects,
            }
            for t in tools
        ]
    }


# Import asyncio for streaming
import asyncio