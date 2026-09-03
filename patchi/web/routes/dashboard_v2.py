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

import asyncio
import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from starlette.templating import Jinja2Templates

router = APIRouter()

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
templates.env.filters["tojson"] = lambda v: json.dumps(v)

_log = logging.getLogger("patchi.web.dashboard_v2")


# Page routes removed — all pages now served from v1 templates/ via main dashboard.py
# Only API endpoints and WebSocket remain here


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
                "mode": conf.get("mode", "confirm"),
                "active_domains": brain.get("active_security_domains", []),
                "project_purpose": brain.get("project_purpose", ""),
            },
        }
    )


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
            await ws.send_json(
                {
                    "event": "council_result",
                    "data": {
                        "issue": issue,
                        "synthesis": session.synthesis,
                        "action_plan": session.action_plan,
                        "consensus": session.consensus_reached,
                    },
                }
            )

        elif action == "tool_call":
            # Execute AI tool call
            from patchi.core.ai.tool_executor import ToolExecutor, WebConfirmationProvider

            tool_name = data.get("tool")
            parameters = data.get("parameters", {})

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
            # 1:1 with the CLI: run the actual `p scan` pipeline, not a
            # stripped-down Brain.scan(). Results are read back from memory
            # because the CLI handler reports via rich console instead of
            # returning values. Offloaded to a thread so the socket stays live.
            import asyncio as _asyncio

            from patchi.core import memory as mem

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
                        },
                    }
                )
            except Exception as e:
                _log.error("CLI scan failed: %s", e)
                await ws.send_json({"event": "error", "data": {"message": f"Scan failed: {e}"}})

        elif action == "start_red_team":
            # Trigger red team assessment
            from patchi.core.security.red_team_engine import run_red_team

            report = await run_red_team(root, safe_mode=data.get("safe_mode", True))
            await ws.send_json(
                {
                    "event": "red_team_completed",
                    "data": {
                        "assessment_id": report.assessment_id,
                        "findings": report.total_findings,
                        "by_severity": report.by_severity,
                    },
                }
            )

        elif action == "start_live_test":
            # Trigger live test
            from patchi.core.testing.live_v2.runner import LiveTestConfigV2, run_live_tests_v2
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
            await ws.send_json(
                {
                    "event": "live_test_completed",
                    "data": result.to_dict(),
                }
            )

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
    from patchi.core.ai.tool_executor import ToolExecutor, WebConfirmationProvider

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


@router.post("/api/v2/council/deliberate")
async def deliberate(request: Request):
    """Run a full Council deliberation on an issue (REST form of the WS action).

    Persists the session into memory so /council history shows it.
    Body: {"issue": "..."}
    """
    from fastapi.responses import JSONResponse

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

    # Persist so the history panel on /council shows it
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


