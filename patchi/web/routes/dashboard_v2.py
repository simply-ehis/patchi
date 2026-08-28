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

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates_v2"))
templates.env.filters["tojson"] = lambda v: json.dumps(v)

_log = logging.getLogger("patchi.web.dashboard_v2")

from patchi.core import config as cfg





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

            def _cli_scan():
                from patchi.cli.commands.scan_cmd import run as cli_scan

                cli_scan(root=root, quiet=True, no_logo=True)

            try:
                await _asyncio.to_thread(_cli_scan)
                from patchi.core import memory as _mem
                brain_mem = _mem.get_brain(root)
                scans = _mem.get_scan_results(root)
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


def _safe_mode(root) -> str:
    try:
        from patchi.core import config as cfg2

        return cfg2.load(root).get("mode", "confirm")
    except Exception:
        return "confirm"


# ── HTML Page Routes — /v2 is now alias to unified / (dashboard.py owns all pages)
@router.get("/v2", response_class=HTMLResponse)
async def dashboard_v2_alias(request: Request):
    """Alias: /v2 → unified Mission Control at /.

    Keeps old bookmarks / e2e alias check passing. 302 to / preserves
    method, 307 also accepted. Return 200 with Mission Control also passes
    e2e, but redirect is cleaner.
    """
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/", status_code=307)

