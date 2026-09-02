"""Unified Dashboard — Single web entry point for Patchi.

Mission: v2 as base + v1 enhancements + full CLI wrapper.
- All v2 pages: brain-map, council, attack-timeline, live-tests, hosted
- v1 enhancements: brain map viz, health components, recent findings, cost alerts, project context
- Full CLI wrapper: every CLI command exposed via web UI/API
- Single design: one nav, one WebSocket (/ws), one template env (templates_v2)
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

_log = logging.getLogger("patchi.web.dashboard")

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
templates.env.filters["tojson"] = lambda v: json.dumps(v)

from patchi.core import config as cfg
from patchi.core.ai.tools.executor import ToolExecutor, WebConfirmationProvider

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _safe_mode(root: Path) -> str:
    try:
        return cfg.load(root).get("mode", "confirm")
    except Exception:
        return "confirm"


def _collect_recent_findings(root: Path, limit: int = 10) -> list[dict]:
    """Collect recent findings from all scanners."""
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    findings = []
    for scanner, data in scan_results.items():
        for finding in data.get("findings", [])[-limit:]:
            if isinstance(finding, dict):
                finding["source_scanner"] = scanner
                findings.append(finding)
    findings.sort(key=lambda f: f.get("timestamp", ""), reverse=True)
    return findings


def _get_brain_data(root: Path) -> dict:
    """Get consolidated brain data for dashboard."""
    from patchi.core import memory as mem
    from patchi.core.health import compute as compute_health

    brain = mem.get_brain(root)
    hs = compute_health(root)

    return {
        "health_score": hs.total,
        "health_grade": hs.grade,
        "health_components": hs.to_dict().get("components", {}),
        "file_count": brain.get("file_count", 0),
        "route_count": brain.get("route_count", 0),
        "framework": brain.get("framework", "Unknown"),
        "languages": brain.get("languages", {}),
        "project_purpose": brain.get("project_purpose", ""),
        "project_domain": brain.get("project_domain", ""),
        "active_security_domains": brain.get("active_security_domains", []),
        "recent_findings": _collect_recent_findings(root, 10),
        "stale": brain.get("stale", False),
        "last_scan": brain.get("last_scan", ""),
    }


# ──────────────────────────────────────────────────────────────────────
# Main Dashboard (/)
# ──────────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Unified Mission Control — single entry point at /."""
    root = request.app.state.root

    cost_alert = None
    try:
        from patchi.core.tenant import check_tenant_cost_alert
        cost_alert = check_tenant_cost_alert(root, cfg.load(root))
    except Exception as _exc:
        _log.warning('dashboard failed: %s', _exc)

    import asyncio as _asyncio
    brain_data = await _asyncio.to_thread(_get_brain_data, request.app.state.root)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "request": request,
            **brain_data,
            "cost_alert": cost_alert,
            "mode": _safe_mode(request.app.state.root),
        },
    )


@router.get("/landing", response_class=HTMLResponse)
async def landing_page(request: Request):
    """Public landing / marketing page (templates/landing.html)."""
    root = request.app.state.root
    brain = _get_brain_data(root)
    brain["active_domains"] = brain.get("active_security_domains", [])
    return templates.TemplateResponse(
        request,
        "landing.html",
        {"request": request, **brain},
    )


@router.get("/doctor", response_class=HTMLResponse)
async def doctor_page(request: Request):
    """Web front-end for `p doctor` — shows environment diagnostics."""
    from patchi.web.api_legacy import web_doctor

    resp = await web_doctor(request)
    data = json.loads(resp.body)
    checks = data.get("checks", [])
    errors = data.get("errors", 0)

    rows = []
    for c in checks:
        badge = "ok" if c.get("ok") else "fail"
        rows.append(
            f"<tr><td>{c.get('label','')}</td>"
            f"<td class='badge {badge}'>{'OK' if c.get('ok') else 'FAIL'}</td>"
            f"<td>{c.get('note','')}</td></tr>"
        )
    rows_html = "\n".join(rows)

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Patchi · Doctor</title>
<style>
  body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: #0d1117; color: #e6edf3; padding: 2rem; }}
  h1 {{ font-size: 1.6rem; }} .wrap {{ max-width: 720px; margin: 0 auto; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  td {{ padding: .6rem .8rem; border-bottom: 1px solid #21262d; }}
  .badge {{ font-weight: 600; }}
  .badge.ok {{ color: #3fb950; }} .badge.fail {{ color: #f85149; }}
  .summary {{ margin-top: 1rem; font-weight: 600; }}
  a {{ color: #58a6ff; }}
</style></head>
<body><div class="wrap">
  <h1>Patchi Doctor</h1>
  <p>Environment diagnostics for this Patchi installation.</p>
  <table>{rows_html}</table>
  <div class="summary">{'All checks passed.' if errors == 0 else str(errors) + ' check(s) failed.'}</div>
  <p><a href="/">← Back to Mission Control</a></p>
</div></body></html>"""
    return HTMLResponse(html)


# ──────────────────────────────────────────────────────────────────────
# HTML Page Routes
# ──────────────────────────────────────────────────────────────────────

@router.get("/brain-map", response_class=HTMLResponse)
async def brain_map_page(request: Request):
    """Brain map visualization with full import graph."""
    root = request.app.state.root
    from patchi.core import memory as mem
    layers_data = mem.get_layers(root)
    return templates.TemplateResponse(
        request, "brain.html", {"request": request, "layers_data": layers_data}
    )


@router.get("/council", response_class=HTMLResponse)
async def council_page(request: Request):
    """Council deliberation view with session history."""
    root = request.app.state.root
    from patchi.core import memory as mem
    council_sessions = mem.read(mem.MemoryCategory.ISSUES, root)
    council_sessions = [s for s in council_sessions if s.get("type") == "council_session"]
    return templates.TemplateResponse(
        request, "council.html", {"request": request, "council_sessions": council_sessions[-20:]}
    )


@router.get("/attack-timeline", response_class=HTMLResponse)
async def attack_timeline_page(request: Request):
    """Attack simulation timeline (Red Team results)."""
    root = request.app.state.root
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    attack_data = scan_results.get("RedTeamEngineAgent", {})
    return templates.TemplateResponse(
        request, "attacks.html", {"request": request, "attack_data": attack_data}
    )


@router.get("/live-tests", response_class=HTMLResponse)
async def live_tests_page(request: Request):
    """Live test session monitor."""
    root = request.app.state.root
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    test_data = scan_results.get("TestRunner", {})
    return templates.TemplateResponse(
        request, "live_testing.html", {"request": request, "test_data": test_data}
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


# ──────────────────────────────────────────────────────────────────────
# CLI Wrapper API Routes — Every CLI command exposed
# ──────────────────────────────────────────────────────────────────────

@router.get("/api/cli/commands")
async def list_cli_commands(request: Request):
    """List all available CLI commands for web exposure."""
    from patchi.cli.registry import COMMANDS as REGISTRY_COMMANDS
    commands = []
    for cmd in REGISTRY_COMMANDS:
        commands.append({
            "name": cmd.name,
            "help": cmd.help,
            "args": [{"name": a.name, "help": a.help, "required": not a.nargs or a.nargs != "?"} for a in cmd.args],
            "subcommands": [{"name": sc.name, "help": sc.help} for sc in cmd.subcommands] if cmd.subcommands else [],
        })
    return {"commands": commands}


@router.get("/api/v2/agents/stream")
async def agents_stream(request: Request):
    """Server-sent events stream for live agent progress."""
    root = request.app.state.root
    from patchi.core import memory as mem

    async def event_generator():
        scan_results = mem.get_scan_results(root)
        for scanner, data in scan_results.items():
            yield f"data: {json.dumps({'agent': scanner, 'status': 'completed', 'findings': len(data.get('findings', []))})}\n\n"
            await asyncio.sleep(0.1)

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


# ──────────────────────────────────────────────────────────────────────
# WebSocket
# ──────────────────────────────────────────────────────────────────────

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
    from patchi.core import memory as mem
    from patchi.core.health import compute as compute_health

    brain = mem.get_brain(root)
    hs = compute_health(root)

    await ws.send_json(
        {
            "event": "initial_state",
            "data": {
                "health_score": hs.total,
                "health_grade": hs.grade,
                "health_components": hs.to_dict().get("components", {}),
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
    from patchi.core import memory as mem
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
        def _cli_scan():
            from patchi.cli.commands.scan_cmd import run as cli_scan
            cli_scan(root=root, quiet=True, no_logo=True)

        try:
            await asyncio.to_thread(_cli_scan)
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
    elif action == "run_fix":
        # Execute fix command via CLI
        def _cli_fix():
            from patchi.cli.commands.fix_cmd import run as cli_fix
            cli_fix(root=root, dry_run=False)

        try:
            await asyncio.to_thread(_cli_fix)
            await ws.send_json({"event": "fix_completed", "data": {"success": True}})
        except Exception as e:
            _log.error("Fix failed: %s", e)
            await ws.send_json({"event": "error", "data": {"message": str(e)}})
    elif action == "run_council":
        issue = msg.get("issue", "")
        if issue:
            try:
                from patchi.core.brain.council import run_council
                session = await run_council(root, issue)
                await ws.send_json({
                    "event": "council_completed",
                    "data": {
                        "issue": issue,
                        "synthesis": session.synthesis,
                        "consensus": session.consensus_reached,
                        "action_plan": session.action_plan,
                    }
                })
            except Exception as e:
                _log.error("Council failed: %s", e)
                await ws.send_json({"event": "error", "data": {"message": str(e)}})
    elif action == "status.request":
        # Legacy base.html polls for current status on connect.
        import time

        try:
            conf = cfg.load(root)
        except Exception:
            conf = {}
        try:
            brain = mem.get_brain(root)
        except Exception:
            brain = {}
        await ws.send_json(
            {
                "event": "status",
                "data": {
                    "connected": True,
                    "mode": conf.get("mode", "confirm"),
                    "project_purpose": brain.get("project_purpose", ""),
                    "timestamp": time.time(),
                },
            }
        )


def _safe_mode(root: Path) -> str:
    try:
        return cfg.load(root).get("mode", "confirm")
    except Exception:
        return "confirm"
