"""
FastAPI app factory for Patchi Web UI.

Exposes:
  GET  /                    → dashboard (Brain Map + security overview)
  GET  /findings            → findings list with filters
  GET  /review              → patch review with diffs
  GET  /guard               → hosted guard monitoring
  GET  /chat                → security AI chat
  GET  /brain               → brain knowledge viewer
  WS   /ws                  → WebSocket for live events
  /api/*                    → REST + htmx endpoints
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from patchi.web.ws import manager


def create_app(root: Path) -> FastAPI:
    """Build and return the FastAPI application."""
    app = FastAPI(title="Patchi", docs_url=None, redoc_url=None)

    # Restrict CORS to localhost for security - allow_origins can be configured via env var
    import os

    from fastapi.middleware.cors import CORSMiddleware
    allowed_origins = os.environ.get("PATCHI_CORS_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["*"],
    )

    # Store project root
    app.state.root = root

    # Initialize cost tracker (was only in dead server.py — now wired here)
    try:
        from patchi.core.ai.cost_tracker import init_cost

        init_cost(root)
    except Exception as e:
        import logging
        logging.getLogger("patchi.web").warning("Cost tracker init failed: %s", e)

    # Initialize SpawnManager (was only in dead server.py — now wired here)
    try:
        from patchi.web.spawn import SpawnManager

        app.state.spawner = SpawnManager(root)
    except Exception as e:
        import logging
        logging.getLogger("patchi.web").warning("SpawnManager init failed: %s", e)
        app.state.spawner = None

    # Wire RequestInterceptor as ASGI middleware for runtime threat detection
    try:
        from patchi.core import config as _cfg
        from patchi.core.security.request_interceptor import RequestInterceptor
        _conf = _cfg.load(root)
        interceptor = RequestInterceptor(root, _conf)
        interceptor.enabled = _conf.get("pipeline", {}).get("interceptor", {}).get("enabled", False)
        app.state.interceptor = interceptor
        if interceptor.enabled:
            @app.middleware("http")
            async def security_interceptor(request, call_next):
                result = interceptor.inspect_request(
                    request.method,
                    str(request.url.path),
                    dict(request.headers),
                )
                if result["should_block"]:
                    from fastapi.responses import JSONResponse
                    return JSONResponse(
                        status_code=403,
                        content={"error": "Request blocked", "reason": result["reason"]},
                    )
                return await call_next(request)
            import logging as _lg
            _lg.getLogger("patchi.web").info("RequestInterceptor enabled — %d paths excluded", len(interceptor.exclude_paths))
    except Exception as e:
        import logging
        logging.getLogger("patchi.web").warning("RequestInterceptor init failed: %s", e)
        app.state.interceptor = None

    # Mount static files
    import sys as _sys
    if getattr(_sys, 'frozen', False):
        _base = Path(_sys._MEIPASS) / "patchi" / "web"
    else:
        _base = Path(__file__).parent
    static_dir = _base / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Import and register routes
    from patchi.web.api.brain_map import router as brain_map_router
    from patchi.web.api.charts import router as charts_router
    from patchi.web.api.chat import router as chat_api_router
    from patchi.web.api.fix import router as fix_router
    from patchi.web.api.guard import router as guard_api_router
    from patchi.web.api.hosted import router as hosted_router
    from patchi.web.api.scan import router as scan_router
    from patchi.web.api_legacy import router as legacy_router
    from patchi.web.routes.brain import router as brain_router
    from patchi.web.routes.chat import router as chat_router
    from patchi.web.routes.dashboard import router as dashboard_router
    try:
        from patchi.web.routes.dashboard_v2 import router as dashboard_v2_router
    except Exception as e:  # v2 dashboard is additive — never break core UI
        import logging as _logging

        _logging.getLogger("patchi.web").warning("Dashboard v2 not available: %s", e)
        dashboard_v2_router = None
    from patchi.web.routes.findings import router as findings_router
    from patchi.web.routes.guard import router as guard_router
    from patchi.web.routes.history import router as history_router
    from patchi.web.routes.review import router as review_router
    from patchi.web.routes.settings import router as settings_router
    from patchi.web.routes.tokens import router as tokens_router
    from patchi.web.routes.assurance import router as assurance_router

    app.include_router(legacy_router)
    app.include_router(dashboard_router)
    app.include_router(findings_router)
    app.include_router(review_router)
    app.include_router(guard_router)
    app.include_router(chat_router)
    app.include_router(brain_router)
    app.include_router(settings_router)
    app.include_router(history_router)
    app.include_router(brain_map_router)
    app.include_router(scan_router)
    app.include_router(charts_router)
    app.include_router(fix_router)
    app.include_router(hosted_router)
    app.include_router(assurance_router)
    app.include_router(chat_api_router)
    app.include_router(guard_api_router)
    app.include_router(tokens_router)
    if dashboard_v2_router is not None:
        app.include_router(dashboard_v2_router)

    # WebSocket endpoint
    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await ws.accept()
        await manager.connect(ws)
        # Push current status to newly connected client (LIMIT-05)
        try:
            import json

            from patchi.core import config as _cfg
            from patchi.core import memory as _mem
            from patchi.core.health import compute as compute_health

            hs = compute_health(root)
            _conf = _cfg.load(root)
            _brain = _mem.get_brain(root)
            status_data = {
                "health_score": hs.total,
                "mode": _conf.get("mode", "confirm"),
                "framework": _brain.get("framework", ""),
            }
            await ws.send_text(json.dumps({"event": "status.update", "data": status_data}))
        except Exception as e:
            import logging
            logging.getLogger("patchi.web").warning("Initial status push failed: %s", e)
        try:
            while True:
                raw = await ws.receive_text()
                # Route client-sent actions
                try:
                    import json

                    msg = json.loads(raw)
                    action = msg.get("action", "")
                    data = msg.get("data", {})

                    if action == "ping":
                        await ws.send_text(json.dumps({"event": "pong", "data": {}}))

                    elif action == "queue.pause":
                        from patchi.core.queue import get_queue

                        get_queue(root).pause()
                        await manager.broadcast("queue.paused", {})

                    elif action == "queue.resume":
                        from patchi.core.queue import get_queue

                        get_queue(root).resume()
                        await manager.broadcast("queue.resumed", {})

                    elif action == "queue.skip":
                        from patchi.core.queue import get_queue

                        get_queue(root).skip_current()
                        await manager.broadcast("queue.skipped", {})

                    elif action == "status.request":
                        # Client connecting mid-scan requests current status
                        from patchi.core import config as cfg_mod
                        from patchi.core import memory as mem_mod
                        from patchi.core.health import compute as compute_health

                        try:
                            hs = compute_health(root)
                            brain = mem_mod.get_brain(root)
                            conf = cfg_mod.load(root)
                            status_data = {
                                "health_score": hs.total,
                                "mode": conf.get("mode", "confirm"),
                                "framework": brain.get("framework", ""),
                            }
                            await ws.send_text(
                                json.dumps({"event": "status.update", "data": status_data})
                            )
                        except Exception as e:
                            import logging
                            logging.getLogger("patchi.web").warning("Status fetch failed: %s", e)

                    elif action == "queue.clear":
                        from patchi.core.queue import get_queue

                        get_queue(root).clear()
                        await manager.broadcast("queue.cleared", {})

                    elif action == "fix.accept":
                        patch_id = data.get("patch_id", "")
                        if patch_id:
                            from patchi.core.fix.applier import PatchApplier
                            from patchi.core.fix.patch import PatchState, list_patches

                            patches = list_patches(root)
                            for p in patches:
                                if p.get("id") == patch_id:
                                    from patchi.core.fix.patch import Patch

                                    patch = Patch.from_dict(p)
                                    applier = PatchApplier(root)
                                    result = applier.apply(patch)
                                    await manager.broadcast(
                                        "fix.applied",
                                        {
                                            "patch_id": patch_id,
                                            "success": result.success,
                                        },
                                    )
                                    break

                    elif action == "fix.reject":
                        patch_id = data.get("patch_id", "")
                        if patch_id:
                            from patchi.core.fix.patch import PatchState, save_patch_state

                            save_patch_state(root, patch_id, PatchState.REJECTED)
                            await manager.broadcast("fix.rejected", {"patch_id": patch_id})

                    elif action == "fix.undo":
                        patch_id = data.get("patch_id", "")
                        snapshot_id = data.get("snapshot_id", "")
                        from patchi.core.fix.applier import PatchApplier

                        applier = PatchApplier(root)
                        result = applier.rollback(patch_id, snapshot_id)
                        await manager.broadcast(
                            "fix.rolled_back",
                            {
                                "patch_id": patch_id,
                                "success": result.success,
                            },
                        )

                    elif action == "spawn.ant":
                        node_id = data.get("node_id", "")
                        spawner = app.state.spawner
                        if spawner and node_id:
                            ant_id, reason = spawner.try_spawn(node_id)
                            if ant_id:
                                await manager.broadcast(
                                    "ant.spawned",
                                    {"node_id": node_id, "ant_id": ant_id},
                                )
                            else:
                                await manager.broadcast(
                                    "ant.spawn_failed",
                                    {"node_id": node_id, "reason": reason},
                                )

                    elif action == "mode.change":
                        new_mode = data.get("mode", "")
                        if new_mode in ("auto", "confirm", "silent"):
                            from patchi.core.config import load as load_config
                            from patchi.core.config import save as save_config

                            conf = load_config(root)
                            conf["mode"] = new_mode
                            save_config(root, conf)
                            await manager.broadcast("mode.changed", {"mode": new_mode})

                    elif action == "scan.cancel":
                        from patchi.core.queue import get_queue

                        get_queue(root).clear()
                        await manager.broadcast("scan.cancelled", {})

                except (ValueError, KeyError) as e:
                    import logging
                    logging.getLogger("patchi.web").warning("Malformed WS message: %s", e)

        except WebSocketDisconnect:
            await manager.disconnect(ws)

    # Error handlers
    @app.exception_handler(404)
    async def not_found(request, exc):
        return HTMLResponse(
            """<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><title>404 — Patchi</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body style="display:flex;align-items:center;justify-content:center;height:100vh;background:var(--bg-primary)">
<div style="text-align:center">
  <h1 style="font-size:72px;color:var(--accent);margin:0">404</h1>
  <p style="color:var(--text-secondary);margin:16px 0 24px">This page doesn't exist.</p>
  <a href="/" class="btn btn-primary" style="text-decoration:none">← Back to Dashboard</a>
</div></body></html>""",
            status_code=404,
        )

    @app.exception_handler(500)
    async def server_error(request, exc):
        return HTMLResponse(
            """<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><title>500 — Patchi</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body style="display:flex;align-items:center;justify-content:center;height:100vh;background:var(--bg-primary)">
<div style="text-align:center">
  <h1 style="font-size:72px;color:var(--critical);margin:0">500</h1>
  <p style="color:var(--text-secondary);margin:16px 0 24px">Something went wrong on our end.</p>
  <a href="/" class="btn btn-primary" style="text-decoration:none">← Back to Dashboard</a>
</div></body></html>""",
            status_code=500,
        )

    # Favicon
    @app.get("/favicon.ico")
    async def favicon():
        return HTMLResponse("")

    return app
