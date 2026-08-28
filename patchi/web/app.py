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

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles


def create_app(root: Path) -> FastAPI:
    """Build and return the FastAPI application."""
    app = FastAPI(title="Patchi", docs_url=None, redoc_url=None)

    # Restrict CORS to localhost for security - allow_origins can be configured via env var
    import os

    from fastapi.middleware.cors import CORSMiddleware

    allowed_origins = os.environ.get(
        "PATCHI_CORS_ORIGINS", "http://localhost:3000,http://localhost:8000"
    ).split(",")
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

    # Initialize tenant manager for multi-project isolation
    try:
        from patchi.core.tenant import get_tenant_manager

        tenant_mgr = get_tenant_manager()
        tenant_mgr.register_project(root)
        tenant_mgr.switch_project(root)
        app.state.tenant_manager = tenant_mgr
    except Exception as e:
        import logging

        logging.getLogger("patchi.web").warning("Tenant manager init failed: %s", e)

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

            _lg.getLogger("patchi.web").info(
                "RequestInterceptor enabled — %d paths excluded", len(interceptor.exclude_paths)
            )
    except Exception as e:
        import logging

        logging.getLogger("patchi.web").warning("RequestInterceptor init failed: %s", e)
        app.state.interceptor = None

    # ── Tenant context middleware ──────────────────────────────────────────
    # Wraps every request so get_current_tenant_root() returns the active
    # project, and call_ai() can resolve the model router's profiler data.
    try:
        from patchi.core.tenant import tenant_context

        @app.middleware("http")
        async def tenant_middleware(request, call_next):
            root = request.app.state.root
            with tenant_context(root):
                return await call_next(request)
    except Exception:
        pass  # non-critical

    # Mount static files
    import sys as _sys

    if getattr(_sys, "frozen", False):
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

    try:
        from patchi.web.api.hosted_v2 import router as hosted_v2_router
    except Exception as e:
        _logging = __import__("logging")
        _logging.getLogger("patchi.web").warning("Hosted v2 API not available: %s", e)
        hosted_v2_router = None
    from patchi.web.api.dev_check import router as dev_check_router
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
    from patchi.web.api.cicd import router as cicd_router
    from patchi.web.api.dast_evidence import router as dast_evidence_router
    from patchi.web.api.live_testing import router as live_testing_api_router
    from patchi.web.api.smart import router as smart_api_router
    from patchi.web.api.tenant import router as tenant_router
    from patchi.web.routes.assurance import router as assurance_router
    from patchi.web.routes.charter import router as charter_router
    from patchi.web.routes.findings import router as findings_router
    from patchi.web.routes.guard import router as guard_router
    from patchi.web.routes.history import router as history_router
    from patchi.web.routes.live_testing import router as live_testing_router
    from patchi.web.routes.review import router as review_router
    from patchi.web.routes.self_improvement import router as self_improvement_router
    from patchi.web.routes.settings import router as settings_router
    from patchi.web.routes.tokens import router as tokens_router

    app.include_router(legacy_router)
    app.include_router(dashboard_router)
    app.include_router(findings_router)
    app.include_router(charter_router)
    app.include_router(review_router)
    app.include_router(guard_router)
    app.include_router(chat_router)
    app.include_router(brain_router)
    app.include_router(settings_router)
    app.include_router(history_router)
    app.include_router(brain_map_router)
    app.include_router(dev_check_router)
    app.include_router(scan_router)
    app.include_router(charts_router)
    app.include_router(fix_router)
    app.include_router(hosted_router)
    if hosted_v2_router is not None:
        app.include_router(hosted_v2_router)
    app.include_router(assurance_router)
    app.include_router(chat_api_router)
    app.include_router(guard_api_router)
    app.include_router(tokens_router)
    app.include_router(live_testing_router)
    app.include_router(self_improvement_router)
    app.include_router(cicd_router)
    app.include_router(live_testing_api_router)
    app.include_router(smart_api_router)
    app.include_router(tenant_router)
    app.include_router(dast_evidence_router)
    if dashboard_v2_router is not None:
        app.include_router(dashboard_v2_router)

    # WebSocket endpoint - use unified handler from dashboard
    from patchi.web.routes.dashboard import websocket_endpoint as unified_ws_endpoint

    app.websocket("/ws")(unified_ws_endpoint)

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
