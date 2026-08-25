"""Tenant API — project switching and multi-tenant state isolation.

Endpoints:
  GET  /api/tenant/list      — registered (previously opened) projects
  GET  /api/tenant/active    — currently active project
  GET  /api/tenant/discover  — scan disk near the active project for other
                                 Patchi projects (dirs containing .patchi)
  POST /api/tenant/switch    — swap the server's active project root at runtime.
                               Refuses targets that are not existing Patchi
                               projects unless init=true is passed explicitly.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/tenant")


class SwitchProjectRequest(BaseModel):
    path: str
    init: bool = False  # explicitly create .patchi if missing


@router.get("/list")
async def list_projects(request: Request):
    """List all registered projects."""
    try:
        from patchi.core.tenant import get_tenant_manager

        mgr = get_tenant_manager()
        projects = mgr.list_projects()
        active = mgr.get_active()
        return {
            "projects": [p.to_dict() for p in projects],
            "active": active.to_dict() if active else None,
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/discover")
async def discover_projects(request: Request):
    """Scan near the current project for other Patchi projects."""
    try:
        from patchi.core.tenant import get_tenant_manager

        mgr = get_tenant_manager()
        base = request.app.state.root
        found = mgr.discover_projects(near=base)
        active = mgr.get_active()
        return {
            "current": active.to_dict() if active else {"root": str(base), "name": base.name},
            "discovered": [
                {
                    "path": str(p),
                    "name": p.name,
                    "is_current": str(p.resolve()) == str(base.resolve()),
                }
                for p in found
            ],
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.post("/switch")
async def switch_project(req: SwitchProjectRequest, request: Request):
    """Switch to a different project.

    Safety: only directories that already contain a .patchi/ are accepted,
    unless the caller explicitly passes init=true (which creates one).
    """
    try:
        target = Path(req.path).expanduser().resolve()

        if not target.exists():
            return JSONResponse(status_code=404, content={"error": f"Path not found: {req.path}"})
        if not target.is_dir():
            return JSONResponse(status_code=400, content={"error": f"Not a directory: {target}"})

        if not (target / ".patchi").is_dir():
            if not req.init:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": f"No .patchi project at {target}. Pass init=true to create one.",
                        "hint": "Found by accident? Only real Patchi projects can be viewed.",
                    },
                )

        from patchi.core.tenant import get_tenant_manager

        mgr = get_tenant_manager()
        tenant = mgr.switch_project(target)
        # Update app state — every route reads root from here
        request.app.state.root = tenant.root
        return {"success": True, "project": tenant.to_dict()}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/active")
async def active_project(request: Request):
    """Get the currently active project."""
    try:
        from patchi.core.tenant import get_tenant_manager

        mgr = get_tenant_manager()
        active = mgr.get_active()
        return {"project": active.to_dict() if active else None}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
