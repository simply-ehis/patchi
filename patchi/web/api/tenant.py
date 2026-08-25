"""Tenant API — project switching and multi-tenant state isolation."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/tenant")


class SwitchProjectRequest(BaseModel):
    path: str


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


@router.post("/switch")
async def switch_project(req: SwitchProjectRequest, request: Request):
    """Switch to a different project."""
    try:
        from patchi.core.tenant import get_tenant_manager
        mgr = get_tenant_manager()
        target = Path(req.path)
        if not target.exists():
            return JSONResponse(status_code=404, content={"error": f"Path not found: {req.path}"})
        tenant = mgr.switch_project(target)
        # Update app state
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
