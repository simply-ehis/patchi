"""Fix API — apply/reject patches."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/fix")


@router.post("/apply/{patch_id}")
async def apply_patch(patch_id: str, request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core import memory as mem

    patches = mem.read("patches", root)
    patch = next((p for p in patches if p.get("id") == patch_id), None)

    if not patch:
        return JSONResponse({"ok": False, "error": "Patch not found"}, status_code=404)

    from patchi.core.fix.applier import PatchApplier
    from patchi.core.fix.patch import Patch

    try:
        p = Patch.from_dict(patch)
        applier = PatchApplier(root)
        applier.apply(p)
        return JSONResponse({"ok": True, "message": f"Applied patch {patch_id}"})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.post("/reject/{patch_id}")
async def reject_patch(patch_id: str, request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core import memory as mem

    try:
        mem.record_rejection(patch_id, "web_user", root)
        return JSONResponse({"ok": True, "message": f"Rejected patch {patch_id}"})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
