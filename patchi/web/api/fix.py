"""Fix API — apply/reject patches."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from patchi.core.tenant import tenant_context

router = APIRouter(prefix="/api/fix")


@router.post("/apply/{patch_id}")
async def apply_patch(patch_id: str, request: Request) -> JSONResponse:
    root = request.app.state.root
    # IDOR fix: use context manager for tenant isolation and verify patch ownership
    with tenant_context(root):
        from patchi.core import memory as mem

        patches = mem.read("patches", root)
        patch = next((p for p in patches if p.get("id") == patch_id), None)

        if not patch:
            return JSONResponse({"ok": False, "error": "Patch not found"}, status_code=404)

        # Verify patch belongs to this tenant/project (prevent IDOR enumeration)
        patch_project = patch.get("project") or patch.get("tenant") or ""
        if patch_project and patch_project != str(root) and patch_project not in str(root):
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

    # Fallback (unreachable due to with)
    return JSONResponse({"ok": False, "error": "Tenant error"}, status_code=500)


@router.post("/reject/{patch_id}")
async def reject_patch(patch_id: str, request: Request) -> JSONResponse:
    root = request.app.state.root
    with tenant_context(root):
        from patchi.core import memory as mem

        try:
            mem.record_rejection(patch_id, "web_user", root)
            return JSONResponse({"ok": True, "message": f"Rejected patch {patch_id}"})
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.post("/apply-all-safe")
async def apply_all_safe(request: Request) -> JSONResponse:
    """Apply every pending patch that passes the risk gate for auto-apply.

    Patches the gate flags as BLOCK or REQUIRE_REVIEW are skipped and reported,
    never applied. This backs the "Apply all safe" button in the review UI.
    """
    root = request.app.state.root
    from patchi.core import memory as mem
    from patchi.core.fix.applier import PatchApplier
    from patchi.core.fix.patch import Patch
    from patchi.core.fix.risk_gate import RiskGate

    patches_raw = mem.read("patches", root)
    if not patches_raw:
        return JSONResponse(
            {
                "ok": True,
                "applied": [],
                "skipped": [],
                "failed": [],
                "message": "No patches pending",
            }
        )

    gate = RiskGate(root)
    applier = PatchApplier(root)

    applied: list[dict] = []
    skipped: list[dict] = []
    failed: list[dict] = []

    for raw in patches_raw:
        pid = raw.get("id", "?")
        state = raw.get("state", "")
        if state in ("applied", "rejected"):
            continue  # only pending patches
        try:
            patch = Patch.from_dict(raw)
        except Exception as e:
            failed.append({"id": pid, "reason": f"unparseable: {e}"})
            continue

        decision = gate.evaluate(patch)
        if decision.is_blocked() or decision.needs_review():
            skipped.append(
                {
                    "id": pid,
                    "reason": decision.decision.value
                    if hasattr(decision.decision, "value")
                    else str(decision.decision),
                    "detail": getattr(decision, "reasons", None) or "",
                }
            )
            continue

        try:
            result = applier.apply(patch)
            entry = {"id": pid}
            if result.success:
                applied.append(entry)
            else:
                entry["reason"] = getattr(result, "error", "") or "applier refused"
                failed.append(entry)
        except Exception as e:
            failed.append({"id": pid, "reason": str(e)})

    return JSONResponse(
        {
            "ok": True,
            "applied": applied,
            "skipped": skipped,
            "failed": failed,
            "message": f"{len(applied)} applied, {len(skipped)} need review, {len(failed)} failed",
        }
    )
