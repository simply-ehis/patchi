"""Ready API — ship-readiness gate for the web UI (mirrors `p ready`).

POST /api/ready → runs unit, regression, secrets, misconfig, api_contract
agents and returns a summary with is_ready boolean.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api")


@router.post("/ready")
async def run_ready(request: Request):
    """Run ship-readiness checks."""
    root = request.app.state.root
    try:
        import asyncio

        from patchi.cli.commands.ready_cmd import (
            _check_integration,
            _check_security,
            _check_testing,
        )
        from patchi.core import config as cfg
        from patchi.core import memory as mem

        config = cfg.load(root) if root.exists() else {}
        brain = mem.get_brain(root)

        testing, security, integration = await asyncio.to_thread(
            lambda: (
                _check_testing(root, brain, config),
                _check_security(root, brain, config),
                _check_integration(root, brain, config),
            )
        )
        all_results = {**testing, **security, **integration}
        failed = [k for k, v in all_results.items() if v.get("status") not in ("done", "succeeded", "passed", "skipped")]
        is_ready = not failed
        return {
            "ok": True,
            "is_ready": is_ready,
            "failed": failed,
            "results": all_results,
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@router.get("/ready")
async def ready_status(request: Request):
    """Readiness hint without running agents (for button state)."""
    return {"ok": True, "hint": "POST to run readiness checks"}
