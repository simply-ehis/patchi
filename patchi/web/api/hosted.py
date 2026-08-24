"""Hosted API — hosted mode actions."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/hosted")


@router.get("/status")
async def hosted_status(request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core import config as cfg

    try:
        config = cfg.load(root)
    except Exception:
        config = {}

    hosted = config.get("hosted", {})
    return JSONResponse(
        {
            "enabled": hosted.get("enabled", False),
            "log_path": hosted.get("log_path", ""),
        }
    )


@router.post("/init")
async def hosted_init(request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core import config as cfg_mod

    try:
        body = await request.json()
        log_path = body.get("log_path", "/var/log/nginx/access.log")
        log_format = body.get("log_format", "nginx")
        escalate = body.get("escalate", True)

        cfg_mod.set_value("hosted.log_path", log_path, root)
        cfg_mod.set_value("hosted.log_format", log_format, root)
        cfg_mod.set_value("hosted.escalate", escalate, root)
        cfg_mod.set_value("hosted.enabled", True, root)

        hosted_dir = root / ".patchi" / "hosted"
        hosted_dir.mkdir(parents=True, exist_ok=True)

        return JSONResponse(
            {
                "ok": True,
                "message": "Hosted mode configured",
                "log_path": log_path,
                "log_format": log_format,
            }
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.get("/tokens")
async def list_tokens(request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted import tokens as tokens_mod

    return JSONResponse({"tokens": tokens_mod.list_tokens(root)})


@router.post("/tokens")
async def create_token(request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted import tokens as tokens_mod

    try:
        body = await request.json()
        name = body.get("name", "unnamed")
        plaintext = tokens_mod.generate(root, name)
        return JSONResponse(
            {
                "ok": True,
                "token": plaintext,
                "message": "Token generated — shown once",
            }
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.delete("/tokens/{token_id}")
async def revoke_token(token_id: str, request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted import tokens as tokens_mod

    ok = tokens_mod.revoke(root, token_id)
    if ok:
        return JSONResponse({"ok": True, "message": f"Token {token_id} revoked"})
    return JSONResponse({"ok": False, "error": "Token not found"}, status_code=404)


@router.post("/block/{ip}")
async def block_ip(ip: str, request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted import ip_reputation

    ip_reputation.block(ip, root)
    return JSONResponse({"ok": True, "message": f"Blocked {ip}"})


@router.post("/unblock/{ip}")
async def unblock_ip(ip: str, request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted import ip_reputation

    ip_reputation.unblock(ip, root)
    return JSONResponse({"ok": True, "message": f"Unblocked {ip}"})
