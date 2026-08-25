"""Hosted API v2 — the higher-value hosted surface.

Adds on top of /api/hosted:
  GET  /api/hosted/v2/overview           — one-payload mission dashboard
  GET  /api/hosted/v2/compliance/report  — auditor-ready evidence pack
  GET  /api/hosted/v2/webhooks           — list alert webhooks
  POST /api/hosted/v2/webhooks           — register webhook
  DELETE /api/hosted/v2/webhooks/{id}    — remove webhook
  POST /api/hosted/v2/webhooks/test      — send a test event
  GET  /api/hosted/v2/usage              — scans, tokens, AI cost summary
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/hosted/v2")


@router.get("/overview")
async def hosted_overview(request: Request) -> JSONResponse:
    """Single aggregated payload for the hosted control plane."""
    root = request.app.state.root
    from patchi.core import config as cfg
    from patchi.core import memory as mem
    from patchi.core.ai.cost_tracker import get_stats as ai_stats
    from patchi.core.hosted import ip_reputation
    from patchi.core.hosted import webhooks as hooks_mod
    from patchi.core.hosted.audit_log import read_recent
    from patchi.core.hosted.tokens import count as token_count

    brain = mem.get_brain(root)
    scans = mem.get_scan_results(root)
    conf = _safe_config(cfg, root)
    hosted_conf = conf.get("hosted", {})

    # Findings by severity across all agents
    sev_totals: dict[str, int] = {}
    active_agents = 0
    for data in scans.values():
        if isinstance(data, dict):
            active_agents += 1
            for f in data.get("findings", []):
                if isinstance(f, dict):
                    sev = f.get("severity", "info")
                    sev_totals[sev] = sev_totals.get(sev, 0) + 1

    try:
        threats = ip_reputation.get_top_threats(root, limit=5)
    except Exception:
        threats = []

    try:
        recent_audit = read_recent(root, limit=10)
    except Exception:
        recent_audit = []

    try:
        ai = ai_stats()
    except Exception:
        ai = {}

    return JSONResponse({
        "enabled": hosted_conf.get("enabled", False),
        "health_score": (brain.get("health_score") or {}).get("total"),
        "last_scan": brain.get("last_scan", ""),
        "file_count": brain.get("file_count", 0),
        "active_agents": active_agents,
        "findings_by_severity": sev_totals,
        "active_domains": brain.get("active_security_domains", []),
        "guard": {
            "interceptor_enabled": conf.get("pipeline", {}).get("interceptor", {}).get("enabled", False),
            "tokens": _safe_count(token_count, root),
            "top_threats": threats,
        },
        "webhooks": len(hooks_mod.list_webhooks(root)),
        "recent_activity": [
            {"ts": e.get("ts"), "event": e.get("event"), "actor": e.get("actor")}
            for e in recent_audit[:10]
        ],
        "ai_usage": ai if isinstance(ai, dict) else {},
    })


@router.get("/compliance/report")
async def compliance_report(request: Request, standard: str = "owasp-asvs") -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted.compliance_report import generate_report

    report = generate_report(root, standard)
    if "error" in report:
        return JSONResponse(report, status_code=400)

    # Audit that a report was pulled (auditors like trails)
    try:
        from patchi.core.hosted.audit_log import write as audit_write

        audit_write(root, "compliance.report_generated", data={"standard": standard})
    except Exception:
        pass

    return JSONResponse(report)


@router.get("/webhooks")
async def list_webhooks(request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted import webhooks as hooks_mod

    return JSONResponse({"webhooks": hooks_mod.list_webhooks(root)})


@router.post("/webhooks")
async def add_webhook(request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted import webhooks as hooks_mod

    body = await request.json()
    url = (body.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return JSONResponse({"ok": False, "error": "url must be http(s)"}, status_code=400)

    record = hooks_mod.add_webhook(
        root,
        url=url,
        events=body.get("events") or ["finding", "anomaly", "scan_completed"],
        name=body.get("name", ""),
        secret=body.get("secret", ""),
    )
    try:
        from patchi.core.hosted.audit_log import write as audit_write

        audit_write(root, "webhook.added", data={"id": record["id"], "url": url})
    except Exception:
        pass
    return JSONResponse({"ok": True, "webhook": record})


@router.delete("/webhooks/{hook_id}")
async def delete_webhook(hook_id: str, request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted import webhooks as hooks_mod

    if hooks_mod.remove_webhook(root, hook_id):
        return JSONResponse({"ok": True})
    return JSONResponse({"ok": False, "error": "not found"}, status_code=404)


@router.post("/webhooks/test")
async def test_webhooks(request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core.hosted import webhooks as hooks_mod

    delivered = hooks_mod.dispatch_event(
        root, "test", {"message": "Patchi hosted webhook test", "ok": True}
    )
    return JSONResponse({"ok": True, "delivered": delivered})


@router.get("/usage")
async def usage(request: Request) -> JSONResponse:
    """Usage + cost summary for billing surfaces."""
    root = request.app.state.root
    from patchi.core import memory as mem
    from patchi.core.ai.cost_tracker import get_stats as ai_stats
    from patchi.core.hosted.tokens import list_tokens

    scans = mem.get_scan_results(root)
    scan_events = {
        name: {"timestamp": data.get("timestamp"), "finding_count": len(data.get("findings", []))}
        for name, data in scans.items()
        if isinstance(data, dict)
    }

    try:
        ai = ai_stats()
    except Exception:
        ai = {}

    try:
        tokens = list_tokens(root)
    except Exception:
        tokens = []

    return JSONResponse({
        "scans": {"agents_run": len(scan_events), "detail": scan_events},
        "ai_usage": ai if isinstance(ai, dict) else {},
        "active_tokens": sum(1 for t in tokens if not t.get("revoked")),
        "budget": _budget_status(root),
    })


# ── helpers ───────────────────────────────────────────────────────────────────


def _safe_config(cfg, root):
    try:
        return cfg.load(root)
    except Exception:
        return {}


def _safe_count(fn, *args):
    try:
        return fn(*args)
    except Exception:
        return 0


def _budget_status(root) -> dict:
    try:
        from patchi.core import config as cfg
        from patchi.core.ai.cost_tracker import check_budget

        conf = cfg.load(root)
        state = check_budget(conf)
        return {
            "limit_enabled": conf.get("ai", {}).get("cost_limit_enabled", False),
            "state": state or "ok",
        }
    except Exception:
        return {"limit_enabled": False, "state": "unknown"}
