"""Charter page — project guard rules, violation history, and set form."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.templating import Jinja2Templates as _Jinja2Templates

from patchi.core.tenant import tenant_context

router = APIRouter()
templates = _Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
_log = logging.getLogger("patchi.web.charter")


@router.get("/charter")
async def charter_page(request: Request) -> HTMLResponse:
    """Render the charter page with rules and violations."""
    root = request.app.state.root
    with tenant_context(root):
        from patchi.core.security.charter import Charter, load_charter
        from patchi.core.memory import get_brain

        charter = load_charter(root)
        brain = get_brain(root)

        # Get violations if we have layers
        violations = []
        if charter.rules and brain:
            try:
                from patchi.core.security.charter import check_boundary_violations, check_convention_violations
                from patchi.core.memory import get_layers

                layers = get_layers(root)
                import_edges = []
                for name, layer in layers.items():
                    for dep in layer.get("depends_on", []):
                        import_edges.append((name, dep))

                violations = [v.to_dict() for v in check_boundary_violations(charter, import_edges)]
            except Exception as e:
                _log.debug("Violation check failed: %s", e)

        return templates.TemplateResponse(
            request,
            "charter.html",
            {
                "request": request,
                "rules": [r.to_dict() for r in charter.rules],
                "charter_text": charter.text or "",
                "violations": violations,
                "rule_count": len(charter.rules),
                "violation_count": len(violations),
            },
        )


@router.get("/api/charter")
async def get_charter(request: Request) -> JSONResponse:
    """Get current charter as JSON."""
    root = request.app.state.root
    with tenant_context(root):
        from patchi.core.security.charter import load_charter

        charter = load_charter(root)
        return JSONResponse(charter.to_dict())


@router.post("/api/charter")
async def set_charter(request: Request) -> JSONResponse:
    """Set charter from natural language text."""
    root = request.app.state.root
    try:
        body = await request.json()
        text = body.get("text", "").strip()
        if not text:
            return JSONResponse({"ok": False, "error": "No charter text provided"})

        with tenant_context(root):
            from patchi.core.security.charter import Charter, parse_nl_to_rules, save_charter

            rules = parse_nl_to_rules(text)
            charter = Charter(text=text, rules=rules)
            save_charter(charter, root)

            return JSONResponse({
                "ok": True,
                "rule_count": len(rules),
                "rules": [r.to_dict() for r in rules],
            })
    except Exception as e:
        _log.error("Failed to set charter: %s", e)
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/api/charter/check")
async def check_violations(request: Request) -> JSONResponse:
    """Check charter violations against current codebase."""
    root = request.app.state.root
    with tenant_context(root):
        from patchi.core.security.charter import (
            Charter,
            load_charter,
            check_boundary_violations,
            check_convention_violations,
        )
        from patchi.core.memory import get_brain, get_layers

        charter = load_charter(root)
        brain = get_brain(root)

        if not charter.rules:
            return JSONResponse({"ok": True, "violations": [], "message": "No charter set"})

        violations = []
        try:
            layers = get_layers(root) if brain else {}
            import_edges = []
            for name, layer in layers.items():
                for dep in layer.get("depends_on", []):
                    import_edges.append((name, dep))

            violations = [v.to_dict() for v in check_boundary_violations(charter, import_edges)]
        except Exception as e:
            _log.debug("Check failed: %s", e)

        return JSONResponse({
            "ok": True,
            "violations": violations,
            "rule_count": len(charter.rules),
        })
