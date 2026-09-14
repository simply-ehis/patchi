"""Charter page — project guard rules, violation history, and set form."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
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
        from patchi.core.memory import get_brain
        from patchi.core.security.charter import load_charter

        charter = load_charter(root)
        brain = get_brain(root)

        # Get violations if we have layers
        violations = []
        if charter.rules and brain:
            try:
                from patchi.core.memory import get_layers
                from patchi.core.security.charter import (
                    check_boundary_violations,
                )

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

            return JSONResponse(
                {
                    "ok": True,
                    "rule_count": len(rules),
                    "rules": [r.to_dict() for r in rules],
                }
            )
    except Exception as e:
        _log.error("Failed to set charter: %s", e)
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/api/charter/check")
async def check_violations(request: Request) -> JSONResponse:
    """Check charter violations against current codebase."""
    root = request.app.state.root
    with tenant_context(root):
        from patchi.core.memory import get_brain, get_layers
        from patchi.core.security.charter import (
            check_boundary_violations,
            load_charter,
        )

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

        return JSONResponse(
            {
                "ok": True,
                "violations": violations,
                "rule_count": len(charter.rules),
            }
        )


@router.post("/api/charter/autofix")
async def charter_autofix(request: Request) -> JSONResponse:
    """Run proactive auto-fix on project files.

    POST /api/charter/autofix
    Body: {"preview": true/false, "paths": ["optional", "file", "list"]}

    - preview=true: dry-run, returns what would be fixed without applying
    - preview=false: actually applies fixes
    - paths: optional list of file paths to fix (default: all Python files)
    """
    root = request.app.state.root
    try:
        body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    except Exception:
        body = {}

    preview = body.get("preview", False)
    paths = body.get("paths", [])

    with tenant_context(root):
        from pathlib import Path

        from patchi.core.security.auto_fix_proactive import (
            proactive_fix_files,
        )
        from patchi.core.security.charter import load_charter

        charter = load_charter(root)
        if not charter.rules:
            return JSONResponse(
                {
                    "ok": True,
                    "message": "No charter set. Set a charter first.",
                    "report": None,
                }
            )

        # Collect files to check
        if paths:
            file_paths = [
                Path(p) for p in paths if (Path(p).is_file() if not Path(p).is_absolute() else Path(p).is_file())
            ]
        else:
            # Default: scan all Python files in the project
            file_paths = [
                f
                for f in root.rglob("*.py")
                if f.is_file() and ".patchi" not in str(f) and "node_modules" not in str(f)
            ]
            # Limit to 500 files for performance
            file_paths = file_paths[:500]

        if not file_paths:
            return JSONResponse(
                {
                    "ok": True,
                    "message": "No files found to check",
                    "report": None,
                }
            )

        report = proactive_fix_files(root, file_paths, apply=not preview)
        return JSONResponse(
            {
                "ok": True,
                "preview": preview,
                "report": report.to_dict(),
            }
        )


@router.get("/api/charter/fix-history")
async def get_fix_history(request: Request) -> JSONResponse:
    """Load fix history for the charter page."""
    root = request.app.state.root
    try:
        from patchi.core.brain.proactive import load_fix_history

        history = load_fix_history(root, limit=20)
        return JSONResponse({"ok": True, "history": history})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e), "history": []})


@router.post("/api/charter/revert")
async def revert_fix(request: Request) -> JSONResponse:
    """Revert a fix operation by restoring files from git."""
    root = request.app.state.root
    try:
        body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    except Exception:
        body = {}

    fix_id = body.get("fix_id", "")
    if not fix_id:
        return JSONResponse({"ok": False, "error": "No fix_id provided"})

    try:
        from patchi.core.brain.proactive import revert_fix

        result = revert_fix(root, fix_id)
        return JSONResponse({"ok": result["success"], **result})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})
