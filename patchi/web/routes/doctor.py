"""Doctor route — system health check and stale command detection."""

from __future__ import annotations

import importlib
import json
import logging
import shutil
import sys
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

logger = logging.getLogger("patchi.web.doctor")

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


# ── Stale commands data (shared with CLI) ─────────────────────────────
STALE_COMMANDS = {
    "brain": {"replacement": "p agents list --brain", "reason": "Merged into agents command"},
    "smart": {"replacement": "p chat --stream", "reason": "Merged into chat command"},
    "health": {"replacement": "p status --deep", "reason": "Merged into status command"},
    "doctor": {"replacement": "p status --validate", "reason": "Merged into status command"},
    "security": {"replacement": "p scan", "reason": "Merged into scan command"},
    "ignore": {"replacement": "p memory ignore", "reason": "Merged into memory command"},
    "explain": {"replacement": "p chat 'explain <type>'", "reason": "Merged into chat command"},
    "profile": {"replacement": "p agent-stats", "reason": "Merged into agent-stats command"},
    "learning": {"replacement": "p agent-stats --learning", "reason": "Merged into agent-stats command"},
    "ask": {"replacement": "p chat", "reason": "Alias — chat is the unified interface"},
}


@router.get("/doctor", response_class=HTMLResponse)
async def doctor_page(request: Request):
    """Render the doctor page with system health and stale commands."""
    root = request.app.state.root
    checks = _run_checks(root)

    return templates.TemplateResponse(
        request,
        "doctor.html",
        {
            "request": request,
            "checks": checks,
            "errors": sum(1 for c in checks if c["status"] == "error"),
            "warnings": sum(1 for c in checks if c["status"] == "warning"),
            "passed": sum(1 for c in checks if c["status"] == "ok"),
        },
    )


@router.get("/api/doctor")
async def doctor_api(request: Request) -> JSONResponse:
    """Return system health as JSON."""
    root = request.app.state.root
    checks = _run_checks(root)
    return JSONResponse({
        "ok": all(c["status"] != "error" for c in checks),
        "checks": checks,
    })


def _run_checks(root: Path) -> list[dict]:
    """Run all doctor checks and return results."""
    checks = []

    # Python version
    pyver = sys.version_info
    if pyver >= (3, 11):
        checks.append({"label": "Python", "status": "ok", "note": f"{pyver.major}.{pyver.minor}.{pyver.micro}"})
    else:
        checks.append({"label": "Python", "status": "error", "note": f"{pyver.major}.{pyver.minor} — requires ≥ 3.11"})

    # Required dependencies
    _REQUIRED = [
        ("rich", "rich"), ("watchfiles", "watchfiles"), ("httpx", "httpx"),
        ("fastapi", "fastapi"), ("uvicorn", "uvicorn"), ("psutil", "psutil"),
        ("yaml", "pyyaml"), ("loguru", "loguru"),
    ]
    for import_name, pip_name in _REQUIRED:
        try:
            importlib.import_module(import_name)
            checks.append({"label": f"dep: {pip_name}", "status": "ok", "note": "Installed"})
        except ImportError:
            checks.append({"label": f"dep: {pip_name}", "status": "error", "note": f"Missing — pip install {pip_name}"})

    # Project root
    if root and root.exists():
        checks.append({"label": "Project root", "status": "ok", "note": str(root)})
    else:
        checks.append({"label": "Project root", "status": "warning", "note": "Not found"})

    # Stale commands
    from patchi.cli.registry import COMMANDS
    cmd_names = [c.name for c in COMMANDS]
    found_stale = [(name, info) for name, info in STALE_COMMANDS.items() if name not in cmd_names]
    if found_stale:
        for name, info in found_stale:
            checks.append({
                "label": f"stale: {name}",
                "status": "warning",
                "note": f"Use '{info['replacement']}' instead — {info['reason']}",
                "replacement": info["replacement"],
            })
    else:
        checks.append({"label": "Stale commands", "status": "ok", "note": "No stale commands"})

    # API keys
    try:
        from patchi.core import config as cfg
        config = cfg.load(root)
        ai_keys = config.get("ai", {}).get("keys", [])
        if ai_keys:
            checks.append({"label": "API keys", "status": "ok", "note": f"{len(ai_keys)} key(s)"})
        else:
            checks.append({"label": "API keys", "status": "warning", "note": "No keys configured"})
    except Exception:
        checks.append({"label": "API keys", "status": "warning", "note": "Could not check"})

    # Optional: test tooling
    for cmd, pip_name in [("pytest", "pytest"), ("npx", "node/npm")]:
        present = shutil.which(cmd) is not None
        checks.append({
            "label": f"opt: {cmd}",
            "status": "ok" if present else "info",
            "note": "Installed" if present else f"Optional — {pip_name}",
        })

    # .patchi/ size
    patchi_dir = root / ".patchi"
    if patchi_dir.exists():
        total_bytes = sum(f.stat().st_size for f in patchi_dir.rglob("*") if f.is_file())
        total_files = sum(1 for f in patchi_dir.rglob("*") if f.is_file())
        if total_bytes > 50 * 1024 * 1024:
            size_str = f"{total_bytes / (1024 * 1024):.1f} MB"
            checks.append({
                "label": ".patchi/ size",
                "status": "warning",
                "note": f"{size_str} ({total_files} files) — consider 'p cleanup'",
            })
        else:
            size_str = f"{total_bytes / 1024:.1f} KB" if total_bytes < 1024 * 1024 else f"{total_bytes / (1024 * 1024):.1f} MB"
            checks.append({"label": ".patchi/ size", "status": "ok", "note": f"{size_str} ({total_files} files)"})

    return checks
