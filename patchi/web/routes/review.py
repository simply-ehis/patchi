"""Review route — patch review with diffs."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/review", response_class=HTMLResponse)
async def review(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    raw_patches = mem.read("patches", root)

    # Enrich each patch with diff content if available
    patches = []
    for p in raw_patches:
        if isinstance(p, dict):
            # Build a unified diff string from FileChange objects if not already present
            if not p.get("diff") and p.get("changes"):
                diff_lines = []
                for change in p["changes"]:
                    path = change.get("path", "unknown")
                    before = change.get("before", "")
                    proposed = change.get("proposed", "")
                    if before or proposed:
                        import difflib

                        diff = list(
                            difflib.unified_diff(
                                before.splitlines(keepends=True) if before else [],
                                proposed.splitlines(keepends=True) if proposed else [],
                                fromfile=f"a/{path}",
                                tofile=f"b/{path}",
                                lineterm="",
                            )
                        )
                        diff_lines.extend(diff)
                p["diff"] = "\n".join(diff_lines) if diff_lines else ""
            patches.append(p)

    return templates.TemplateResponse(
        request,
        "review.html",
        {
            "request": request,
            "patches": patches,
            "total": len(patches),
        },
    )
