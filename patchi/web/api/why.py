"""Why API — file-explain data for the dashboard's file-explain view.

GET /api/why?path=<file> — the same two explanation-path sequence diagrams
`p why --mermaid` renders (dependents walk + call-flow walk), computed from
the cached import graph by the shared ``_why_diagrams`` helper so the web
view and the CLI can never disagree. Machine-pure JSON per the --json
convention: exactly one document, errors as data (never an HTML error page).
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/why")


def _doc(ok: bool, **fields) -> JSONResponse:
    body = {"ok": ok, **fields}
    return JSONResponse(body, status_code=200 if ok else 404)


@router.get("")
@router.get("/")
async def why_api(request: Request, path: str = "") -> JSONResponse:
    """Explanation-path diagrams for one file.

    Response shapes:
      ok:   {ok, path, file, layer, importance, purpose, depended_on_by,
             files_in_layer, diagrams: [{title, mermaid}, ...]}
      miss: {ok: false, error}
    """
    from patchi.cli.commands.reason_cmd import _why_diagrams

    root = request.app.state.root
    if not path:
        return _doc(False, error="provide ?path=<file> — e.g. /api/why?path=patchi/core/brain/reasoning.py")

    diagrams = _why_diagrams(root, path)
    if diagrams is None:
        return _doc(False, error=f"no import graph data for '{path}' — run `p scan` first")

    # Layer facts come from the same engine the CLI's p why uses; layered-brain
    # absence narrows the answer to graph-only rather than failing the request.
    info: dict = {}
    try:
        from patchi.core.brain.reasoning import ReasoningEngine

        info = ReasoningEngine(root).why(path) or {}
    except Exception:
        info = {}
    info.pop("error", None)

    return _doc(
        True,
        path=path,
        file=info.get("file", path),
        layer=info.get("layer"),
        importance=info.get("importance"),
        purpose=info.get("purpose"),
        depended_on_by=info.get("depended_on_by", []),
        files_in_layer=info.get("files_in_layer"),
        diagrams=[{"title": title, "mermaid": diagram} for title, diagram in diagrams],
    )
