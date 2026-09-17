"""Impact API — affected-neighborhood diagrams for the web dashboard.

GET /api/impact?files=<a.py,b.py> — the same affected-neighborhood
flowchart `p impact --mermaid` renders (changed files + everything that
transitively depends on them), computed by the CLI's shared
``neighborhood_diagram`` renderer over the same cached import graph, so
the web view and the CLI can never disagree. Machine-pure JSON per the
--json convention: exactly one document, errors as data (never an HTML
error page).

With no ``files`` parameter, the endpoint falls back to the files touched
by the most recent fix run (``.patchi/memory/patches.json``), i.e. the
dashboard panel answers "what did my last fix take down?" without the
caller having to know the file list.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/impact")


def _doc(ok: bool, **fields) -> JSONResponse:
    body = {"ok": ok, **fields}
    return JSONResponse(body, status_code=200 if ok else 404)


def _recent_fix_files(root) -> list[str]:
    """Files touched by the most recent fix run (best-effort, newest first)."""
    from pathlib import Path

    from patchi.core import memory as mem

    try:
        patches = mem.list_patches(Path(root)) or []
    except Exception:
        return []
    if not patches:
        return []
    latest = patches[-1]
    files = latest.get("affected_paths") or latest.get("files") or []
    return [f for f in files if isinstance(f, str) and f]


@router.get("")
@router.get("/")
async def impact_api(
    request: Request, files: str = "", max_nodes: int = 60
) -> JSONResponse:
    """Affected-neighborhood diagram for a change set.

    Response shapes:
      ok:   {ok, files, mermaid, stats: {changed, total_affected, rendered,
            omitted, max_distance, risk, truncated}}
      miss: {ok: false, error}

    ``max_nodes`` caps the neighborhood (default 60, matching `p impact
    --mermaid`); values < 1 fall back to the default rather than erroring,
    since this is a display control, not a data request.
    """
    from patchi.cli.commands.reason_cmd import _cached_graph
    from patchi.core.brain.mermaid import neighborhood_diagram

    root = request.app.state.root

    if max_nodes < 1:
        max_nodes = 60

    requested = [f.strip() for f in files.split(",") if f.strip()] if files else []
    source = "explicit"
    if not requested:
        requested = _recent_fix_files(root)
        source = "recent_fix"
    if not requested:
        return _doc(
            False,
            error="provide ?files=<a.py,b.py> — e.g. /api/impact?files=core.py,helper.py"
            " (or run `p fix` so recent-patch files can be inferred)",
        )

    graph = _cached_graph(root)
    if graph is None:
        return _doc(False, error="no import graph data — run `p scan` first")

    try:
        mermaid, stats = neighborhood_diagram(graph, requested, max_nodes=max_nodes)
    except Exception as e:
        return _doc(False, error=f"diagram render failed: {e}")

    return _doc(
        True,
        files=requested,
        source=source,
        mermaid=mermaid,
        stats=stats,
    )
