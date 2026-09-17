"""Impact API — affected-neighborhood diagrams and blast-radius maps.

GET /api/impact?files=<a.py,b.py> — the same affected-neighborhood
flowchart `p impact --mermaid` renders (changed files + everything that
transitively depends on them), computed by the CLI's shared
``neighborhood_diagram`` renderer over the same cached import graph, so
the web view and the CLI can never disagree. Machine-pure JSON per the
--json convention: exactly one document, errors as data (never an HTML
error page).

``mode=map`` swaps the neighborhood for the whole-graph blast-radius map:
the same ``dependency_diagram`` the README and `p scan` render, with the
changed files highlighted, and blast radii computed by the CLI's own
``_blast_radii`` helper — the map's risk histogram is the CLI table's
ranking, not a parallel implementation.

With no ``files`` parameter, the endpoint falls back to the files touched
by the most recent fix run (``.patchi/memory/patches.json``), i.e. the
dashboard panel answers "what did my last fix take down?" without the
caller having to know the file list.
"""

from __future__ import annotations

from collections import defaultdict

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
    request: Request, files: str = "", max_nodes: int = 60, mode: str = "neighborhood"
) -> JSONResponse:
    """Affected-neighborhood or whole-graph blast-radius map for a change set.

    Response shapes:
      ok:   {ok, mode, files, mermaid, stats: {changed, total_affected,
            rendered, omitted, max_distance, risk, truncated}}
      miss: {ok: false, error}

    ``mode=neighborhood`` (default) renders the affected neighborhood of the
    changed files — the exact diagram `p impact --mermaid` puts in PRs.
    ``mode=map`` renders the whole-graph dependency map (highest fan-in
    first, capped by ``max_nodes``) with the changed files highlighted, plus
    the per-file blast radii from the CLI's ``_blast_radii`` helper so the
    ranking the CLI table shows is the same data this serves. Values < 1
    for ``max_nodes`` fall back to the default rather than erroring, since
    this is a display control, not a data request.
    """
    from patchi.cli.commands.reason_cmd import _blast_radii, _cached_graph
    from patchi.core.brain.mermaid import dependency_diagram, neighborhood_diagram

    root = request.app.state.root

    if max_nodes < 1:
        max_nodes = 60

    requested = [f.strip() for f in files.split(",") if f.strip()] if files else []

    graph = _cached_graph(root)
    if graph is None:
        return _doc(False, error="no import graph data — run `p scan` first")

    if mode == "map":
        radii = _blast_radii(graph)
        known = {f for f in requested if f in graph.nodes}
        try:
            mermaid = dependency_diagram(
                graph, max_nodes=max_nodes, title="Blast-radius map", highlight=sorted(known)
            )
        except Exception as e:
            return _doc(False, error=f"diagram render failed: {e}")
        return _doc(
            True,
            mode="map",
            files=requested,
            mermaid=mermaid,
            stats={
                "nodes": len(graph.nodes),
                "rendered": min(max_nodes, len(graph.nodes)),
                "highlighted": len(known),
                "requested": len(requested),
                "unknown": len(requested) - len(known),
                "risk": _risk_histogram(radii, max_nodes),
            },
        )

    if mode != "neighborhood":
        return _doc(False, error=f"unknown mode '{mode}' — use 'neighborhood' or 'map'")

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

    try:
        mermaid, stats = neighborhood_diagram(graph, requested, max_nodes=max_nodes)
    except Exception as e:
        return _doc(False, error=f"diagram render failed: {e}")

    return _doc(
        True,
        mode="neighborhood",
        files=requested,
        source=source,
        mermaid=mermaid,
        stats=stats,
    )


def _risk_histogram(radii: list[tuple[str, int, int]], top: int) -> dict[str, int]:
    """Risk-class counts over the same top slice `_show_all_blast_radii`
    renders (30 rows) — the map's stats answer 'how risky is what I see'."""
    from patchi.core.brain.mermaid import risk_class

    counts: dict[str, int] = defaultdict(int)
    for _file, _direct, total in radii[:30]:
        counts[risk_class(total)] += 1
    return dict(sorted(counts.items()))
