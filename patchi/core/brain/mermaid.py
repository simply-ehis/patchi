"""Mermaid diagram generation from Brain graph data (Part 4 §2 / Item 31).

Generates Mermaid ``flowchart`` and ``sequenceDiagram`` blocks directly from
import_graph edges and route_mapper data.  Pure code — no AI calls, no
ambiguity to resolve, only formatting.

Public API:
    dependency_diagram(graph, *, max_nodes, title) -> str
    route_diagram(routes, *, title) -> str
    sequence_diagram(routes, graph, *, entry, max_hops) -> str
"""

from __future__ import annotations

import html
import re
from collections import defaultdict
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from patchi.core.brain.import_graph import ImportGraph
    from patchi.core.brain.route_mapper import RouteInfo


# ── Helpers ──────────────────────────────────────────────────────────────────

_LABEL_MAX = 40


def _safe_id(path: str) -> str:
    """Turn a file path into a valid Mermaid node ID."""
    # Mermaid IDs: alphanumeric + underscore, must start with letter/underscore.
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", path)
    # Collapse runs of underscores.
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    if not cleaned or cleaned[0].isdigit():
        cleaned = "n_" + cleaned
    return cleaned


def _short_label(path: str) -> str:
    """Produce a short display label from a file path."""
    stem = PurePosixPath(path.replace("\\", "/")).stem
    if len(stem) > _LABEL_MAX:
        stem = stem[: _LABEL_MAX - 3] + "..."
    return html.escape(stem)


def _group_by_dir(nodes: list[str]) -> dict[str, list[str]]:
    """Group file paths by their first directory level."""
    groups: dict[str, list[str]] = defaultdict(list)
    for n in nodes:
        parts = PurePosixPath(n.replace("\\", "/")).parts
        if len(parts) > 1:
            groups[parts[0]].append(n)
        else:
            groups["root"].append(n)
    return dict(groups)


# ── Dependency diagram ───────────────────────────────────────────────────────


def dependency_diagram(
    graph: ImportGraph,
    *,
    max_nodes: int = 80,
    title: str = "Dependency Graph",
) -> str:
    """Generate a Mermaid flowchart from import_graph edges.

    Groups files by top-level directory and renders subgraphs.
    Nodes beyond *max_nodes* are truncated (the highest fan-in nodes
    are kept first, per Part 4 §1).
    """
    # Rank by fan-in across the WHOLE graph first, then truncate. Ranking
    # after truncation would keep the first *max_nodes* alphabetically and
    # silently drop the actual hubs (and with them most edges).
    all_nodes = sorted(graph.nodes)
    fan_in: dict[str, int] = {n: len(graph.reverse.get(n, set())) for n in all_nodes}
    nodes = sorted(all_nodes, key=lambda n: fan_in.get(n, 0), reverse=True)[:max_nodes]
    node_set = set(nodes)

    lines = ["---", f"title: {title}", "---", "flowchart LR"]

    # Group nodes by top-level directory.
    groups = _group_by_dir(nodes)

    # Disambiguate colliding stems (e.g. several base.py) by prefixing the
    # parent directory — same-text boxes read as the same module otherwise.
    from collections import Counter

    stem_counts = Counter(_short_label(m) for m in nodes)

    for dir_name, members in sorted(groups.items()):
        sub_id = _safe_id(dir_name)
        lines.append(f"    subgraph {sub_id} [{html.escape(dir_name)}]")
        for m in members:
            nid = _safe_id(m)
            label = _short_label(m)
            if stem_counts[label] > 1:
                parent = PurePosixPath(m.replace("\\", "/")).parent.name
                label = html.escape(f"{parent}/{label}")
            lines.append(f'        {nid}["{label}"]')
        lines.append("    end")

    # Edges.
    for src in nodes:
        for tgt in sorted(graph.edges.get(src, set())):
            if tgt in node_set:
                lines.append(f"    {_safe_id(src)} --> {_safe_id(tgt)}")

    return "\n".join(lines)


# ── Route diagram ────────────────────────────────────────────────────────────


def route_diagram(
    routes: list[RouteInfo],
    *,
    title: str = "Route Map",
) -> str:
    """Generate a Mermaid flowchart showing route → handler mapping.

    Groups routes by HTTP method for visual clarity.
    """
    if not routes:
        return f"---\ntitle: {title}\n---\nflowchart LR\n    empty[\"No routes found\"]"

    lines = ["---", f"title: {title}", "---", "flowchart LR"]

    # Group by method.
    by_method: dict[str, list[RouteInfo]] = defaultdict(list)
    for r in routes:
        by_method[r.method.upper()].append(r)

    method_order = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

    for method in method_order:
        method_routes = by_method.get(method, [])
        if not method_routes:
            continue

        sub_id = f"method_{method.lower()}"
        lines.append(f"    subgraph {sub_id} [{method}]")
        for r in method_routes[:30]:  # Cap per method.
            nid = _safe_id(f"{method}_{r.path}")
            label = r.path[:_LABEL_MAX]
            lines.append(f'        {nid}["{html.escape(label)}"]')
        lines.append("    end")

    return "\n".join(lines)


# ── Sequence diagram ─────────────────────────────────────────────────────────


def sequence_diagram(
    routes: list[RouteInfo],
    graph: ImportGraph,
    *,
    entry: str | None = None,
    max_hops: int = 8,
    title: str = "Request Flow",
) -> str:
    """Generate a Mermaid sequenceDiagram for one request flow.

    Walks the call chain: route handler → files it imports → files they
    import, up to *max_hops* depth.  If *entry* is provided, only traces
    from that route path; otherwise picks the first POST/PUT/DELETE route
    as the most interesting flow.
    """
    # Find the target route.
    target: RouteInfo | None = None
    if entry:
        for r in routes:
            if r.path == entry or entry in r.path:
                target = r
                break
    if target is None:
        # Pick the first state-changing route.
        for r in routes:
            if r.method.upper() in {"POST", "PUT", "DELETE", "PATCH"}:
                target = r
                break
    if target is None and routes:
        target = routes[0]
    if target is None:
        return (
            f"---\ntitle: {title}\n---\nsequenceDiagram\n"
            f"    participant client\n    participant server\n"
            f"    client->>server: (no routes found)"
        )

    handler_file = target.file
    lines = ["---", f"title: {title} — {target.method} {target.path}", "---"]
    lines.append("sequenceDiagram")
    lines.append("    participant client")
    lines.append(f"    participant handler as {_short_label(handler_file)}")

    visited = {handler_file}
    current = handler_file
    hops = 0

    while hops < max_hops:
        imported = sorted(graph.edges.get(current, set()))
        if not imported:
            break
        # Pick the most-imported target (by fan-in) as the next hop.
        best = max(
            imported,
            key=lambda f: len(graph.reverse.get(f, set())),
            default=imported[0],
        )
        if best in visited:
            break
        visited.add(best)
        lines.append(f"    handler->>handler: {_short_label(best)}")
        current = best
        hops += 1

    return "\n".join(lines)
