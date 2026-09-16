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
from collections import defaultdict, deque
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


# ── Risk classes (shared with the CLI table/markdown renderers) ─────────────


def risk_class(total_affected: int) -> str:
    """Blast-radius risk band for a file, from its transitive-dependent count.

    Bands: 0 = low, 1-3 = med, 4-10 = high, 11+ = critical. Single source of
    truth for every renderer (CLI table, markdown report, diagram styling)
    so the bands can never drift apart.
    """
    if total_affected <= 0:
        return "low"
    if total_affected <= 3:
        return "med"
    if total_affected <= 10:
        return "high"
    return "critical"


# ── Affected-neighborhood diagram ────────────────────────────────────────────


def _transitive_dependents(graph: ImportGraph, start: str) -> set[str]:
    """Everything that (transitively) imports ``start`` — the closure that a
    change to ``start`` can drag down. Excludes ``start`` itself."""
    seen: set[str] = set()
    queue = deque(graph.reverse.get(start, set()))
    while queue:
        n = queue.popleft()
        if n in seen:
            continue
        seen.add(n)
        queue.extend(graph.reverse.get(n, set()))
    seen.discard(start)
    return seen


def _distance_map(graph: ImportGraph, starts: set[str]) -> dict[str, int]:
    """BFS hops from the changed set through the dependents graph."""
    dist = dict.fromkeys(starts, 0)
    frontier = deque(starts)
    while frontier:
        cur = frontier.popleft()
        for nxt in graph.reverse.get(cur, set()):
            if nxt not in dist:
                dist[nxt] = dist[cur] + 1
                frontier.append(nxt)
    return dist


def neighborhood_diagram(
    graph: ImportGraph,
    changed: list[str],
    *,
    max_nodes: int = 60,
    title: str | None = None,
) -> tuple[str, dict]:
    """Mermaid flowchart of the *affected neighborhood* of a change set.

    Scoped by construction: only the changed files and the code that
    transitively depends on them appear — the rest of the graph is not in
    the data model of this function at all. Edges point in the blast
    direction (importer --> imported, "who breaks me"), so the chart reads
    as an impact flow rather than a generic dependency map.

    Node set is adaptive: everything fits unless the neighborhood exceeds
    *max_nodes*, in which case the closest BFS shells are kept first (the
    files a change hits soonest), and the omitted tail is reported in the
    stats rather than silently dropped. Nodes carry risk classes computed
    from their real transitive-dependent counts.

    Returns ``(mermaid_source, stats)``; stats is machine-readable::

        {changed, total_affected, rendered, omitted, max_distance,
         omitted_by_distance: {distance: count},
         risk: {class: count}, truncated: bool}

    """
    changed_set = {c for c in changed if c in graph.nodes}
    # A changed file the graph doesn't know still deserves a node — it may
    # be brand-new. It simply has no neighborhood edges yet.
    unknown = [c for c in changed if c not in graph.nodes]

    # Unknown changed files are part of the neighborhood (they're being
    # changed); BFS them too so a dependents chain discovered through a new
    # file still renders.
    dist = _distance_map(graph, changed_set | set(unknown))
    affected = {n: d for n, d in dist.items() if n not in changed_set and n not in unknown}

    kept: set[str] = set(changed_set) | set(affected)
    omitted_by_distance: dict[int, int] = {}
    if len(dist) > max_nodes:
        # Keep the changed files themselves always; then shells outward.
        by_d: dict[int, list[str]] = defaultdict(list)
        for n, d in affected.items():
            by_d[d].append(n)
        kept = set(changed_set)  # restart from the always-kept core
        for d in sorted(by_d):
            if len(kept) + len(by_d[d]) <= max_nodes:
                kept.update(by_d[d])
            else:
                room = max_nodes - len(kept)
                # Within a shell, keep the highest fan-in first — the files
                # whose breakage would be most visible.
                for n in sorted(by_d[d], key=lambda f: -len(graph.reverse.get(f, set())))[:room]:
                    kept.add(n)
                break
        # Anything a kept shell couldn't fit counts as omitted, by shell.
        for d in sorted(by_d):
            missing = [n for n in by_d[d] if n not in kept]
            if missing:
                omitted_by_distance[d] = len(missing)

    # Risk classes from real transitive-dependent counts (not distance).
    risk_counts: dict[str, int] = defaultdict(int)
    node_risk: dict[str, str] = {}
    for n in kept:
        rc = risk_class(len(_transitive_dependents(graph, n)))
        node_risk[n] = rc
        risk_counts[rc] += 1

    # Dynamic title when none given: shape of the neighborhood, not a label.
    if title is None:
        affected_count = len(dist) - len(changed_set) - len(unknown)
        title = f"Impact neighborhood — {len(changed_set) + len(unknown)} changed, {affected_count} affected"

    lines = ["---", f"title: {title}", "---", "flowchart TD"]

    def _cls(name: str) -> str:
        if name in changed_set:
            return "changed"
        if name in node_risk:
            return f"risk-{node_risk[name]}"
        return "risk-low"

    for n in sorted(kept):
        lines.append(f'    {_safe_id(n)}["{_short_label(n)}"]:::{_cls(n)}')
    for n in sorted(unknown):
        lines.append(f'    {_safe_id(n)}["{_short_label(n)}"]:::changed')

    # Edges in blast direction: importer --> imported, restricted to the
    # rendered universe (kept + unknown changed files, which carry no edges
    # of their own but are edge TARGETS from their importers).
    universe = kept | set(unknown)
    edge_count = 0
    for src in sorted(universe):
        for tgt in sorted(graph.edges.get(src, set())):
            if tgt in universe:
                lines.append(f"    {_safe_id(src)} --> {_safe_id(tgt)}")
                edge_count += 1

    # Style from data (counts), not hardcoded assumptions.
    lines.append("    classDef changed fill:#C8621A,stroke:#F2EDD6,color:#0A0A0A,stroke-width:2px;")
    lines.append("    classDef risk-low fill:#1A2418,stroke:#4ADE80,color:#F2EDD6;")
    lines.append("    classDef risk-med fill:#1A2418,stroke:#FACC15,color:#F2EDD6;")
    lines.append("    classDef risk-high fill:#2A1A1A,stroke:#FF8C42,color:#F2EDD6;")
    lines.append("    classDef risk-critical fill:#3A1418,stroke:#FF4D6D,color:#F2EDD6,stroke-width:2px;")

    rendered_count = len(kept) + len(unknown)
    stats = {
        "changed": len(changed_set) + len(unknown),
        "total_affected": len(dist) - len(changed_set) - len(unknown),
        "rendered": rendered_count,
        "omitted": len(dist) - rendered_count,
        "max_distance": max((d for n, d in dist.items() if n in universe), default=0),
        "omitted_by_distance": dict(sorted(omitted_by_distance.items())),
        "risk": dict(sorted(risk_counts.items())),
        "truncated": len(dist) - rendered_count > 0,
        "edges": edge_count,
    }
    return "\n".join(lines), stats


# ── Sequence diagram ─────────────────────────────────────────────────────────


def sequence_diagram(
    routes: list[RouteInfo],
    graph: ImportGraph,
    *,
    entry: str | None = None,
    max_hops: int = 0,
    title: str = "Request Flow",
) -> str:
    """Generate a Mermaid sequenceDiagram for one request flow.

    Walks the call chain: route handler → files it imports → files they
    import, until the chain ends naturally (``max_hops`` only caps runaway
    cycles; 0 = no cap).  If *entry* is provided, only traces from that
    route path; otherwise picks the first POST/PUT/DELETE route as the most
    interesting flow.
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

    while max_hops <= 0 or hops < max_hops:
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
