#!/usr/bin/env python3
"""
Generate the README's architecture diagrams from Patchi's own Brain.

Runs the same pipeline `p scan` uses on THIS repository — FileScanner →
FrameworkDetector → RouteMapper → build_graph — then renders Mermaid
blocks through patchi.core.brain.mermaid and rewrites the marked section
of README.md. The diagrams are therefore always derived from the real
codebase, never hand-drawn.

Managed README section (do not edit between the markers):

    <!-- BEGIN GENERATED: architecture-diagrams -->
    ...
    <!-- END GENERATED: architecture-diagrams -->

Usage:
  python tools/generate_arch_diagrams.py             # regenerate + rewrite README.md
  python tools/generate_arch_diagrams.py --check     # exit 1 if README section is stale (CI)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

BEGIN = "<!-- BEGIN GENERATED: architecture-diagrams -->"
END = "<!-- END GENERATED: architecture-diagrams -->"

# The overview diagram stays readable: only the most-depended-on core
# modules (highest fan-in) are shown.
_MAX_NODES = 22


def _curated_graph(files: list, root: Path) -> object:
    """build_graph, then filter nodes/edges to patchi/*.py modules.

    The raw graph resolves e.g. a GitHub-Actions YAML stem onto the
    `patchi` package (filename collisions) and keeps data files as nodes;
    both are noise in an architecture overview.
    """
    from patchi.core.brain.import_graph import build_graph

    raw = build_graph(files, root)

    keep = {n for n in raw.nodes if n.startswith("patchi/") and n.endswith(".py")}
    filtered = type(raw)()
    filtered.nodes = {n for n in raw.nodes if n in keep}
    for src, targets in raw.edges.items():
        if src not in keep:
            continue
        for tgt in targets:
            if tgt in keep:
                filtered.add_edge(src, tgt)
    # Trim the leafy patchi.* prefix so Mermaid subgraphs group by real
    # package level instead of one monolithic box: patchi/core/... loses
    # both segments (subgraphs become agents/brain/security/fix/...), while
    # patchi/cli/... and patchi/web/... keep theirs.
    def _rebase(p: str) -> str:
        if p.startswith("patchi/core/"):
            return p[len("patchi/core/") :]
        if p.startswith("patchi/"):
            return p[len("patchi/") :]
        return p

    rebase = type(raw)()
    for n in filtered.nodes:
        rebase.nodes.add(_rebase(n))
    for src, targets in filtered.edges.items():
        for tgt in targets:
            rebase.add_edge(_rebase(src), _rebase(tgt))
    return rebase


def _collect_data() -> tuple[object, list]:  # (ImportGraph, list[RouteInfo])
    from patchi.core.brain.framework import FrameworkDetector, FrameworkInfo
    from patchi.core.brain.route_mapper import RouteMapper
    from patchi.core.brain.scanner import FileScanner

    files = FileScanner(REPO_ROOT).scan()
    graph = _curated_graph(files, REPO_ROOT)

    # Patchi's own web UI is FastAPI, but the generic stack detector
    # misfires on this repo (repo-local configs read as Svelte/Swift).
    # Route extraction is framework-gated, so inject the truth instead of
    # teaching the detector about self-hosted edge cases.
    stack = FrameworkDetector(REPO_ROOT).detect()
    if not any(f.name == "FastAPI" for f in stack.frameworks):
        stack.frameworks.append(
            FrameworkInfo(
                name="FastAPI",
                language="python",
                version="",
                config_file="pyproject.toml",
                confidence=1.0,
            )
        )
    web_files = [f for f in files if f.path.startswith("patchi/web/")]
    routes = RouteMapper(REPO_ROOT, stack).extract(web_files)
    return graph, routes


def _render_diagrams() -> str:
    from patchi.core.brain.mermaid import dependency_diagram, route_diagram

    graph, routes = _collect_data()

    parts: list[str] = []
    parts.append("### Module dependency map")
    parts.append("")
    parts.append(
        "Auto-generated from the live import graph — the highest fan-in core "
        f"modules ({_MAX_NODES} shown of {len(graph.nodes)} Python modules)."
    )
    parts.append("")
    parts.append("```mermaid")
    parts.append(
        dependency_diagram(
            graph,
            max_nodes=_MAX_NODES,
            title="Patchi core module dependencies",
        )
    )
    parts.append("```")
    parts.append("")

    if routes:
        parts.append("### Web dashboard routes")
        parts.append("")
        parts.append(f"Auto-generated route map — {len(routes)} endpoints in the bundled web UI.")
        parts.append("")
        parts.append("```mermaid")
        parts.append(route_diagram(routes, title="Patchi web dashboard routes"))
        parts.append("```")
        parts.append("")
    else:
        parts.append("### Web dashboard routes")
        parts.append("")
        parts.append("*(No routes detected in this checkout — run a scan first.)*")
        parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate README architecture diagrams from the Brain pipeline."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit 1 if the README section is out of date",
    )
    args = parser.parse_args()

    text = README.read_text(encoding="utf-8")
    i, j = text.find(BEGIN), text.find(END)
    if i == -1 or j == -1 or j < i:
        print(f"error: markers not found in {README.name} — add {BEGIN!r} ... {END!r}", file=sys.stderr)
        return 2

    new_block = f"{BEGIN}\n{_render_diagrams()}{END}"
    updated = text[:i] + new_block + text[j + len(END) :]

    if args.check:
        if updated == text:
            print("README architecture diagrams are up to date.")
            return 0
        print("README architecture diagrams are STALE — run: python tools/generate_arch_diagrams.py", file=sys.stderr)
        return 1

    README.write_text(updated, encoding="utf-8")
    n_nodes = _MAX_NODES
    print(f"Rewrote {README.name} diagram section (dependency map, up to {n_nodes} nodes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
