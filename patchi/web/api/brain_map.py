"""Brain Map API — node and edge data for the canvas."""

from __future__ import annotations

import os

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/brain-map")


@router.get("/nodes")
async def get_nodes(request: Request) -> JSONResponse:
    root = request.app.state.root
    from collections import Counter

    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    import_graph = brain.get("import_graph", {})
    nodes_raw = import_graph.get("nodes", [])
    health = brain.get("health_score", {})
    dead_files = set(brain.get("dead_files", []))

    # Compute finding counts per file from scan results
    scan_results = mem.get_scan_results(root)
    finding_counts: dict[str, int] = Counter()
    finding_severities: dict[str, str] = {}
    for agent_name, data in scan_results.items():
        for f in data.get("findings", []):
            file_path = f.get("file", "")
            if file_path:
                finding_counts[file_path] += 1
                sev = f.get("severity", "info")
                existing = finding_severities.get(file_path)
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                if existing is None or sev_order.get(sev, 4) < sev_order.get(existing, 4):
                    finding_severities[file_path] = sev

    # Build node list with metadata
    nodes = []
    for i, node_id in enumerate(nodes_raw):
        # Determine type (maps to BrainMap node shape/color)
        if any(x in node_id for x in ["main.py", "app.py", "server.py", "__main__.py"]):
            node_type = "entry_point"
        elif any(x in node_id for x in ["base.py", "coordinator.py", "brain.py", "config.py"]):
            node_type = "component"
        elif any(x in node_id for x in ["test_", "tests/"]):
            node_type = "test"
        elif any(x in node_id for x in [".json", ".yaml", ".yml", ".toml", ".env"]):
            node_type = "config"
        else:
            node_type = "default"

        fcount = finding_counts.get(node_id, 0)
        fsev = finding_severities.get(node_id, "info")

        # Determine status
        if node_id in dead_files:
            status = "dead"
        elif fcount > 0 and fsev == "critical":
            status = "critical"
        elif fcount > 5:
            status = "warning"
        elif health.get("total", 0) < 30:
            status = "critical"
        elif health.get("total", 0) < 70:
            status = "warning"
        else:
            status = "healthy"

        # Position hint based on type
        x = 0
        y = 0
        if node_type == "entry_point":
            y = -100  # float to top
        elif node_type == "dead":
            y = 100  # sink to bottom

        nodes.append(
            {
                "id": node_id,
                "label": os.path.basename(node_id),
                "file": node_id,
                "type": node_type,
                "status": status,
                "finding_count": fcount,
                "severity": fsev,
                "x": x,
                "y": y,
            }
        )

    return JSONResponse({"nodes": nodes})


@router.get("/edges")
async def get_edges(request: Request) -> JSONResponse:
    root = request.app.state.root
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    import_graph = brain.get("import_graph", {})
    edges_raw = import_graph.get("edges", {})

    # Convert {source: [targets]} to [{from, to}] format
    edges = []
    for source, targets in edges_raw.items():
        if isinstance(targets, list):
            for target in targets:
                edges.append({"from": source, "to": target, "source": source, "target": target})

    return JSONResponse({"edges": edges})
