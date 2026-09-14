"""
Body Tags — understander-first tagging for Patchi.

Generates .patchi/memory/body_tags.json on every Brain.scan from
deterministic signals already computed: import_graph fan-in, blast_radius,
layered_brain level, route hit, stack framework, file size.

Roles map to human anatomy (Body skill):
  brain  = orchestrators, contracts, memory, config
  muscle = agents, scanners, security, testing, fix
  bone   = data types, schemas, constants, models
  blood  = wiring (import_graph hubs, routing)
  skin   = web/api/cli surface
  nerve  = watchers, interceptors, guards, queue

Criticality: critical|high|medium|low based on fan-in + dependents + route adjacency.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

_log = logging.getLogger("patchi.brain.body_tags")

BODY_TAGS_FILE = ".patchi/memory/body_tags.json"


def _classify_role(path: str, layers: dict, is_route_file: bool, is_hub: bool) -> tuple[str, str]:
    p = path.lower()
    if "brain" in p or "memory" in p or "config" in p or "contract" in p:
        return "brain", "orchestrator"
    if "web/routes" in p or "web/api" in p or "cli/commands" in p:
        return "skin", "surface"
    if "security" in p or "agents" in p or "testing" in p or "fix/" in p:
        return "muscle", "scanner" if "security" in p or "agents" in p else "fixer"
    if "constants" in p or "scanner" in p or "file_corpus" in p or "import_graph" in p:
        return "bone", "structure"
    if is_hub or "import_graph" in p or "route_mapper" in p or "blast_radius" in p:
        return "blood", "wiring"
    if "watch" in p or "interceptor" in p or "guard" in p or "queue" in p:
        return "nerve", "guard"
    # fallback via layered brain
    for lname, lyr in layers.items():
        if path in getattr(lyr, "files", []):
            if lyr.level == 1:
                return "bone", "module"
            unicode = "skin" if "web" in lname or "cli" in lname else "muscle"
            return unicode, lname
    return "muscle", "general"


def build_body_tags(
    file_infos: list[Any],
    graph: Any,
    layers: dict,
    routes: list[Any],
    blast_map: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    # fan-in via graph.reverse, hub threshold
    reverse = getattr(graph, "reverse", {}) if graph else {}
    fan_in_counts = {fp: len(reverse.get(fp, [])) for fp in [fi.path for fi in file_infos]}
    hub_threshold = 5  # top hubs
    sorted_fan = sorted(fan_in_counts.items(), key=lambda x: -x[1])
    hubs = {fp for fp, _ in sorted_fan[:20] if _ >= hub_threshold}
    # route adjacency
    _route_paths = {getattr(r, "path", "") for r in (routes or [])}
    route_files = set()
    for fi in file_infos:
        low = fi.path.lower()
        if any(seg in low for seg in ["route", "web", "api", "handler"]):
            route_files.add(fi.path)

    tags: dict[str, dict[str, Any]] = {}
    for fi in file_infos:
        path = fi.path
        fan_in = fan_in_counts.get(path, 0)
        is_hub = path in hubs
        is_route = path in route_files
        role, system = _classify_role(path, layers, is_route, is_hub)
        # criticality
        br = blast_map.get(path) if blast_map and path in blast_map else None
        all_deps = getattr(br, "all_dependents", None) if br is not None else None
        if all_deps is None:
            all_deps = getattr(br, "dependents", []) if br is not None else []
        dep_count = len(all_deps) if isinstance(all_deps, (list, set, tuple)) else 0
        if fan_in >= 10 or dep_count >= 15 or path.lower() in ("patchi/core/brain/brain.py", "patchi/core/memory.py"):
            crit = "critical"
        elif fan_in >= 5 or is_hub or is_route or "core/brain" in path:
            crit = "high"
        elif fan_in >= 2 or "core/" in path:
            crit = "medium"
        else:
            crit = "low"
        # layer name
        layer_name = ""
        for lname, lyr in layers.items():
            if path in getattr(lyr, "files", []):
                layer_name = lname
                break
        # score for understander ranking
        score = (
            fan_in * 10
            + dep_count * 3
            + (20 if crit == "critical" else 10 if crit == "high" else 0)
            + (5 if is_route else 0)
        )
        tags[path] = {
            "role": role,
            "system": system,
            "layer": layer_name,
            "criticality": crit,
            "fan_in": fan_in,
            "score": score,
            "is_hub": is_hub,
            "is_route_file": is_route,
        }
    return tags


def save_body_tags(tags: dict[str, dict], root: Path) -> Path:
    out = root / BODY_TAGS_FILE
    out.parent.mkdir(parents=True, exist_ok=True)
    # atomic write
    tmp = out.with_suffix(".tmp")
    payload = {"version": 1, "count": len(tags), "tags": tags}
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # replace dance for win32
    import sys as _sys

    if _sys.platform == "win32" and out.exists():
        out.unlink()
    tmp.replace(out)
    _log.info("body_tags: wrote %d tags to %s", len(tags), out)
    return out


def load_body_tags(root: Path) -> dict[str, dict]:
    p = root / BODY_TAGS_FILE
    if not p.exists():
        return {}
    try:
        data: Any = json.loads(p.read_text(encoding="utf-8"))
        return data.get("tags", {}) if isinstance(data, dict) else {}
    except Exception as exc:  # noqa: BLE001
        _log.debug("body_tags load failed: %s", exc)
        return {}
