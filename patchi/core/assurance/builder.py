"""Build an AssuranceGraph from brain scan data.

Called after every ``p scan`` to populate the graph with claims derived from
detected routes, import graph, auth patterns, and domain knowledge.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .graph import AssuranceGraph, Evidence

_log = logging.getLogger("patchi.core.assurance.builder")

ASSURANCE_FILE = ".patchi/assurance_graph.json"


def build_assurance_graph(
    root: Path,
    brain_data: dict[str, Any] | None = None,
    route_map: list[dict] | None = None,
    import_graph_data: dict | None = None,
) -> AssuranceGraph:
    """Build an AssuranceGraph from brain scan data.

    Parameters
    ----------
    root : Path
        Project root.
    brain_data : dict
        Brain report summary (from ``report.summary_dict()``).
    route_map : list[dict]
        Detected routes (from ``RouteMapper``).
    import_graph_data : dict
        Import graph as dict (from ``ImportGraph.to_dict()``).
    """
    graph = AssuranceGraph()
    brain = brain_data or {}
    routes = route_map or []
    imp = import_graph_data or {}

    # ── Components (frameworks detected) ──────────────────────────────────
    frameworks = brain.get("detected_frameworks", [])
    if not frameworks and brain.get("stack"):
        frameworks = [brain["stack"].get("framework", "unknown")]
    for fw in frameworks:
        if fw and fw != "unknown":
            _add_framework_claim(graph, fw)

    # ── Actors (from auth patterns) ──────────────────────────────────────
    auth_patterns = brain.get("auth_patterns", brain.get("project_context", {}).get("auth", {}))
    actors = _extract_actors(auth_patterns)
    for actor in actors:
        _add_actor_claim(graph, actor)

    # ── Assets (endpoints from route mapper) ─────────────────────────────
    for route in routes:
        path = route.get("path", route.get("route", ""))
        methods = route.get("methods", route.get("http_methods", ["GET"]))
        auth_required = route.get("auth_required", route.get("requires_auth", False))
        if path:
            _add_endpoint_claim(graph, path, methods, auth_required)

    # ── Data flows (from import graph) ───────────────────────────────────
    edges = imp.get("edges", [])
    for edge in edges[:100]:  # cap for performance
        src = edge.get("source", edge.get("from", ""))
        dst = edge.get("target", edge.get("to", ""))
        if src and dst:
            _add_data_flow_claim(graph, src, dst)

    # ── Dependency health ────────────────────────────────────────────────
    vulns = brain.get("dependency_vulnerabilities", [])
    for v in vulns[:20]:
        pkg = v.get("package", v.get("name", ""))
        cve = v.get("cve", v.get("id", ""))
        if pkg:
            _add_dependency_claim(graph, pkg, cve)

    # ── State machine (from session/auth analysis) ───────────────────────
    _add_state_claims(graph, auth_patterns)

    return graph


def _add_framework_claim(graph: AssuranceGraph, framework: str) -> None:
    graph.upsert_claim(
        f"framework-{framework}",
        f"Project uses {framework}",
        domain="architecture",
        severity_if_disproved="info",
    )
    graph.attach_evidence(
        f"framework-{framework}",
        Evidence(source="brain_scan", detail=f"Detected framework: {framework}", supports=True),
    )


def _add_actor_claim(graph: AssuranceGraph, actor: str) -> None:
    graph.upsert_claim(
        f"actor-{actor}",
        f"System has actor role: {actor}",
        domain="auth",
        severity_if_disproved="medium",
    )
    graph.attach_evidence(
        f"actor-{actor}",
        Evidence(source="brain_scan", detail=f"Actor detected: {actor}", supports=True),
    )


def _add_endpoint_claim(
    graph: AssuranceGraph, path: str, methods: list, auth_required: bool
) -> None:
    claim_id = f"endpoint-{path.replace('/', '_').strip('_')}"
    graph.upsert_claim(
        claim_id,
        f"Endpoint {path} requires authentication",
        domain="auth-endpoint",
        severity_if_disproved="high" if auth_required else "medium",
    )
    # If we know auth is required, that's evidence supporting the claim
    # that it *should* require auth (we're asserting it as a property)
    graph.attach_evidence(
        claim_id,
        Evidence(
            source="route_mapper",
            detail=f"Route {path} ({', '.join(methods)}) auth_required={auth_required}",
            supports=True,
            artifact={"path": path, "methods": methods, "auth_required": auth_required},
        ),
    )


def _add_data_flow_claim(graph: AssuranceGraph, source: str, sink: str) -> None:
    claim_id = f"flow-{source.replace('.', '_')}-{sink.replace('.', '_')}"
    graph.upsert_claim(
        claim_id,
        f"Data flow from {source} to {sink} is properly secured",
        domain="data-flow",
        severity_if_disproved="medium",
    )
    graph.attach_evidence(
        claim_id,
        Evidence(
            source="import_graph",
            detail=f"Import edge: {source} → {sink}",
            supports=True,
            artifact={"source": source, "sink": sink},
        ),
    )


def _add_dependency_claim(graph: AssuranceGraph, pkg: str, cve: str) -> None:
    claim_id = f"dep-{pkg}"
    graph.upsert_claim(
        claim_id,
        f"Dependency {pkg} has no known vulnerabilities",
        domain="dependency",
        severity_if_disproved="high",
    )
    if cve:
        # CVE found = refutes the claim (it IS vulnerable)
        graph.attach_evidence(
            claim_id,
            Evidence(
                source="dependency_scan",
                detail=f"Vulnerability {cve} found in {pkg}",
                supports=False,
                artifact={"package": pkg, "cve": cve},
            ),
        )


def _extract_actors(auth_patterns: Any) -> list[str]:
    """Extract actor roles from auth pattern data."""
    actors = ["anonymous", "authenticated"]
    if isinstance(auth_patterns, dict):
        if auth_patterns.get("has_admin"):
            actors.append("admin")
        if auth_patterns.get("has_roles"):
            actors.extend(["moderator", "service"])
        if auth_patterns.get("has_api_key"):
            actors.append("api_client")
    return actors


def _add_state_claims(graph: AssuranceGraph, auth_patterns: Any) -> None:
    """Add state machine claims from auth analysis."""
    states = ["anonymous", "authenticated"]
    if isinstance(auth_patterns, dict) and auth_patterns.get("has_admin"):
        states.append("admin")

    for state in states:
        claim_id = f"state-{state}"
        graph.upsert_claim(
            claim_id,
            f"State '{state}' transitions are properly guarded",
            domain="state-machine",
            severity_if_disproved="high",
        )

    # Login transition
    graph.upsert_claim(
        "state-login-transition",
        "Login transition regenerates session ID",
        domain="state-machine",
        severity_if_disproved="critical",
    )
