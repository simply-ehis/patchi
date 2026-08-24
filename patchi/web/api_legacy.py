"""
REST API endpoints for the Patchi web UI (legacy, consolidated).

Mounted on the FastAPI app by app.py (legacy api.py renamed to avoid
shadowing the api/ package directory). All endpoints read from project
root stored in app.state.root.

Routes:
  GET  /api/status          — mode, queue depth, brain freshness, agent count
  GET  /api/config          — full config dict (no secrets)
  POST /api/config          — update one config key
  GET  /api/queue           — queue items list
  POST /api/queue/pause     — pause the queue
  POST /api/queue/resume    — resume the queue
  GET  /api/findings        — latest scan findings from memory
  GET  /api/brain/nodes     — Brain Map node list (files + metrics)
  GET  /api/ants            — active user-spawned ants
  GET  /api/review          — pending fixes for review
  GET  /api/history         — scan and fix history
  GET  /api/security        — security findings
  GET  /api/tests           — test results
  GET  /api/memory          — memory categories and data
  GET  /api/memory/brain    — brain knowledge viewer
  GET  /api/memory/patches  — patch history
  GET  /api/memory/issues   — known issues
  GET  /api/memory/failed   — failed patches
  GET  /api/memory/scans    — scan results
  GET  /api/memory/restrictions — restrictions
  GET  /api/memory/tokens   — dev tokens
  POST /api/security/quick-scan  — trigger quick security scan
  POST /api/security/full-scan   — trigger full security scan
  POST /api/tests/create-suite   — create test suite
  POST /api/hosted/init          — initialize hosted mode
  POST /api/fix/accept           — accept a pending fix
  POST /api/fix/reject           — reject a pending fix
  POST /api/fix/apply            — apply a specific patch
  POST /api/patch/apply          — apply a specific patch
  POST /api/patch/reject         — reject a specific patch
  POST /api/patch/delete         — delete a patch from history
  POST /api/issue/resolve        — resolve a known issue
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

import patchi.core.config as cfg_mod
import patchi.core.health as health_mod
import patchi.core.memory as memory_mod
import patchi.core.queue as queue_mod
from patchi.core.constants import PROVIDERS, MemoryCategory

logger = logging.getLogger("patchi.web.api")

router = APIRouter(prefix="/api")


def _root(request: Request) -> Path:
    return request.app.state.root


def _error_response(message: str, status_code: int = 500) -> JSONResponse:
    """Standard error response with consistent format."""
    return JSONResponse(
        {"ok": False, "error": message},
        status_code=status_code,
    )


def _safe_json(request: Request, default=None):
    """Safely parse JSON body from request, return default on failure."""
    try:
        import json as _json
        body = request._body
        if body is None:
            return default
        return _json.loads(body)
    except Exception:
        return default


# ── Status ────────────────────────────────────────────────────────────────────


@router.get("/status")
async def get_status(request: Request) -> JSONResponse:
    root = _root(request)
    try:
        cfg = cfg_mod.load(root)
        health = health_mod.compute(root)
        spawner = request.app.state.spawner
        from patchi.core.ai.cost_tracker import check_budget, get_stats

        ai_stats = get_stats()
        budget_warn = check_budget(cfg)
        return JSONResponse(
            {
                "mode": cfg.get("mode", "confirm"),
                "queue_depth": queue_mod.depth(root),
                "queue_paused": queue_mod.is_paused(root),
                "brain_fresh": health.total > 50,
                "active_ants": spawner.active_count(),
                "patchi_active": getattr(request.app.state.spawner, "_is_active", False),
                "health_score": health.total,
                "brain_last_scan": getattr(health, "last_scan_time", "unknown"),
                "ai_calls": ai_stats.get("calls", 0),
                "ai_tokens": ai_stats.get("total_tokens", 0),
                "ai_cost": round(ai_stats.get("cost_estimate", 0.0), 6),
                "ai_budget_warning": budget_warn or "",
            }
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Config ────────────────────────────────────────────────────────────────────

_SAFE_KEYS = frozenset(
    {
        "mode",
        "theme",
        "fps",
        "device_tier",
        "scan_depth",
        "risk_threshold",
        "dead_code_confirmation",
        "show_confidence_scores",
        "brain_freshness_any_change",
        "digest_frequency",
        "ollama_model",
        "cost_limit",
        "enable_cost_limit",
        "lang_js",
        "lang_ts",
        "lang_py",
        "lang_html",
        "lang_css",
        "scan_ignore_paths",
        "scan_depth_limit",
        "auto_rescan_on_save",
        "risk_threshold_auto",
        "require_blast_radius",
        "max_fixes_per_cycle",
        "queue_mode",
        "max_parallel_agents",
        "max_queue_depth",
        "context_window_size",
        "websocket_timeout",
        "canvas_max_nodes",
        "quiet_hours_start",
        "quiet_hours_end",
        "quiet_hours_timezone",
        "temperature_scanner",
        "temperature_security",
        "temperature_fixer",
        "temperature_tester",
        "context_window_override",
        "websocket_timeout_s",
        "canvas_max_nodes_before_clustering",
        "canvas_max_visible_ants",
        "max_parallel_scanners",
        "max_parallel_security",
        "max_active_fix_agents",
        "max_parallel_testers",
        "max_total_agents_in_queue",
        "animation_speed",
        "font_size",
        "compact_mode",
        "language",
        "local_model_path",
        "key_priority_order",
        "fallback_enabled",
        "cost_limit_per_run",
        "languages_include",
        "paths_ignore",
        "brain_freshness_threshold",
        "auto_rescan_on_file_save",
        "risk_threshold_for_auto_mode",
        "require_blast_radius_high_risk",
        "show_confidence_score_fix_cards",
        "queue_mode_selector",
        "max_parallel_agents_per_category",
        "max_queue_depth_setting",
        "hidden_by_default",
        "temperature_per_agent",
        "context_window_size_override",
        "canvas_max_nodes_before_clustering_setting",
        "canvas_max_visible_ants_setting",
    }
)


@router.get("/config")
async def get_config(request: Request) -> JSONResponse:
    root = _root(request)
    try:
        raw = cfg_mod.load(root)
        # Strip sensitive keys before sending to browser
        safe = {k: v for k, v in raw.items() if k in _SAFE_KEYS}
        return JSONResponse(safe)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# /config POST is defined at end of file with full bulk+single support


# ── Queue ─────────────────────────────────────────────────────────────────────


@router.get("/queue")
async def get_queue(request: Request) -> JSONResponse:
    root = _root(request)
    try:
        return JSONResponse(
            {
                "items": queue_mod.list_items(root=root),
                "depth": queue_mod.depth(root),
                "paused": queue_mod.is_paused(root),
            }
        )
    except Exception as e:
        return JSONResponse({"items": [], "depth": 0, "paused": False, "error": str(e)})


@router.post("/queue/pause")
async def pause_queue(request: Request) -> JSONResponse:
    try:
        queue_mod.pause(_root(request))
        return JSONResponse({"ok": True, "paused": True})
    except Exception as e:
        return _error_response(str(e))


@router.post("/queue/resume")
async def resume_queue(request: Request) -> JSONResponse:
    try:
        queue_mod.resume(_root(request))
        return JSONResponse({"ok": True, "paused": False})
    except Exception as e:
        return _error_response(str(e))


# ── Findings ──────────────────────────────────────────────────────────────────


@router.get("/findings")
async def get_findings(request: Request) -> JSONResponse:
    root = _root(request)
    try:
        issues = memory_mod.list_issues(root)
        # Also include scanner findings from scan results
        scans = memory_mod.get_scan_results(root)
        scanner_findings = []
        for agent_name, scan_data in scans.items():
            for f in scan_data.get("findings", []):
                if isinstance(f, dict):
                    scanner_findings.append(f)
        all_findings = issues + scanner_findings
        return JSONResponse({"findings": all_findings})
    except Exception:
        return JSONResponse({"findings": []})


# ── Brain Map nodes ───────────────────────────────────────────────────────────


@router.get("/brain/nodes")
async def get_brain_nodes(request: Request) -> JSONResponse:
    """Return brain map nodes + edges from the import graph stored in brain memory."""
    root = _root(request)
    try:
        brain_data = memory_mod.read(MemoryCategory.BRAIN, root=root)
        if not isinstance(brain_data, dict):
            brain_data = {}

        # Build nodes from import_graph
        import_graph = brain_data.get("import_graph", {})
        graph_nodes = import_graph.get("nodes", [])
        graph_edges_raw = import_graph.get("edges", {})

        # Build per-file findings map from scan results
        scan_results = memory_mod.read(MemoryCategory.SCANS, root=root)
        findings_by_file = {}
        if isinstance(scan_results, dict):
            for scanner_name, scanner_data in scan_results.items():
                findings = (
                    scanner_data.get("findings", []) if isinstance(scanner_data, dict) else []
                )
                for f in findings:
                    fpath = f.get("file", "")
                    if not fpath:
                        continue
                    fentry = findings_by_file.setdefault(fpath, {"count": 0, "severities": []})
                    fentry["count"] += 1
                    sev = f.get("severity", "low")
                    fentry["severities"].append(sev)

        nodes = []
        for node_id in graph_nodes:
            # Determine node type from file extension / role
            ntype = "default"
            fname = node_id.split("/")[-1].lower()
            if node_id.endswith((".test.", ".spec.")) or fname.startswith("test_"):
                ntype = "test"
            elif node_id.endswith(
                ("config.py", "settings.py", ".env", "config.json", "config.yaml")
            ):
                ntype = "config"
            elif node_id in brain_data.get("dead_files", []):
                ntype = "dead"
            elif fname in ("main.py", "app.py", "index.py", "__init__.py", "server.py", "cli.py"):
                ntype = "entry_point"
            else:
                # Check if file has routes (is a route handler)
                routes = brain_data.get("routes", [])
                if isinstance(routes, list):
                    for route in routes:
                        if isinstance(route, dict) and route.get("file") == node_id:
                            ntype = "route_handler"
                            break
                        elif hasattr(route, "file") and route.file == node_id:
                            ntype = "route_handler"
                            break
            if ntype == "default":
                if "sensitive" in fname or "secret" in fname or "credential" in fname:
                    ntype = "sensitive"
                elif any(
                    r.get("path") == node_id
                    for r in (
                        brain_data.get("restrictions", [])
                        if isinstance(brain_data.get("restrictions"), list)
                        else []
                    )
                ):
                    ntype = "restricted"

            finfo = findings_by_file.get(node_id, {"count": 0, "severities": []})
            sevs = finfo["severities"]
            max_sev = "info"
            if any(s == "critical" for s in sevs):
                max_sev = "critical"
            elif any(s == "high" for s in sevs):
                max_sev = "high"
            elif any(s == "medium" for s in sevs):
                max_sev = "medium"
            elif any(s == "low" for s in sevs):
                max_sev = "low"

            nodes.append(
                {
                    "id": node_id,
                    "path": node_id,
                    "label": node_id.split("/")[-1],
                    "type": ntype,
                    "finding_count": finfo["count"],
                    "severity": max_sev,
                }
            )

        edges = []
        for source, targets in graph_edges_raw.items():
            for target in targets:
                edges.append({"from": source, "to": target, "type": "import_dependency"})

        return JSONResponse({"nodes": nodes, "edges": edges})
    except Exception:
        return JSONResponse({"nodes": [], "edges": []})


# ── Active ants ───────────────────────────────────────────────────────────────


@router.get("/ants")
async def get_ants(request: Request) -> JSONResponse:
    spawner = request.app.state.spawner
    return JSONResponse({"ants": spawner.all_active()})


# ── Review ────────────────────────────────────────────────────────────────────


@router.get("/review")
async def get_review(request: Request) -> JSONResponse:
    """Get pending fixes for review."""
    root = _root(request)
    try:
        # Get all patches and filter for pending ones
        all_patches = memory_mod.list_patches(root)
        # Filter for patches that are not yet applied (pending review)
        pending_patches = [p for p in all_patches if p.get("state") in ["proposed", "pending"]]
        return JSONResponse({"pending_patches": pending_patches})
    except Exception:
        return JSONResponse({"pending_patches": []})


@router.post("/fix/accept")
async def accept_fix(request: Request) -> JSONResponse:
    """Accept a pending fix — apply it to disk via PatchApplier."""
    try:
        body = await request.json()
        patch_id = body.get("patch_id")
        root = _root(request)

        # Load patch from memory
        patch_data = memory_mod.get_patch(patch_id, root)
        if not patch_data:
            return JSONResponse(
                {"ok": False, "error": f"Patch {patch_id} not found"}, status_code=404
            )

        from patchi.core.fix.applier import PatchApplier
        from patchi.core.fix.patch import Patch, PatchState

        patch = Patch.from_dict(patch_data)
        patch.state = PatchState.APPLYING
        applier = PatchApplier(root)
        result = applier.apply(patch)

        if result.success:
            patch.state = PatchState.APPLIED
            memory_mod.save_patch(patch.to_dict(), root)
            try:
                import asyncio

                from patchi.web.events import evt_review_updated, manager

                pending = len(
                    [
                        p
                        for p in memory_mod.list_patches(root)
                        if p.get("state") in ("proposed", "pending")
                    ]
                )
                asyncio.get_running_loop().create_task(manager.broadcast(evt_review_updated(pending)))
            except Exception as exc:
                logger.warning("Failed to broadcast review_updated event: %s", exc)
            return JSONResponse({"ok": True, "message": f"Patch {patch_id} applied"})
        else:
            patch.state = PatchState.FAILED
            memory_mod.save_patch(patch.to_dict(), root)
            memory_mod.save_failed(patch_id, result.error, root=root)
            return JSONResponse({"ok": False, "error": result.error})
    except Exception as e:
        return _error_response(str(e))


@router.post("/fix/reject")
async def reject_fix(request: Request) -> JSONResponse:
    """Reject a pending fix — mark as rejected in memory."""
    try:
        body = await request.json()
        patch_id = body.get("patch_id")
        root = _root(request)

        patch_data = memory_mod.get_patch(patch_id, root)
        if not patch_data:
            return _error_response(f"Patch {patch_id} not found", status_code=404)

        from patchi.core.fix.patch import Patch, PatchState

        patch = Patch.from_dict(patch_data)
        patch.state = PatchState.REJECTED
        memory_mod.save_patch(patch.to_dict(), root)
        return JSONResponse({"ok": True, "message": f"Patch {patch_id} rejected"})
    except Exception as e:
        return _error_response(str(e))


# ── History ───────────────────────────────────────────────────────────────────


@router.get("/history")
async def get_history(request: Request) -> JSONResponse:
    """Get scan and fix history."""
    root = _root(request)
    try:
        # Get patch history and other historical data
        patches = memory_mod.list_patches(root)
        scan_results = memory_mod.get_scan_results(root)
        failed_patches = memory_mod.list_failed(root)

        return JSONResponse(
            {
                "patches": patches,
                "scan_results": scan_results,
                "failed_patches": failed_patches,
                "health_history": [],  # Would come from health module
            }
        )
    except Exception:
        return JSONResponse({"patches": [], "scan_results": {}, "failed_patches": []})


# ── Security ──────────────────────────────────────────────────────────────────


@router.get("/security")
async def get_security(request: Request) -> JSONResponse:
    """Get security findings."""
    root = _root(request)
    try:
        # Get security-related findings from issues
        all_issues = memory_mod.list_issues(root)
        security_findings = [issue for issue in all_issues if issue.get("category") == "security"]
        return JSONResponse({"findings": security_findings})
    except Exception:
        return JSONResponse({"findings": []})


@router.post("/security/quick-scan")
async def post_quick_security_scan(request: Request) -> JSONResponse:
    """Trigger a quick security scan — runs targeted agents (taint, secrets, config)."""
    import asyncio

    root = _root(request)

    async def _run():
        from patchi.web.events import (
            evt_security_finding,
            evt_security_scan_completed,
            evt_security_scan_started,
            manager,
        )

        try:
            import patchi.core.security.security_agents  # noqa: F401
            from patchi.core.agents.coordinator import Coordinator

            await manager.broadcast(evt_security_scan_started("quick"))
            coord = Coordinator(root)
            results = await asyncio.to_thread(
                coord.run_agents, ["TaintAnalyzer", "SecretScanner", "ConfigAuditAgent"]
            )

            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for r in results:
                for f in r.findings:
                    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    counts[sev] = counts.get(sev, 0) + 1
                    await manager.broadcast(
                        evt_security_finding(sev, f.type, f.file, f.line, "", f.title)
                    )
            await manager.broadcast(
                evt_security_scan_completed(
                    counts["critical"], counts["high"], counts["medium"], counts["low"]
                )
            )
        except Exception as exc:
            logger.warning("Quick security scan failed: %s", exc)

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "message": "Quick security scan started"})


@router.post("/security/full-scan")
async def post_full_security_scan(request: Request) -> JSONResponse:
    """Trigger a full security scan — runs all 19 defensive security agents."""
    import asyncio

    root = _root(request)

    async def _run():
        from patchi.web.events import (
            evt_security_finding,
            evt_security_scan_completed,
            evt_security_scan_started,
            manager,
        )

        try:
            import patchi.core.security.security_agents  # noqa: F401
            from patchi.core.agents.base import AgentGroup
            from patchi.core.agents.coordinator import Coordinator

            await manager.broadcast(evt_security_scan_started("full"))
            coord = Coordinator(root)
            results = await asyncio.to_thread(coord.run_group, AgentGroup.SECURITY)

            # Orchestrate: dedup, correlate, score
            from patchi.core.security.orchestrator import SecurityOrchestrator

            orch = SecurityOrchestrator()
            report = orch.correlate(results)

            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for c in report.findings:
                sev = c.finding.severity.value
                counts[sev] = counts.get(sev, 0) + 1
                await manager.broadcast(
                    evt_security_finding(
                        sev,
                        c.finding.type,
                        c.finding.file,
                        c.finding.line,
                        c.owasp_category,
                        c.finding.message,
                    )
                )
            await manager.broadcast(
                evt_security_scan_completed(
                    counts["critical"], counts["high"], counts["medium"], counts["low"]
                )
            )
        except Exception as exc:
            logger.warning("Full security scan failed: %s", exc)

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "message": "Full security scan started"})


@router.get("/security/report")
async def get_security_report(request: Request) -> JSONResponse:
    """Orchestrated security report: deduplicated, correlated, OWASP-mapped."""
    root = _root(request)
    try:
        import patchi.core.security.security_agents  # noqa
        from patchi.core.agents.base import AgentGroup
        from patchi.core.agents.coordinator import Coordinator
        from patchi.core.security.orchestrator import SecurityOrchestrator

        coord = Coordinator(root)
        results = coord.run_group(AgentGroup.SECURITY)
        from patchi.core.security.pattern_context import suppress_findings

        for r in results:
            suppress_findings(r)
        orch = SecurityOrchestrator()
        report = orch.correlate(results)
        return JSONResponse(report.to_dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Tests ─────────────────────────────────────────────────────────────────────


@router.get("/tests")
async def get_tests(request: Request) -> JSONResponse:
    """Get test results."""
    root = _root(request)
    try:
        # Get test results from memory
        scan_results = memory_mod.get_scan_results(root)
        # Extract test-related results
        test_results = {k: v for k, v in scan_results.items() if "test" in k.lower()}
        return JSONResponse(test_results)
    except Exception:
        return JSONResponse({"unit": [], "browser": [], "stress": []})


@router.post("/tests/create-suite")
async def post_create_test_suite(request: Request) -> JSONResponse:
    """Create a test suite for the project."""
    try:
        # For now, return success - this would create actual test suite
        return JSONResponse({"ok": True, "message": "Test suite creation started"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Memory ────────────────────────────────────────────────────────────────────


@router.get("/memory")
async def get_memory(request: Request) -> JSONResponse:
    """Get memory categories and data."""
    root = _root(request)
    try:
        # Return memory data for various categories
        memory_data = {
            "brain_state": memory_mod.read(MemoryCategory.BRAIN, root),
            "patch_history": memory_mod.read(MemoryCategory.PATCHES, root),
            "failed_patches": memory_mod.read(MemoryCategory.FAILED, root),
            "scan_results": memory_mod.read(MemoryCategory.SCANS, root),
            "known_issues": memory_mod.read(MemoryCategory.ISSUES, root),
            "restrictions": memory_mod.read(MemoryCategory.RESTRICTIONS, root),
            "dev_tokens": memory_mod.read(MemoryCategory.TOKENS, root),
        }
        return JSONResponse(memory_data)
    except Exception as e:
        return JSONResponse({"error": str(e)})


@router.get("/memory/brain")
async def get_memory_brain(request: Request) -> JSONResponse:
    """Get brain knowledge viewer data."""
    root = _root(request)
    try:
        brain_data = memory_mod.get_brain(root)
        return JSONResponse(brain_data)
    except Exception as e:
        return JSONResponse({"error": str(e)})


@router.get("/memory/patches")
async def get_memory_patches(request: Request) -> JSONResponse:
    """Get patch history."""
    root = _root(request)
    try:
        patches = memory_mod.list_patches(root)
        return JSONResponse({"patches": patches})
    except Exception:
        return JSONResponse({"patches": []})


@router.get("/memory/issues")
async def get_memory_issues(request: Request) -> JSONResponse:
    """Get known issues."""
    root = _root(request)
    try:
        issues = memory_mod.list_issues(root)
        return JSONResponse({"issues": issues})
    except Exception:
        return JSONResponse({"issues": []})


@router.get("/memory/failed")
async def get_memory_failed(request: Request) -> JSONResponse:
    """Get failed patches."""
    root = _root(request)
    try:
        failed = memory_mod.list_failed(root)
        return JSONResponse({"failed": failed})
    except Exception:
        return JSONResponse({"failed": []})


@router.get("/memory/scans")
async def get_memory_scans(request: Request) -> JSONResponse:
    """Get scan results."""
    root = _root(request)
    try:
        scans = memory_mod.get_scan_results(root)
        return JSONResponse({"scans": scans})
    except Exception:
        return JSONResponse({"scans": {}})


@router.get("/memory/restrictions")
async def get_memory_restrictions(request: Request) -> JSONResponse:
    """Get restrictions."""
    root = _root(request)
    try:
        restrictions = memory_mod.read(MemoryCategory.RESTRICTIONS, root)
        return JSONResponse({"restrictions": restrictions})
    except Exception:
        return JSONResponse({"restrictions": []})


@router.get("/memory/tokens")
async def get_memory_tokens(request: Request) -> JSONResponse:
    """Get dev tokens."""
    root = _root(request)
    try:
        tokens = memory_mod.list_tokens(root)
        return JSONResponse({"tokens": tokens})
    except Exception:
        return JSONResponse({"tokens": []})


# ── Patch Operations ──────────────────────────────────────────────────────────


@router.post("/patch/apply")
async def apply_patch(request: Request) -> JSONResponse:
    """Apply a specific patch to disk."""
    try:
        body = await request.json()
        patch_id = body.get("patch_id")
        root = _root(request)

        patch_data = memory_mod.get_patch(patch_id, root)
        if not patch_data:
            return _error_response(f"Patch {patch_id} not found", status_code=404)

        from patchi.core.fix.applier import PatchApplier
        from patchi.core.fix.patch import Patch, PatchState

        patch = Patch.from_dict(patch_data)
        patch.state = PatchState.APPLYING
        applier = PatchApplier(root)
        result = applier.apply(patch)

        if result.success:
            patch.state = PatchState.APPLIED
            memory_mod.save_patch(patch.to_dict(), root)
            return JSONResponse({"ok": True, "message": f"Patch {patch_id} applied"})
        else:
            patch.state = PatchState.FAILED
            memory_mod.save_patch(patch.to_dict(), root)
            return _error_response(result.error)
    except Exception as e:
        return _error_response(str(e))


@router.post("/patch/reject")
async def reject_patch(request: Request) -> JSONResponse:
    """Reject a specific patch."""
    try:
        body = await request.json()
        patch_id = body.get("patch_id")
        root = _root(request)

        patch_data = memory_mod.get_patch(patch_id, root)
        if not patch_data:
            return _error_response(f"Patch {patch_id} not found", status_code=404)

        from patchi.core.fix.patch import Patch, PatchState

        patch = Patch.from_dict(patch_data)
        patch.state = PatchState.REJECTED
        memory_mod.save_patch(patch.to_dict(), root)
        return JSONResponse({"ok": True, "message": f"Patch {patch_id} rejected"})
    except Exception as e:
        return _error_response(str(e))


@router.post("/patch/delete")
async def delete_patch(request: Request) -> JSONResponse:
    """Delete a patch from history by removing it from memory."""
    try:
        body = await request.json()
        patch_id = body.get("patch_id")
        root = _root(request)

        patches = memory_mod.list_patches(root)
        patches = [p for p in patches if p.get("id") != patch_id]
        from patchi.core.constants import MemoryCategory

        memory_mod._write(MemoryCategory.PATCHES, patches, root)
        return JSONResponse({"ok": True, "message": f"Patch {patch_id} deleted"})
    except Exception as e:
        return _error_response(str(e))


# ── Issue Operations ──────────────────────────────────────────────────────────


@router.post("/issue/resolve")
async def resolve_issue(request: Request) -> JSONResponse:
    """Resolve a known issue."""
    try:
        body = await request.json()
        issue_id = body.get("issue_id")
        root = _root(request)
        success = memory_mod.resolve_issue(issue_id, root)
        if success:
            return JSONResponse({"ok": True, "message": f"Issue {issue_id} resolved"})
        else:
            return _error_response(f"Issue {issue_id} not found", status_code=404)
    except Exception as e:
        return _error_response(str(e))


# ── Hosted ────────────────────────────────────────────────────────────────────


@router.post("/hosted/init")
async def post_hosted_init(request: Request) -> JSONResponse:
    """Initialize hosted mode with provided config."""
    try:
        body = await request.json()
        log_path = body.get("log_path", "/var/log/nginx/access.log")
        log_format = body.get("log_format", "nginx")
        escalate = body.get("escalate", True)

        root = _root(request)
        cfg_mod.set_value("hosted.log_path", log_path, root)
        cfg_mod.set_value("hosted.log_format", log_format, root)
        cfg_mod.set_value("hosted.escalate", escalate, root)
        cfg_mod.set_value("hosted.enabled", True, root)

        hosted_dir = root / ".patchi" / "hosted"
        hosted_dir.mkdir(parents=True, exist_ok=True)

        return JSONResponse(
            {
                "ok": True,
                "message": "Hosted mode configured",
                "log_path": log_path,
                "log_format": log_format,
            }
        )
    except Exception as e:
        return _error_response(str(e))


# ── Scan lifecycle (activates/deactivates tap-to-spawn) ───────────────────────


@router.post("/scan/start")
async def scan_start(request: Request) -> JSONResponse:
    """
    Called when a scan begins — activates tap-to-spawn.
    The web UI calls this before kicking off a scan via the API.
    """
    try:
        request.app.state.spawner.set_active(True)
        return JSONResponse({"ok": True, "active": True})
    except Exception as e:
        return _error_response(str(e))


@router.post("/scan/stop")
async def scan_stop(request: Request) -> JSONResponse:
    """Called when a scan ends — deactivates tap-to-spawn."""
    try:
        request.app.state.spawner.set_active(False)
        return JSONResponse({"ok": True, "active": False})
    except Exception as e:
        return _error_response(str(e))


# ── Action triggers (web UI → CLI command equivalent) ─────────────────────────


@router.post("/action/scan")
async def trigger_scan(request: Request) -> JSONResponse:
    """Trigger a full brain scan + scanner agents in a background thread."""
    import asyncio

    root = _root(request)
    spawner = request.app.state.spawner
    spawner.set_active(True)

    async def _run():
        from patchi.web.events import (
            evt_scan_completed,
            evt_scan_failed,
            evt_scan_file_found,
            manager,
        )
        from patchi.web.ws import evt_scan_complete, evt_scan_started

        try:
            import patchi.core.agents.scanners  # noqa: F401 — trigger registration
            from patchi.core.agents.coordinator import Coordinator, CoordinatorProgress
            from patchi.core.brain.brain import Brain, ScanProgress

            def on_progress(sp: ScanProgress):
                try:
                    loop = asyncio.get_running_loop()
                    loop.call_soon_threadsafe(
                        asyncio.ensure_future,
                        manager.broadcast(
                            {
                                "event": "scan.progress",
                                "data": {
                                    "phase": sp.phase,
                                    "current": sp.current,
                                    "total": sp.total,
                                    "message": sp.message,
                                },
                            }
                        ),
                    )
                    if sp.file_path:
                        loop.call_soon_threadsafe(
                            asyncio.ensure_future,
                            manager.broadcast(evt_scan_file_found(sp.file_path, "", sp.message)),
                        )
                except Exception as exc:
                    logger.warning("Scan progress callback error: %s", exc)

            brain = Brain(root, on_progress=on_progress)
            await evt_scan_started(0)
            report = await asyncio.to_thread(brain.scan)

            # Run scanner agents
            def on_agent_progress(cp: CoordinatorProgress):
                pass

            coord = Coordinator(root, on_progress=on_agent_progress)
            scope = list(report.import_graph.nodes) if report.import_graph else []
            agent_results = await asyncio.to_thread(coord.run_all_scanners, scope=scope)

            total_findings = sum(r.finding_count for r in agent_results)
            await manager.broadcast(evt_scan_completed(report.file_count, report.route_count, 0))
            await evt_scan_complete(total_findings, 0)
        except Exception as e:
            await manager.broadcast(evt_scan_failed(str(e), {}))
        finally:
            spawner.set_active(False)

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "message": "Scan started"})


@router.post("/action/scan-deep")
async def trigger_scan_deep(request: Request) -> JSONResponse:
    """Trigger a deep (LLM-assisted) scan."""
    import asyncio

    root = _root(request)
    spawner = request.app.state.spawner
    spawner.set_active(True)

    async def _run():
        from patchi.web.events import (
            evt_scan_completed,
            evt_scan_failed,
            manager,
        )
        from patchi.web.ws import evt_scan_complete, evt_scan_started

        try:
            import patchi.core.agents.scanners  # noqa: F401
            from patchi.core.agents.coordinator import Coordinator
            from patchi.core.brain.brain import Brain

            await evt_scan_started(0)
            brain = Brain(root)
            report = await asyncio.to_thread(brain.scan)

            coord = Coordinator(root)
            scope = list(report.import_graph.nodes) if report.import_graph else []
            agent_results = await asyncio.to_thread(coord.run_all_scanners, scope=scope)

            total_findings = sum(r.finding_count for r in agent_results)
            await manager.broadcast(evt_scan_completed(report.file_count, report.route_count, 0))
            await evt_scan_complete(total_findings, 0)
        except Exception as e:
            await manager.broadcast(evt_scan_failed(str(e), {}))
        finally:
            spawner.set_active(False)

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "message": "Deep scan started"})


@router.post("/action/fix")
async def trigger_fix(request: Request) -> JSONResponse:
    """Trigger the full fix cycle: load findings → run fix agents → risk gate → apply/queue."""
    import asyncio

    root = _root(request)

    async def _run():
        from patchi.web.events import evt_fix_proposed, manager
        from patchi.web.ws import evt_fix_applied, evt_scan_complete

        try:
            import patchi.core.fix.fix_agents  # noqa: F401 — trigger registration
            from patchi.core import memory as mem
            from patchi.core.agents.base import AgentGroup, list_agents
            from patchi.core.agents.coordinator import Coordinator
            from patchi.core.fix.applier import PatchApplier
            from patchi.core.fix.patch import Patch, PatchState
            from patchi.core.fix.risk_gate import RiskGate

            issues = mem.list_issues(root)
            if not issues:
                await evt_scan_complete(0, 0)
                return

            fix_classes = list_agents(AgentGroup.FIX)
            if not fix_classes:
                await evt_scan_complete(0, 0)
                return

            coord = Coordinator(root)
            results = await asyncio.to_thread(
                coord.run_agents,
                [c.name for c in fix_classes],
                scope=None,
                extra={"findings": issues},
            )

            # Collect patches from results
            patches: list[Patch] = []
            for r in results:
                if hasattr(r, "data") and r.data and "patch" in r.data:
                    patches.append(r.data["patch"])

            gate = RiskGate(root)
            applier = PatchApplier(root)
            applied = 0
            queued = 0

            for patch in patches:
                gate_result = gate.evaluate(patch)
                if gate_result.is_blocked:
                    continue
                if gate_result.is_auto:
                    result = await asyncio.to_thread(applier.apply, patch)
                    if result.success:
                        applied += 1
                        await evt_fix_applied(patch.id, "")
                else:
                    patch.state = PatchState.PENDING
                    mem.save_patch(patch.to_dict(), root)
                    queued += 1
                    await manager.broadcast(
                        evt_fix_proposed(patch.id, patch.risk_score, patch.confidence, {}, [])
                    )

            await evt_scan_complete(applied + queued, 0)
        except Exception as exc:
            logger.warning("Fix cycle failed: %s", exc)

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "message": "Fix cycle started"})


@router.post("/action/security")
async def trigger_security(request: Request) -> JSONResponse:
    """Trigger a security scan in the background."""
    import asyncio

    body = await request.json()
    mode = body.get("mode", "full")
    root = _root(request)

    async def _run():
        from patchi.web.events import (
            evt_security_finding,
            evt_security_scan_completed,
            evt_security_scan_started,
            manager,
        )

        try:
            import patchi.core.security.security_agents  # noqa: F401
            from patchi.core.agents.base import AgentGroup
            from patchi.core.agents.coordinator import Coordinator

            await manager.broadcast(evt_security_scan_started(mode))
            coord = Coordinator(root)
            results = await asyncio.to_thread(coord.run_group, AgentGroup.SECURITY)

            # Correlate via SecurityOrchestrator (WIRE-01)
            try:
                from patchi.core.security.orchestrator import SecurityOrchestrator

                report = SecurityOrchestrator().correlate(results)
                correlated = report.findings
            except Exception as exc:
                logger.warning("SecurityOrchestrator.correlate failed, using fallback: %s", exc)
                correlated = []
                for r in results:
                    for f in r.findings:

                        class _Wrapped:
                            def __init__(self, finding):
                                self.finding = finding
                                self.owasp_category = ""

                        correlated.append(_Wrapped(f))

            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for c in correlated:
                sev = (
                    c.finding.severity.value
                    if hasattr(c.finding.severity, "value")
                    else str(c.finding.severity)
                )
                counts[sev] = counts.get(sev, 0) + 1
                await manager.broadcast(
                    evt_security_finding(
                        sev,
                        c.finding.type,
                        c.finding.file,
                        c.finding.line,
                        c.owasp_category,
                        c.finding.title,
                    )
                )

            await manager.broadcast(
                evt_security_scan_completed(
                    counts["critical"], counts["high"], counts["medium"], counts["low"]
                )
            )
        except Exception as exc:
            logger.warning("Security scan background task failed: %s", exc)

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "message": f"Security scan ({mode}) started"})


@router.post("/action/test")
async def trigger_test(request: Request) -> JSONResponse:
    """Trigger test suite in the background."""
    import asyncio

    body = await request.json()
    kind = body.get("kind", "unit")
    root = _root(request)

    async def _run():
        from patchi.web.events import (
            evt_test_case_passed,
            evt_test_suite_completed,
            evt_test_suite_started,
            manager,
        )

        try:
            await manager.broadcast(evt_test_suite_started(kind, 0))
            import subprocess

            if kind == "unit":
                import time as _time

                _t0 = _time.monotonic()
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["python", "-m", "pytest", "tests/", "-q", "--tb=short"],
                    cwd=str(root),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                duration_ms = int((_time.monotonic() - _t0) * 1000)
                passed = result.returncode == 0
                await manager.broadcast(evt_test_case_passed("pytest", duration_ms))
                await manager.broadcast(
                    evt_test_suite_completed(1 if passed else 0, 0 if passed else 1, 0)
                )
            else:
                await manager.broadcast(evt_test_suite_completed(0, 0, 0))
        except Exception as exc:
            logger.warning("Test run background task failed: %s", exc)

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "message": f"Test run ({kind}) started"})


@router.get("/health-breakdown")
async def get_health_breakdown(request: Request) -> JSONResponse:
    """Full health score breakdown for the Overview panel."""
    try:
        import patchi.core.health as hm

        h = hm.compute(_root(request))
        return JSONResponse(h.to_dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/markdown")
async def get_report_markdown(request: Request) -> JSONResponse:
    """Generate a markdown report from latest scan data."""
    try:
        from datetime import datetime, timezone

        from patchi.core import health as hm
        from patchi.core import memory as mem

        root = _root(request)
        brain = mem.get_brain(root)
        issues = mem.list_issues(root)
        patches = mem.list_patches(root)
        health = hm.compute(root)

        # Build the data dict that _render_markdown expects
        findings_by_sev = {"critical": [], "high": [], "medium": [], "low": []}
        for issue in issues:
            sev = issue.get("severity", "low").lower()
            if sev in findings_by_sev:
                findings_by_sev[sev].append(issue)

        totals = {k: len(v) for k, v in findings_by_sev.items()}

        data = {
            "health": health.to_dict(),
            "project": {
                "root": str(root),
                "framework": brain.get("framework", "Unknown"),
                "file_count": brain.get("file_count", 0),
                "route_count": brain.get("route_count", 0),
                "last_scan": brain.get("last_scan", "never"),
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "finding_totals": totals,
            "findings": findings_by_sev,
            "patches": [
                {
                    "id": p.get("id", ""),
                    "file": (p.get("changes", [{}])[0].get("path", "") if p.get("changes") else ""),
                    "status": p.get("state", ""),
                }
                for p in patches[-20:]
            ],
            "recommendations": [
                f"Health score is {health.total}/100 — {'good' if health.total >= 80 else 'needs improvement'}",
                f"{totals['critical']} critical findings to address",
                f"{len(patches)} patches in history",
            ],
        }

        from patchi.cli.commands.report_cmd import _render_markdown

        md = _render_markdown(data)
        return JSONResponse({"ok": True, "markdown": md})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Missing endpoints panels.js requires ──────────────────────────────────────


@router.get("/guard")
async def get_guard(request: Request) -> JSONResponse:
    """Guard panel — returns hosted mode status, alerts, and threat data."""
    root = _root(request)
    try:
        import patchi.core.config as cfg

        config = cfg.load(root)
        hosted = config.get("hosted", {})
        enabled = hosted.get("enabled", False)

        alerts: list[dict] = []
        top_threats: list[dict] = []
        blocked_count = 0

        if enabled:
            try:
                import time

                from patchi.core.hosted.audit_log import read_recent

                raw = read_recent(root, 20)
                for e in raw:
                    if e.get("event") == "anomaly_detected":
                        d = e.get("data", {})
                        alerts.append(
                            {
                                "type": d.get("detector", "anomaly"),
                                "message": d.get("title", "Anomaly detected"),
                                "level": d.get("severity", "medium"),
                                "ip": d.get("ip", ""),
                                "timestamp": time.strftime(
                                    "%H:%M:%S", time.localtime(e.get("timestamp", 0))
                                ),
                            }
                        )
            except Exception as exc:
                logger.warning("Failed to read audit log for guard panel: %s", exc)

            try:
                from patchi.core.hosted.watchlist import WatchlistTracker

                tracker = WatchlistTracker(root)
                top_threats = tracker.top(10)
            except Exception as exc:
                logger.warning("Failed to load top threats for guard panel: %s", exc)

            try:
                from patchi.core.hosted import ip_reputation

                rep_data = ip_reputation._load(root)
                blocked_count = len(rep_data.get("blocked", []))
            except Exception as exc:
                logger.warning("Failed to load IP reputation data for guard panel: %s", exc)

        return JSONResponse(
            {
                "connected": enabled,
                "log_path": hosted.get("log_path", ""),
                "log_format": hosted.get("log_format", ""),
                "last_seen": alerts[0]["timestamp"] if alerts else "—",
                "alerts": alerts,
                "top_threats": top_threats,
                "blocked_count": blocked_count,
            }
        )
    except Exception as e:
        return JSONResponse({"connected": False, "alerts": [], "error": str(e)})


@router.post("/queue/clear")
async def clear_queue(request: Request) -> JSONResponse:
    """Clear all pending queue items."""
    root = _root(request)
    try:
        queue_mod.clear(root)
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/memory/clear")
async def clear_memory(request: Request) -> JSONResponse:
    """Clear all memory categories."""
    root = _root(request)
    try:
        memory_mod.clear_all(root)
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/config")
async def set_config_bulk(request: Request) -> JSONResponse:
    """
    Save settings. Accepts either:
      { "key": "mode", "value": "confirm" }   — single key
      { "mode": "confirm", "device_tier": ... } — bulk update from settings panel
    """
    root = _root(request)
    try:
        body = await request.json()
        current = cfg_mod.load(root)

        _ALLOWED = {"mode", "queue_mode", "device_tier", "risk_threshold", "theme", "dev_mode"}

        # Single-key form
        if "key" in body and "value" in body and len(body) == 2:
            k = body["key"]
            if k not in _ALLOWED:
                return JSONResponse(
                    {"ok": False, "error": f"Key '{k}' is not configurable via web UI"},
                    status_code=400,
                )
            current[k] = body["value"]
            cfg_mod.save(current, root)
            return JSONResponse({"ok": True})

        # Bulk form — only overwrite allowed keys
        for k, v in body.items():
            if k in _ALLOWED:
                try:
                    current[k] = int(v) if k == "risk_threshold" else v
                except (ValueError, TypeError):
                    current[k] = v
        cfg_mod.save(current, root)
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


# ── Key Management (web UI direct key entry) ──────────────────────────────────


@router.get("/keys")
async def list_keys_web(request: Request) -> JSONResponse:
    """List all configured API keys (names + status, no values)."""
    root = _root(request)
    try:
        import os

        import patchi.core.config as cfg

        config = cfg.load(root)
        raw = config.get("ai", {}).get("keys", [])
        result = []
        for k in raw:
            env_var = k.get("env_var", "")
            has_val = bool(os.environ.get(env_var) or _read_env_file_key(root, env_var))
            result.append(
                {
                    "nickname": k.get("nickname", ""),
                    "provider": k.get("base_url", "").replace("https://", "").split("/")[0],
                    "model": k.get("model", ""),
                    "env_var": env_var,
                    "status": "ok" if has_val else "missing",
                }
            )
        return JSONResponse({"keys": result})
    except Exception as e:
        return JSONResponse({"keys": [], "error": str(e)})


@router.post("/keys/add")
async def add_key_web(request: Request) -> JSONResponse:
    """
    Add an API key directly from the web UI.
    Body: { provider: str, key: str, nickname?: str }
    Stores the key in .patchi/.env and records metadata in config.
    """
    root = _root(request)
    try:
        import patchi.core.config as cfg

        body = await request.json()
        provider = body.get("provider", "").strip()
        key_val = body.get("key", "").strip()
        nickname = body.get("nickname", provider).strip() or provider

        if not provider or not key_val:
            return JSONResponse(
                {"ok": False, "error": "provider and key are required"}, status_code=400
            )

        # Map provider name to config using shared PROVIDERS constant
        pkey = provider.lower()
        pconf_raw = PROVIDERS.get(
            pkey, {"base_url": provider, "model": "gpt-4o-mini", "format": "openai"}
        )
        pconf = {
            "base": pconf_raw.get("base_url", ""),
            "model": pconf_raw.get("model", "gpt-4o-mini"),
            "fmt": pconf_raw.get("format", "openai"),
        }

        env_var = f"PATCHI_KEY_{nickname.upper().replace(' ', '_').replace('-', '_')}"

        # Write to .patchi/.env
        env_file = root / ".patchi" / ".env"
        _write_env_file_key(env_file, env_var, key_val)

        # Update config
        config = cfg.load(root)
        keys = config.setdefault("ai", {}).setdefault("keys", [])
        # Remove if already exists by nickname
        keys[:] = [k for k in keys if k.get("nickname") != nickname]
        keys.insert(
            0,
            {
                "nickname": nickname,
                "base_url": pconf["base"],
                "model": pconf["model"],
                "format": pconf["fmt"],
                "env_var": env_var,
                "status": "ok",
            },
        )
        cfg.save(config, root)

        return JSONResponse({"ok": True, "env_var": env_var, "nickname": nickname})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.post("/keys/remove")
async def remove_key_web(request: Request) -> JSONResponse:
    """Remove a key by nickname."""
    root = _root(request)
    try:
        import patchi.core.config as cfg

        body = await request.json()
        nickname = body.get("nickname", "").strip()
        config = cfg.load(root)
        keys = config.get("ai", {}).get("keys", [])
        target = next((k for k in keys if k.get("nickname") == nickname), None)
        if target:
            env_var = target.get("env_var", "")
            keys[:] = [k for k in keys if k.get("nickname") != nickname]
            cfg.save(config, root)
            if env_var:
                _remove_env_file_key(root / ".patchi" / ".env", env_var)
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


# ── Undo / Redo ──────────────────────────────────────────────────────────────


@router.post("/undo")
async def web_undo(request: Request) -> JSONResponse:
    """Undo last applied patch."""
    root = _root(request)
    try:
        from patchi.cli.commands.undo_cmd import _find_for_undo, _mark_undone
        from patchi.core.fix.applier import PatchApplier
        from patchi.core.fix.patch import Patch

        target = _find_for_undo(None, root)
        if not target:
            return JSONResponse({"ok": False, "error": "Nothing to undo"})
        patch = Patch.from_dict(target)
        if not patch.snapshot_id:
            return JSONResponse({"ok": False, "error": "Patch has no snapshot"})
        applier = PatchApplier(root)
        result = applier.rollback(patch.id, patch.snapshot_id)
        if result.success:
            _mark_undone(patch.id, root)
            return JSONResponse({"ok": True, "patch_id": patch.id})
        return JSONResponse({"ok": False, "error": result.error})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/redo")
async def web_redo(request: Request) -> JSONResponse:
    """Redo last undone patch."""
    root = _root(request)
    try:
        from patchi.cli.commands.undo_cmd import _find_for_redo, _mark_applied
        from patchi.core.fix.applier import PatchApplier
        from patchi.core.fix.patch import Patch, PatchState

        target = _find_for_redo(None, root)
        if not target:
            return JSONResponse({"ok": False, "error": "Nothing to redo"})
        patch = Patch.from_dict(target)
        patch.state = PatchState.PENDING
        applier = PatchApplier(root)
        result = applier.apply(patch)
        if result.success:
            _mark_applied(patch.id, root)
            return JSONResponse({"ok": True, "patch_id": patch.id})
        return JSONResponse({"ok": False, "error": result.error})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


# ── Notifications ────────────────────────────────────────────────────────────


@router.get("/notifications")
async def get_notifications(request: Request):
    """List all notification channels."""
    root = _root(request)
    html = False
    try:
        import patchi.core.config as cfg
        from patchi.core.notifications.channels import channel_to_dict, load_channels

        config = cfg.load(root)
        channels = load_channels(config)
        html = request.headers.get("hx-request", "").lower() == "true"
        if html:
            lst = "".join(
                f'<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 8px;border-bottom:1px solid var(--border)">'
                f'<span><strong>{ch.get("name","?")}</strong> <span style="color:var(--text-dim)">{ch.get("type","?")}</span></span>'
                f'<span style="font-size:11px;color:var(--text-dim)">{ch.get("min_severity","medium")}+</span>'
                f'</div>'
                for ch in [channel_to_dict(ch) for ch in channels]
            ) or '<div style="color:var(--text-dim);padding:8px">No notification channels configured.</div>'
            from fastapi.responses import HTMLResponse
            return HTMLResponse(lst)
        return JSONResponse(
            {
                "channels": [channel_to_dict(ch) for ch in channels],
            }
        )
    except Exception as e:
        if html:
            from fastapi.responses import HTMLResponse
            return HTMLResponse(f'<div style="color:var(--critical)">Error: {e}</div>')
        return JSONResponse({"channels": [], "error": str(e)})


@router.post("/notifications/add")
async def add_notification(request: Request) -> JSONResponse:
    """Add a notification channel."""
    root = _root(request)
    try:
        import patchi.core.config as cfg
        from patchi.core.notifications.channels import from_config

        body = await request.json()
        entry = from_config(body)
        config = cfg.load(root)
        config.setdefault("notifications", []).append(
            {
                "name": entry.name,
                "type": entry.channel_type.value,
                "apprise_url": entry.apprise_url,
                "min_severity": entry.min_severity,
                "in_digest": entry.in_digest,
            }
        )
        cfg.save(config, root)
        return JSONResponse({"ok": True, "name": entry.name})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/notifications/test")
async def test_notification(request: Request) -> JSONResponse:
    """Test a notification channel by name."""
    root = _root(request)
    try:
        import patchi.core.config as cfg
        from patchi.core.notifications.notifier import Notifier

        body = await request.json()
        name = body.get("name", "")
        config = cfg.load(root)
        notifier = Notifier(root, config)
        results = notifier.test(channel_name=name)
        ok = any(success for _, success in results)
        return JSONResponse({"ok": ok, "channel": name, "results": [(ch, s) for ch, s in results]})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/notifications/remove")
async def remove_notification(request: Request) -> JSONResponse:
    """Remove a notification channel by name."""
    root = _root(request)
    try:
        import patchi.core.config as cfg

        body = await request.json()
        name = body.get("name", "")
        if not name:
            return JSONResponse({"ok": False, "error": "name required"})

        config = cfg.load(root)
        channels = config.get("notifications", [])
        config["notifications"] = [ch for ch in channels if ch.get("name") != name]
        cfg.save(config, root)
        return JSONResponse({"ok": True, "name": name})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


# ── Doctor ───────────────────────────────────────────────────────────────────


@router.get("/doctor")
async def web_doctor(request: Request) -> JSONResponse:
    """Run diagnostic checks and return structured results."""
    root = _root(request)
    try:
        import importlib
        import sys

        checks: list[dict] = []

        pyver = sys.version_info
        checks.append(
            {
                "label": "Python",
                "ok": pyver >= (3, 11),
                "note": f"{pyver.major}.{pyver.minor}.{pyver.micro}",
            }
        )

        for import_name, pip_name, desc in [
            ("rich", "rich", "Terminal UI"),
            ("httpx", "httpx", "HTTP client"),
            ("fastapi", "fastapi", "Web backend"),
            ("uvicorn", "uvicorn", "Web server"),
            ("vulture", "vulture", "Dead code"),
            ("yaml", "pyyaml", "YAML"),
        ]:
            ok = False
            try:
                importlib.import_module(import_name)
                ok = True
            except ImportError:
                pass
            checks.append({"label": f"dep: {pip_name}", "ok": ok, "note": desc})

        config = cfg_mod.load(root)
        ai_keys = config.get("ai", {}).get("keys", [])
        checks.append(
            {
                "label": "API keys",
                "ok": len(ai_keys) > 0,
                "note": f"{len(ai_keys)} key(s)" if ai_keys else "No keys configured",
            }
        )

        local_model = config.get("ai", {}).get("local_model_name")
        checks.append(
            {
                "label": "Ollama",
                "ok": bool(local_model),
                "note": local_model or "Not configured",
            }
        )

        errors = sum(1 for c in checks if not c["ok"])
        return JSONResponse({"checks": checks, "errors": errors, "warnings": 0})
    except Exception as e:
        return JSONResponse({"checks": [], "errors": 1, "warnings": 0, "error": str(e)})


# ── Model management ─────────────────────────────────────────────────────────


@router.get("/model/status")
async def get_model_status(request: Request) -> JSONResponse:
    """Get current AI model configuration and Ollama status."""
    root = _root(request)
    try:
        import httpx

        config = cfg_mod.load(root)
        ai_cfg = config.get("ai", {})
        local_model = ai_cfg.get("local_model_name", "")

        ollama_running = False
        ollama_models: list[str] = []
        try:
            from patchi.core.constants import OLLAMA_TAGS_URL

            async with httpx.AsyncClient() as client:
                resp = await client.get(OLLAMA_TAGS_URL, timeout=3)
                if resp.status_code == 200:
                    ollama_running = True
                    ollama_models = [m["name"] for m in resp.json().get("models", [])]
        except Exception as exc:
            logger.warning("Ollama connection check failed: %s", exc)

        active_keys = ai_cfg.get("keys", [])
        return JSONResponse(
            {
                "local_model": local_model,
                "ollama_running": ollama_running,
                "ollama_models": ollama_models,
                "active_keys": [k.get("nickname", k.get("name", "?")) for k in active_keys],
                "horde_enabled": ai_cfg.get("horde_fallback", False),
            }
        )
    except Exception as e:
        return JSONResponse({"error": str(e)})


@router.post("/model/set")
async def set_model(request: Request) -> JSONResponse:
    """Set active local Ollama model."""
    root = _root(request)
    try:
        body = await request.json()
        model_name = body.get("model", "").strip()
        if not model_name:
            return JSONResponse({"ok": False, "error": "model name required"})
        config = cfg_mod.load(root)
        config.setdefault("ai", {})["local_model_name"] = model_name
        cfg_mod.save(config, root)
        return JSONResponse({"ok": True, "model": model_name})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


# ── Agents list ──────────────────────────────────────────────────────────────


@router.get("/agents")
async def get_agents(request: Request) -> JSONResponse:
    """List all registered agents with their status."""
    try:
        import patchi.core.agents.scanners  # noqa: F401
        import patchi.core.fix.fix_agents  # noqa: F401
        import patchi.core.security.security_agents  # noqa: F401
        import patchi.core.testing.test_agents  # noqa: F401
        from patchi.core.agents.base import list_agents

        agents = list_agents()
        result = []
        for a in agents:
            result.append(
                {
                    "name": a.name,
                    "group": a.group.value if hasattr(a.group, "value") else str(a.group),
                    "description": getattr(a, "description", ""),
                }
            )
        return JSONResponse({"agents": result})
    except Exception as e:
        return JSONResponse({"agents": [], "error": str(e)})


# ── Watch mode ───────────────────────────────────────────────────────────────


@router.post("/watch/start")
async def start_watch(request: Request) -> JSONResponse:
    """Start file watcher in background thread."""
    root = _root(request)
    try:
        from patchi.core.brain.freshness import BrainWatcher

        watcher = BrainWatcher(root=root, debounce_ms=600)
        watcher.start()
        request.app.state.watcher = watcher
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/watch/stop")
async def stop_watch(request: Request) -> JSONResponse:
    """Stop file watcher."""
    try:
        watcher = getattr(request.app.state, "watcher", None)
        if watcher:
            watcher.stop()
            request.app.state.watcher = None
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


def _read_env_file_key(root, env_var: str) -> str:
    env_file = root / ".patchi" / ".env"
    if not env_file.exists():
        return ""
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(f"{env_var}="):
            return line[len(env_var) + 1 :].strip().strip('"').strip("'")
    return ""


def _write_env_file_key(env_file, env_var: str, value: str) -> None:
    env_file = Path(env_file)
    env_file.parent.mkdir(parents=True, exist_ok=True)
    lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
    lines = [line for line in lines if not line.startswith(f"{env_var}=")]
    lines.append(f'{env_var}="{value}"')
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Ensure .patchi/.env is in .gitignore
    gi = env_file.parent.parent / ".gitignore"
    if gi.exists():
        content = gi.read_text(encoding="utf-8")
        if ".patchi/.env" not in content:
            gi.write_text(content.rstrip() + "\n.patchi/.env\n", encoding="utf-8")


def _remove_env_file_key(env_file, env_var: str) -> None:
    env_file = Path(env_file)
    if not env_file.exists():
        return
    lines = [
        line
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if not line.startswith(f"{env_var}=")
    ]
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── Live Test Execution (web UI → live test runner) ───────────────────────────


@router.post("/action/test-live")
async def trigger_live_test(request: Request) -> JSONResponse:
    """
    Trigger live test execution via the LiveTestRunner.
    Streams results in real-time via WebSocket events.
    Body: { "types": ["buttons", "layout", "e2e", "visual", "smoke", "full"], "area": "optional" }
    """
    import asyncio

    body = await request.json()
    test_types = body.get("types", ["smoke"])
    area = body.get("area")
    root = _root(request)

    async def _run():
        from patchi.web.events import manager

        try:
            from patchi.core.testing.live_test_runner import LiveTestRunner, TestRunConfig

            runner = LiveTestRunner(root)

            # Stream events to WebSocket
            async def on_event(event: str, data: dict):
                await manager.broadcast(
                    {"event": f"test.{event}", "data": data, "ts": __import__("time").time()}
                )

            runner.set_event_callback(on_event)

            config = TestRunConfig(
                test_types=test_types,
                area=area,
            )

            result = await runner.run(config)

            # Final summary event
            await manager.broadcast(
                {
                    "event": "test.run_completed",
                    "data": result.to_dict(),
                    "ts": __import__("time").time(),
                }
            )

        except Exception as e:
            await manager.broadcast(
                {
                    "event": "test.run_failed",
                    "data": {"error": str(e)},
                    "ts": __import__("time").time(),
                }
            )

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "message": f"Live test run started: {', '.join(test_types)}"})


@router.get("/test-agents")
async def list_test_agents(request: Request) -> JSONResponse:
    """List all available test agents and their types."""
    try:
        import patchi.core.testing.e2e_flow_agent  # noqa
        import patchi.core.testing.test_agents  # noqa
        import patchi.core.testing.ui_accessibility_agent  # noqa
        import patchi.core.testing.ui_button_agent  # noqa
        import patchi.core.testing.ui_layout_agent  # noqa
        import patchi.core.testing.visual_regression_agent  # noqa
        from patchi.core.agents.base import AgentGroup, list_agents

        agents = list_agents(AgentGroup.TEST)
        result = []
        for a in agents:
            result.append(
                {
                    "name": a.name,
                    "description": a.description if hasattr(a, "description") else "",
                    "group": "test",
                }
            )
        return JSONResponse({"agents": result})
    except Exception as e:
        return JSONResponse({"agents": [], "error": str(e)})


# ── Restrict endpoints ────────────────────────────────────────────────────────


@router.get("/restrict")
async def get_restrictions(request: Request) -> JSONResponse:
    """List all file restrictions."""
    root = _root(request)
    try:
        restrictions = cfg_mod.get_restrictions(root)
        return JSONResponse({"restrictions": restrictions})
    except Exception as e:
        return JSONResponse({"restrictions": [], "error": str(e)})


@router.post("/restrict/add")
async def add_restriction(request: Request) -> JSONResponse:
    """Add a file restriction."""
    root = _root(request)
    try:
        body = await request.json()
        path = body.get("path", "")
        rtype = body.get("type", "no_touch")
        reason = body.get("reason", "")

        from patchi.core.constants import RestrictionType

        type_map = {
            "no_touch": RestrictionType.NO_TOUCH,
            "scan_only": RestrictionType.SCAN_ONLY,
            "sensitive": RestrictionType.SENSITIVE,
        }
        restriction_type = type_map.get(rtype)
        if not restriction_type:
            return JSONResponse({"ok": False, "error": f"Invalid type: {rtype}"}, status_code=400)

        cfg_mod.add_restriction(path, restriction_type, reason, root)
        return JSONResponse({"ok": True, "path": path, "type": rtype})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/restrict/remove")
async def remove_restriction(request: Request) -> JSONResponse:
    """Remove a file restriction."""
    root = _root(request)
    try:
        body = await request.json()
        path = body.get("path", "")
        removed = cfg_mod.remove_restriction(path, root)
        return JSONResponse({"ok": removed, "path": path})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


@router.post("/restrict/toggle")
async def toggle_restriction(request: Request) -> JSONResponse:
    """Enable or disable a file restriction."""
    root = _root(request)
    try:
        body = await request.json()
        path = body.get("path", "")
        enabled = body.get("enabled", True)
        ok = cfg_mod.toggle_restriction(path, enabled=enabled, root=root)
        return JSONResponse({"ok": ok, "path": path, "enabled": enabled})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


# ── Explain endpoint ──────────────────────────────────────────────────────────


@router.get("/explain")
async def explain_findings(request: Request) -> JSONResponse:
    """Explain findings in plain English."""
    root = _root(request)
    try:
        from patchi.cli.commands.explain_cmd import _EXPLANATIONS

        issues = memory_mod.list_issues(root)

        explanations = []
        for issue in issues:
            ftype = issue.get("type", "unknown")
            if ftype in _EXPLANATIONS:
                info = _EXPLANATIONS[ftype].copy()
                info["finding"] = issue
                explanations.append(info)

        return JSONResponse(
            {
                "explanations": explanations,
                "total": len(issues),
                "explained": len(explanations),
                "available_types": list(_EXPLANATIONS.keys()),
            }
        )
    except Exception as e:
        return JSONResponse({"explanations": [], "error": str(e)})


# ── Blast radius endpoint ─────────────────────────────────────────────────────


@router.get("/blast")
async def get_blast_radius(request: Request) -> JSONResponse:
    """Get blast radius for a file."""
    root = _root(request)
    try:
        from collections import deque

        from patchi.core.brain.import_graph import ImportGraph

        # Build graph
        graph = ImportGraph()
        brain = memory_mod.get_brain(root)
        graph_data = brain.get("import_graph", {})

        # Populate graph from brain data
        for src, targets in graph_data.get("edges", {}).items():
            for target in targets:
                graph.add_edge(src, target)

        if not graph.nodes:
            return JSONResponse({"error": "No import graph data. Run scan first.", "radii": []})

        # Calculate blast radius for all files
        radii = []
        for node in graph.nodes:
            direct = graph.reverse.get(node, set())
            all_affected = set()
            queue = deque(direct)
            while queue:
                n = queue.popleft()
                if n == node or n in all_affected:
                    continue
                all_affected.add(n)
                for parent in graph.reverse.get(n, set()):
                    if parent not in all_affected:
                        queue.append(parent)

            risk = "LOW"
            if len(all_affected) > 10:
                risk = "CRITICAL"
            elif len(all_affected) > 3:
                risk = "HIGH"
            elif len(all_affected) > 0:
                risk = "MEDIUM"

            radii.append(
                {
                    "file": node,
                    "direct": len(direct),
                    "total": len(all_affected),
                    "risk": risk,
                }
            )

        radii.sort(key=lambda x: -x["total"])
        return JSONResponse({"radii": radii[:50]})
    except Exception as e:
        return JSONResponse({"radii": [], "error": str(e)})


# ── Audit endpoint ────────────────────────────────────────────────────────────


@router.post("/action/audit")
async def trigger_audit(request: Request) -> JSONResponse:
    """Run full project audit (scan + security + tests + health)."""
    import asyncio

    root = _root(request)

    async def _run():
        try:
            # Phase 1: Brain scan
            from patchi.core.brain.brain import Brain

            brain_instance = Brain(root)
            brain_instance.scan()
            memory_mod.get_brain(root)

            # Phase 2: Security scan
            import patchi.core.security.security_agents  # noqa: F401
            from patchi.core.agents.base import AgentGroup, list_agents
            from patchi.core.agents.coordinator import Coordinator

            sec_agents = [a.name for a in list_agents(AgentGroup.SECURITY)]
            coord = Coordinator(root)
            sec_results = await asyncio.to_thread(coord.run_agents, sec_agents)

            # Phase 3: Health score
            from patchi.core import health as hm

            health = hm.compute(root)

            return JSONResponse(
                {
                    "ok": True,
                    "health": health.to_dict(),
                    "security_findings": sum(
                        r.finding_count for r in sec_results if hasattr(r, "finding_count")
                    ),
                }
            )
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)})

    asyncio.create_task(_run())
    return JSONResponse({"ok": True, "message": "Full audit started"})


# ── Trend endpoint ────────────────────────────────────────────────────────────


@router.get("/trend")
async def get_trend(request: Request) -> JSONResponse:
    """Get health and quality trend data."""
    root = _root(request)
    try:
        scans = memory_mod.get_scan_results(root)

        trend_data = []
        for name, data in scans.items():
            if not isinstance(data, dict):
                continue
            trend_data.append(
                {
                    "timestamp": data.get("timestamp", ""),
                    "agent": name,
                    "finding_count": data.get("finding_count", 0),
                    "status": data.get("status", "done"),
                    "duration_ms": data.get("duration_ms", 0),
                }
            )

        trend_data.sort(key=lambda x: x.get("timestamp", ""))
        return JSONResponse({"trend": trend_data[-50:]})
    except Exception as e:
        return JSONResponse({"trend": [], "error": str(e)})


# ── Learn endpoint ────────────────────────────────────────────────────────────


@router.post("/action/learn")
async def trigger_learn(request: Request) -> JSONResponse:
    """Learn project conventions."""
    import time as time_mod

    root = _root(request)
    try:
        from patchi.cli.commands.learn_cmd import (
            _analyze_dependencies,
            _analyze_error_handling,
            _analyze_framework,
            _analyze_imports,
            _analyze_naming,
            _analyze_structure,
            _analyze_testing,
        )

        brain = memory_mod.get_brain(root)

        conventions = {
            "learned_at": time_mod.time(),
            "structure": _analyze_structure(root),
            "naming": _analyze_naming(root),
            "imports": _analyze_imports(root),
            "error_handling": _analyze_error_handling(root),
            "testing": _analyze_testing(root),
            "framework": _analyze_framework(root, brain),
            "dependencies": _analyze_dependencies(root),
        }

        brain["conventions"] = conventions
        memory_mod.save_brain(brain, root)

        return JSONResponse({"ok": True, "conventions": conventions})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


# ── AI status endpoint ────────────────────────────────────────────────────────


@router.get("/ai/status")
async def get_ai_status(request: Request) -> JSONResponse:
    """Get AI provider status."""
    root = _root(request)
    try:
        config = cfg_mod.load(root)
        ai_cfg = config.get("ai", {})

        return JSONResponse(
            {
                "local_model": ai_cfg.get("local_model_name", ""),
                "has_keys": len(ai_cfg.get("keys", [])) > 0,
                "key_count": len(ai_cfg.get("keys", [])),
                "cost_limit": ai_cfg.get("cost_limit", 0),
                "enable_cost_limit": ai_cfg.get("enable_cost_limit", False),
            }
        )
    except Exception as e:
        return JSONResponse({"error": str(e)})


@router.post("/ai/test")
async def test_ai(request: Request) -> JSONResponse:
    """Test AI provider connection."""
    try:
        body = await request.json()
        provider = body.get("provider", "horde")

        if provider == "horde":
            from patchi.core.ai.client import _call_ai_horde
            from patchi.core.constants import AI_HORDE_ANON_KEY

            result = _call_ai_horde(
                AI_HORDE_ANON_KEY, "Say 'Patchi AI Horde connection OK' in exactly 5 words.", 50
            )
            if result:
                return JSONResponse({"ok": True, "message": result.strip()})
            else:
                return JSONResponse(
                    {
                        "ok": False,
                        "message": "AI Horde did not respond. It may be under heavy load — try again in a moment.",
                    }
                )
        elif provider == "ollama":
            from patchi.core.ai.client import _call_ollama

            cfg = cfg_mod.load(_root(request))
            result = _call_ollama(cfg, "Say OK", max_tokens=10)
            if result:
                return JSONResponse(
                    {"ok": True, "message": f"Ollama responded: {result.strip()[:100]}"}
                )
            else:
                return JSONResponse(
                    {"ok": False, "message": "Ollama not responding. Is it running? (ollama serve)"}
                )
        else:
            return JSONResponse(
                {
                    "ok": False,
                    "message": f"Provider '{provider}' test not implemented. Try 'ollama' or 'horde'.",
                }
            )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})
