"""CI/CD REST API â€” trigger scans, retrieve results, health checks.

Endpoints:
  POST /api/cicd/scan          â€” trigger scan and wait for results (sync)
  POST /api/cicd/scan/async    â€” trigger scan, return immediately (async)
  GET  /api/cicd/scan/status   â€” get current scan status
  GET  /api/cicd/scan/results  â€” get latest scan results
  GET  /api/cicd/health        â€” health check
  GET  /api/cicd/assurance     â€” get assurance graph data
  GET  /api/cicd/findings      â€” get findings with filters
  GET  /api/cicd/summary       â€” project summary (findings, agents, health)

Usage from CI/CD:
  curl -X POST http://localhost:1612/api/cicd/scan -d '{"scan_type":"all"}'
  curl http://localhost:1612/api/cicd/health
  curl http://localhost:1612/api/cicd/findings?severity=critical&limit=10
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

_log = logging.getLogger("patchi.web.cicd")

router = APIRouter(prefix="/api/cicd")

# ── API Key Authentication ───────────────────────────────────────────────────
# The API key is read from:
#   1. Environment variable PATCHI_API_KEY (recommended for production)
#   2. .patchi/api_key file (auto-generated on first run if missing)
#   3. If neither exists, auth is disabled (local-only mode)
#
# Clients send the key via X-API-Key header.
# Health check endpoint is always unauthenticated.


def _get_api_key(root: Path | None = None) -> str | None:
    """Resolve the API key from env or .patchi/api_key file."""
    # 1. Environment variable (always checked first)
    env_key = os.environ.get("PATCHI_API_KEY", "")
    if env_key:
        return env_key.strip()
    # 2. File-based key (generated lazily)
    if root is None:
        try:
            from patchi.core.config import require_project_root

            root = require_project_root()
        except Exception:
            return None
    try:
        key_file = root / ".patchi" / "api_key"
        if key_file.is_file():
            return key_file.read_text(encoding="utf-8").strip()
        # Auto-generate on first access
        import secrets

        new_key = secrets.token_urlsafe(32)
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(new_key, encoding="utf-8")
        _log.info("Generated CI/CD API key: %s...", new_key[:8])
        return new_key
    except Exception:
        return None


def _verify_api_key(x_api_key: str | None = Header(None)) -> str | None:
    """FastAPI dependency: verify X-API-Key header.

    Returns the API key if valid, or None if auth is disabled.
    Raises HTTPException 401 if auth is enabled but key is missing/wrong.
    """
    required = _get_api_key()
    if not required:
        return None  # auth disabled
    if not x_api_key:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=401,
            detail={
                "error": "Missing X-API-Key header",
                "hint": "Send X-API-Key header with your request",
            },
        )
    # Constant-time comparison to prevent timing attacks
    if not hashlib.compare_digest(x_api_key, required):
        from fastapi import HTTPException

        raise HTTPException(
            status_code=401,
            detail={
                "error": "Invalid API key",
                "hint": "Send X-API-Key header with your request",
            },
        )
    return x_api_key


# â”€â”€ Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class ScanRequest(BaseModel):
    scan_type: str = "all"
    deep: bool = False
    pipeline: bool = False


# â”€â”€ Scan status (shared state) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_scan_state = {
    "running": False,
    "started_at": None,
    "completed_at": None,
    "last_result": None,
    "last_error": None,
    "agents_run": 0,
    "total_findings": 0,
}


# â”€â”€ Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


@router.get("/health")
async def health(request: Request) -> JSONResponse:
    """Health check endpoint for CI/CD monitoring."""
    root = request.app.state.root

    # Check brain data
    brain_exists = (root / ".patchi" / "brain.json").is_file()

    # Check assurance graph
    assurance_exists = (root / ".patchi" / "assurance_graph.json").is_file()

    # Check scan results
    scan_results_exist = False
    try:
        from patchi.core import memory as mem

        results = mem.get_scan_results(root)
        scan_results_exist = bool(results)
    except Exception:
        pass

    return JSONResponse(
        {
            "status": "healthy",
            "version": "0.6.0",
            "project_root": str(root),
            "brain_ready": brain_exists,
            "assurance_ready": assurance_exists,
            "scan_results_ready": scan_results_exist,
            "scan_running": _scan_state["running"],
            "last_scan": _scan_state["completed_at"],
        }
    )


@router.post("/scan")
async def scan_sync(
    request: Request, body: ScanRequest = None, _key: str | None = Depends(_verify_api_key)
) -> JSONResponse:
    """Trigger scan and wait for results (synchronous, for CI/CD).

    Returns scan results when complete. Timeout: 300s.
    """
    if _scan_state["running"]:
        return JSONResponse(
            {
                "ok": False,
                "error": "Scan already running",
                "started_at": _scan_state["started_at"],
            },
            status_code=409,
        )

    body = body or ScanRequest()
    root = request.app.state.root

    _scan_state["running"] = True
    _scan_state["started_at"] = time.time()
    _scan_state["completed_at"] = None
    _scan_state["last_error"] = None

    try:
        result = await _run_scan(root, body.scan_type, body.deep, body.pipeline)
        _scan_state["last_result"] = result
        _scan_state["completed_at"] = time.time()
        return JSONResponse(result)
    except Exception as e:
        _scan_state["last_error"] = str(e)
        return JSONResponse(
            {
                "ok": False,
                "error": str(e),
                "duration_ms": int((time.time() - _scan_state["started_at"]) * 1000),
            },
            status_code=500,
        )
    finally:
        _scan_state["running"] = False


@router.post("/scan/async")
async def scan_async(
    request: Request, body: ScanRequest = None, _key: str | None = Depends(_verify_api_key)
) -> JSONResponse:
    """Trigger scan and return immediately (async, for CI/CD).

    Poll /api/cicd/scan/status for completion.
    """
    if _scan_state["running"]:
        return JSONResponse(
            {
                "ok": False,
                "error": "Scan already running",
                "started_at": _scan_state["started_at"],
            },
            status_code=409,
        )

    body = body or ScanRequest()
    root = request.app.state.root

    _scan_state["running"] = True
    _scan_state["started_at"] = time.time()
    _scan_state["completed_at"] = None

    async def _bg():
        try:
            result = await _run_scan(root, body.scan_type, body.deep, body.pipeline)
            _scan_state["last_result"] = result
            _scan_state["completed_at"] = time.time()
        except Exception as e:
            _scan_state["last_error"] = str(e)
        finally:
            _scan_state["running"] = False

    asyncio.create_task(_bg())

    return JSONResponse(
        {
            "ok": True,
            "message": "Scan started",
            "started_at": _scan_state["started_at"],
            "poll_url": "/api/cicd/scan/status",
        }
    )


@router.get("/scan/status")
async def scan_status(_key: str | None = Depends(_verify_api_key)) -> JSONResponse:
    """Get current scan status."""
    return JSONResponse(
        {
            "running": _scan_state["running"],
            "started_at": _scan_state["started_at"],
            "completed_at": _scan_state["completed_at"],
            "agents_run": _scan_state["agents_run"],
            "total_findings": _scan_state["total_findings"],
            "error": _scan_state["last_error"],
        }
    )


@router.get("/scan/results")
async def scan_results(
    request: Request, _key: str | None = Depends(_verify_api_key)
) -> JSONResponse:
    """Get latest scan results."""
    root = request.app.state.root

    if _scan_state["last_result"]:
        return JSONResponse(_scan_state["last_result"])

    # Load from memory
    try:
        from patchi.core import memory as mem

        results = mem.get_scan_results(root)
        findings = []
        for agent_name, data in (results or {}).items():
            for f in data.get("findings", []):
                f["agent"] = agent_name
                findings.append(f)

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

        return JSONResponse(
            {
                "ok": True,
                "total": len(findings),
                "findings": findings[:100],
                "by_severity": {
                    s: sum(1 for f in findings if f.get("severity") == s)
                    for s in ["critical", "high", "medium", "low", "info"]
                },
            }
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.get("/findings")
async def findings(
    request: Request,
    severity: str | None = None,
    agent: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _key: str | None = Depends(_verify_api_key),
) -> JSONResponse:
    """Get findings with filters."""
    root = request.app.state.root

    try:
        from patchi.core import memory as mem

        results = mem.get_scan_results(root)
        all_findings = []
        for agent_name, data in (results or {}).items():
            for f in data.get("findings", []):
                f["agent"] = agent_name
                all_findings.append(f)

        # Apply filters
        if severity:
            all_findings = [f for f in all_findings if f.get("severity") == severity]
        if agent:
            all_findings = [f for f in all_findings if f.get("agent") == agent]

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

        total = len(all_findings)
        page = all_findings[offset : offset + limit]

        return JSONResponse(
            {
                "ok": True,
                "total": total,
                "offset": offset,
                "limit": limit,
                "findings": page,
            }
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.get("/assurance")
async def assurance(request: Request, _key: str | None = Depends(_verify_api_key)) -> JSONResponse:
    """Get assurance graph data."""
    root = request.app.state.root

    try:
        from patchi.core.assurance.graph import AssuranceGraph

        graph = AssuranceGraph.load(root)
        coverage = graph.coverage()

        claims = []
        for claim in graph.claims.values():
            claims.append(
                {
                    "id": claim.id,
                    "statement": claim.statement,
                    "domain": claim.domain,
                    "verdict": claim.verdict.value,
                    "severity": claim.severity_if_disproved,
                    "evidence_count": len(claim.evidence),
                }
            )

        return JSONResponse(
            {
                "ok": True,
                "coverage": coverage,
                "claims": claims,
                "total_claims": len(claims),
            }
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.get("/summary")
async def summary(request: Request, _key: str | None = Depends(_verify_api_key)) -> JSONResponse:
    """Project summary for CI/CD dashboards."""
    root = request.app.state.root

    try:
        from patchi.core import memory as mem

        # Brain data
        brain = mem.get_brain(root)
        file_count = brain.get("file_count", 0)
        route_count = brain.get("route_count", 0)

        # Findings
        results = mem.get_scan_results(root)
        all_findings = []
        for agent_name, data in (results or {}).items():
            for f in data.get("findings", []):
                f["agent"] = agent_name
                all_findings.append(f)

        by_severity = {
            s: sum(1 for f in all_findings if f.get("severity") == s)
            for s in ["critical", "high", "medium", "low", "info"]
        }

        # Assurance
        assurance_claims = 0
        assurance_proved = 0
        try:
            from patchi.core.assurance.graph import AssuranceGraph

            graph = AssuranceGraph.load(root)
            assurance_claims = len(graph.claims)
            assurance_proved = sum(1 for c in graph.claims.values() if c.verdict.value == "proved")
        except Exception:
            pass

        # Model routing stats
        routing_stats = {}
        try:
            from patchi.core.ai.model_router import get_model_router

            router = get_model_router(root=root)
            routing_stats = router.get_routing_stats()
        except Exception:
            pass

        # Tenant cost
        tenant_cost = 0.0
        try:
            from patchi.core.tenant import get_tenant_cost

            tenant_cost = get_tenant_cost(root)
        except Exception:
            pass

        return JSONResponse(
            {
                "ok": True,
                "project": str(root),
                "files": file_count,
                "routes": route_count,
                "findings": {
                    "total": len(all_findings),
                    "by_severity": by_severity,
                },
                "assurance": {
                    "claims": assurance_claims,
                    "proved": assurance_proved,
                },
                "routing": routing_stats,
                "tenant_cost": tenant_cost,
                "health_score": _compute_health_score(
                    all_findings, assurance_claims, assurance_proved
                ),
            }
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


async def _run_scan(root: Path, scan_type: str, deep: bool, pipeline: bool) -> dict:
    """Run a scan and return results."""
    import patchi.core.security.security_agents  # noqa: F401
    from patchi.core import config as cfg
    from patchi.core import memory as mem
    from patchi.core.agents.base import AgentGroup, AgentInput, list_agents

    config = cfg.load(root) if (root / "pyproject.toml").exists() else {}
    brain = mem.get_brain(root)

    # Determine agents
    _SKIP = {"SecurityProber", "RedTeamAgent"}
    if scan_type == "all":
        to_run = [a for a in list_agents(AgentGroup.SECURITY) if a.name not in _SKIP]
    else:
        all_agents = {a.name: a for a in list_agents(AgentGroup.SECURITY)}
        if scan_type in all_agents:
            to_run = [all_agents[scan_type]]
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")

    # Run agents
    results = []
    for agent_cls in to_run:
        inp = AgentInput(root=root, scope=[], brain=brain, config=config)
        result = await asyncio.to_thread(agent_cls().run, inp)
        results.append(result)

    _scan_state["agents_run"] = len(results)
    _scan_state["total_findings"] = sum(r.finding_count for r in results)

    # Correlate
    try:
        from patchi.core.security.orchestrator import SecurityOrchestrator

        report = SecurityOrchestrator().correlate(results)
        total = report.total_findings
    except Exception:
        total = sum(r.finding_count for r in results)

    # Build response
    all_findings = []
    for r in results:
        for f in r.findings:
            all_findings.append(
                {
                    "agent": r.agent_name,
                    "type": f.type,
                    "severity": f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity),
                    "file": f.file,
                    "line": f.line,
                    "message": f.message,
                }
            )

    return {
        "ok": True,
        "scan_type": scan_type,
        "agents_run": len(results),
        "total_findings": total,
        "findings": all_findings[:200],
        "by_severity": {
            s: sum(1 for f in all_findings if f.get("severity") == s)
            for s in ["critical", "high", "medium", "low", "info"]
        },
        "duration_ms": int((time.time() - _scan_state["started_at"]) * 1000),
    }


def _compute_health_score(findings: list, claims: int, proved: int) -> int:
    """Compute a 0-100 health score."""
    score = 100

    # Deductions for findings
    for f in findings:
        sev = f.get("severity", "info")
        if sev == "critical":
            score -= 15
        elif sev == "high":
            score -= 8
        elif sev == "medium":
            score -= 3
        elif sev == "low":
            score -= 1

    # Bonus for assurance coverage
    if claims > 0:
        coverage_pct = proved / claims
        score += int(coverage_pct * 10)

    return max(0, min(100, score))
