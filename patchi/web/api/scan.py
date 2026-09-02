"""Scan API — trigger security scans.

Scans run agents in parallel batches (default: 8 concurrent) so the
scan finishes faster while the event loop stays free for dashboard
requests.  Each agent gets its own timeout so a hung agent can't block
the whole scan.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path

import logging
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from patchi.core.tenant import tenant_context
_log = logging.getLogger("patchi.web.api.scan")


router = APIRouter(prefix="/api")

# ── Scan state ──────────────────────────────────────────────────────────────
# Global scan state so the dashboard and cancel endpoint can inspect it.
_scan_state: dict = {
    "running": False,
    "task": None,         # asyncio.Task | None
    "cancel": None,       # asyncio.Event — set to abort
    "started_at": 0.0,
    "agent_index": 0,
    "agent_total": 0,
    "current_agent": "",
}

# Max agents that run concurrently inside each batch.
BATCH_SIZE = 8
# Per-agent hard timeout (seconds).  Agents that exceed this are killed.
AGENT_TIMEOUT = 120


@router.post("/scan")
async def trigger_scan(
    request: Request,
    scan_type: str = "all",
    auto_fix: bool = False,
) -> JSONResponse:
    """Trigger a security scan.  Runs in background, sends progress via WS."""
    if _scan_state["running"]:
        return JSONResponse(
            status_code=409,
            content={"ok": False, "error": "Scan already running"},
        )

    root = request.app.state.root
    import patchi.core.security.security_agents  # noqa: F401
    from patchi.core import config as cfg
    from patchi.core import memory as mem
    from patchi.core.agents.base import AgentGroup, AgentInput, list_agents
    from patchi.web.ws import (
        evt_scan_complete,
        evt_scan_progress,
        evt_scan_started,
    )

    try:
        config = cfg.load(root)
    except Exception:
        config = {}

    brain = mem.get_brain(root)

    # Determine agents to run
    all_agents = {a.name: a for a in list_agents(AgentGroup.SECURITY)}
    if scan_type == "all":
        _SKIP = {"SecurityProber", "RedTeamAgent"}
        to_run = [a for a in list_agents(AgentGroup.SECURITY) if a.name not in _SKIP]
    elif scan_type in all_agents:
        to_run = [all_agents[scan_type]]
    else:
        return JSONResponse({"ok": False, "error": f"Unknown scan type: {scan_type}"})

    cancel_event = asyncio.Event()
    _scan_state.update({
        "running": True,
        "cancel": cancel_event,
        "started_at": time.time(),
        "agent_total": len(to_run),
    })

    async def _run():
        try:
            # Wrap everything in tenant_context for proper scoping
            with tenant_context(root):
                await evt_scan_started(len(to_run))

                results = []
                total = len(to_run)

                # Run agents in batches so the event loop stays free.
                for batch_start in range(0, total, BATCH_SIZE):
                    if cancel_event.is_set():
                        break

                    batch = to_run[batch_start : batch_start + BATCH_SIZE]
                    batch_tasks = []

                    for agent_cls in batch:
                        if cancel_event.is_set():
                            break
                        idx = batch_start + batch.index(agent_cls) + 1
                        _scan_state["agent_index"] = idx
                        _scan_state["current_agent"] = agent_cls.name
                        await evt_scan_progress(agent_cls.name, "scanning", idx, total)

                        inp = AgentInput(root=root, scope=[], brain=brain, config=config)
                        task = asyncio.create_task(
                            _run_agent_with_timeout(agent_cls, inp, AGENT_TIMEOUT)
                        )
                        batch_tasks.append(task)

                    # Wait for all agents in this batch concurrently.
                    # yield control between batches so the event loop can
                    # handle HTTP requests, WS pings, etc.
                    if batch_tasks:
                        batch_results = await asyncio.gather(
                            *batch_tasks, return_exceptions=True
                        )
                        for r in batch_results:
                            if isinstance(r, Exception):
                                # Agent timed out or crashed — record as empty result
                                from patchi.core.agents.base import (
                                    AgentResult, AgentStatus,
                                )
                                r = AgentResult(
                                    agent_name="unknown",
                                    status=AgentStatus.FAILED,
                                    errors=[str(r)],
                                )
                            results.append(r)
                            await evt_scan_progress(
                                getattr(r, "agent_name", "?"), "done",
                                min(len(results), total), total,
                            )

                total_findings = sum(r.finding_count for r in results)

                # Deduplicate + correlate
                try:
                    from patchi.core.security.orchestrator import SecurityOrchestrator
                    report = SecurityOrchestrator().correlate(results)
                    deduped_count = report.total_findings
                except Exception:
                    deduped_count = total_findings

                await evt_scan_complete(deduped_count, 0)

                # Record scan in history
                try:
                    from patchi.core.memory import record_scan
                    import time as _time
                    elapsed = round(_time.time() - _scan_state.get('started_at', _time.time()), 1)
                    agent_names = [getattr(r, 'agent_name', '?') for r in results]
                    record_scan({
                        'timestamp': datetime.now(UTC).isoformat(),
                        'total_findings': deduped_count,
                        'agents_run': len(results),
                        'agents_list': agent_names[:20],
                        'duration_s': elapsed,
                        'auto_fix': auto_fix,
                        'cancelled': cancel_event.is_set(),
                    }, root)
                except Exception as _exc:
                    _log.debug("record_scan history write skipped: %s", _exc)

                # Auto-fix
                if auto_fix and deduped_count > 0 and not cancel_event.is_set():
                    await evt_scan_progress("auto_fix", "running", total, total)
                    try:
                        await asyncio.to_thread(_run_proactive_fix, root, config)
                    except Exception as e:
                        import logging
                        logging.getLogger("patchi.web.scan").warning(
                            "Auto-fix failed: %s", e
                        )
                    await evt_scan_progress("auto_fix", "done", total + 1, total + 1)
        finally:
            _scan_state["running"] = False
            _scan_state["cancel"] = None
            _scan_state["task"] = None

    task = asyncio.create_task(_run())
    _scan_state["task"] = task

    return JSONResponse({"ok": True, "message": f"Scan started with {len(to_run)} agents"})


async def _run_agent_with_timeout(agent_cls, inp, timeout: int):
    """Run a single agent with a hard timeout."""
    return await asyncio.wait_for(
        asyncio.to_thread(agent_cls().run, inp),
        timeout=timeout,
    )


@router.post("/scan/cancel")
async def cancel_scan() -> JSONResponse:
    """Cancel a running scan."""
    if not _scan_state["running"]:
        return JSONResponse({"ok": True, "message": "No scan running"})
    cancel = _scan_state.get("cancel")
    if cancel:
        cancel.set()
    task = _scan_state.get("task")
    if task and not task.done():
        task.cancel()
    return JSONResponse({"ok": True, "message": "Scan cancellation requested"})


@router.get("/scan/status")
async def scan_status() -> JSONResponse:
    """Get current scan status for polling."""
    if not _scan_state["running"]:
        return JSONResponse({"running": False})
    elapsed = time.time() - _scan_state["started_at"]
    return JSONResponse({
        "running": True,
        "elapsed": round(elapsed, 1),
        "current_agent": _scan_state["current_agent"],
        "agent_index": _scan_state["agent_index"],
        "agent_total": _scan_state["agent_total"],
    })


@router.get("/scan/history")
async def scan_history(request: Request, limit: int = 10) -> JSONResponse:
    """Return the last N scan summaries from history."""
    root = request.app.state.root
    from patchi.core.memory import get_scan_history
    history = get_scan_history(root)
    return JSONResponse({"ok": True, "scans": history[:limit], "total": len(history)})


def _run_proactive_fix(root, config):
    """Run proactive fixes after a scan."""
    from patchi.core.brain.proactive import ProactiveFixer

    try:
        fixer = ProactiveFixer(root)
        fixer.run()
    except Exception as e:
        import logging
        logging.getLogger("patchi.web.scan").warning("_run_proactive_fix failed: %s", e)


@router.get("/scan")
async def get_scan_report(request: Request) -> JSONResponse:
    """GET /api/scan — return cached scan results / report."""
    root = request.app.state.root
    from patchi.core import memory as mem

    scan_results = mem.get_scan_results(root)
    all_findings = []
    for agent_name, data in scan_results.items():
        if not isinstance(data, dict):
            continue
        for f in data.get("findings", []):
            if isinstance(f, dict):
                f["agent"] = agent_name
                all_findings.append(f)

    try:
        from patchi.core.agents.base import AgentGroup, AgentResult, Finding
        from patchi.core.security.orchestrator import SecurityOrchestrator

        synth = []
        for name, data in scan_results.items():
            if not isinstance(data, dict):
                continue
            ar = AgentResult(agent_name=name, agent_group=AgentGroup.SECURITY)
            for f in data.get("findings", []):
                if isinstance(f, dict):
                    ar.findings.append(Finding.from_dict(f))
            synth.append(ar)
        if synth:
            report = SecurityOrchestrator().correlate(synth)
            payload = report.to_dict()
            payload["ok"] = True
            payload["cached"] = True
            payload["total_findings"] = report.total_findings
            return JSONResponse(payload)
    except Exception as _exc:
        _log.warning('get_scan_report failed: %s', _exc)

    return JSONResponse({
        "ok": True,
        "total_findings": len(all_findings),
        "findings": all_findings[:50],
        "cached": True,
    })


@router.post("/scan/quick")
async def quick_scan(request: Request) -> JSONResponse:
    """On-demand scan: runs only agents relevant to git-diff changed files."""
    root = request.app.state.root

    try:
        import patchi.core.agents.scanners  # noqa: F401
        from patchi.core.agents.base import AgentGroup, AgentInput, list_agents
        from patchi.core.security.domain_activator_v2 import DomainActivatorV2
        from patchi.core.security.git_diff_activator import activate_from_diff
        from patchi.web.ws import evt_scan_complete

        # 1. Activate domains from git diff
        diff_result = activate_from_diff(root, commits=1)
        if diff_result.error:
            return JSONResponse({"ok": False, "error": diff_result.error})

        # 2. Map domains to agents
        activator = DomainActivatorV2(root)
        relevant = activator.get_relevant_agents(list(diff_result.activated_domains.keys()))
        relevant.extend(["PreCheckAgent", "PlanAuditorAgent"])
        relevant = list(dict.fromkeys(relevant))

        all_agents = {a.name: a for a in list_agents(AgentGroup.SCANNER)}
        to_run = [all_agents[n] for n in relevant if n in all_agents]

        if not to_run:
            return JSONResponse(
                {
                    "ok": True,
                    "message": "No agents match changed files",
                    "changed_files": diff_result.changed_files,
                    "domains": diff_result.activated_domains,
                    "agents_run": 0,
                }
            )

        # 3. Run filtered agents
        from patchi.core import config as cfg
        from patchi.core import memory as mem

        config = cfg.load(root) if root.exists() else {}
        brain = mem.get_brain(root)

        async def _run():
            results = []
            for agent_cls in to_run:
                inp = AgentInput(root=root, scope=[], brain=brain, config=config)
                result = await asyncio.to_thread(agent_cls().run, inp)
                results.append(result)
            total = sum(r.finding_count for r in results)
            await evt_scan_complete(total, 0)

        asyncio.create_task(_run())

        return JSONResponse(
            {
                "ok": True,
                "message": f"Quick scan started: {len(to_run)} agents",
                "changed_files": diff_result.changed_files[:20],
                "domains": diff_result.activated_domains,
                "agents_queued": [a.name for a in to_run],
            }
        )

    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.post("/scan/dast")
async def trigger_dast(request: Request) -> JSONResponse:
    """Trigger DAST (Dynamic Application Security Testing) scan with Playwright."""
    root = request.app.state.root

    from patchi.core import config as cfg
    from patchi.core import memory as mem
    from patchi.core.agents.base import AgentInput
    from patchi.web.ws import evt_scan_complete, evt_scan_progress, evt_scan_started

    try:
        config = cfg.load(root)
    except Exception:
        config = {}

    brain = mem.get_brain(root)

    # Import DAST agent
    try:
        from patchi.core.security.dast_agent import DASTAgent
    except ImportError:
        return JSONResponse({"ok": False, "error": "Playwright not installed. Run: pip install playwright && playwright install"}, status_code=500)

    async def _run():
        with tenant_context(root):
            await evt_scan_started(1)
            await evt_scan_progress("DASTAgent", "scanning", 0, 1)

            inp = AgentInput(root=root, scope=[], brain=brain, config=config)
            agent = DASTAgent()
            result = await asyncio.to_thread(agent.run, inp)

            total_findings = result.finding_count
            await evt_scan_progress("DASTAgent", "done", 1, 1)
            await evt_scan_complete(total_findings, 0)

    asyncio.create_task(_run())

    return JSONResponse({"ok": True, "message": "DAST scan started"})


@router.get("/findings-table")
async def get_findings(request: Request, limit: int = 20) -> HTMLResponse:
    """Get recent findings as HTML fragment."""
    root = request.app.state.root
    from fastapi.templating import Jinja2Templates

    from patchi.core import memory as mem

    templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

    scan_results = mem.get_scan_results(root)
    all_findings = []
    for agent_name, data in scan_results.items():
        for f in data.get("findings", [])[:limit]:
            f["agent"] = agent_name
            all_findings.append(f)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    return templates.TemplateResponse(
        request,
        "partials/findings_list.html",
        {
            "request": request,
            "findings": all_findings[:limit],
        },
    )


@router.get("/agents/status")
async def get_agents_status(request: Request) -> HTMLResponse:
    """Get agent status as HTML fragment."""
    root = request.app.state.root
    from fastapi.templating import Jinja2Templates

    from patchi.core import memory as mem

    templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

    scan_results = mem.get_scan_results(root)
    agents = []
    for agent_name, data in scan_results.items():
        agents.append(
            {
                "name": agent_name,
                "status": data.get("status", "unknown"),
                "findings": data.get("finding_count", 0),
                "duration_ms": data.get("duration_ms", 0),
            }
        )

    return templates.TemplateResponse(
        request,
        "partials/agent_grid.html",
        {
            "request": request,
            "agents": agents,
        },
    )
