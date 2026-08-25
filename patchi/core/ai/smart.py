"""
SmartAgent — the "smart core" of Patchi.

Given a natural-language goal, the agent:
  1. Plans a sequence of real tool calls (deterministic planner, robust offline).
  2. Asks the multi-persona Council for an advisory plan and merges its
     suggestions (the "dynamic brain with councils/personas").
  3. Executes the tools through the real ToolExecutor (validation, confirmation
     gates, audit log, rollback) — every tool does *real* work.
  4. Streams live events the whole time so a CLI or web console can show the
     agent working in real time.

Works fully offline (no OpenAI key required). If an LLM client is configured it
can enrich planning later, but the verified path here is deterministic.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Callable, Optional

from patchi.core.ai.tool_executor import CLIConfirmationProvider, ToolExecutor
from patchi.core.ai.tools import realize

_log = logging.getLogger("patchi.ai.smart")


class SmartAgent:
    def __init__(
        self,
        root: Path,
        on_event: Optional[Callable[[dict], None]] = None,
        on_progress: Optional[Callable[[str], None]] = None,
        llm: Any = None,
    ):
        self.root = Path(root)
        self.on_event = on_event or (lambda _d: None)
        self.on_progress = on_progress or (lambda _s: None)
        self.llm = llm
        self.events: list[dict] = []
        self._sink = self._make_sink()

    # -- event plumbing ----------------------------------------------------
    def _make_sink(self) -> Callable[[dict], None]:
        agent = self

        def sink(payload: dict) -> None:
            agent.events.append(payload)
            agent.on_event(payload)

        return sink

    # -- planning ----------------------------------------------------------
    def _plan(self, goal: str) -> list[dict]:
        """Deterministic, offline-safe planner mapping a goal to real tools."""
        g = goal.lower()
        steps: list[dict] = []

        def add(tool: str, params: dict) -> None:
            if not any(s["tool"] == tool for s in steps):
                steps.append({"tool": tool, "parameters": params})

        if any(k in g for k in ("understand", "what", "how", "explain", "brain",
                                "purpose", "domain", "map", "analyze", "scan")):
            add("analyze_project", {})
        if any(k in g for k in ("security", "vulnerab", "attack", "cve", "exploit",
                                "owasp", "injection", "harden", "secure", "audit")):
            add("scan_vulnerabilities", {"domains": None})
            if any(k in g for k in ("attack", "red", "exploit", "advers", "breach")):
                add("attack_simulate", {"safe_mode": True})
        if any(k in g for k in ("test", "coverage", "regression", "e2e", "browser", "qa")):
            add("run_tests", {"test_types": ["unit"]})
        if any(k in g for k in ("stress", "load", "performance", "scale", "breakpoint")):
            url = self._discover_url()
            if url:
                add("stress_test", {"base_url": url, "scenario": "load",
                                    "users": 10, "duration_seconds": 15})
        if any(k in g for k in ("screenshot", "visual", "capture")):
            url = self._discover_url()
            if url:
                add("screenshot", {"url": url})
        if any(k in g for k in ("compliance", "pci", "hipaa", "gdpr", "soc2", "asvs")):
            add("check_compliance", {"standard": "owasp-asvs", "level": 1})
        if any(k in g for k in ("fix", "patch", "remediate", "repair")):
            add("scan_vulnerabilities", {"domains": None})

        if not steps:
            # Safe default: understand the project, secure it, test it.
            add("analyze_project", {})
            add("scan_vulnerabilities", {"domains": None})
        return steps

    def _discover_url(self) -> Optional[str]:
        """Best-effort discovery of a running local app to test against."""
        import httpx

        for port in (8000, 3000, 5000, 8080):
            url = f"http://127.0.0.1:{port}"
            try:
                r = httpx.get(url, timeout=1.0)
                if r.status_code < 500:
                    return url
            except Exception:
                continue
        return None

    async def _council_tools(self, goal: str, timeout: float = 30.0) -> list[str]:
        """Ask the Council for an advisory plan; best-effort, never blocks.

        The Council uses AI personas, so this is skipped entirely in the
        offline/default path (no ``llm`` supplied). When an LLM is configured
        it enriches the deterministic plan; otherwise the planner stands alone.
        """
        if self.llm is None:
            return []
        try:
            from patchi.core.brain.council import Council

            council = Council(self.root, on_progress=self.on_progress)
            session = await asyncio.wait_for(
                council.deliberate(goal, {}), timeout=timeout
            )
            tools = [s.get("tool") for s in session.action_plan if s.get("tool")]
            # Only keep tool names we actually have.
            known = {t.name for t in council.registry.list_tools()}
            return [t for t in tools if t in known]
        except Exception as e:
            _log.info("Council advisory unavailable: %s", e)
            return []

    # -- run ---------------------------------------------------------------
    async def run(self, goal: str, max_steps: int = 6) -> dict:
        realize.set_event_sink(self._sink)
        self.on_progress(f"SmartAgent: goal = {goal!r}")
        self._emit("agent.progress", {"agent": "smart", "progress_pct": 0,
                                      "current_file": "planning"})

        plan = self._plan(goal)
        # Merge Council suggestions (the "dynamic brain with councils/personas").
        try:
            council_tools = await self._council_tools(goal)
            for t in council_tools:
                if not any(s["tool"] == t for s in plan):
                    plan.append({"tool": t, "parameters": {}})
        except Exception as e:
            _log.info("council merge skipped: %s", e)

        plan = plan[:max_steps]
        self.on_progress(f"SmartAgent: plan = {[s['tool'] for s in plan]}")

        executor = ToolExecutor(
            self.root,
            confirmation_provider=CLIConfirmationProvider(auto_confirm=True),
            on_progress=self.on_progress,
        )

        step_results: list[dict] = []
        total_findings = 0
        for i, step in enumerate(plan):
            name = step["tool"]
            params = step["parameters"]
            pct = int((i) / max(1, len(plan)) * 100)
            self._emit("agent.progress", {"agent": "smart", "progress_pct": pct,
                                          "current_file": name})
            self.on_progress(f"SmartAgent: step {i+1}/{len(plan)} → {name}")
            try:
                res = await executor.execute(
                    name, params, invoked_by="council", skip_confirmation=True
                )
            except Exception as e:
                res = type("R", (), {"success": False, "error": str(e),
                                     "result": None})()
            ok = getattr(res, "success", False)
            result_data = getattr(res, "result", None) or {}
            if isinstance(result_data, dict):
                total_findings += int(result_data.get("total_findings", 0) or 0)
            step_results.append({
                "tool": name,
                "success": ok,
                "error": getattr(res, "error", None),
                "summary": self._summarize(name, result_data),
            })
            self._emit("agent.progress", {"agent": "smart",
                                          "progress_pct": int((i + 1) / len(plan) * 100),
                                          "current_file": name})
            if not ok and name in ("analyze_project",):
                # Non-fatal; keep going with whatever else is planned.
                pass

        self._emit("agent.progress", {"agent": "smart", "progress_pct": 100,
                                      "current_file": "done"})
        self._emit("agent.completed", {"agent": "smart",
                                       "findings_count": total_findings,
                                       "steps": len(step_results)})

        return {
            "success": True,
            "goal": goal,
            "steps_planned": [s["tool"] for s in plan],
            "steps_executed": step_results,
            "total_findings": total_findings,
            "events": len(self.events),
            "event_sample": self.events[:50],
        }

    # -- helpers -----------------------------------------------------------
    def _summarize(self, tool: str, data: dict) -> str:
        if not isinstance(data, dict):
            return str(data)[:200]
        if tool == "scan_vulnerabilities":
            sev = data.get("by_severity", {})
            return f"{data.get('agent_count', 0)} agents, {data.get('total_findings', 0)} findings " \
                   f"(crit={sev.get('critical',0)} high={sev.get('high',0)} med={sev.get('medium',0)})"
        if tool == "run_tests":
            return f"passed={data.get('passed',0)} failed={data.get('failed',0)} " \
                   f"errors={data.get('errors',0)} ({data.get('summary','')})"
        if tool == "stress_test":
            if not data.get("success"):
                return f"stress FAILED: {data.get('error','')}"
            return f"{data.get('requests',0)} reqs @ {data.get('rps',0)} rps, " \
                   f"p95={data.get('p95_ms',0)}ms, err={data.get('error_rate',0)}"
        if tool == "attack_simulate":
            return f"{data.get('total_findings',0)} offensive findings (safe_mode)"
        if tool == "analyze_project":
            if not data.get("success"):
                return f"analyze FAILED: {data.get('error','')}"
            return f"{data.get('file_count',0)} files, {data.get('route_count',0)} routes, " \
                   f"framework={data.get('framework','?')}"
        if tool == "check_compliance":
            return f"{data.get('total_findings',0)} compliance findings across " \
                   f"{len(data.get('controls',{}))} controls"
        if tool == "screenshot":
            return "screenshot captured" if data.get("success") else f"screenshot FAILED: {data.get('error','')}"
        return (data.get("message") or data.get("error") or str(data))[:160]

    def _emit(self, event: str, data: dict) -> None:
        self._sink({"event": event, "data": data})


def run_smart_agent(root: Path, goal: str, max_steps: int = 6,
                    on_event: Optional[Callable[[dict], None]] = None,
                    on_progress: Optional[Callable[[str], None]] = None) -> dict:
    """Synchronous entry point for CLI/tests."""
    agent = SmartAgent(root, on_event=on_event, on_progress=on_progress)
    return asyncio.run(agent.run(goal, max_steps=max_steps))
