"""
Agent Coordinator for Patchi.

PRIMARY ENGINE: ThreadPoolExecutor (stdlib, zero extra dependencies).
  - Scanner agents run in parallel (they are all read-only, never conflict).
  - Fix agents always run sequentially (prevents file conflicts).
  - Test agents run on their own independent track.

OPTIONAL LLM COORDINATION:
  When an AI key is configured, the coordinator can ask the LLM which agents
  to prioritise for a given project context. This uses direct httpx calls to
  the configured provider — no third-party orchestration library required.
  Falls back to full parallel execution if no LLM is configured.

Design:
  - Agents are stateless. All state lives in AgentInput / AgentResult.
  - Coordinator never writes to disk.
  - Results always returned as list[AgentResult] regardless of path taken.
  - Progress callback fires after each agent completes.
"""

from __future__ import annotations

# ── Progress event ─────────────────────────────────────────────────────────────
import logging
import queue
import threading
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from loguru import logger

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    list_agents,
)
from patchi.core.agents.cache import AgentCache

_log = logging.getLogger("patchi.agents.coordinator")


def _run_ai_bounded(func, timeout: float):
    """Call `func on a daemon thread, waiting at most `timeout` seconds for it.

    A worker abandoned mid-call (e.g. an LLM call we no longer wait for) must
    never keep the interpreter alive at exit: `concurrent.futures` joins its
    threads at `_python_exit`, so a hung non-daemon worker blocks process
    shutdown indefinitely. A daemon thread + bounded queue get avoids that
    entirely and needs no private executor internals.
    """
    q = queue.Queue(maxsize=1)
    t = threading.Thread(target=lambda f=func: q.put(f()), daemon=True)
    t.start()
    try:
        return q.get(timeout=timeout)
    except Exception:
        return None


@dataclass
class CoordinatorProgress:
    agent_name: str
    status: AgentStatus
    current: int
    total: int
    finding_count: int = 0
    message: str = ""


# ── Coordinator ────────────────────────────────────────────────────────────────


class RunMode:
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    PROCESS = "process"
    AUTO = "auto"


class Coordinator:
    """
    Spawns and collects agent results.

    Usage:
        coord = Coordinator(project_root)
        results = coord.run_group(AgentGroup.SCANNER)
        results = coord.run_agents(["CoreScanner", "EnvScanner"])
    """

    # Circuit breaker — tracks consecutive failures per agent (LIMIT-04)
    # Key: agent_name, Value: consecutive_failures
    # NOTE: Moved to instance-level in __init__ to avoid cross-instance corruption.
    _CB_THRESHOLD = 3

    def __init__(
        self,
        root: Path,
        on_progress: Callable[[CoordinatorProgress], None] | None = None,
        run_mode: str = RunMode.AUTO,
    ):
        self.run_mode = run_mode
        self.root = root
        self.on_progress = on_progress or (lambda _: None)
        self.last_security_report: Any = None
        self._circuit_breaker: dict[str, int] = {}
        self._active_domains: list[str] = []  # git-diff on-demand domains

        try:
            self._config = cfg.load(root)
        except Exception as e:
            _log.warning("Coordinator.__init__ failed: %s", e)
            self._config = {}

        try:
            self._brain = mem.get_brain(root)
        except Exception as e:
            _log.warning("Coordinator.__init__ failed: %s", e)
            self._brain = {}

    def _build_llm(self) -> dict | None:
        """Build LLM config for deep scan analysis.

        Returns ai config dict if an AI provider is available (Ollama, API key,
        or horde fallback), or None if no provider is reachable.

        Used by scan_cmd.py --deep to get a ready-to-use LLM context.
        """
        ai_cfg = self._config.get("ai", {})

        # Local Ollama
        if ai_cfg.get("local_model_name"):
            return {"provider": "ollama", "config": self._config}

        # API keys
        keys = ai_cfg.get("keys", [])
        if keys:
            for k in keys:
                env_var = k.get("env_var", "")
                import os
                if os.environ.get(env_var) or os.environ.get("_PATCHI_ENV_LOADED"):
                    return {"provider": "api", "config": self._config}
            return {"provider": "api", "config": self._config}

        # Horde fallback
        if ai_cfg.get("horde_fallback"):
            return {"provider": "horde", "config": self._config}

        return None

    def reset_circuit_breaker(self, agent_name: str | None = None) -> list[str]:
        """Reset circuit breaker for one or all agents. Returns list of reset names."""
        if agent_name:
            self._circuit_breaker.pop(agent_name, None)
            return [agent_name]
        reset = list(self._circuit_breaker.keys())
        self._circuit_breaker.clear()
        return reset

    @property
    def circuit_broken_agents(self) -> list[str]:
        """Return list of agents currently blocked by circuit breaker."""
        return [
            name
            for name, failures in self._circuit_breaker.items()
            if failures >= self._CB_THRESHOLD
        ]

    def _is_circuit_broken(self, agent_name: str) -> bool:
        return self._circuit_breaker.get(agent_name, 0) >= self._CB_THRESHOLD

    def run_group(
        self,
        group: AgentGroup,
        scope: list[str] | None = None,
        extra: dict | None = None,
    ) -> list[AgentResult]:
        try:
            from patchi.core.security.governance import patchi_action_log

            patchi_action_log(
                self.root,
                "agent_group_start",
                group.value if hasattr(group, "value") else str(group),
                detail=f"scope={len(scope or [])} files",
            )
        except Exception as e:
            _log.warning("Coordinator.run_group failed: %s", e)
        # ── On-demand domain filtering ────────────────────────────────────────
        agent_classes = list_agents(group)
        if self._active_domains:
            try:
                from patchi.core.security.domain_activator_v2 import (
                    DomainActivatorV2,
                )
                activator = DomainActivatorV2(self.root)
                relevant = activator.get_relevant_agents(self._active_domains)
                # Always run core agents (PreCheckAgent, etc.)
                core = ["PreCheckAgent", "PlanAuditorAgent"]
                relevant.extend(core)
                agent_classes = [
                    a for a in agent_classes
                    if getattr(a, "name", "") in relevant
                ]
                _log.info(
                    "Domain filter: %d → %d agents (domains=%s)",
                    len(list_agents(group)), len(agent_classes),
                    self._active_domains[:5],
                )
            except Exception as e:
                _log.debug("Domain filter failed: %s", e)

        results = self._run_classes(agent_classes, scope=scope, extra=extra)

        # Annotate findings with git blame info (all agent groups)
        if self.root and results:
            try:
                from patchi.core.brain.git_aware import annotate_findings_with_blame

                for r in results:
                    if r.findings:
                        annotate_findings_with_blame(r.findings, self.root, max_workers=2)
            except Exception as e:
                _log.warning("Coordinator.run_group failed: %s", e)

        if group == AgentGroup.SECURITY:
            try:
                from patchi.core.security.orchestrator import SecurityOrchestrator

                self.last_security_report = SecurityOrchestrator().correlate(results)
            except Exception as e:
                _log.warning("Coordinator.run_group failed: %s", e)

            # NEW: DetectionPipeline + ConfidenceGate + Defense Layer
            if self._config.get("pipeline", {}).get("enabled", False) and self.last_security_report:
                try:
                    from patchi.core.security.defense_layer import DefenseLayer
                    from patchi.core.security.detection_pipeline import DetectionPipeline

                    pipeline = DetectionPipeline(self.root, self._config)
                    gated = pipeline.process(self.last_security_report)
                    self.last_gated_report = gated
                    if gated.findings:
                        defense = DefenseLayer(self.root, self._config)
                        defend_results = defense.defend_all(gated.defend)
                        self.last_defend_results = defend_results
                except Exception as e:
                    _log.warning("Coordinator.run_group failed: %s", e)
                    import traceback

                    logger.warning(f"Pipeline error: {traceback.format_exc()}")
        return results

    def run_agents(
        self,
        agent_names: list[str],
        scope: list[str] | None = None,
        extra: dict | None = None,
    ) -> list[AgentResult]:
        from patchi.core.agents.base import get_agent

        try:
            from patchi.core.security.governance import patchi_action_log

            patchi_action_log(
                self.root,
                "agent_run_start",
                ",".join(agent_names),
                detail=f"scope={len(scope or [])} files",
            )
        except Exception as e:
            _log.warning("Coordinator.run_agents failed: %s", e)
        classes = [get_agent(n) for n in agent_names if get_agent(n)]
        return self._run_classes(classes, scope=scope, extra=extra)

    # Side file scanner names — excluded when side=False
    _SIDE_SCANNERS = frozenset(
        {
            "SideFileScanner",
            "DependencyScanner",
            "EnvScanner",
            "RouteGraphScanner",
            "CommentScanner",
        }
    )

    def set_active_domains(self, domains: list[str]) -> None:
        """Set domains for on-demand activation (from git diff)."""
        self._active_domains = domains

    def run_all_scanners(
        self, scope: list[str] | None = None, side: bool = True
    ) -> list[AgentResult]:
        if side:
            return self.run_group(AgentGroup.SCANNER, scope=scope)
        # Filter out side scanners — source-only scan
        agents = list_agents(AgentGroup.SCANNER)
        filtered = [a for a in agents if getattr(a, "name", "") not in self._SIDE_SCANNERS]
        return self._run_classes(filtered, scope=scope)

    def _build_input(self, scope: list[str] | None, extra: dict | None) -> AgentInput:
        brain = self._brain or {}
        project_ctx = brain.get("project_context") or {}
        return AgentInput(
            root=self.root,
            scope=scope or [],
            brain=brain,
            config=self._config,
            extra=extra or {},
            purpose=brain.get("project_purpose", "") or project_ctx.get("purpose", ""),
            domain=brain.get("project_domain", "") or project_ctx.get("domain", ""),
            context=project_ctx,
            active_domains=brain.get("active_security_domains", []),
            on_message=None,
        )

    def _maybe_reorder(self, agent_classes: list[type[BaseAgent]]) -> list[type[BaseAgent]]:
        if len(agent_classes) <= 1:
            return agent_classes
        brain = self._brain or {}
        has_security = any(
            getattr(a, "name", "")
            in ("EnvScanner", "SecretScanner", "ConfigAuditAgent", "TaintAnalyzer", "CORSAuditor")
            for a in agent_classes
        )
        if not has_security:
            return agent_classes
        languages = brain.get("languages", {})
        fw_raw = brain.get("frameworks", brain.get("framework", ""))
        if isinstance(fw_raw, list):
            fw_raw = fw_raw[0] if fw_raw else ""
        if isinstance(fw_raw, dict):
            framework = fw_raw.get("name", "") or ""
        elif isinstance(fw_raw, str):
            framework = fw_raw
        else:
            framework = str(fw_raw) if fw_raw else ""

        # Offline scans must never attempt an LLM call — avoid even spawning
        # the bounded worker thread.
        import os
        if os.environ.get("PATCHI_OFFLINE"):
            return agent_classes

        # Cache key: agent set + framework so we only call LLM when something changes
        agent_names_frozen = frozenset(getattr(a, "name", str(a)) for a in agent_classes)
        cache_key = (agent_names_frozen, framework)
        cached = getattr(self, "_reorder_cache", {})
        if cache_key in cached:
            ordered_names = cached[cache_key]
            name_map = {getattr(a, "name", ""): a for a in agent_classes}
            reordered = [name_map[n] for n in ordered_names if n in name_map]
            remaining = [
                a for a in agent_classes if getattr(a, "name", "") not in set(ordered_names)
            ]
            return reordered + remaining

        prompt = (
            f"Project: {languages} files, framework: {framework}\n"
            f"Agents: {', '.join(getattr(a, 'name', str(a)) for a in agent_classes)}\n"
            f"Prioritise critical agents first for this project type. Return ONLY a comma-separated list of agent names in desired order."
        )
        try:
            from patchi.core.ai.client import call_ai

            # Bounded call: an unreachable fallback provider (e.g. AI Horde
            # DNS hang on Windows) must never freeze the scan. Time out and
            # fall back to the original order. The daemon worker thread plus
            # call_ai's own overall timeout mean even a hung provider can
            # never keep the process alive past the 15s bound — not even at
            # interpreter exit, when concurrent.futures joins every non-daemon
            # worker.
            result = _run_ai_bounded(
                lambda: call_ai(
                    self._config,
                    "You are a project analysis coordinator.",
                    prompt,
                    max_tokens=200,
                    timeout=15,
                ),
                timeout=15,
            )

            if result:
                ordered = [n.strip() for n in result.split(",")]
                name_map = {getattr(a, "name", ""): a for a in agent_classes}
                reordered = [name_map[n] for n in ordered if n in name_map]
                remaining = [a for a in agent_classes if getattr(a, "name", "") not in ordered]
                if reordered:
                    # Store in cache
                    if not hasattr(self, "_reorder_cache"):
                        self._reorder_cache: dict = {}
                    self._reorder_cache[cache_key] = ordered
                    return reordered + remaining
        except Exception as e:
            _log.debug("Coordinator._maybe_reorder failed: %s", e)
        return agent_classes

    def _run_classes(
        self,
        agent_classes: list[type[BaseAgent]],
        scope: list[str] | None = None,
        extra: dict | None = None,
    ) -> list[AgentResult]:
        if not agent_classes:
            return []

        agent_classes = self._maybe_reorder(agent_classes)
        # Filter out circuit-broken agents (LIMIT-04)
        filtered = []
        for cls in agent_classes:
            name = getattr(cls, "name", str(cls))
            if self._is_circuit_broken(name):
                continue
            filtered.append(cls)
        agent_classes = filtered

        # Init agent result cache
        cache = AgentCache(self.root)
        use_cache = not self._config.get("pipeline", {}).get("no_agent_cache", False)

        inp = self._build_input(scope, extra)
        total = len(agent_classes)
        completed = [0]

        def on_done(result: AgentResult) -> None:
            completed[0] += 1
            self.on_progress(
                CoordinatorProgress(
                    agent_name=result.agent_name,
                    status=result.status,
                    current=completed[0],
                    total=total,
                    finding_count=result.finding_count,
                )
            )
            # Update circuit breaker (LIMIT-04)
            if result.status == AgentStatus.FAILED:
                self._circuit_breaker[result.agent_name] = (
                    self._circuit_breaker.get(result.agent_name, 0) + 1
                )
            else:
                self._circuit_breaker[result.agent_name] = 0  # Reset on success
            try:
                mem.save_scan_result(
                    result.agent_name,
                    {
                        "status": result.status.value,
                        "duration_ms": result.duration_ms,
                        "finding_count": result.finding_count,
                        "files_scanned": result.files_scanned,
                        "errors": result.errors[:3],
                        "findings": [f.to_dict() for f in result.findings],
                        "circuit_broken": self._is_circuit_broken(result.agent_name),
                    },
                    self.root,
                )
                from patchi.core.security.governance import patchi_action_log

                patchi_action_log(
                    self.root,
                    "agent_complete",
                    result.agent_name,
                    agent=result.agent_name,
                    detail=f"{result.finding_count} findings, {result.duration_ms}ms",
                    status="ok" if result.status == AgentStatus.DONE else "error",
                )
            except Exception as e:
                _log.warning("Coordinator.on_done failed: %s", e)

        # Check cache for each agent — skip if valid cached result exists
        agent_classes_run: list[type[BaseAgent]] = []
        cached_results: list[AgentResult] = []

        if use_cache:
            for cls in agent_classes:
                cached = cache.get(cls.name)
                if cached is not None:
                    cached_results.append(cached)
                    on_done(cached)
                else:
                    agent_classes_run.append(cls)
        else:
            agent_classes_run = list(agent_classes)

        if not agent_classes_run:
            return cached_results

        has_fix_agents = any(a.group == AgentGroup.FIX for a in agent_classes_run)
        if has_fix_agents:
            # Fix agents always run sequentially (spec: non-negotiable)
            run_results = _run_sequential(agent_classes_run, inp, on_done)
        elif getattr(self, "run_mode", RunMode.AUTO) == RunMode.SEQUENTIAL:
            run_results = _run_sequential(agent_classes_run, inp, on_done)
        elif getattr(self, "run_mode", RunMode.AUTO) == RunMode.PROCESS:
            run_results = _run_process_parallel(
                agent_classes_run, inp, on_done, self._config, self.root
            )
        else:
            run_results = _run_parallel(agent_classes_run, inp, on_done, self._config)

        # Store results in cache
        if use_cache:
            for r in run_results:
                cache.put(r.agent_name, r)

        return cached_results + run_results


# ── Execution engines ──────────────────────────────────────────────────────────


def _run_parallel(
    agent_classes: list[type[BaseAgent]],
    inp: AgentInput,
    on_done: Callable[[AgentResult], None],
    config: dict,
) -> list[AgentResult]:
    """ThreadPoolExecutor — I/O-bound agents benefit from threads."""
    device_tier = config.get("device_tier", "mid")
    from patchi.core.constants import DeviceTier

    try:
        max_workers = DeviceTier(device_tier).max_parallel_agents()
    except ValueError:
        max_workers = 8

    results: list[AgentResult] = []
    futures: dict[Future, str] = {}
    # Per-agent timeouts from agent class attribute (LIMIT-04)
    timeout_map: dict[Future, int] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for cls in agent_classes:
            agent_timeout = getattr(cls, "timeout", 120)
            future = executor.submit(_run_agent_safe, cls(), inp)
            futures[future] = cls.name
            timeout_map[future] = agent_timeout

        for future in as_completed(futures):
            agent_timeout = timeout_map.get(future, 120)
            try:
                result = future.result(timeout=agent_timeout)
            except Exception as e:
                result = AgentResult(
                    agent_name=futures[future],
                    agent_group=AgentGroup.SCANNER,
                    status=AgentStatus.FAILED,
                    errors=[f"Coordinator caught: {e}"],
                )
            on_done(result)
            results.append(result)

    return results


def _process_worker_init(cache: Any) -> None:
    """ProcessPoolExecutor initializer — runs in EACH worker before any task.

    Installs the parent-built ScanCache as the shared read-only scan cache for
    this worker (one walk in the parent replaces N parallel re-walks), and
    resets the parse-once tree cache so every worker starts cold with a
    bounded, per-process tree cache.
    """
    try:
        from patchi.core.agents.scan_cache import activate_worker_cache

        activate_worker_cache(cache)
    except Exception as e:
        _log.warning("Coordinator._process_worker_init failed: %s", e)


def _process_worker_run(cls: Any, inp: AgentInput) -> AgentResult:
    """Module-level worker task: instantiate the agent and run it safely.

    Module-level so Windows spawn can pickle it by reference. Agent classes
    pickle by qualified name; AgentInput/AgentResult are plain dataclasses.
    """
    try:
        return _run_agent_safe(cls(), inp)
    except Exception as e:
        return AgentResult(
            agent_name=getattr(cls, "name", str(cls)),
            agent_group=getattr(cls, "group", AgentGroup.SCANNER),
            status=AgentStatus.FAILED,
            errors=[f"Process worker failed: {e}"],
        )


def _run_process_parallel(
    agent_classes: list[type[BaseAgent]],
    inp: AgentInput,
    on_done: Callable[[AgentResult], None],
    config: dict,
    root: Path,
) -> list[AgentResult]:
    """ProcessPoolExecutor fanout — CPU-bound agents scale past the GIL.

    The parent builds the shared read-only ScanCache exactly once (one
    filesystem walk + content hashes) and hands the same immutable listing to
    every worker's initializer; per-worker parse results are deduplicated by
    languages.parse_source's content-hash cache. This is the "single-pass
    scan" extended across processes.

    Falls back to the thread pool on any pool-setup failure (spawn-pickle
    edge cases, interactive interpreters without a __main__ guard, exotic
    environments) — the process pool is a performance mode, never a
    correctness fork. Fix agents never take this path (sequencing is
    non-negotiable).
    """
    device_tier = config.get("device_tier", "mid")
    from patchi.core.constants import DeviceTier

    try:
        max_workers = DeviceTier(device_tier).max_parallel_agents()
    except ValueError:
        max_workers = 8
    max_workers = max(1, min(max_workers, 8))

    try:
        from concurrent.futures import ProcessPoolExecutor

        from patchi.core.agents.scan_cache import build_scan_cache

        cache = build_scan_cache(root)
    except Exception as e:
        _log.warning("Coordinator process pool unavailable (%s) - using threads", e)
        return _run_parallel(agent_classes, inp, on_done, config)

    results: list[AgentResult] = []
    try:
        with ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=_process_worker_init,
            initargs=(cache,),
        ) as executor:
            futures: dict[Future, str] = {}
            timeout_map: dict[Future, int] = {}
            for cls in agent_classes:
                agent_timeout = getattr(cls, "timeout", 120)
                future = executor.submit(_process_worker_run, cls, inp)
                futures[future] = cls.name
                timeout_map[future] = agent_timeout

            for future in as_completed(futures):
                agent_timeout = timeout_map.get(future, 120)
                try:
                    result = future.result(timeout=agent_timeout)
                except Exception as e:
                    result = AgentResult(
                        agent_name=futures[future],
                        agent_group=AgentGroup.SCANNER,
                        status=AgentStatus.FAILED,
                        errors=[f"Coordinator caught: {e}"],
                    )
                on_done(result)
                results.append(result)
    except Exception as e:
        _log.warning("Coordinator process pool crashed (%s) - falling back to threads", e)
        return _run_parallel(agent_classes, inp, on_done, config)

    return results


def _run_fix_agents_batched(
    agent_classes: list[type[BaseAgent]],
    inp: AgentInput,
    on_done: Callable[[AgentResult], None],
    config: dict,
) -> list[AgentResult]:
    """Run fix agents with file-based batching.

    Agents targeting different files run in parallel.
    Agents targeting the same file run sequentially.
    """
    device_tier = config.get("device_tier", "mid")
    from patchi.core.constants import DeviceTier

    try:
        max_workers = DeviceTier(device_tier).max_parallel_agents()
    except ValueError:
        max_workers = 8

    batches = _group_fix_agents_by_file(agent_classes)

    if len(batches) <= 1:
        return _run_sequential(agent_classes, inp, on_done)

    results: list[AgentResult] = []

    with ThreadPoolExecutor(max_workers=min(max_workers, len(batches))) as executor:
        batch_futures: dict[Future, list[str]] = {}
        for batch in batches:
            future = executor.submit(_run_sequential, batch, inp, on_done)
            batch_futures[future] = [c.name for c in batch]

        for future in as_completed(batch_futures):
            try:
                batch_results = future.result(timeout=300)
                results.extend(batch_results)
            except Exception as e:
                for name in batch_futures[future]:
                    results.append(
                        AgentResult(
                            agent_name=name,
                            agent_group=AgentGroup.FIX,
                            status=AgentStatus.FAILED,
                            errors=[f"Batch failed: {e}"],
                        )
                    )

    return results


def _group_fix_agents_by_file(
    agent_classes: list[type[BaseAgent]],
) -> list[list[type[BaseAgent]]]:
    """Group fix agents by their declared target files.

    Agents that declare overlapping target files are placed in the same batch
    (must run sequentially). Agents targeting different files go into separate
    batches (can run in parallel).

    Each agent class may define a ``target_files()`` classmethod returning
    ``list[str]`` of relative file paths it operates on.  If no agent declares
    targets, every agent gets its own batch (optimistic parallelism).
    """
    file_map: dict[str, list[type[BaseAgent]]] = defaultdict(list)
    ungrouped: list[type[BaseAgent]] = []

    for cls in agent_classes:
        target_files_fn = getattr(cls, "target_files", None)
        if callable(target_files_fn):
            try:
                files = list(target_files_fn())
            except Exception as e:
                _log.warning("_group_fix_agents_by_file failed: %s", e)
                ungrouped.append(cls)
                continue
        else:
            ungrouped.append(cls)
            continue

        if not files:
            ungrouped.append(cls)
            continue

        key = tuple(sorted(files))
        file_map[key].append(cls)

    batches: list[list[type[BaseAgent]]] = list(file_map.values())

    # Ungrouped agents each get their own batch (can run in parallel with others)
    for cls in ungrouped:
        batches.append([cls])

    return batches if batches else [[c for c in agent_classes]]


def _run_sequential(
    agent_classes: list[type[BaseAgent]],
    inp: AgentInput,
    on_done: Callable[[AgentResult], None],
) -> list[AgentResult]:
    results: list[AgentResult] = []
    for cls in agent_classes:
        result = _run_agent_safe(cls(), inp)
        on_done(result)
        results.append(result)
    return results


def _run_agent_safe(agent: BaseAgent, inp: AgentInput) -> AgentResult:
    try:
        return agent.run(inp)
    except Exception as e:
        return AgentResult(
            agent_name=agent.name,
            agent_group=agent.group,
            status=AgentStatus.FAILED,
            errors=[f"Unhandled: {e}"],
        )


# ── Merge helper ───────────────────────────────────────────────────────────────


def merge_results(results: list[AgentResult]) -> dict:
    all_findings: list[Finding] = []
    all_data: dict[str, Any] = {}
    errors: list[str] = []
    total_files = 0
    total_ms = 0

    for r in results:
        all_findings.extend(r.findings)
        all_data[r.agent_name] = r.data
        errors.extend(r.errors)
        total_files += r.files_scanned
        total_ms += r.duration_ms

    all_findings.sort(key=lambda f: (f.severity.sort_key(), f.file, f.line))

    return {
        "findings": [f.to_dict() for f in all_findings],
        "by_agent": all_data,
        "total_findings": len(all_findings),
        "total_files": total_files,
        "total_ms": total_ms,
        "agent_count": len(results),
        "errors": errors,
    }
