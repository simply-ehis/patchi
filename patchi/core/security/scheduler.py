"""
ScanScheduler — configurable periodic execution of Layer 1 detectors.

Config:
  {
    "pipeline": {
      "scheduler": {
        "enabled": true,
        "intervals": {
          "default": "1h",
          "overrides": {
            "SecretScanner": "5m",
            "CVEMonitorAgent": "30m",
            "DependencyScanner": "24h",
            "EnvScanner": "15m"
          }
        }
      }
    }
  }

The scheduler runs a background thread that checks due detectors every 60s.
Results persist to the existing SQLite history database.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.agents.base import AgentGroup, AgentInput, BaseAgent, list_agents

_log = logging.getLogger("patchi.security.scheduler")


def _parse_interval(s: str) -> int:
    """Parse interval string like '5m', '1h', '30s' into seconds."""
    s = s.strip().lower()
    m = re.match(r"^(\d+)\s*(s|m|h|d)$", s)
    if not m:
        logger.warning("Invalid interval '%s' — defaulting to 1h", s)
        return 3600  # default 1h
    val = int(m.group(1))
    unit = m.group(2)
    return {"s": val, "m": val * 60, "h": val * 3600, "d": val * 86400}[unit]


@dataclass
class ScheduledAgent:
    """A scheduled agent with its interval and last-run tracking."""

    name: str
    agent_cls: type[BaseAgent]
    interval_sec: int
    last_run: float = 0.0  # time.monotonic()
    consecutive_failures: int = 0
    enabled: bool = True


@dataclass
class ScheduleResult:
    """Result of a scheduled scan run."""

    agent_name: str
    status: str  # "started" | "completed" | "skipped" | "failed"
    duration_ms: int = 0
    message: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class ScanScheduler:
    """
    Configurable periodic scanner execution.

    Usage:
        scheduler = ScanScheduler(root, config)
        scheduler.start()           # runs in background thread
        scheduler.stop()            # stops background thread
        scheduler.run_due()         # manually check and run due agents
    """

    def __init__(
        self,
        root: Path,
        config: dict | None = None,
        on_result: Callable[[ScheduleResult], None] | None = None,
    ):
        self.root = root
        self.config = config or cfg.load(root)
        self.on_result = on_result or (lambda r: None)

        scheduler_cfg = self.config.get("pipeline", {}).get("scheduler", {})
        self.enabled = scheduler_cfg.get("enabled", False)
        intervals = scheduler_cfg.get("intervals", {})
        default_interval = intervals.get("default", "1h")
        overrides = intervals.get("overrides", {})

        # Build schedule from registered SECURITY + SCANNER agents
        self._agents: list[ScheduledAgent] = []
        for cls in list_agents(AgentGroup.SECURITY):
            name = getattr(cls, "name", str(cls))
            interval = overrides.get(name, default_interval)
            self._agents.append(
                ScheduledAgent(
                    name=name,
                    agent_cls=cls,
                    interval_sec=_parse_interval(interval),
                )
            )
        for cls in list_agents(AgentGroup.SCANNER):
            name = getattr(cls, "name", str(cls))
            interval = overrides.get(name, default_interval)
            self._agents.append(
                ScheduledAgent(
                    name=name,
                    agent_cls=cls,
                    interval_sec=_parse_interval(interval),
                )
            )

        # Background thread state
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the scheduler background thread."""
        if not self.enabled:
            logger.info("ScanScheduler is disabled (pipeline.scheduler.enabled=false)")
            return
        if self._thread and self._thread.is_alive():
            logger.warning("ScanScheduler already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="ScanScheduler")
        self._thread.start()
        logger.info(f"ScanScheduler started with {len(self._agents)} agents")

    def stop(self) -> None:
        """Stop the scheduler background thread."""
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            self._thread.join(timeout=5)
            logger.info("ScanScheduler stopped")

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Core loop ─────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Background loop: check due agents every 60s."""
        while not self._stop_event.is_set():
            try:
                self.run_due()
            except Exception as e:
                logger.error(f"ScanScheduler error: {e}")
            self._stop_event.wait(60)

    def run_due(self) -> list[ScheduleResult]:
        """Run all agents whose interval has elapsed. Returns results."""
        results: list[ScheduleResult] = []
        now = time.monotonic()

        with self._lock:
            due = [a for a in self._agents if a.enabled and (now - a.last_run) >= a.interval_sec]

        for agent in due:
            result = self._run_agent(agent)
            results.append(result)
            self.on_result(result)

            with self._lock:
                if result.status == "completed":
                    agent.last_run = now
                    agent.consecutive_failures = 0
                elif result.status == "failed":
                    agent.consecutive_failures += 1
                    if agent.consecutive_failures >= 3:
                        agent.enabled = False
                        logger.warning(f"Agent {agent.name} disabled after 3 consecutive failures")

        return results

    # ── Single agent run ──────────────────────────────────────────────────

    def _build_input(self) -> AgentInput:
        try:
            brain = mem.get_brain(self.root)
        except Exception as e:
            _log.warning("ScanScheduler._build_input failed: %s", e)
            brain = {}
        return AgentInput(
            root=self.root,
            scope=[],
            brain=brain,
            config=self.config,
            extra={"source": "scheduler"},
        )

    def _run_agent(self, agent: ScheduledAgent) -> ScheduleResult:
        """Run a single scheduled agent and return the result."""
        logger.debug(f"Running scheduled agent: {agent.name}")
        inp = self._build_input()
        instance = agent.agent_cls()
        t0 = time.monotonic()

        try:
            result = instance.run(inp)
            dur = int((time.monotonic() - t0) * 1000)

            # Save result to history
            try:
                mem.save_scan_result(
                    agent.name,
                    {
                        "status": result.status.value if hasattr(result.status, "value") else str(result.status),
                        "duration_ms": dur,
                        "finding_count": len(result.findings),
                        "files_scanned": result.files_scanned,
                        "source": "scheduler",
                    },
                    self.root,
                )
            except Exception as e:
                _log.warning("ScanScheduler._run_agent failed: %s", e)

            status = "completed" if result.status.value in ("done", "succeeded") else "failed"
            msg = f"{len(result.findings)} findings, {result.files_scanned} files in {dur}ms"
            if result.errors:
                msg += f" ({len(result.errors)} errors)"

            return ScheduleResult(
                agent_name=agent.name,
                status=status,
                duration_ms=dur,
                message=msg,
            )

        except Exception as e:
            dur = int((time.monotonic() - t0) * 1000)
            return ScheduleResult(
                agent_name=agent.name,
                status="failed",
                duration_ms=dur,
                message=f"Unhandled error: {e}",
            )

    # ── Status / introspection ────────────────────────────────────────────

    def status(self) -> dict:
        """Return scheduler status for dashboard."""
        now = time.monotonic()
        with self._lock:
            agents = []
            for a in self._agents:
                next_run = max(0.0, a.interval_sec - (now - a.last_run))
                agents.append(
                    {
                        "name": a.name,
                        "interval_sec": a.interval_sec,
                        "next_run_sec": int(next_run),
                        "enabled": a.enabled,
                        "consecutive_failures": a.consecutive_failures,
                    }
                )
        return {
            "enabled": self.enabled,
            "running": self.is_running,
            "agent_count": len(agents),
            "agents": agents,
        }
