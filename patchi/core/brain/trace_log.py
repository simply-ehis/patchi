"""
Structured logging for agent execution traces.

Provides a lightweight trace logger that records:
  - Agent name, start/end time, duration
  - Input file count, finding count
  - Success/failure status
  - Error messages

Uses loguru if available, falls back to stdlib logging.

Usage:
    from patchi.core.brain.trace_log import trace_agent
    with trace_agent("InjectionAgent", root=path) as trace:
        result = AgentResult()
        agent._run(inp, result)
        trace.findings = len(result.findings)
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from loguru import logger as _logger

    _HAS_LOGURU = True
except ImportError:
    import logging

    _logger = logging.getLogger("patchi.trace")
    _HAS_LOGURU = False


@dataclass
class AgentTrace:
    """Record of a single agent execution."""

    agent_name: str
    root: Path
    start_time: float = 0.0
    end_time: float = 0.0
    duration_ms: int = 0
    files_scanned: int = 0
    findings: int = 0
    status: str = "ok"
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "agent": self.agent_name,
            "root": str(self.root),
            "duration_ms": self.duration_ms,
            "files_scanned": self.files_scanned,
            "findings": self.findings,
            "status": self.status,
            "error": self.error,
            **self.metadata,
        }


_TRACE_LOG: list[AgentTrace] = []


def get_trace_log() -> list[AgentTrace]:
    """Return all recorded traces."""
    return _TRACE_LOG


def clear_trace_log() -> None:
    """Clear the trace log."""
    _TRACE_LOG.clear()


@contextmanager
def trace_agent(agent_name: str, root: Path):
    """Context manager that traces an agent execution."""
    trace = AgentTrace(agent_name=agent_name, root=root)
    trace.start_time = time.perf_counter()
    _TRACE_LOG.append(trace)

    try:
        yield trace
    except Exception as e:
        trace.status = "error"
        trace.error = str(e)
        raise
    finally:
        trace.end_time = time.perf_counter()
        trace.duration_ms = int((trace.end_time - trace.start_time) * 1000)

        if _HAS_LOGURU:
            _logger.debug(
                "agent_trace | {agent} | {duration}ms | {findings} findings | {status}",
                agent=trace.agent_name,
                duration=trace.duration_ms,
                findings=trace.findings,
                status=trace.status,
            )
        else:
            _logger.debug(
                "agent_trace | %s | %dms | %d findings | %s",
                trace.agent_name,
                trace.duration_ms,
                trace.findings,
                trace.status,
            )


def format_trace_summary() -> str:
    """Format a summary of all traces as a table string."""
    if not _TRACE_LOG:
        return "No agent traces recorded."

    lines = ["Agent Trace Summary", "=" * 60]
    total_ms = 0
    total_findings = 0
    for t in _TRACE_LOG:
        total_ms += t.duration_ms
        total_findings += t.findings
        status_icon = "ok" if t.status == "ok" else "FAIL"
        lines.append(f"  {t.agent_name:25s} {t.duration_ms:6d}ms  {t.findings:3d} findings  [{status_icon}]")
    lines.append("-" * 60)
    lines.append(f"  {'TOTAL':25s} {total_ms:6d}ms  {total_findings:3d} findings")
    return "\n".join(lines)
