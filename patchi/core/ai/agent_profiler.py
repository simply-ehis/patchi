"""
Agent Profiler — self-profiling for latency, cost, and accuracy optimization.

Tracks per-agent execution metrics across scan cycles:
  - Latency (wall time, p50/p95)
  - Token cost (input/output tokens, dollar estimate)
  - Accuracy (true-positive rate based on accept/reject feedback)
  - Memory usage (peak RSS)

Feeds into the ModelRouter to prefer faster/cheaper agents when accuracy
is equivalent, and into the Coordinator to schedule agents intelligently.

All data persisted to .patchi/agent_profile.json.
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

_log = logging.getLogger("patchi.ai.agent_profiler")

_PROFILE_FILE = ".patchi/agent_profile.json"
_MAX_ENTRIES_PER_AGENT = 200


@dataclass
class AgentRun:
    """One recorded execution of an agent."""
    agent: str
    start_time: float = 0.0
    end_time: float = 0.0
    wall_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    files_scanned: int = 0
    findings_produced: int = 0
    accepted: int = 0
    rejected: int = 0
    model_used: str = ""
    peak_rss_mb: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AgentRun":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class AgentProfile:
    """Aggregated profile for one agent across all recorded runs."""
    agent: str
    run_count: int = 0
    total_wall_ms: float = 0.0
    p50_wall_ms: float = 0.0
    p95_wall_ms: float = 0.0
    total_cost_usd: float = 0.0
    total_findings: int = 0
    total_accepted: int = 0
    total_rejected: int = 0
    accuracy: float = 0.5  # accept / (accept + reject), 0.5 when unknown
    avg_findings_per_run: float = 0.0
    most_used_model: str = ""
    last_run: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def _load(root: Path) -> dict[str, list[dict]]:
    path = root / _PROFILE_FILE
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        _log.warning("Failed to load agent profile: %s", exc)
        return {}


def _save(root: Path, data: dict[str, list[dict]]) -> None:
    path = root / _PROFILE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


@contextmanager
def record_run(
    root: Path,
    agent: str,
    *,
    model: str = "",
    files_scanned: int = 0,
):
    """Context manager that records an agent execution.

    Usage::

        with record_run(root, "auth_agent", model="gpt-4o-mini") as run:
            findings = run_agent(...)
            run.findings_produced = len(findings)
    """
    import resource

    run = AgentRun(
        agent=agent,
        start_time=time.time(),
        model_used=model,
        files_scanned=files_scanned,
    )
    try:
        yield run
    except Exception as exc:
        run.error = str(exc)[:200]
        raise
    finally:
        run.end_time = time.time()
        run.wall_ms = (run.end_time - run.start_time) * 1000
        # Peak RSS (Linux/macOS only; returns 0 on Windows)
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            run.peak_rss_mb = usage.ru_maxrss / 1024  # KB → MB
        except Exception:
            pass
        _persist_run(root, run)


def _persist_run(root: Path, run: AgentRun) -> None:
    data = _load(root)
    runs = data.setdefault(run.agent, [])
    runs.append(run.to_dict())
    # Trim to last N entries
    data[run.agent] = runs[-_MAX_ENTRIES_PER_AGENT:]
    _save(root, data)
    _log.debug(
        "Recorded %s: %.0fms, %d findings, $%.4f",
        run.agent, run.wall_ms, run.findings_produced, run.cost_usd,
    )


def record_tokens(root: Path, agent: str, prompt_tokens: int, completion_tokens: int) -> None:
    """Update the last run for an agent with token counts (call after LLM usage)."""
    data = _load(root)
    runs = data.get(agent, [])
    if not runs:
        return
    last = runs[-1]
    last["prompt_tokens"] = prompt_tokens
    last["completion_tokens"] = completion_tokens
    # Estimate cost from cost_tracker's per-model rates
    model = last.get("model_used", "gpt-4o-mini")
    try:
        from patchi.core.ai.model_router import MODEL_PROFILES
        profile = MODEL_PROFILES.get(model)
        if profile:
            last["cost_usd"] = (
                prompt_tokens * profile.cost_per_1k_input / 1000
                + completion_tokens * profile.cost_per_1k_output / 1000
            )
    except Exception:
        pass
    _save(root, data)


def record_outcome(root: Path, agent: str, accepted: int, rejected: int) -> None:
    """Update the last run for an agent with accept/reject counts."""
    data = _load(root)
    runs = data.get(agent, [])
    if not runs:
        return
    last = runs[-1]
    last["accepted"] = accepted
    last["rejected"] = rejected
    _save(root, data)


def get_profile(root: Path, agent: str) -> AgentProfile:
    """Get aggregated profile for one agent."""
    data = _load(root)
    runs = [AgentRun.from_dict(r) for r in data.get(agent, [])]
    if not runs:
        return AgentProfile(agent=agent)

    walls = sorted(r.wall_ms for r in runs)
    n = len(walls)
    total_acc = sum(r.accepted for r in runs)
    total_rej = sum(r.rejected for r in runs)
    total = total_acc + total_rej

    # Most used model
    models = [r.model_used for r in runs if r.model_used]
    most_used = max(set(models), key=models.count) if models else ""

    return AgentProfile(
        agent=agent,
        run_count=n,
        total_wall_ms=sum(walls),
        p50_wall_ms=walls[n // 2] if n else 0,
        p95_wall_ms=walls[int(n * 0.95)] if n else 0,
        total_cost_usd=sum(r.cost_usd for r in runs),
        total_findings=sum(r.findings_produced for r in runs),
        total_accepted=total_acc,
        total_rejected=total_rej,
        accuracy=total_acc / total if total >= 3 else 0.5,
        avg_findings_per_run=sum(r.findings_produced for r in runs) / n,
        most_used_model=most_used,
        last_run=max(r.end_time for r in runs),
    )


def get_all_profiles(root: Path) -> dict[str, AgentProfile]:
    """Get profiles for all agents."""
    data = _load(root)
    return {agent: get_profile(root, agent) for agent in data}


def get_slowest_agents(root: Path, limit: int = 10) -> list[AgentProfile]:
    """Return the slowest agents by p95 wall time."""
    profiles = get_all_profiles(root)
    ranked = sorted(profiles.values(), key=lambda p: -p.p95_wall_ms)
    return ranked[:limit]


def get_least_accurate(root: Path, min_runs: int = 5) -> list[AgentProfile]:
    """Return agents with the worst accuracy (above minimum sample size)."""
    profiles = get_all_profiles(root)
    ranked = sorted(
        [p for p in profiles.values() if p.run_count >= min_runs],
        key=lambda p: p.accuracy,
    )
    return ranked


def get_profile_summary(root: Path) -> dict:
    """Summary for display."""
    profiles = get_all_profiles(root)
    if not profiles:
        return {"agents": 0, "total_runs": 0, "total_cost": 0}
    return {
        "agents": len(profiles),
        "total_runs": sum(p.run_count for p in profiles.values()),
        "total_cost": round(sum(p.total_cost_usd for p in profiles.values()), 4),
        "total_findings": sum(p.total_findings for p in profiles.values()),
        "avg_accuracy": round(
            sum(p.accuracy for p in profiles.values() if p.run_count >= 3)
            / max(1, sum(1 for p in profiles.values() if p.run_count >= 3)),
            3,
        ),
        "slowest": [
            {"agent": p.agent, "p95_ms": round(p.p95_wall_ms)}
            for p in get_slowest_agents(root, 5)
        ],
    }
