"""Tests for ScanBus QueueRunner + FindingBus merge (Scan Bus P2)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
)
from patchi.core.scan_bus import FindingBus, QueueRunner, ScanBus


def _inp(root: Path) -> AgentInput:
    return AgentInput(root=root, scope=[], brain={}, config={})


def _finding(agent: str, n: int) -> Finding:
    return Finding(
        agent=agent, type="t", severity=Severity.LOW, file=f"f{n}.py", message="m"
    )


class _FastAgent(BaseAgent):
    name = "BusFastAgent"
    group = AgentGroup.SCANNER

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        result.findings.append(_finding(self.name, 1))
        result.findings.append(_finding(self.name, 2))


class _SlowFailAgent(BaseAgent):
    name = "BusFailAgent"
    group = AgentGroup.SCANNER

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        raise RuntimeError("boom")


def test_runner_runs_all_and_merges_via_bus(tmp_path: Path):
    bus = ScanBus(tmp_path, shard_count=2)
    runner = QueueRunner(bus)
    done: list[str] = []
    results = runner.run(
        [_FastAgent, _FastAgent],
        lambda cls: cls().run(_inp(tmp_path)),
        lambda r: done.append(r.agent_name),
    )
    assert len(results) == 2
    assert len(done) == 2
    assert runner.finding_bus.count == 4
    assert len(runner.drain()) == 4
    assert runner.drain() == []  # drain empties


def test_runner_failure_becomes_failed_result_not_crash(tmp_path: Path):
    runner = QueueRunner(ScanBus(tmp_path, shard_count=2))
    results = runner.run(
        [_SlowFailAgent], lambda cls: cls().run(_inp(tmp_path)), lambda r: None
    )
    assert results[0].status == AgentStatus.FAILED
    assert runner.finding_bus.count == 0


def test_finding_bus_count_is_thread_safe(tmp_path: Path):
    import threading

    fb = FindingBus()
    ts = [threading.Thread(target=lambda: [fb.publish(i) for i in range(50)]) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert fb.count == 200
    assert len(fb.drain()) == 200


def test_coordinator_scan_bus_path_matches_parallel(tmp_path: Path):
    from patchi.core.agents.coordinator import _run_agent_safe, _run_scan_bus

    inp = _inp(tmp_path)
    seen: list[str] = []
    results = _run_scan_bus(
        [_FastAgent], inp, lambda r: seen.append(r.agent_name), {}, tmp_path
    )
    assert len(results) == 1
    assert results[0].finding_count == 2
    assert seen == ["BusFastAgent"]
    assert inp.extra["finding_bus"].count == 2
    assert _run_agent_safe(_FastAgent(), inp).finding_count == 2


def test_registered_fake_agents_do_not_leak():
    from patchi.core.agents.base import _REGISTRY

    assert "BusFastAgent" not in _REGISTRY  # never @register-ed
