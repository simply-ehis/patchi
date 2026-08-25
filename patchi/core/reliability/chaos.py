"""ChaosScenario — identify chaos engineering opportunities.

Maps data flows and identifies points where failures would cascade,
suggesting chaos experiments to validate resilience.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from patchi.core.assurance.graph import AssuranceGraph

_log = logging.getLogger("patchi.reliability.chaos")


@dataclass
class ChaosExperiment:
    """A suggested chaos experiment."""

    name: str
    target: str  # file or function
    fault_type: str  # "network_partition", "disk_full", "cpu_spike", "memory_pressure"
    description: str
    blast_radius: str  # "low", "medium", "high"
    expected_impact: str
    recovery_check: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "target": self.target,
            "fault_type": self.fault_type,
            "description": self.description,
            "blast_radius": self.blast_radius,
            "expected_impact": self.expected_impact,
            "recovery_check": self.recovery_check,
        }


class ChaosScenario:
    """Analyze the project for chaos engineering opportunities."""

    def __init__(self, root: Path, graph: AssuranceGraph | None = None):
        self._root = root
        self._graph = graph
        self._flows: list[dict] = []

    def load_flows(self, flows: list[dict]) -> None:
        """Load data flows from brain data."""
        self._flows = flows

    def analyze(self, max_experiments: int = 20) -> list[ChaosExperiment]:
        """Generate chaos experiments based on the project's data flows."""
        experiments: list[ChaosExperiment] = []

        # Analyze from graph if available
        if self._graph:
            experiments.extend(self._graph_based_experiments())

        # Analyze from data flows
        experiments.extend(self._flow_based_experiments())

        # General resilience checks
        experiments.extend(self._general_resilience_experiments())

        return experiments[:max_experiments]

    def _graph_based_experiments(self) -> list[ChaosExperiment]:
        """Generate experiments from assurance graph data flows."""
        experiments: list[ChaosExperiment] = []

        # Find critical paths (data flows through auth boundaries)
        for claim in self._graph.claims.values():
            for ev in claim.evidence:
                if not ev.supports:
                    continue
                artifact = ev.artifact
                if "sink" in artifact and "source" in artifact:
                    source = artifact["source"]
                    sink = artifact["sink"]
                    experiments.append(
                        ChaosExperiment(
                            name=f"partition_{source}_to_{sink}",
                            target=source,
                            fault_type="network_partition",
                            description=f"Simulate network partition between {source} and {sink}",
                            blast_radius="medium",
                            expected_impact=f"Requests from {source} to {sink} should timeout gracefully",
                            recovery_check=f"Verify {sink} returns 503 or cached response",
                        )
                    )

        return experiments

    def _flow_based_experiments(self) -> list[ChaosExperiment]:
        """Generate experiments from data flow analysis."""
        experiments: list[ChaosExperiment] = []

        # Group flows by source
        by_source: dict[str, list[dict]] = {}
        for flow in self._flows:
            source = flow.get("source", "unknown")
            by_source.setdefault(source, []).append(flow)

        # For each source with multiple outgoing flows, test dependency failure
        for source, flows in by_source.items():
            if len(flows) >= 2:
                experiments.append(
                    ChaosExperiment(
                        name=f"dependency_failure_{source}",
                        target=source,
                        fault_type="dependency_failure",
                        description=f"Simulate failure of one dependency of {source} (has {len(flows)} outgoing flows)",
                        blast_radius="medium",
                        expected_impact=f"{source} should degrade gracefully when one dependency fails",
                        recovery_check="Verify partial results are returned, not a crash",
                    )
                )

        return experiments

    def _general_resilience_experiments(self) -> list[ChaosExperiment]:
        """Generate general resilience experiments."""
        return [
            ChaosExperiment(
                name="disk_full_on_scan",
                target=".patchi/",
                fault_type="disk_full",
                description="Simulate disk full during scan result persistence",
                blast_radius="low",
                expected_impact="Scan should complete in memory and warn about persistence failure",
                recovery_check="Verify scan results are still available in memory",
            ),
            ChaosExperiment(
                name="memory_pressure_large_project",
                target="scanner",
                fault_type="memory_pressure",
                description="Test scanner behavior with very large file corpus",
                blast_radius="medium",
                expected_impact="Scanner should process files in batches, not load all into memory",
                recovery_check="Verify scan completes without OOM",
            ),
            ChaosExperiment(
                name="database_locked",
                target="history",
                fault_type="database_lock",
                description="Simulate SQLite database locked by another process",
                blast_radius="low",
                expected_impact="History writes should retry or queue, not crash",
                recovery_check="Verify scan completes and results are eventually persisted",
            ),
            ChaosExperiment(
                name="network_timeout_ai",
                target="llm_security_agent",
                fault_type="network_partition",
                description="Simulate AI provider timeout during LLM security analysis",
                blast_radius="low",
                expected_impact="LLM analysis should timeout gracefully, deterministic agents still work",
                recovery_check="Verify deterministic findings are still produced",
            ),
        ]
