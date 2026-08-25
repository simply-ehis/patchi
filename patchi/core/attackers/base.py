"""Base attacker — shared types and ABC for adversarial personalities."""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field

from patchi.core.assurance.graph import AssuranceGraph

_log = logging.getLogger("patchi.core.attackers")


@dataclass
class Hypothesis:
    """An attacker's hypothesis about where a vulnerability exists."""

    attacker: str
    objective: str
    target: str  # file, endpoint, or state
    risk: str  # "critical", "high", "medium", "low"
    confidence: float  # 0.0–1.0
    description: str = ""
    evidence_required: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "attacker": self.attacker,
            "objective": self.objective,
            "target": self.target,
            "risk": self.risk,
            "confidence": self.confidence,
            "description": self.description,
        }


@dataclass
class AttackResult:
    """Result of testing a hypothesis."""

    hypothesis: Hypothesis
    confirmed: bool
    evidence: str = ""
    severity: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "hypothesis": self.hypothesis.to_dict(),
            "confirmed": self.confirmed,
            "evidence": self.evidence,
            "severity": self.severity,
            "remediation": self.remediation,
        }


class BaseAttacker(abc.ABC):
    """Base class for adversarial personalities."""

    name: str = "base"
    objective: str = "unknown"

    def __init__(self, graph: AssuranceGraph):
        self._graph = graph

    @abc.abstractmethod
    def hypothesize(self) -> list[Hypothesis]:
        """Generate hypotheses about where vulnerabilities might exist."""

    @abc.abstractmethod
    def test(self, hypothesis: Hypothesis) -> AttackResult:
        """Test a specific hypothesis."""

    def run(self) -> list[AttackResult]:
        """Generate and test all hypotheses."""
        hypotheses = self.hypothesize()
        results: list[AttackResult] = []
        for h in hypotheses:
            try:
                result = self.test(h)
                results.append(result)
            except Exception as e:
                _log.warning("Attacker %s failed testing %s: %s", self.name, h.target, e)
                results.append(AttackResult(
                    hypothesis=h,
                    confirmed=False,
                    evidence=f"Test error: {e}",
                ))
        return results
