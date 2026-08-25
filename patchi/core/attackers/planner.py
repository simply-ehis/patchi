"""AttackPlanner — orchestrates all attackers, scores and prioritizes hypotheses."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from patchi.core.assurance.graph import AssuranceGraph

from .api_abuse import ApiAbuseAttacker
from .auth_bypass import AuthBypassAttacker
from .base import AttackResult, BaseAttacker, Hypothesis
from .business_logic import BusinessLogicAttacker
from .priv_escalation import PrivEscAttacker
from .recon import ReconAttacker

_log = logging.getLogger("patchi.core.attackers.planner")

# Objective priority weights (higher = more important to test)
_OBJECTIVE_PRIORITY: dict[str, float] = {
    "authentication_bypass": 1.0,
    "privilege_escalation": 0.9,
    "api_abuse": 0.7,
    "reconnaissance": 0.5,
    "business_logic_abuse": 0.6,
}

_RISK_SCORES: dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.2,
}


@dataclass
class AttackPlan:
    """A prioritized plan of hypotheses to test."""

    hypotheses: list[Hypothesis]
    total_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "hypotheses": [h.to_dict() for h in self.hypotheses[:20]],
            "total_score": round(self.total_score, 2),
            "count": len(self.hypotheses),
        }


class AttackPlanner:
    """Orchestrate all attackers, score hypotheses, and run the top ones."""

    def __init__(self, graph: AssuranceGraph, max_run: int = 50):
        self._graph = graph
        self._max_run = max_run
        self._attackers: list[BaseAttacker] = [
            ReconAttacker(graph),
            AuthBypassAttacker(graph),
            PrivEscAttacker(graph),
            BusinessLogicAttacker(graph),
            ApiAbuseAttacker(graph),
        ]

    def plan(self) -> AttackPlan:
        """Generate and score all hypotheses."""
        all_hypotheses: list[Hypothesis] = []
        for attacker in self._attackers:
            all_hypotheses.extend(attacker.hypothesize())

        # Score and sort
        for h in all_hypotheses:
            h._score = self._score(h)  # type: ignore[attr-defined]

        all_hypotheses.sort(key=lambda h: getattr(h, "_score", 0), reverse=True)
        total = sum(getattr(h, "_score", 0) for h in all_hypotheses)

        return AttackPlan(
            hypotheses=all_hypotheses[: self._max_run],
            total_score=total,
        )

    def run_all(self) -> list[AttackResult]:
        """Run all attackers and collect results."""
        results: list[AttackResult] = []
        for attacker in self._attackers:
            try:
                results.extend(attacker.run())
            except Exception as e:
                _log.warning("Attacker %s failed: %s", attacker.name, e)
        return results

    def run_campaign(self, objective: str) -> list[AttackResult]:
        """Run attackers matching a specific objective."""
        results: list[AttackResult] = []
        for attacker in self._attackers:
            if attacker.objective == objective:
                try:
                    results.extend(attacker.run())
                except Exception as e:
                    _log.warning("Attacker %s failed: %s", attacker.name, e)
        return results

    def _score(self, hypothesis: Hypothesis) -> float:
        """Score a hypothesis by risk × confidence × objective priority."""
        risk = _RISK_SCORES.get(hypothesis.risk, 0.3)
        priority = _OBJECTIVE_PRIORITY.get(hypothesis.objective, 0.3)
        return risk * hypothesis.confidence * priority
