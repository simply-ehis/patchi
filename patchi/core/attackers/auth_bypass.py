"""AuthBypassAttacker — test authentication bypass vulnerabilities."""

from __future__ import annotations

from .base import AttackResult, BaseAttacker, Hypothesis


class AuthBypassAttacker(BaseAttacker):
    """Tests for unauthenticated access, unguarded state transitions, weak auth mechanisms."""

    name = "auth_bypass"
    objective = "authentication_bypass"

    def hypothesize(self) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []

        for claim in self._graph.claims.values():
            if "auth" in claim.domain.lower() or "session" in claim.domain.lower():
                if claim.verdict.value in ("not_proved", "unproven"):
                    hypotheses.append(Hypothesis(
                        attacker=self.name,
                        objective=self.objective,
                        target=claim.id,
                        risk="high",
                        confidence=0.7,
                        description=f"Auth property unverified: {claim.statement}",
                    ))

            # State transitions without auth guards
            if "transition" in claim.statement.lower() and "guard" not in claim.statement.lower():
                hypotheses.append(Hypothesis(
                    attacker=self.name,
                    objective=self.objective,
                    target=claim.id,
                    risk="high",
                    confidence=0.5,
                    description=f"State transition may lack auth guard: {claim.statement}",
                ))

        return hypotheses

    def test(self, hypothesis: Hypothesis) -> AttackResult:
        claim = self._graph.claims.get(hypothesis.target)
        if claim is None:
            return AttackResult(hypothesis=hypothesis, confirmed=False, evidence="Claim not found")

        refuting = [e for e in claim.evidence if not e.supports]
        if refuting:
            return AttackResult(
                hypothesis=hypothesis,
                confirmed=False,
                evidence=f"Auth verified: {refuting[0].detail}",
            )

        supporting = [e for e in claim.evidence if e.supports]
        if supporting:
            return AttackResult(
                hypothesis=hypothesis,
                confirmed=True,
                evidence=f"Auth bypass confirmed: {supporting[0].detail}",
                severity="critical",
                remediation="Add authentication check before this operation",
            )

        return AttackResult(
            hypothesis=hypothesis,
            confirmed=False,
            evidence="Insufficient evidence",
        )
