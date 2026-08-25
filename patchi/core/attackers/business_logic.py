"""BusinessLogicAttacker — test business logic abuse (replay, race conditions)."""

from __future__ import annotations

from .base import AttackResult, BaseAttacker, Hypothesis


class BusinessLogicAttacker(BaseAttacker):
    """Tests for replay attacks, concurrent races, unprotected business flows."""

    name = "business_logic"
    objective = "business_logic_abuse"

    def hypothesize(self) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []

        for claim in self._graph.claims.values():
            # Idempotency concerns
            if "idempoten" in claim.statement.lower():
                if claim.verdict.value in ("not_proved", "unproven"):
                    hypotheses.append(
                        Hypothesis(
                            attacker=self.name,
                            objective=self.objective,
                            target=claim.id,
                            risk="medium",
                            confidence=0.6,
                            description=f"Idempotency unverified: {claim.statement}",
                        )
                    )

            # Race conditions
            if "concurrent" in claim.statement.lower() or "race" in claim.statement.lower():
                hypotheses.append(
                    Hypothesis(
                        attacker=self.name,
                        objective=self.objective,
                        target=claim.id,
                        risk="high",
                        confidence=0.5,
                        description=f"Race condition unverified: {claim.statement}",
                    )
                )

            # State machine integrity
            if "state" in claim.domain.lower() and "transition" in claim.statement.lower():
                if claim.verdict.value == "unproven":
                    hypotheses.append(
                        Hypothesis(
                            attacker=self.name,
                            objective=self.objective,
                            target=claim.id,
                            risk="medium",
                            confidence=0.4,
                            description=f"State machine integrity unverified: {claim.statement}",
                        )
                    )

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
                evidence=f"Business logic verified: {refuting[0].detail}",
            )

        supporting = [e for e in claim.evidence if e.supports]
        if supporting:
            return AttackResult(
                hypothesis=hypothesis,
                confirmed=True,
                evidence=f"Business logic abuse confirmed: {supporting[0].detail}",
                severity=hypothesis.risk,
                remediation="Add idempotency keys, rate limiting, or state guards",
            )

        return AttackResult(
            hypothesis=hypothesis,
            confirmed=False,
            evidence="Insufficient evidence",
        )
