"""PrivEscAttacker — test privilege escalation vulnerabilities."""

from __future__ import annotations

from .base import AttackResult, BaseAttacker, Hypothesis


class PrivEscAttacker(BaseAttacker):
    """Tests for illegal state transitions, missing isolation, shared endpoints."""

    name = "priv_escalation"
    objective = "privilege_escalation"

    def hypothesize(self) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []

        for claim in self._graph.claims.values():
            # Authorization boundary claims
            if "admin" in claim.statement.lower() or "escalat" in claim.statement.lower():
                if claim.verdict.value in ("not_proved", "unproven"):
                    hypotheses.append(
                        Hypothesis(
                            attacker=self.name,
                            objective=self.objective,
                            target=claim.id,
                            risk="critical",
                            confidence=0.6,
                            description=f"Privilege boundary unverified: {claim.statement}",
                        )
                    )

            # Missing tenant isolation
            if "tenant" in claim.statement.lower() or "isolation" in claim.statement.lower():
                hypotheses.append(
                    Hypothesis(
                        attacker=self.name,
                        objective=self.objective,
                        target=claim.id,
                        risk="critical",
                        confidence=0.7,
                        description=f"Tenant isolation unverified: {claim.statement}",
                    )
                )

            # Shared endpoints with different privilege levels
            if "role" in claim.statement.lower() and "check" in claim.statement.lower():
                if claim.verdict.value == "unproven":
                    hypotheses.append(
                        Hypothesis(
                            attacker=self.name,
                            objective=self.objective,
                            target=claim.id,
                            risk="high",
                            confidence=0.5,
                            description=f"Role-based access unverified: {claim.statement}",
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
                evidence=f"Isolation verified: {refuting[0].detail}",
            )

        supporting = [e for e in claim.evidence if e.supports]
        if supporting:
            return AttackResult(
                hypothesis=hypothesis,
                confirmed=True,
                evidence=f"Privilege escalation confirmed: {supporting[0].detail}",
                severity="critical",
                remediation="Add role/tenant check before this operation",
            )

        return AttackResult(
            hypothesis=hypothesis,
            confirmed=False,
            evidence="Insufficient evidence",
        )
