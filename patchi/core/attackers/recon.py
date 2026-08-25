"""ReconAttacker — test reconnaissance vulnerabilities.

Looks for unprotected endpoints, excess permissions, info disclosure,
and unsanitized data flows.
"""

from __future__ import annotations

from .base import AttackResult, BaseAttacker, Hypothesis


class ReconAttacker(BaseAttacker):
    """Reconnaissance attacker — finds information disclosure and unprotected endpoints."""

    name = "recon"
    objective = "reconnaissance"

    def hypothesize(self) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []

        for claim in self._graph.claims.values():
            # Unprotected endpoints
            if "endpoint" in claim.domain.lower() and "auth" in claim.statement.lower():
                if claim.verdict.value in ("not_proved", "unproven"):
                    hypotheses.append(Hypothesis(
                        attacker=self.name,
                        objective=self.objective,
                        target=claim.id,
                        risk="medium",
                        confidence=0.6,
                        description=f"Endpoint may be unprotected: {claim.statement}",
                        evidence_required=["route scan", "auth check"],
                    ))

            # Excess permissions
            if "permission" in claim.statement.lower() or "access" in claim.statement.lower():
                if claim.verdict.value == "unproven":
                    hypotheses.append(Hypothesis(
                        attacker=self.name,
                        objective=self.objective,
                        target=claim.id,
                        risk="medium",
                        confidence=0.5,
                        description=f"Permission boundary unverified: {claim.statement}",
                        evidence_required=["access control check"],
                    ))

        return hypotheses

    def test(self, hypothesis: Hypothesis) -> AttackResult:
        claim = self._graph.claims.get(hypothesis.target)
        if claim is None:
            return AttackResult(
                hypothesis=hypothesis,
                confirmed=False,
                evidence="Claim not found in assurance graph",
            )

        # Check if any refuting evidence exists (someone already found it's protected)
        refuting = [e for e in claim.evidence if not e.supports]
        if refuting:
            return AttackResult(
                hypothesis=hypothesis,
                confirmed=False,
                evidence=f"Already disproved: {refuting[0].detail}",
            )

        # Check if any supporting evidence exists (someone confirmed it's unprotected)
        supporting = [e for e in claim.evidence if e.supports]
        if supporting:
            return AttackResult(
                hypothesis=hypothesis,
                confirmed=True,
                evidence=f"Confirmed: {supporting[0].detail}",
                severity=hypothesis.risk,
                remediation="Add authentication/authorization check",
            )

        return AttackResult(
            hypothesis=hypothesis,
            confirmed=False,
            evidence="Insufficient evidence to confirm or deny",
        )
