"""ApiAbuseAttacker — test API abuse (injection, rate limiting, info disclosure)."""

from __future__ import annotations

from .base import AttackResult, BaseAttacker, Hypothesis


class ApiAbuseAttacker(BaseAttacker):
    """Tests for injection risks, missing rate limits, information disclosure."""

    name = "api_abuse"
    objective = "api_abuse"

    def hypothesize(self) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []

        for claim in self._graph.claims.values():
            # Injection risks
            if any(kw in claim.statement.lower() for kw in ["inject", "sanitiz", "validat"]):
                if claim.verdict.value in ("not_proved", "unproven"):
                    hypotheses.append(Hypothesis(
                        attacker=self.name,
                        objective=self.objective,
                        target=claim.id,
                        risk="high",
                        confidence=0.7,
                        description=f"Injection risk unverified: {claim.statement}",
                    ))

            # Rate limiting
            if "rate" in claim.statement.lower() and "limit" in claim.statement.lower():
                hypotheses.append(Hypothesis(
                    attacker=self.name,
                    objective=self.objective,
                    target=claim.id,
                    risk="medium",
                    confidence=0.5,
                    description=f"Rate limiting unverified: {claim.statement}",
                ))

            # Information disclosure
            if "error" in claim.statement.lower() and ("detail" in claim.statement.lower() or "disclose" in claim.statement.lower()):
                hypotheses.append(Hypothesis(
                    attacker=self.name,
                    objective=self.objective,
                    target=claim.id,
                    risk="medium",
                    confidence=0.4,
                    description=f"Info disclosure unverified: {claim.statement}",
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
                evidence=f"API protection verified: {refuting[0].detail}",
            )

        supporting = [e for e in claim.evidence if e.supports]
        if supporting:
            return AttackResult(
                hypothesis=hypothesis,
                confirmed=True,
                evidence=f"API abuse confirmed: {supporting[0].detail}",
                severity=hypothesis.risk,
                remediation="Add input validation, rate limiting, or error sanitization",
            )

        return AttackResult(
            hypothesis=hypothesis,
            confirmed=False,
            evidence="Insufficient evidence",
        )
