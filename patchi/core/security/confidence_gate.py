"""
Confidence Gate — scores each finding 0.0–1.0 and routes by tier.

HIGH   >= 0.7  -> defend (auto-fix / block)
MEDIUM >= 0.4  -> ai_analyze (Layer 2 AI confirmation)
LOW    <  0.4  -> human_review (if severe) or discard

Scoring factors (additive):
  + method_precision      regex=0.3, AST=0.5, taint/flow=0.7, deterministic=0.9
  + severity_bonus        high=+0.1, critical=+0.2
  + multi_agent_bonus     +0.1 per confirming agent, max +0.3
  + location_precision    exact line=+0.1, within 5 lines=+0.05
  - known_fp_penalty      -0.3 if matches known false-positive pattern
  - ambiguity_penalty     -0.2 if no code snippet or heuristic match
"""

from __future__ import annotations

import json
from pathlib import Path

from patchi.core.security.gated_finding import GatedFinding, GatedReport
from patchi.core.security.orchestrator import CorrelatedFinding, SecurityReport

# ── Method precision lookup ──────────────────────────────────────────────────

_METHOD_PRECISION: dict[str, float] = {
    "regex": 0.3,
    "ast": 0.5,
    "flow": 0.7,
    "deterministic": 0.9,
}

_SEVERITY_BONUS: dict[str, float] = {
    "critical": 0.2,
    "high": 0.1,
    "medium": 0.0,
    "low": 0.0,
    "info": -0.1,
}


class ConfidenceGate:
    """Scores findings and assigns routing tiers."""

    def __init__(self, root: Path, config: dict | None = None):
        self.root = root
        self.config = config or {}
        self._known_fps: set[tuple] = set()
        self._load_known_fps()

    def _load_known_fps(self) -> None:
        import logging

        _log = logging.getLogger("patchi.confidence_gate")
        fp_path = self.root / ".patchi" / "memory" / "known_false_positives.json"
        if fp_path.exists():
            try:
                data = json.loads(fp_path.read_text(encoding="utf-8"))
                for entry in data:
                    fp_key = (entry.get("file", ""), entry.get("type", ""), entry.get("line", 0))
                    self._known_fps.add(fp_key)
            except Exception as exc:
                _log.warning("Failed to parse known_false_positives.json: %s", exc)

    def gate(self, cf: CorrelatedFinding) -> GatedFinding:
        score = self._compute_score(cf)
        tier = self._assign_tier(score)
        routing = self._assign_routing(tier, cf)
        return GatedFinding(
            finding=cf.finding,
            confidence_score=score,
            confidence_tier=tier,
            routing=routing,
            routing_reason=self._routing_reason(routing, score, cf),
            confirmed_by=cf.confirmed_by,
            composite_score=cf.composite_score,
            owasp_category=cf.owasp_category,
            cwe_ids=cf.cwe_ids,
        )

    def gate_all(self, report: SecurityReport) -> GatedReport:
        gated_list = [self.gate(cf) for cf in report.findings]
        stats = {
            "total": len(gated_list),
            "defend": sum(1 for g in gated_list if g.routing == "defend"),
            "ai_analyze": sum(1 for g in gated_list if g.routing == "ai_analyze"),
            "human_review": sum(1 for g in gated_list if g.routing == "human_review"),
            "discarded": sum(1 for g in gated_list if g.routing == "discard"),
        }
        return GatedReport(findings=gated_list, stats=stats)

    def _compute_score(self, cf: CorrelatedFinding) -> float:
        score = 0.0
        f = cf.finding

        # 1. Method precision — infer from finding metadata
        method = "regex"
        if f.code_snippet and len(f.code_snippet) > 50:
            method = "flow"
        elif f.cwe and f.cwe.strip():
            method = "ast"
        if cf.composite_score >= 70:
            method = "deterministic"
        score += _METHOD_PRECISION.get(method, 0.3)

        # 2. Severity bonus
        score += _SEVERITY_BONUS.get(
            f.severity.value if hasattr(f.severity, "value") else str(f.severity), 0.0
        )

        # 3. Multi-agent confirmation
        confirm_count = len(cf.confirmed_by)
        score += min(confirm_count * 0.1, 0.3)

        # 4. Location precision
        if f.line > 0:
            score += 0.1

        # 5. Known false-positive penalty
        fp_key = (f.file, f.type, f.line)
        if fp_key in self._known_fps:
            score -= 0.3

        # 6. Ambiguity penalty
        if not f.code_snippet:
            score -= 0.2

        return max(0.0, min(1.0, score))

    def _assign_tier(self, score: float) -> str:
        if score >= 0.7:
            return "high"
        if score >= 0.4:
            return "medium"
        if score > 0.0:
            return "low"
        return "low"

    def _assign_routing(self, tier: str, cf: CorrelatedFinding) -> str:
        if tier == "high":
            return "defend"
        if tier == "medium":
            return "ai_analyze"
        sev = cf.finding.severity
        if hasattr(sev, "value"):
            sv = sev.value
        else:
            sv = str(sev)
        if sv in ("critical", "high"):
            return "human_review"
        return "discard"

    def _routing_reason(self, routing: str, score: float, cf: CorrelatedFinding) -> str:
        reasons = {
            "defend": f"High confidence ({score:.2f}) — {len(cf.confirmed_by)} agent(s) confirmed",
            "ai_analyze": f"Medium confidence ({score:.2f}) — needs AI confirmation",
            "human_review": f"Low confidence ({score:.2f}) but severity is {cf.finding.severity} — needs human review",
            "discard": f"Low confidence ({score:.2f}) or known false positive — filtered",
        }
        return reasons.get(routing, f"Routed to {routing} (score={score:.2f})")
