from __future__ import annotations

from dataclasses import dataclass, field

from patchi.core.agents.base import Finding


@dataclass
class GatedFinding:
    """A finding with confidence score and routing decision."""

    finding: Finding
    confidence_score: float = 0.0
    confidence_tier: str = "low"
    routing: str = "discard"
    routing_reason: str = ""
    confirmed_by: list[str] = field(default_factory=list)
    composite_score: float = 0.0
    owasp_category: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    domain_controls: list[dict] = field(default_factory=list)
    playbook_ref: str = ""
    fix_strategy: str = ""

    @property
    def should_skip(self) -> bool:
        return self.routing == "discard"

    @property
    def needs_ai(self) -> bool:
        return self.routing == "ai_analyze"

    @property
    def can_defend(self) -> bool:
        return self.routing == "defend"

    @property
    def needs_review(self) -> bool:
        return self.routing == "human_review"

    def to_dict(self) -> dict:
        return {
            "finding": self.finding.to_dict(),
            "confidence_score": self.confidence_score,
            "confidence_tier": self.confidence_tier,
            "routing": self.routing,
            "routing_reason": self.routing_reason,
            "confirmed_by": self.confirmed_by,
            "composite_score": self.composite_score,
            "owasp_category": self.owasp_category,
            "cwe_ids": self.cwe_ids,
            "domain_controls": self.domain_controls,
            "playbook_ref": self.playbook_ref,
            "fix_strategy": self.fix_strategy,
        }


@dataclass
class GatedReport:
    """Output of DetectionPipeline — all findings with routing decisions."""

    findings: list[GatedFinding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    @property
    def defend(self) -> list[GatedFinding]:
        return [f for f in self.findings if f.can_defend]

    @property
    def ai_analyze(self) -> list[GatedFinding]:
        return [f for f in self.findings if f.needs_ai]

    @property
    def human_review(self) -> list[GatedFinding]:
        return [f for f in self.findings if f.needs_review]

    @property
    def discarded(self) -> list[GatedFinding]:
        return [f for f in self.findings if f.should_skip]

    def to_dict(self) -> dict:
        return {
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }
