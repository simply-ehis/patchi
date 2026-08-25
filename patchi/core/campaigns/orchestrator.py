"""CampaignOrchestrator — run all registered campaigns and aggregate results."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from patchi.core.assurance.graph import AssuranceGraph

from .base import Campaign, CampaignStep
from .data_flow_abuse import DataFlowAbuseCampaign
from .state_transitions import StateTransitionCampaign

_log = logging.getLogger("patchi.core.campaigns.orchestrator")

# Registry of available campaigns
CAMPAIGN_REGISTRY: dict[str, type[Campaign]] = {
    "state_transitions": StateTransitionCampaign,
    "data_flow_abuse": DataFlowAbuseCampaign,
}


@dataclass
class CampaignResult:
    """Result of running a single campaign."""

    name: str
    steps: list[CampaignStep]
    total_findings: int = 0
    critical: int = 0
    high: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "steps": [s.to_dict() for s in self.steps],
            "total_findings": self.total_findings,
            "critical": self.critical,
            "high": self.high,
        }


@dataclass
class OrchestratorResult:
    """Aggregated result of all campaigns."""

    campaigns: list[CampaignResult]
    total_findings: int = 0
    critical: int = 0
    high: int = 0

    def to_dict(self) -> dict:
        return {
            "campaigns": [c.to_dict() for c in self.campaigns],
            "total_findings": self.total_findings,
            "critical": self.critical,
            "high": self.high,
        }


class CampaignOrchestrator:
    """Orchestrate all registered campaigns against the assurance graph."""

    def __init__(self, graph: AssuranceGraph):
        self._graph = graph

    def run_all(self) -> OrchestratorResult:
        """Run all registered campaigns."""
        results: list[CampaignResult] = []
        total_findings = 0
        critical = 0
        high = 0

        for name, cls in CAMPAIGN_REGISTRY.items():
            try:
                campaign = cls(self._graph)
                steps = campaign.run()

                campaign_findings = 0
                campaign_critical = 0
                campaign_high = 0
                for step in steps:
                    campaign_findings += len(step.findings)
                    for f in step.findings:
                        sev = f.get("severity", "")
                        if sev == "critical":
                            campaign_critical += 1
                        elif sev == "high":
                            campaign_high += 1

                result = CampaignResult(
                    name=name,
                    steps=steps,
                    total_findings=campaign_findings,
                    critical=campaign_critical,
                    high=campaign_high,
                )
                results.append(result)
                total_findings += campaign_findings
                critical += campaign_critical
                high += campaign_high
            except Exception as e:
                _log.warning("Campaign %s failed: %s", name, e)
                results.append(CampaignResult(
                    name=name,
                    steps=[CampaignStep(name="error", description=str(e), status="failed")],
                    total_findings=1,
                ))

        return OrchestratorResult(
            campaigns=results,
            total_findings=total_findings,
            critical=critical,
            high=high,
        )

    def run_campaign(self, name: str) -> CampaignResult:
        """Run a specific campaign by name."""
        cls = CAMPAIGN_REGISTRY.get(name)
        if cls is None:
            raise ValueError(f"Unknown campaign: {name}. Available: {list(CAMPAIGN_REGISTRY.keys())}")

        campaign = cls(self._graph)
        steps = campaign.run()

        total = sum(len(s.findings) for s in steps)
        critical = sum(1 for s in steps for f in s.findings if f.get("severity") == "critical")
        high = sum(1 for s in steps for f in s.findings if f.get("severity") == "high")

        return CampaignResult(
            name=name,
            steps=steps,
            total_findings=total,
            critical=critical,
            high=high,
        )
