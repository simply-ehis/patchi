"""Base campaign class and CampaignStep."""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field

from patchi.core.assurance.graph import AssuranceGraph

_log = logging.getLogger("patchi.core.campaigns")


@dataclass
class CampaignStep:
    """One step in a campaign."""

    name: str
    description: str
    status: str = "pending"  # "pending", "running", "passed", "failed"
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "findings_count": len(self.findings),
        }


class Campaign(abc.ABC):
    """Base class for assurance campaigns."""

    name: str = "base"
    description: str = ""

    def __init__(self, graph: AssuranceGraph):
        self._graph = graph

    @abc.abstractmethod
    def steps(self) -> list[CampaignStep]:
        """Define the steps in this campaign."""

    def run(self) -> list[CampaignStep]:
        """Execute all steps and return results."""
        results: list[CampaignStep] = []
        for step in self.steps():
            try:
                step.status = "running"
                self._execute_step(step)
                step.status = "failed" if step.findings else "passed"
            except Exception as e:
                _log.warning("Campaign %s step %s failed: %s", self.name, step.name, e)
                step.status = "failed"
                step.findings.append({"error": str(e)})
            results.append(step)
        return results

    @abc.abstractmethod
    def _execute_step(self, step: CampaignStep) -> None:
        """Execute a single step (modifies step.findings in place)."""
