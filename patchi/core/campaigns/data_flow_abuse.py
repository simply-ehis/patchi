"""DataFlowAbuseCampaign — test data flow security.

Maps data flows, tests sanitization, encoding bypass, cross-boundary
flows, and security meaning changes.
"""

from __future__ import annotations

import logging

from .base import Campaign, CampaignStep

_log = logging.getLogger("patchi.core.campaigns.data_flow_abuse")


class DataFlowAbuseCampaign(Campaign):
    """Test data flow injection and security meaning."""

    name = "data_flow_abuse"
    description = "Tests data flow injection and security"

    def steps(self) -> list[CampaignStep]:
        return [
            CampaignStep(name="map_flows", description="Map all data flows from the graph"),
            CampaignStep(
                name="identify_transformations",
                description="Identify data transformations in flows",
            ),
            CampaignStep(name="test_sanitization", description="Test sanitization on sensitive flows"),
            CampaignStep(name="test_encoding_bypass", description="Test encoding bypass on transformations"),
            CampaignStep(name="test_cross_boundary", description="Test cross-boundary data flows"),
            CampaignStep(name="test_security_meaning", description="Test security meaning changes"),
        ]

    def _execute_step(self, step: CampaignStep) -> None:
        if step.name == "map_flows":
            self._map_flows(step)
        elif step.name == "identify_transformations":
            self._identify_transformations(step)
        elif step.name == "test_sanitization":
            self._test_sanitization(step)
        elif step.name == "test_encoding_bypass":
            self._test_encoding_bypass(step)
        elif step.name == "test_cross_boundary":
            self._test_cross_boundary(step)
        elif step.name == "test_security_meaning":
            self._test_security_meaning(step)

    def _map_flows(self, step: CampaignStep) -> None:
        """Map all data flows mentioned in the graph."""
        flows: list[dict] = []
        for claim in self._graph.claims.values():
            for ev in claim.evidence:
                a = ev.artifact
                if "source" in a and "sink" in a:
                    flows.append(
                        {
                            "source": a["source"],
                            "sink": a["sink"],
                            "sanitized": a.get("sanitized", False),
                            "cross_boundary": a.get("cross_boundary", False),
                        }
                    )

        if not flows:
            step.findings.append(
                {
                    "type": "no_flows_found",
                    "severity": "info",
                    "detail": "No data flows discovered from the assurance graph",
                }
            )
        else:
            step.findings.append(
                {
                    "type": "flows_mapped",
                    "severity": "info",
                    "detail": f"Found {len(flows)} data flows",
                }
            )

    def _identify_transformations(self, step: CampaignStep) -> None:
        """Check for unsanitized transformations in data flows."""
        for claim in self._graph.claims.values():
            for ev in claim.evidence:
                a = ev.artifact
                if "source" in a and "sink" in a:
                    if not a.get("sanitized", True):
                        step.findings.append(
                            {
                                "type": "unsanitized_flow",
                                "severity": "high",
                                "detail": f"Unsanitized flow: {a['source']} → {a['sink']}",
                            }
                        )

    def _test_sanitization(self, step: CampaignStep) -> None:
        """Test that sensitive data flows are properly sanitized."""
        for claim in self._graph.claims.values():
            if "sanitiz" in claim.statement.lower():
                if claim.verdict.value == "disproved":
                    step.findings.append(
                        {
                            "type": "sanitization_bypass",
                            "severity": "critical",
                            "detail": f"Sanitization bypassed: {claim.statement}",
                        }
                    )

    def _test_encoding_bypass(self, step: CampaignStep) -> None:
        """Test for encoding bypass on data transformations."""
        for claim in self._graph.claims.values():
            if "encod" in claim.statement.lower() or "transform" in claim.statement.lower():
                if claim.verdict.value == "disproved":
                    step.findings.append(
                        {
                            "type": "encoding_bypass",
                            "severity": "high",
                            "detail": f"Encoding bypass found: {claim.statement}",
                        }
                    )

    def _test_cross_boundary(self, step: CampaignStep) -> None:
        """Test that cross-boundary flows have proper controls."""
        for claim in self._graph.claims.values():
            for ev in claim.evidence:
                a = ev.artifact
                if a.get("cross_boundary", False):
                    if ev.supports:  # evidence supports that it's uncontrolled
                        step.findings.append(
                            {
                                "type": "uncontrolled_cross_boundary",
                                "severity": "critical",
                                "detail": f"Cross-boundary flow without controls: {a.get('source', '?')} →"
                                f" {a.get('sink', '?')}",
                            }
                        )

    def _test_security_meaning(self, step: CampaignStep) -> None:
        """Test that data flow transformations don't change security meaning."""
        for claim in self._graph.claims.values():
            if "meaning" in claim.statement.lower() and "security" in claim.statement.lower():
                if claim.verdict.value == "disproved":
                    step.findings.append(
                        {
                            "type": "security_meaning_change",
                            "severity": "high",
                            "detail": f"Security meaning changed: {claim.statement}",
                        }
                    )
