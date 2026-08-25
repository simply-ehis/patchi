"""StateTransitionCampaign — test application state machine security.

Discovers states, maps transitions, tests legal/illegal sequences,
checks for replay attacks and concurrent race conditions.
"""

from __future__ import annotations

import logging

from .base import Campaign, CampaignStep

_log = logging.getLogger("patchi.core.campaigns.state_transitions")


class StateTransitionCampaign(Campaign):
    """Test state machine security: legal transitions, illegal transitions, replay, concurrency."""

    name = "state_transitions"
    description = "Tests application state machine security"

    def steps(self) -> list[CampaignStep]:
        return [
            CampaignStep(
                name="discover_states", description="Discover all application states from the graph"
            ),
            CampaignStep(name="map_transitions", description="Map all legal state transitions"),
            CampaignStep(
                name="identify_guards", description="Identify guards protecting state transitions"
            ),
            CampaignStep(
                name="test_legal_sequences", description="Test legal state transition sequences"
            ),
            CampaignStep(
                name="test_illegal_sequences", description="Test illegal state transition sequences"
            ),
            CampaignStep(
                name="test_replay", description="Test replay attacks on state transitions"
            ),
            CampaignStep(name="test_concurrent", description="Test concurrent state transitions"),
        ]

    def _execute_step(self, step: CampaignStep) -> None:
        if step.name == "discover_states":
            self._discover_states(step)
        elif step.name == "map_transitions":
            self._map_transitions(step)
        elif step.name == "identify_guards":
            self._identify_guards(step)
        elif step.name == "test_legal_sequences":
            self._test_legal_sequences(step)
        elif step.name == "test_illegal_sequences":
            self._test_illegal_sequences(step)
        elif step.name == "test_replay":
            self._test_replay(step)
        elif step.name == "test_concurrent":
            self._test_concurrent(step)

    def _discover_states(self, step: CampaignStep) -> None:
        """Find all states mentioned in the assurance graph."""
        states: set[str] = set()
        for claim in self._graph.claims.values():
            for ev in claim.evidence:
                a = ev.artifact
                if "from_state" in a:
                    states.add(a["from_state"])
                if "to_state" in a:
                    states.add(a["to_state"])

        if not states:
            step.findings.append(
                {
                    "type": "no_states_found",
                    "severity": "info",
                    "detail": "No application states discovered from the assurance graph",
                }
            )
        else:
            step.findings.append(
                {
                    "type": "states_discovered",
                    "severity": "info",
                    "detail": f"Found {len(states)} states: {', '.join(sorted(states))}",
                }
            )

    def _map_transitions(self, step: CampaignStep) -> None:
        """Map all legal transitions and check for completeness."""
        transitions: list[dict] = []
        for claim in self._graph.claims.values():
            for ev in claim.evidence:
                a = ev.artifact
                if "from_state" in a and "to_state" in a:
                    transitions.append(
                        {
                            "from": a["from_state"],
                            "to": a["to_state"],
                            "action": a.get("action", "unknown"),
                            "guarded": a.get("guarded", False),
                        }
                    )

        # Check for transitions without guards
        unguarded = [t for t in transitions if not t["guarded"]]
        if unguarded:
            for t in unguarded:
                step.findings.append(
                    {
                        "type": "unguarded_transition",
                        "severity": "medium",
                        "detail": f"Unguarded transition: {t['from']} → {t['to']} via {t['action']}",
                    }
                )

    def _identify_guards(self, step: CampaignStep) -> None:
        """Check that transitions have authorization guards."""
        for claim in self._graph.claims.values():
            if "guard" in claim.statement.lower() or "auth" in claim.statement.lower():
                if claim.verdict.value == "disproved":
                    step.findings.append(
                        {
                            "type": "guard_broken",
                            "severity": "critical",
                            "detail": f"Guard violated: {claim.statement}",
                        }
                    )

    def _test_legal_sequences(self, step: CampaignStep) -> None:
        """Test that legal transition sequences don't bypass guards."""
        # Check for claims about legal sequences
        for claim in self._graph.claims.values():
            if "sequence" in claim.statement.lower() and claim.verdict.value == "disproved":
                step.findings.append(
                    {
                        "type": "sequence_bypass",
                        "severity": "high",
                        "detail": f"Legal sequence bypasses guard: {claim.statement}",
                    }
                )

    def _test_illegal_sequences(self, step: CampaignStep) -> None:
        """Test that illegal transitions are properly blocked."""
        # Find claims about forbidden transitions
        for claim in self._graph.claims.values():
            if "must not" in claim.statement.lower() or "forbidden" in claim.statement.lower():
                if claim.verdict.value == "disproved":
                    step.findings.append(
                        {
                            "type": "illegal_transition_allowed",
                            "severity": "critical",
                            "detail": f"Forbidden transition is possible: {claim.statement}",
                        }
                    )

    def _test_replay(self, step: CampaignStep) -> None:
        """Test for replay vulnerabilities in state transitions."""
        for claim in self._graph.claims.values():
            if "replay" in claim.statement.lower() and claim.verdict.value == "disproved":
                step.findings.append(
                    {
                        "type": "replay_vulnerability",
                        "severity": "high",
                        "detail": f"Replay attack possible: {claim.statement}",
                    }
                )

    def _test_concurrent(self, step: CampaignStep) -> None:
        """Test for concurrent state transition race conditions."""
        for claim in self._graph.claims.values():
            if "concurrent" in claim.statement.lower() or "race" in claim.statement.lower():
                if claim.verdict.value == "disproved":
                    step.findings.append(
                        {
                            "type": "race_condition",
                            "severity": "high",
                            "detail": f"Race condition found: {claim.statement}",
                        }
                    )
