"""
Dispatcher — routes detection events to the correct specialist agent.

Consumes Event objects (raw or Sigma-enriched) and decides:
1. Which agent to dispatch to (based on technique_id, suggested_agent, confidence)
2. Whether the action should be synchronous (block) or async (investigate)
3. Whether to rate-limit, deduplicate, or skip

The dispatcher is the orchestration layer between detector output and agent execution.
It does NOT execute agents itself — it produces DispatchInstruction objects that
the caller (Coordinator or standalone runner) executes.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from patchi.core.agents.base import list_agents
from patchi.core.detector.event import Event, EventSeverity, TechniqueID

logger = logging.getLogger("patchi.detector.dispatcher")


class DispatchUrgency(str):
    SYNC_BLOCK = "sync_block"       # Block the request / stop processing immediately
    SYNC_INVESTIGATE = "sync_inv"   # Investigate synchronously (hold response)
    ASYNC_PRIORITY = "async_pri"    # High-priority async (process within seconds)
    ASYNC_NORMAL = "async_normal"   # Normal async queue
    ASYNC_DEFERRED = "async_defer"  # Low-priority, batch later
    DISCARD = "discard"             # Drop (below threshold)


@dataclass
class DispatchInstruction:
    """What the dispatcher wants done — one instruction per event."""
    event_id: str
    technique_id: str
    agent_name: str
    urgency: str
    confidence: float
    reason: str
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.monotonic)


class Dispatcher:
    """
    Routes events to agents based on technique_id, confidence, and agent availability.

    Resolution order:
      1. If event has `suggested_agent` AND confidence >= threshold → dispatch to that agent
      2. Map technique_id → agent from TechniqueID.for_agent_type() or agent registration
      3. If no mapping found and severity >= HIGH → dispatch to TriageAgent
      4. Otherwise → DISCARD (below threshold)

    Urgency is determined by severity:
      - CRITICAL → SYNC_BLOCK
      - HIGH     → SYNC_INVESTIGATE
      - MEDIUM   → ASYNC_PRIORITY
      - LOW/INFO → ASYNC_NORMAL
    """

    def __init__(
        self,
        min_confidence: float = 0.3,
        agent_whitelist: set[str] | None = None,
    ):
        self._min_confidence = min_confidence
        self._agent_whitelist = agent_whitelist
        self._agent_registry: dict[str, str] = {}  # technique_id -> agent_name
        self._dedup_window: dict[str, float] = {}  # event_id -> timestamp (for dedup)
        self._dedup_ttl_s = 300.0                   # 5 minute dedup window

        # Build agent registry from TechniqueID mapping + known agents
        self._build_registry()

    def _build_registry(self) -> None:
        """Build technique_id → agent_name mapping from all registered agents."""
        for agent_cls in list_agents():
            name = getattr(agent_cls, "name", "") or agent_cls.__name__
            for agent_type in ("injection", "auth", "authz", "dependency", "secret",
                               "network", "runtime", "crypto", "compliance", "triage"):
                if agent_type.lower() in name.lower():
                    tid = TechniqueID.for_agent_type(agent_type)
                    self._agent_registry[tid.value] = name

        # Hard-coded fallbacks for agents that match by technique rather than name
        fallbacks = {
            TechniqueID.INJECTION.value: "InjectionAgent",
            TechniqueID.BRUTE_FORCE.value: "AuthenticationAuditAgent",
            TechniqueID.SECRETS_FROM_STORE.value: "SecretScanner",
            TechniqueID.RESOURCE_DEVELOPMENT.value: "DependencyVulnerabilityAgent",
            TechniqueID.TRAFFIC_SIGNALING.value: "NetworkAgent",
            TechniqueID.EXECUTION.value: "RuntimeValidatorAgent",
            TechniqueID.DEFENSE_EVASION.value: "CryptoAgent",
            TechniqueID.UNKNOWN.value: "TriageAgent",
        }
        self._agent_registry.update(fallbacks)

    # ── Core dispatch logic ──────────────────────────────────────────────────

    def dispatch(self, event: Event, sigma_matches: list | None = None) -> DispatchInstruction:
        """
        Create a dispatch instruction for a single event.

        Uses both the raw event and any Sigma rule matches to determine routing.
        """
        event_id = event.event_id

        # Dedup check
        if event_id in self._dedup_window:
            elapsed = time.monotonic() - self._dedup_window[event_id]
            if elapsed < self._dedup_ttl_s:
                return DispatchInstruction(
                    event_id=event_id,
                    technique_id="",
                    agent_name="",
                    urgency=DispatchUrgency.DISCARD,
                    confidence=0.0,
                    reason="Deduplicated (same event_id within window)",
                )

        self._dedup_window[event_id] = time.monotonic()

        # Step 1: Extract the best technique_id and agent hint
        technique_id, confidence, suggested_agent = self._resolve_routing(event, sigma_matches)

        if technique_id == TechniqueID.NONE.value:
            return DispatchInstruction(
                event_id=event_id,
                technique_id=technique_id,
                agent_name="",
                urgency=DispatchUrgency.DISCARD,
                confidence=0.0,
                reason="No technique mapping (info/heartbeat)",
            )

        # Step 2: Find the agent to dispatch to
        agent_name = self._resolve_agent(technique_id, suggested_agent)

        if not agent_name:
            if event.severity.sort_key() <= EventSeverity.LOW.sort_key():
                return DispatchInstruction(
                    event_id=event_id,
                    technique_id=technique_id,
                    agent_name="",
                    urgency=DispatchUrgency.DISCARD,
                    confidence=confidence,
                    reason=f"No agent found for technique {technique_id} and severity too low",
                )
            agent_name = "TriageAgent"

        # Step 3: Apply whitelist filter
        if self._agent_whitelist and agent_name not in self._agent_whitelist:
            return DispatchInstruction(
                event_id=event_id,
                technique_id=technique_id,
                agent_name="",
                urgency=DispatchUrgency.DISCARD,
                confidence=confidence,
                reason=f"Agent {agent_name} not in whitelist",
            )

        # Step 4: Determine urgency
        urgency = self._resolve_urgency(event.severity, confidence)

        # Build reason string
        reason_parts = []
        if suggested_agent:
            reason_parts.append(f"suggested={suggested_agent}")
        reason_parts.append(f"confidence={confidence:.2f}")
        reason_parts.append(f"severity={event.severity.value}")
        if sigma_matches:
            reason_parts.append(f"sigma_rules={len(sigma_matches)}")

        return DispatchInstruction(
            event_id=event_id,
            technique_id=technique_id,
            agent_name=agent_name,
            urgency=urgency,
            confidence=confidence,
            reason="; ".join(reason_parts),
            payload=event.payload,
        )

    def dispatch_batch(self, events: list[Event]) -> list[DispatchInstruction]:
        """Dispatch a batch of events. Deduplicates by event_id."""
        seen: set[str] = set()
        results: list[DispatchInstruction] = []
        for event in events:
            if event.event_id in seen:
                continue
            seen.add(event.event_id)
            instruction = self.dispatch(event)
            if instruction.urgency != DispatchUrgency.DISCARD:
                results.append(instruction)
        return results

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_routing(
        self,
        event: Event,
        sigma_matches: list | None,
    ) -> tuple[str, float, str]:
        """Determine the best technique_id, confidence, and suggested_agent."""
        tid = event.technique_id.value if isinstance(event.technique_id, TechniqueID) else event.technique_id
        confidence = event.confidence
        suggested_agent = event.suggested_agent or ""

        # If Sigma matched, boost confidence and use Sigma's technique_id
        if sigma_matches:
            best = sigma_matches[0]
            tid = best.technique_id.value if isinstance(best.technique_id, TechniqueID) else str(best.technique_id)
            confidence = max(confidence, best.confidence)
            if best.target_agent:
                suggested_agent = best.target_agent

        return tid, confidence, suggested_agent

    def _resolve_agent(self, technique_id: str, suggested_agent: str | None) -> str:
        """Find the agent to handle this technique, with fallback logic."""
        if suggested_agent:
            return suggested_agent
        return self._agent_registry.get(technique_id, "")

    def _resolve_urgency(self, severity: EventSeverity, confidence: float) -> str:
        """Map severity + confidence to urgency level."""
        if severity == EventSeverity.CRITICAL:
            if confidence >= 0.7:
                return DispatchUrgency.SYNC_BLOCK
            return DispatchUrgency.SYNC_INVESTIGATE
        if severity == EventSeverity.HIGH:
            if confidence >= 0.5:
                return DispatchUrgency.SYNC_INVESTIGATE
            return DispatchUrgency.ASYNC_PRIORITY
        if severity == EventSeverity.MEDIUM:
            return DispatchUrgency.ASYNC_PRIORITY if confidence >= 0.5 else DispatchUrgency.ASYNC_NORMAL
        return DispatchUrgency.ASYNC_NORMAL

    def stats(self) -> dict:
        return {
            "agent_registry_size": len(self._agent_registry),
            "dedup_window_size": len(self._dedup_window),
            "known_techniques": list(self._agent_registry.keys()),
        }

    def clear_dedup(self) -> None:
        self._dedup_window.clear()
