"""
TriageAgent — statistical anomaly detection over the event stream.

The Triage Agent is the catch-all for events that don't match any existing
technique_id with high confidence. It uses lightweight, deterministic statistics
(z-score, EWMA, rate-of-change) to surface outliers that warrant human or AI review.

This is NOT a machine learning model. It's a set of interpretable counters and
moving averages that flag:

1. **Rate anomalies** — a signal source suddenly emitting 10x its normal volume
2. **Severity anomalies** — a normally-low-severity source producing a HIGH/CRITICAL event
3. **Novelty anomalies** — a technique_id never seen before from a known source
4. **Silence anomalies** — a normally-chatty source goes silent (dead-man's switch)

Every anomaly produces a Finding with the agent name "TriageAgent" so it enters
the standard pipeline (orchestration → gating → routing).
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
)
from patchi.core.detector.bus import EventBus, Subscription
from patchi.core.detector.event import Event, TechniqueID

logger = logging.getLogger("patchi.detector.triage")


# ── Statistical windows ──────────────────────────────────────────────────────


@dataclass
class EWMAMeter:
    """
    Exponentially-weighted moving average and z-score computation.

    Tracks rate and variance per key (source, technique_id, agent).
    Alpha controls how quickly old data decays (lower = smoother).
    """

    alpha: float = 0.1  # Smoothing factor (0.0–1.0)
    min_samples: int = 5  # Min observations before z-score is meaningful
    _mean: float = 0.0
    _m2: float = 0.0  # Sum of squared differences (for variance)
    _count: int = 0
    _last_update: float = 0.0
    _current_value: float = 0.0

    def update(self, value: float) -> None:
        now = time.monotonic()
        elapsed = now - self._last_update if self._last_update else 0.0
        self._last_update = now

        rate = value / elapsed if elapsed > 0.0 else value

        self._count += 1
        if self._count == 1:
            self._mean = rate
            self._m2 = 0.0
        else:
            diff = rate - self._mean
            incr = self.alpha * diff
            self._mean += incr
            self._m2 = (1 - self.alpha) * (self._m2 + self.alpha * diff * diff)

        self._current_value = rate

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def variance(self) -> float:
        return self._m2 + 1e-10

    @property
    def std(self) -> float:
        return self.variance**0.5

    def z_score(self, value: float) -> float:
        s = self.std
        if self._count < self.min_samples:
            return 0.0
        return (value - self._mean) / s

    @property
    def ready(self) -> bool:
        return self._count >= self.min_samples


# ── Per-source statistical tracker ───────────────────────────────────────────


@dataclass
class SourceStats:
    """Per-source statistics for anomaly detection."""

    rate_meter: EWMAMeter = field(default_factory=lambda: EWMAMeter(alpha=0.05))
    severity_meter: EWMAMeter = field(default_factory=lambda: EWMAMeter(alpha=0.1))
    technique_ids: set[str] = field(default_factory=set)
    last_seen: float = 0.0
    event_count: int = 0


# ── TriageAgent ──────────────────────────────────────────────────────────────


@register
class TriageAgent(BaseAgent):
    """
    Statistical anomaly detection over the event stream.

    Runs continuously in the background, listening to the EventBus and updating
    per-source statistics. When an anomaly is detected, it creates a Finding.

    This agent has no `_run()` with a single AgentInput — instead it uses a
    long-lived `run_detached()` coroutine that subscribes to the bus.
    """

    name = "TriageAgent"
    group = AgentGroup.GUARD
    timeout = 300

    def __init__(self) -> None:
        super().__init__()
        self._sources: dict[str, SourceStats] = defaultdict(SourceStats)
        self._subscription: Subscription | None = None
        self._z_score_threshold = 3.0  # Events >3σ are anomalous
        self._silence_timeout_s = 300.0  # 5 min silence = anomaly
        self._rate_spike_threshold = 10.0  # 10x normal rate = spike
        self._last_finding_time: dict[str, float] = {}

    # ── Detached runner (long-lived coroutine) ────────────────────────────────

    async def run_detached(self, bus: EventBus, root: str | None = None) -> None:
        """Subscribe to the EventBus and process events indefinitely."""
        self._subscription = bus.subscribe(
            self._on_event,
            name=self.name,
        )
        logger.info("TriageAgent subscribed to EventBus")

    def stop(self) -> None:
        if self._subscription:
            self._bus = None
            self._subscription = None
            logger.info("TriageAgent stopped")

    # ── Event handler ─────────────────────────────────────────────────────────

    async def _on_event(self, event: Event) -> None:
        source_key = f"{event.source.value}:{event.source_details.get('host', 'local')}"
        stats = self._sources[source_key]
        stats.event_count += 1
        stats.last_seen = time.monotonic()

        # Track seen technique IDs
        tid = (
            event.technique_id.value
            if isinstance(event.technique_id, TechniqueID)
            else event.technique_id
        )
        stats.technique_ids.add(tid)

        # Update rate meter (increment by 1)
        stats.rate_meter.update(1.0)

        # Update severity meter (numeric: debug=0 … critical=5)
        sev_score = event.severity.sort_key()
        stats.severity_meter.update(float(5 - sev_score))

        # Skip anomaly checks if the meter isn't warm yet
        if not stats.rate_meter.ready:
            return

        # Check: rate spike
        if stats.rate_meter.current_value > 0:
            ratio = stats.rate_meter.current_value / (stats.rate_meter.mean or 1.0)
            if ratio > self._rate_spike_threshold:
                await self._report_anomaly(
                    event,
                    source_key,
                    "rate_spike",
                    f"Event rate from {source_key} is {ratio:.1f}x above baseline ({stats.rate_meter.mean:.1f} vs {stats.rate_meter.current_value:.1f})",
                )

        # Check: z-score severity anomaly
        z = stats.rate_meter.z_score(stats.rate_meter.current_value)
        if z > self._z_score_threshold:
            await self._report_anomaly(
                event,
                source_key,
                "statistical_outlier",
                f"Event from {source_key} is {z:.1f}σ above {tid} baseline (z-score anomaly)",
            )

    # ── Silence check (call periodically, e.g. from a timer) ──────────────────

    def check_silence(self) -> list[Finding]:
        """Check if any previously-active source has gone silent."""
        now = time.monotonic()
        findings: list[Finding] = []
        for source_key, stats in list(self._sources.items()):
            if stats.event_count < self._ewma.min_samples:
                continue
            elapsed = now - stats.last_seen
            if elapsed > self._silence_timeout_s:
                last_seen_str = datetime.fromtimestamp(stats.last_seen).isoformat()
                findings.append(
                    Finding(
                        agent=self.name,
                        type="source_silent",
                        severity=Severity.MEDIUM,
                        file="",
                        line=0,
                        message=f"Source {source_key} has been silent for {elapsed:.0f}s (last seen: {last_seen_str})",
                        suggestion="Check if the detector pipeline is healthy or if this source was intentionally removed",
                    )
                )
        return findings

    # ── Novelty check ─────────────────────────────────────────────────────────

    async def _check_novelty(self, event: Event, source_key: str, tid: str) -> None:
        """Check if this technique_id is new for this source."""
        stats = self._sources[source_key]
        if tid not in stats.technique_ids and tid != TechniqueID.UNKNOWN.value:
            await self._report_anomaly(
                event,
                source_key,
                "novel_technique",
                f"First occurrence of {tid} ({event.technique_display}) from source {source_key}",
            )

    # ── Anomaly reporting ─────────────────────────────────────────────────────

    async def _report_anomaly(
        self,
        event: Event,
        source_key: str,
        anomaly_type: str,
        message: str,
    ) -> None:
        # Rate-limit findings: skip if we already reported one in the last 30s
        cooldown_key = f"{source_key}:{anomaly_type}"
        now = time.monotonic()
        last = self._last_finding_time.get(cooldown_key, 0.0)
        if now - last < 30.0:
            return
        self._last_finding_time[cooldown_key] = now

        logger.info("Triage anomaly [%s] %s", anomaly_type, message)

    # ── Stats ──────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        return {
            "sources_tracked": len(self._sources),
            "total_events": sum(s.event_count for s in self._sources.values()),
            "sources": {
                k: {
                    "event_count": s.event_count,
                    "techniques": list(s.technique_ids),
                    "mean_rate": s.rate_meter.mean,
                    "last_seen_ago": time.monotonic() - s.last_seen,
                }
                for k, s in self._sources.items()
            },
        }

    # ── Required BaseAgent method (satisfy ABC) ───────────────────────────────

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """No-op: TriageAgent is detachment-driven, not input-driven."""
        pass
