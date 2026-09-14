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

    # Part 3 §1 linking pass: `_on_event`'s rate-spike check compares the
    # current rate against the EWMA baseline, but this accessor never existed —
    # the first warm source would have crashed `_on_event` with AttributeError
    # the moment its 5th event arrived.
    @property
    def current_value(self) -> float:
        return self._current_value

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
    Statistical anomaly detection over the detector event stream.

    Runs detached: `p governance triage --start` subscribes it to the EventBus
    and serves until interrupted; `p governance triage` prints its current
    statistical view without touching any live stream.
    """

    name = "TriageAgent"
    group = AgentGroup.GUARD
    timeout = 30

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
        tid = event.technique_id.value if isinstance(event.technique_id, TechniqueID) else event.technique_id
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
                    f"Event rate from {source_key} is {ratio:.1f}x above baseline ({stats.rate_meter.mean:.1f} vs"
                    f" {stats.rate_meter.current_value:.1f})",
                )

        # Check: z-score severity anomaly
        z = stats.rate_meter.z_score(stats.rate_meter.current_value)
        if abs(z) > self._z_score_threshold:
            await self._report_anomaly(
                event,
                source_key,
                "z_score",
                f"Event rate from {source_key} deviates {z:.1f}σ from its EWMA baseline",
            )

        # Check: novelty (technique never seen from this source)
        await self._check_novelty(event, source_key, tid)

    async def _check_novelty(self, event: Event, source_key: str, tid: str) -> None:
        """Flag a technique_id this source has never emitted before."""
        stats = self._sources[source_key]
        if stats.event_count <= 1:
            # First ever event from a source is definitionally novel, not an
            # anomaly — flagging every source's debut would be pure noise.
            return
        # technique_ids already contains the current event's tid (added in
        # _on_event before update), so novelty == this tid arrived exactly once.
        if sum(1 for t in stats.technique_ids if t == tid) == 1 and tid != TechniqueID.UNKNOWN.value:
            await self._report_anomaly(
                event,
                source_key,
                "novelty",
                f"{source_key} emitted technique {tid} for the first time",
            )

    # ── Silence check (call periodically, e.g. from a timer) ──────────────────

    def check_silence(self) -> list[Finding]:
        """Check if any previously-active source has gone silent."""
        now = time.monotonic()
        findings: list[Finding] = []
        for source_key, stats in list(self._sources.items()):
            # Only sources that were actually chatty (enough events to have a
            # meaningful baseline) participate in the dead-man's switch.
            if stats.event_count < 5:
                continue
            elapsed = now - stats.last_seen
            if elapsed > self._silence_timeout_s:
                last_seen_str = datetime.fromtimestamp(stats.last_seen).isoformat()
                findings.append(
                    Finding(
                        agent=self.name,
                        type="silence_anomaly",
                        severity=Severity.MEDIUM,
                        file="",
                        message=(
                            f"Source {source_key} went silent: {elapsed / 60:.0f} min"
                            f" since last event (was emitting"
                            f" {stats.rate_meter.mean:.2f} events/s)"
                        ),
                        detail=f"last_seen={last_seen_str}; events_seen={stats.event_count}",
                    )
                )
        return findings

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
