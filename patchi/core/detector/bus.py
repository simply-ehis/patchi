"""
EventBus — in-memory async pub/sub for the detector pipeline.

Features:
- Subscribe by EventSource, TechniqueID, severity threshold, or agent name
- Rate-limited dispatch (prevents handler resource exhaustion)
- Batch collection (time/buffer-based for bulk processing)
- Auditable: every published event is forwarded to the audit log
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Awaitable, Callable

from patchi.core.detector.event import Event, EventSeverity, EventSource, TechniqueID

logger = logging.getLogger("patchi.detector.bus")

# Type alias for event handlers
EventHandler = Callable[[Event], Awaitable[None]]


_log = logging.getLogger("patchi.core.bus")

@dataclass
class Subscription:
    """A single subscription to the event bus."""
    handler: EventHandler
    source: set[EventSource] | None = None
    technique_filter: set[str] | None = None
    agent_filter: set[str] | None = None
    min_severity: EventSeverity | None = None
    name: str = ""


class RateLimiter:
    """Sliding-window rate limiter per handler."""

    def __init__(self, max_per_second: float = 100.0):
        self._windows: dict[str, list[float]] = defaultdict(list)
        self._max_per_second = max_per_second

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window = self._windows[key]
        cutoff = now - 1.0
        while window and window[0] < cutoff:
            window.pop(0)
        if len(window) >= self._max_per_second:
            return False
        window.append(now)
        return True

    def reset(self, key: str) -> None:
        self._windows.pop(key, None)


class EventBus:
    """
    In-memory event bus with filtering, rate limiting, and audit forwarding.

    Usage:
        bus = EventBus()

        async def on_scan_event(event: Event):
            print(f"Got: {event.summary}")

        bus.subscribe(on_scan_event, source={EventSource.AGENT})
        await bus.publish(event)

        # Collect in batches
        async for batch in bus.collect_batch(timeout_s=5.0, max_events=100):
            await process(batch)
    """

    def __init__(
        self,
        audit_handler: EventHandler | None = None,
        rate_limit: float = 200.0,
    ):
        self._subscriptions: list[Subscription] = []
        self._lock = asyncio.Lock()
        self._rate_limiter = RateLimiter(max_per_second=rate_limit)
        self._audit_handler = audit_handler
        self._batch_queue: asyncio.Queue[Event] = asyncio.Queue()
        self._running = False

    # ── Subscription management ────────────────────────────────────────────────

    def subscribe(
        self,
        handler: EventHandler,
        *,
        source: set[EventSource] | None = None,
        technique_id: set[str] | None = None,
        agent: set[str] | None = None,
        min_severity: EventSeverity | None = None,
        name: str = "",
    ) -> Subscription:
        sub = Subscription(
            handler=handler,
            source=source,
            technique_filter=technique_id,
            agent_filter=agent,
            min_severity=min_severity,
            name=name or getattr(handler, "__name__", str(id(handler))),
        )
        self._subscriptions.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        if sub in self._subscriptions:
            self._subscriptions.remove(sub)

    def clear(self) -> None:
        self._subscriptions.clear()

    # ── Publishing ─────────────────────────────────────────────────────────────

    async def publish(self, event: Event) -> None:
        """Publish a single event to matching subscribers."""
        tid = event.technique_id.value if isinstance(event.technique_id, TechniqueID) else event.technique_id

        matched_any = False
        async with self._lock:
            for sub in self._subscriptions:
                if not self._matches(event, sub, tid):
                    continue
                handler_key = f"{sub.name}:{tid}"
                if not self._rate_limiter.allow(handler_key):
                    logger.debug("Rate limit hit for %s on %s", sub.name, tid)
                    continue
                matched_any = True
                try:
                    await sub.handler(event)
                except Exception as e:
                    _log.warning("EventBus.publish failed: %s", e)
                    logger.exception("Handler %s failed on event %s", sub.name, event.event_id)

        # Always queue for batch collection
        await self._batch_queue.put(event)

        # Forward to audit handler (separate from subscriptions so it always fires)
        if self._audit_handler:
            try:
                await self._audit_handler(event)
            except Exception as e:
                _log.warning("EventBus.publish failed: %s", e)
                logger.exception("Audit handler failed on event %s", event.event_id)

        if not matched_any:
            logger.debug("Event %s had zero matching subscribers", event.event_id)

    async def publish_batch(self, events: list[Event]) -> None:
        """Publish multiple events in sequence."""
        for event in events:
            await self.publish(event)

    # ── Batch collection ──────────────────────────────────────────────────────

    async def collect_batch(
        self,
        timeout_s: float = 5.0,
        max_events: int = 100,
    ) -> list[Event]:
        """
        Collect events into a batch (blocks until timeout or max_events reached).

        Usage:
            while True:
                batch = await bus.collect_batch(timeout_s=1.0)
                if batch:
                    await save_to_db(batch)
        """
        events: list[Event] = []
        deadline = time.monotonic() + timeout_s

        while len(events) < max_events:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                ev = await asyncio.wait_for(
                    self._batch_queue.get(),
                    timeout=remaining,
                )
                events.append(ev)
            except asyncio.TimeoutError:
                break

        return events

    # ── Stats ──────────────────────────────────────────────────────────────────

    def subscriber_count(self) -> int:
        return len(self._subscriptions)

    def stats(self) -> dict:
        return {
            "subscribers": len(self._subscriptions),
            "queue_depth": self._batch_queue.qsize(),
        }

    # ── Matching logic ─────────────────────────────────────────────────────────

    def _matches(self, event: Event, sub: Subscription, tid: str) -> bool:
        if sub.source is not None and event.source not in sub.source:
            return False
        if sub.technique_filter is not None and tid not in sub.technique_filter:
            return False
        if sub.agent_filter is not None and event.agent_name not in sub.agent_filter:
            return False
        if sub.min_severity is not None and event.severity.sort_key() > sub.min_severity.sort_key():
            return False
        return True
