"""
Tests for the detector pipeline: Event schema, EventBus, AuditLog, TriageAgent.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from unittest import IsolatedAsyncioTestCase, TestCase

from patchi.core.detector.audit import AuditLog
from patchi.core.detector.bus import EventBus
from patchi.core.detector.event import (
    Event,
    EventSeverity,
    EventSource,
    TechniqueID,
)
from patchi.core.detector.triage import EWMAMeter, TriageAgent


class TestEventSchema(TestCase):
    """Event creation, serialization, and helpers."""

    def test_basic_event(self):
        ev = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.INJECTION,
            summary="SQL injection detected in login handler",
            severity=EventSeverity.HIGH,
            agent_name="InjectionAgent",
        )
        self.assertEqual(ev.source, EventSource.AGENT)
        self.assertEqual(ev.technique_id, TechniqueID.INJECTION)
        self.assertEqual(ev.severity, EventSeverity.HIGH)
        self.assertIn("SQL injection", ev.summary)
        self.assertTrue(ev.event_id)
        self.assertTrue(ev.timestamp)

    def test_to_dict_roundtrip(self):
        ev = Event(
            source=EventSource.GIT_EVENT,
            technique_id="T1190",
            summary="Commit with hardcoded secret",
            severity=EventSeverity.CRITICAL,
            payload={"file": "config.py", "commit": "abc123"},
            cwe_ids=["CWE-798"],
            owasp_category="A02:2021",
        )
        d = ev.to_dict()
        self.assertEqual(d["source"], "git_event")
        self.assertEqual(d["technique_id"], "T1190")
        self.assertEqual(d["severity"], "critical")
        self.assertEqual(d["payload"]["file"], "config.py")
        self.assertEqual(d["cwe_ids"], ["CWE-798"])

    def test_technique_display(self):
        ev = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.BRUTE_FORCE,
            summary="Brute force attempt",
        )
        self.assertIn("T1110", ev.technique_display)
        self.assertIn("Brute Force", ev.technique_display)

    def test_for_agent_type_mapping(self):
        self.assertEqual(TechniqueID.for_agent_type("injection"), TechniqueID.INJECTION)
        self.assertEqual(TechniqueID.for_agent_type("auth"), TechniqueID.BRUTE_FORCE)
        self.assertEqual(TechniqueID.for_agent_type("secret"), TechniqueID.SECRETS_FROM_STORE)
        self.assertEqual(TechniqueID.for_agent_type("triage"), TechniqueID.UNKNOWN)
        self.assertEqual(TechniqueID.for_agent_type("unknown_type"), TechniqueID.UNKNOWN)

    def test_severity_sort_key(self):
        self.assertLess(EventSeverity.CRITICAL.sort_key(), EventSeverity.LOW.sort_key())
        self.assertEqual(EventSeverity.DEBUG.sort_key(), 5)


class TestEventBus(IsolatedAsyncioTestCase):
    async def test_publish_receive(self):
        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe(handler, source={EventSource.AGENT})

        ev = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.INJECTION,
            summary="Test event",
        )
        await bus.publish(ev)
        await asyncio.sleep(0.05)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].event_id, ev.event_id)

    async def test_filter_by_source(self):
        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe(handler, source={EventSource.HTTP_TRAFFIC})

        # Should NOT match (wrong source)
        agent_ev = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.INJECTION,
            summary="Agent event",
        )
        # Should match
        http_ev = Event(
            source=EventSource.HTTP_TRAFFIC,
            technique_id=TechniqueID.INJECTION,
            summary="HTTP event",
        )
        await bus.publish(agent_ev)
        await bus.publish(http_ev)
        await asyncio.sleep(0.05)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].summary, "HTTP event")

    async def test_filter_by_min_severity(self):
        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe(handler, min_severity=EventSeverity.HIGH)

        low = Event(source=EventSource.AGENT, technique_id=TechniqueID.UNKNOWN, summary="Low", severity=EventSeverity.LOW)
        high = Event(source=EventSource.AGENT, technique_id=TechniqueID.UNKNOWN, summary="High", severity=EventSeverity.HIGH)

        await bus.publish(low)
        await bus.publish(high)
        await asyncio.sleep(0.05)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].summary, "High")

    async def test_collect_batch(self):
        bus = EventBus()
        for i in range(5):
            ev = Event(
                source=EventSource.AGENT,
                technique_id=TechniqueID.UNKNOWN,
                summary=f"Event {i}",
            )
            await bus.publish(ev)

        batch = await bus.collect_batch(timeout_s=0.5, max_events=10)
        self.assertGreaterEqual(len(batch), 1)

    async def test_multiple_subscribers(self):
        bus = EventBus()
        r1: list[Event] = []
        r2: list[Event] = []

        async def h1(event: Event):
            r1.append(event)

        async def h2(event: Event):
            r2.append(event)

        bus.subscribe(h1)
        bus.subscribe(h2)

        ev = Event(source=EventSource.HEARTBEAT, technique_id=TechniqueID.NONE, summary="Heartbeat")
        await bus.publish(ev)
        await asyncio.sleep(0.05)

        self.assertEqual(len(r1), 1)
        self.assertEqual(len(r2), 1)


class TestAuditLog(IsolatedAsyncioTestCase):
    async def test_write_and_verify_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = AuditLog(root=root)

            ev1 = Event(source=EventSource.AGENT, technique_id=TechniqueID.INJECTION, summary="First")
            ev2 = Event(source=EventSource.AGENT, technique_id=TechniqueID.INJECTION, summary="Second")

            await log.write(ev1)
            await log.write(ev2)
            log.close()

            valid, count = log.verify_chain()
            self.assertTrue(valid)
            self.assertEqual(count, 2)

    def test_corrupt_chain_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / ".patchi" / "detector"
            log_dir.mkdir(parents=True)

            log_path = log_dir / "audit.log.jsonl"
            # Write a valid entry then manually corrupt it
            log_path.write_text(
                '{"event": {}, "previous_hash": "", "entry_hash": "abc", "written_at": "Z"}\n'
                '{"event": {}, "previous_hash": "wrong", "entry_hash": "def", "written_at": "Z"}\n',
                encoding="utf-8",
            )

            log = AuditLog(root=root)
            valid, count = log.verify_chain()
            self.assertFalse(valid)
            log.close()

    def test_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = AuditLog(root=root)

            ev = Event(source=EventSource.AGENT, technique_id=TechniqueID.INJECTION, summary="Test")
            asyncio.run(log.write(ev))
            log.close()

            exported = log.export()
            entries = json.loads(exported)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["event"]["summary"], "Test")


class TestEWMAMeter(TestCase):
    def test_z_score_needs_samples(self):
        meter = EWMAMeter()
        self.assertFalse(meter.ready)
        self.assertEqual(meter.z_score(100.0), 0.0)

        for _ in range(5):
            meter.update(1.0)
        self.assertTrue(meter.ready)

    def test_warmup_and_mean(self):
        meter = EWMAMeter(alpha=0.5)
        for _ in range(20):
            meter.update(10.0)
        self.assertAlmostEqual(meter.mean, 10.0, delta=2.0)

    def test_sees_outliers(self):
        meter = EWMAMeter(alpha=0.3)
        for _ in range(10):
            meter.update(10.0)
        # After warmup, a giant spike should be >3 sigma
        z = meter.z_score(1000.0)
        self.assertGreater(z, 3.0)


class TestTriageAgent(TestCase):
    def test_triage_finding_convention(self):
        """TriageAgent should produce findings with its own name."""
        agent = TriageAgent()
        self.assertEqual(agent.name, "TriageAgent")
        self.assertEqual(agent.group.value, "guard")
