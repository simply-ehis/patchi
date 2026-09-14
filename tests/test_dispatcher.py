"""Tests for the Event Dispatcher."""

from __future__ import annotations

from unittest import TestCase

from patchi.core.detector.dispatcher import Dispatcher, DispatchUrgency
from patchi.core.detector.event import Event, EventSeverity, EventSource, TechniqueID


class TestDispatcher(TestCase):
    def setUp(self):
        self.dispatcher = Dispatcher(min_confidence=0.3)

    def test_dispatches_to_suggested_agent(self):
        event = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.INJECTION,
            summary="SQL injection",
            severity=EventSeverity.CRITICAL,
            confidence=0.9,
            suggested_agent="InjectionAgent",
        )
        instruction = self.dispatcher.dispatch(event)
        self.assertEqual(instruction.agent_name, "InjectionAgent")
        self.assertNotEqual(instruction.urgency, DispatchUrgency.DISCARD)

    def test_critical_gets_sync_block(self):
        event = Event(
            source=EventSource.HTTP_TRAFFIC,
            technique_id=TechniqueID.INJECTION,
            summary="SQL injection",
            severity=EventSeverity.CRITICAL,
            confidence=0.9,
        )
        instruction = self.dispatcher.dispatch(event)
        self.assertEqual(instruction.urgency, DispatchUrgency.SYNC_BLOCK)
        self.assertIn("InjectionAgent", instruction.agent_name)

    def test_high_confidence_high_severity(self):
        event = Event(
            source=EventSource.HTTP_TRAFFIC,
            technique_id=TechniqueID.BRUTE_FORCE,
            summary="Brute force",
            severity=EventSeverity.HIGH,
            confidence=0.8,
        )
        instruction = self.dispatcher.dispatch(event)
        self.assertNotEqual(instruction.urgency, DispatchUrgency.DISCARD)

    def test_low_confidence_low_severity_discarded(self):
        event = Event(
            source=EventSource.HEARTBEAT,
            technique_id=TechniqueID.NONE,
            summary="Heartbeat",
            severity=EventSeverity.DEBUG,
            confidence=0.1,
        )
        instruction = self.dispatcher.dispatch(event)
        self.assertEqual(instruction.urgency, DispatchUrgency.DISCARD)

    def test_dedup_same_event_id(self):
        event = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.INJECTION,
            summary="Dup test",
            severity=EventSeverity.HIGH,
            confidence=0.7,
        )
        first = self.dispatcher.dispatch(event)
        second = self.dispatcher.dispatch(event)
        self.assertEqual(first.agent_name, "InjectionAgent")
        self.assertEqual(second.urgency, DispatchUrgency.DISCARD)

    def test_dispatch_batch(self):
        events = [
            Event(
                source=EventSource.AGENT,
                technique_id=TechniqueID.INJECTION,
                summary="E1",
                severity=EventSeverity.HIGH,
                confidence=0.7,
            ),
            Event(
                source=EventSource.HEARTBEAT,
                technique_id=TechniqueID.NONE,
                summary="E2",
                severity=EventSeverity.INFO,
                confidence=0.1,
            ),
            Event(
                source=EventSource.SECRET_SCAN,
                technique_id=TechniqueID.SECRETS_FROM_STORE,
                summary="E3",
                severity=EventSeverity.CRITICAL,
                confidence=0.9,
            ),
        ]
        results = self.dispatcher.dispatch_batch(events)
        # Heartbeat should be filtered out
        agent_names = [r.agent_name for r in results]
        self.assertIn("InjectionAgent", str(agent_names))
        self.assertIn("SecretScanner", str(agent_names))

    def test_technique_mapped_to_agent(self):
        event = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.INJECTION,
            summary="Test",
            severity=EventSeverity.HIGH,
            confidence=0.7,
        )
        instruction = self.dispatcher.dispatch(event)
        self.assertIn("Injection", instruction.agent_name)

    def test_unknown_technique_routed_to_triage(self):
        event = Event(
            source=EventSource.LOG_LINE,
            technique_id=TechniqueID.UNKNOWN,
            summary="Unknown oddity",
            severity=EventSeverity.HIGH,
            confidence=0.5,
        )
        instruction = self.dispatcher.dispatch(event)
        self.assertEqual(instruction.agent_name, "TriageAgent")

    def test_whitelist_filtering(self):
        dispatcher = Dispatcher(min_confidence=0.3, agent_whitelist={"InjectionAgent"})
        event = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.INJECTION,
            summary="Test",
            severity=EventSeverity.HIGH,
            confidence=0.7,
        )
        instruction = dispatcher.dispatch(event)
        self.assertNotEqual(instruction.urgency, DispatchUrgency.DISCARD)

        # Secret scan event should be discarded (SecretScanner not in whitelist)
        secret_event = Event(
            source=EventSource.SECRET_SCAN,
            technique_id=TechniqueID.SECRETS_FROM_STORE,
            summary="Secret",
            severity=EventSeverity.HIGH,
            confidence=0.9,
        )
        secret_instruction = dispatcher.dispatch(secret_event)
        self.assertEqual(secret_instruction.urgency, DispatchUrgency.DISCARD)


class TestDispatchUrgency(TestCase):
    def test_dispatch_urgency_ordered_by_severity(self):
        dispatcher = Dispatcher(min_confidence=0.1)
        cases = [
            (EventSeverity.CRITICAL, 0.9, DispatchUrgency.SYNC_BLOCK),
            (EventSeverity.CRITICAL, 0.5, DispatchUrgency.SYNC_INVESTIGATE),
            (EventSeverity.HIGH, 0.7, DispatchUrgency.SYNC_INVESTIGATE),
            (EventSeverity.HIGH, 0.3, DispatchUrgency.ASYNC_PRIORITY),
            (EventSeverity.MEDIUM, 0.7, DispatchUrgency.ASYNC_PRIORITY),
            (EventSeverity.MEDIUM, 0.3, DispatchUrgency.ASYNC_NORMAL),
            (EventSeverity.LOW, 0.5, DispatchUrgency.ASYNC_NORMAL),
        ]
        for sev, conf, expected in cases:
            event = Event(
                source=EventSource.AGENT,
                technique_id=TechniqueID.INJECTION,
                summary="",
                severity=sev,
                confidence=conf,
            )
            instruction = dispatcher.dispatch(event)
            self.assertEqual(instruction.urgency, expected)


class TestDispatcherEdgeCases(TestCase):
    def test_no_technique_mapped(self):
        dispatcher = Dispatcher(min_confidence=0.1)
        event = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.COLLECTION,
            summary="Collection",
            severity=EventSeverity.LOW,
            confidence=0.3,
        )
        instruction = dispatcher.dispatch(event)
        self.assertEqual(instruction.urgency, DispatchUrgency.DISCARD)

    def test_empty_payload(self):
        dispatcher = Dispatcher(min_confidence=0.3)
        event = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.INJECTION,
            summary="Test",
            severity=EventSeverity.HIGH,
            confidence=0.7,
        )
        instruction = dispatcher.dispatch(event)
        self.assertIsNotNone(instruction)
        self.assertEqual(instruction.payload, {})
