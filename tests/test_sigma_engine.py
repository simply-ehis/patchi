"""Tests for Sigma rule loading, parsing, and matching."""

from __future__ import annotations

from pathlib import Path
from unittest import TestCase

from patchi.core.detector.event import Event, EventSeverity, EventSource, TechniqueID
from patchi.core.detector.sigma_engine import SigmaRuleSet, sigma_match_to_event

SAMPLE_RULE = """
title: SQL Injection Rule
id: test-001
description: Detects SQL injection patterns
status: stable
level: high
tags:
  - attack.t1190
  - cwe.89
logsource:
  category: webserver
  product: http
detection:
  selection_sqli:
    event.payload.query|contains: "SELECT"
  condition: selection_sqli
falsepositives:
  - "ORM usage"
"""

SAMPLE_RULE_COMPOUND = """
title: Compound Rule Test
id: test-002
status: stable
level: medium
tags:
  - attack.t1110
logsource:
  category: patchi_finding
  product: patchi
detection:
  selection_source:
    event.source: "agent"
  selection_agent:
    event.agent_name: "AuthAgent"
  condition: selection_source and selection_agent
"""


class TestSigmaRuleParsing(TestCase):
    def test_parse_basic_rule(self):
        ruleset = SigmaRuleSet.load_text(SAMPLE_RULE)
        self.assertEqual(ruleset.count, 1)
        rule = ruleset._rules[0]
        self.assertEqual(rule.title, "SQL Injection Rule")
        self.assertEqual(rule.id, "test-001")
        self.assertEqual(rule.level, "high")
        self.assertEqual(rule.technique_id, TechniqueID.INITIAL_ACCESS)

    def test_parse_compound_rule(self):
        ruleset = SigmaRuleSet.load_text(SAMPLE_RULE_COMPOUND)
        self.assertEqual(ruleset.count, 1)
        rule = ruleset._rules[0]
        self.assertEqual(rule.technique_id, TechniqueID.BRUTE_FORCE)
        self.assertIn("selection_source", rule.selections)
        self.assertIn("selection_agent", rule.selections)

    def test_parse_empty_returns_empty(self):
        ruleset = SigmaRuleSet.load_text("")
        self.assertEqual(ruleset.count, 0)

    def test_parse_invalid_returns_empty(self):
        ruleset = SigmaRuleSet.load_text("not: valid: yaml: [")
        self.assertEqual(ruleset.count, 0)


class TestSigmaMatching(TestCase):
    def test_basic_match(self):
        ruleset = SigmaRuleSet.load_text(SAMPLE_RULE)
        event = Event(
            source=EventSource.HTTP_TRAFFIC,
            technique_id=TechniqueID.INITIAL_ACCESS,
            summary="SQL injection attempt",
            severity=EventSeverity.HIGH,
            payload={"query": "SELECT * FROM users WHERE id=1; DROP TABLE users--"},
            source_details={"category": "webserver", "product": "http"},
        )
        matches = ruleset.match(event)
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0].technique_id, TechniqueID.INITIAL_ACCESS)

    def test_no_match_wrong_source(self):
        ruleset = SigmaRuleSet.load_text(SAMPLE_RULE)
        event = Event(
            source=EventSource.HEARTBEAT,
            technique_id=TechniqueID.NONE,
            summary="Heartbeat",
            payload={},
            source_details={"category": "system", "product": "health"},
        )
        matches = ruleset.match(event)
        self.assertEqual(len(matches), 0)

    def test_compound_match(self):
        ruleset = SigmaRuleSet.load_text(SAMPLE_RULE_COMPOUND)
        event = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.BRUTE_FORCE,
            summary="Auth agent dispatch",
            agent_name="AuthAgent",
            source_details={"category": "patchi_finding", "product": "patchi"},
        )
        matches = ruleset.match(event)
        self.assertGreater(len(matches), 0)

    def test_compound_no_match(self):
        ruleset = SigmaRuleSet.load_text(SAMPLE_RULE_COMPOUND)
        event = Event(
            source=EventSource.AGENT,
            technique_id=TechniqueID.INJECTION,
            summary="Injection agent dispatch",
            agent_name="InjectionAgent",
        )
        matches = ruleset.match(event)
        self.assertEqual(len(matches), 0)


class TestSigmaRuleToEvent(TestCase):
    def test_sigma_match_to_event(self):
        ruleset = SigmaRuleSet.load_text(SAMPLE_RULE)
        event = Event(
            source=EventSource.HTTP_TRAFFIC,
            technique_id=TechniqueID.INITIAL_ACCESS,
            summary="Test",
            payload={"query": "SELECT * FROM users"},
            source_details={"category": "webserver", "product": "http"},
        )
        matches = ruleset.match(event)
        self.assertGreater(len(matches), 0)

        result_event = sigma_match_to_event(matches[0], parent_event=event)
        self.assertEqual(result_event.source, EventSource.HTTP_TRAFFIC)
        self.assertEqual(result_event.technique_id, TechniqueID.INITIAL_ACCESS)
        self.assertGreaterEqual(result_event.confidence, 0.5)


class TestSigmaLoadedFromDirectory(TestCase):
    def test_load_directory(self):
        rules_dir = Path(__file__).parent.parent / "patchi" / "core" / "detector" / "sigmarules"
        if rules_dir.exists():
            ruleset = SigmaRuleSet.load_directory(rules_dir)
            self.assertGreater(ruleset.count, 0)


class TestWildcardMatching(TestCase):
    def test_wildcard_match(self):
        ruleset = SigmaRuleSet.load_text(SAMPLE_RULE)
        event = Event(
            source=EventSource.HTTP_TRAFFIC,
            technique_id=TechniqueID.INJECTION,
            summary="SQLi",
            payload={"query": "SELECT password FROM users WHERE id=1"},
            source_details={"category": "webserver", "product": "http"},
        )
        matches = ruleset.match(event)
        self.assertGreater(len(matches), 0)

    def test_wildcard_no_match(self):
        ruleset = SigmaRuleSet.load_text(SAMPLE_RULE)
        event = Event(
            source=EventSource.HTTP_TRAFFIC,
            technique_id=TechniqueID.INJECTION,
            summary="Normal request",
            payload={"query": "GET /api/users"},
            source_details={"category": "webserver", "product": "http"},
        )
        matches = ruleset.match(event)
        self.assertEqual(len(matches), 0)
