"""Unit tests for output redaction + pipeline deadline helpers."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from patchi.core.security.redact import redact_finding, redact_text
from patchi.core.agents.base import AgentStatus
from patchi.core.agents.governor import Governor, PipelinePhase


class TestRedactText(unittest.TestCase):
    def test_provider_prefix(self):
        out = redact_text("key = 'AKIA4Q7X9K2M5P8R3T6V1'")
        self.assertIn("[REDACTED]", out)
        self.assertNotIn("AKIA4Q7X9K2M5P8R3T6V1", out)

    def test_assignment_with_quote_kept(self):
        out = redact_text('password = "supersecretvalue123"')
        self.assertEqual(out, 'password = "[REDACTED]"')

    def test_placeholders_survive(self):
        for placeholder in ('password = "changeme"', "token = '<your-token>'", 'key = "xxx"'):
            self.assertNotIn("[REDACTED]", redact_text(placeholder), placeholder)

    def test_prose_survives(self):
        text = "Normal prose with no secrets at all here."
        self.assertEqual(redact_text(text), text)

    def test_empty_and_none(self):
        self.assertEqual(redact_text(""), "")
        self.assertEqual(redact_text(None), "")

    def test_high_entropy_blob(self):
        blob = "q7x9k2m5p8r3t6v1y4q7x9k2m5p8r3t6v1y4q7"
        self.assertEqual(redact_text(f"token {blob} here"), "token [REDACTED] here")


class TestRedactFinding(unittest.TestCase):
    def test_identity_preserved_values_scrubbed(self):
        finding = {
            "file": "a.py",
            "line": 3,
            "type": "sql_injection",
            "severity": "high",
            "cwe": "CWE-89",
            "agent": "InjectionAgent",
            "message": 'db password = "supersecretvalue123" failed',
            "code_snippet": "password = \"supersecretvalue123\"",
        }
        out = redact_finding(finding)
        self.assertEqual(out["file"], "a.py")
        self.assertEqual(out["line"], 3)
        self.assertEqual(out["type"], "sql_injection")
        self.assertNotIn("supersecret", out["message"])
        self.assertNotIn("supersecret", out["code_snippet"])
        # Input untouched (copy, not mutate).
        self.assertIn("supersecret", finding["message"])


class TestDeadlineHelpers(unittest.TestCase):
    def _gov(self):
        t = Path(tempfile.mkdtemp())
        (t / ".patchi").mkdir(exist_ok=True)
        return Governor(t)

    def test_past_deadline(self):
        g = self._gov()
        try:
            self.assertIsNone(g._past_deadline(None, 0.0))
            self.assertIsNone(g._past_deadline(60.0, time.monotonic()))
            elapsed = g._past_deadline(0.0, time.monotonic() - 5)
            self.assertIsNotNone(elapsed)
            self.assertGreaterEqual(elapsed, 5)
        finally:
            g.close()

    def test_deadline_skips_shape(self):
        g = self._gov()
        try:
            skips = g._deadline_skips(PipelinePhase.SCAN, 60, 61.0)
            phases = [s.phase for s in skips]
            # Every later phase present exactly once, terminal states excluded.
            self.assertIn(PipelinePhase.SCORE_SELECT, phases)
            self.assertNotIn(PipelinePhase.COMPLETE, phases)
            self.assertNotIn(PipelinePhase.FAILED, phases)
            self.assertNotIn(PipelinePhase.SCAN, phases)
            for s in skips:
                self.assertEqual(s.status, AgentStatus.SKIPPED)
                self.assertFalse(s.passed)
                self.assertTrue(s.data.get("deadline_exceeded"))
                self.assertIn("--timeout-minutes", s.errors[0])
        finally:
            g.close()


if __name__ == "__main__":
    unittest.main()
