"""Unit tests for finding matcher, client builders, and the retest loop."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from patchi.cli.commands.report_cmd import _cwe_link, _exec_verdict, _remediation_for
from patchi.cli.commands.retest_cmd import _rerun_agent, finding_key, match_findings

VULN = "import sqlite3\n\n\ndef get_user(user_id):\n    c = sqlite3.connect('a.db').cursor()\n    c.execute('SELECT * FROM users WHERE id = ' + user_id)\n    return c.fetchall()\n"
FIXED = "import sqlite3\n\n\ndef get_user(user_id):\n    c = sqlite3.connect('a.db').cursor()\n    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n    return c.fetchall()\n"


def _finding(file="a.py", type="sql_injection", line=5, **kw):
    d = {"file": file, "type": type, "line": line, "message": f"{type} at {file}:{line}"}
    d.update(kw)
    return d


class TestMatcher(unittest.TestCase):
    def test_fixed_persisting_new(self):
        base = [_finding(line=5), _finding(file="b.py", type="xss", line=10)]
        curr = [_finding(line=8)]  # drifted 3 lines: persists
        diff = match_findings(base, curr)
        self.assertEqual(len(diff["fixed"]), 1)
        self.assertEqual(diff["fixed"][0]["file"], "b.py")
        self.assertEqual(len(diff["persisting"]), 1)
        self.assertEqual(diff["new"], [])

    def test_beyond_tolerance_is_fix_plus_new(self):
        base = [_finding(line=5)]
        curr = [_finding(line=50)]
        diff = match_findings(base, curr)
        self.assertEqual(len(diff["fixed"]), 1)
        self.assertEqual(len(diff["new"]), 1)

    def test_type_change_is_not_a_match(self):
        base = [_finding(type="sql_injection")]
        curr = [_finding(type="command_injection")]
        diff = match_findings(base, curr)
        self.assertEqual(len(diff["fixed"]), 1)
        self.assertEqual(len(diff["new"]), 1)

    def test_empty_both_ways(self):
        self.assertEqual(match_findings([], []), {"fixed": [], "persisting": [], "new": []})
        diff = match_findings([], [_finding()])
        self.assertEqual(len(diff["new"]), 1)

    def test_finding_key(self):
        self.assertEqual(finding_key(_finding()), ("a.py", "sql_injection"))


class TestClientBuilders(unittest.TestCase):
    def test_verdicts(self):
        self.assertTrue(_exec_verdict({"finding_totals": {"critical": 2, "high": 0}}).startswith("NOT READY"))
        self.assertTrue(_exec_verdict({"finding_totals": {"critical": 0, "high": 1}}).startswith("CONDITIONAL"))
        self.assertIn("not a guarantee", _exec_verdict({"finding_totals": {"critical": 0, "high": 0}}))

    def test_cwe_link(self):
        self.assertIn("cwe.mitre.org/data/definitions/89", _cwe_link("CWE-89"))
        self.assertEqual(_cwe_link(""), "—")
        self.assertEqual(_cwe_link("n/a"), "n/a")

    def test_remediation_prefers_suggestion(self):
        self.assertEqual(_remediation_for({"type": "x", "suggestion": "Do Y."}), "Do Y.")
        self.assertIn("standard fix", _remediation_for({"type": "no-such-type-xyz"}))


class TestRetestLoop(unittest.TestCase):
    def test_fix_detected_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".patchi").mkdir(exist_ok=True)
            target = root / "db.py"
            target.write_text(VULN)
            status, before = _rerun_agent(root, "InjectionAgent")
            self.assertEqual(status, "ok")
            self.assertTrue(any(f["type"] == "sql_injection" for f in before))
            target.write_text(FIXED)
            status, after = _rerun_agent(root, "InjectionAgent")
            self.assertEqual(status, "ok")
            diff = match_findings(
                [{"file": "db.py", "type": "sql_injection", "line": 6, "message": "x"}],
                [{"file": f["file"], "type": f["type"], "line": f["line"]} for f in after],
            )
            self.assertEqual(len(diff["persisting"]), 0)
            self.assertGreaterEqual(len(diff["fixed"]), 1)

    def test_unknown_agent_reports_status(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".patchi").mkdir(exist_ok=True)
            status, findings = _rerun_agent(root, "NoSuchAgentXYZ")
            self.assertTrue(status.startswith("skipped:"))
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
