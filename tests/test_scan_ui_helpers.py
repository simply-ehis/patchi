"""Unit tests for scan UI helpers, browser evidence schema, flake evidence."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from patchi.cli.commands.scan_cmd import (
    banner_test_stems,
    discover_test_stems,
    provenance_badge,
    uncovered_critical_flow_ids,
)
from patchi.core.agents.base import AgentResult, AgentStatus
from patchi.core.agents.governor import Governor
from patchi.core.testing._browser import evidence_payload
from patchi.core.testing.coverage_prioritizer import test_stems_from_paths as shared_stems


def _flow(fid: str, critical: bool, files: list) -> SimpleNamespace:
    return SimpleNamespace(id=fid, critical=critical, files=files)


class TestProvenanceBadge(unittest.TestCase):
    def test_offline(self):
        badge, is_offline = provenance_badge({"contract_provenance": "offline-inferred"})
        self.assertIn("offline-inferred", badge)
        self.assertTrue(is_offline)

    def test_ai_and_confirmed(self):
        for prov in ("ai-inferred", "user-confirmed"):
            badge, is_offline = provenance_badge({"contract_provenance": prov})
            self.assertIn(prov, badge)
            self.assertFalse(is_offline)

    def test_unknown_and_missing(self):
        self.assertEqual(provenance_badge({"contract_provenance": "[link=evil]"}), ("", False))
        self.assertEqual(provenance_badge({}), ("", False))
        self.assertEqual(provenance_badge(None), ("", False))


class TestUncoveredIds(unittest.TestCase):
    def test_critical_without_test_listed(self):
        flows = [_flow("api", True, ["src/api.py"]), _flow("web", True, ["src/web.py"])]
        self.assertEqual(uncovered_critical_flow_ids(flows, {"api"}), ["web"])

    def test_noncritical_and_fileless_ignored(self):
        flows = [_flow("a", False, ["src/a.py"]), _flow("b", True, [])]
        self.assertEqual(uncovered_critical_flow_ids(flows, set()), [])

    def test_case_insensitive(self):
        flows = [_flow("api", True, ["src/API.py"])]
        self.assertEqual(uncovered_critical_flow_ids(flows, {"api"}), [])

    def test_none_flows(self):
        self.assertEqual(uncovered_critical_flow_ids(None, set()), [])


class TestDiscoverStems(unittest.TestCase):
    def test_finds_and_normalizes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "test_foo.py").write_text("x = 1")
            (root / "sub").mkdir()
            (root / "sub" / "test_bar.py").write_text("x = 1")
            (root / ".patchi").mkdir()
            (root / ".patchi" / "test_nope.py").write_text("x = 1")
            stems = discover_test_stems(root)
            self.assertIn("foo", stems)
            self.assertIn("bar", stems)
            self.assertNotIn("nope", stems)

    def test_prunes_heavy_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "test_ok.py").write_text("x = 1")
            for junk in ("node_modules", ".git", ".venv", "dist", "build"):
                d = root / junk
                d.mkdir()
                (d / "test_junk.py").write_text("x = 1")
            self.assertEqual(discover_test_stems(root), {"ok"})


class TestSharedStems(unittest.TestCase):
    def test_single_implementation(self):
        paths = ["tests/test_foo.py", "src/x.py", "__pycache__/test_q.py", ".patchi/test_n.py"]
        self.assertEqual(shared_stems(paths), {"foo"})

    def test_banner_prefers_file_infos(self):
        rep = SimpleNamespace(
            area=None,
            file_infos=[
                SimpleNamespace(path="tests/test_foo.py"),
                SimpleNamespace(path="src/foo.py"),
            ],
        )
        # Would raise if it tried to walk: root does not exist.
        self.assertEqual(banner_test_stems(rep, Path("/nonexistent-root-xyz")), {"foo"})


class TestEvidencePayload(unittest.TestCase):
    def test_relative_and_truncation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ev = evidence_payload(
                screenshot=root / "shot.png",
                status=500,
                console_errors=["e1", "e2", "e3", "e4", "e5", "e6"],
                root=root,
            )
            self.assertEqual(ev["screenshot"], "shot.png")
            self.assertEqual(ev["http_status"], 500)
            self.assertEqual(len(ev["console_errors"]), 5)
            self.assertIsNone(ev["video"])

    def test_outside_root_basename_only(self):
        ev = evidence_payload(screenshot="/etc/secret/shot.png", root=Path("/repo"))
        self.assertEqual(ev["screenshot"], "shot.png")
        self.assertNotIn("/etc", ev["screenshot"])


class TestFlakeEvidence(unittest.TestCase):
    def _gov(self):
        t = Path(tempfile.mkdtemp())
        (t / ".patchi").mkdir(exist_ok=True)
        return Governor(t), t

    def _candidate(self, score: float = 0.9):
        return {
            "agent_name": "Fixer",
            "score": score,
            "findings": 0,
            "breakdown": {},
        }

    def _result(self):
        r = AgentResult(agent_name="Fixer", status=AgentStatus.DONE)
        r.data.update({"patches": []})
        return r

    def test_flake_key_present_when_clean(self):
        g, _ = self._gov()
        try:
            g._last_candidates = [self._candidate()]
            g._last_fix_results = [self._result()]
            res = g.run_score_select()
            self.assertIn("flake", res.data["evidence"])
            self.assertEqual(res.data["evidence"]["flake"]["flaky_count"], 0)
        finally:
            g.close()

    def test_detector_failure_is_unknown_not_zero(self):
        import patchi.core.testing.flake_detector_agent as flake_mod

        g, _ = self._gov()
        orig = flake_mod._detect_flaky_tests
        flake_mod._detect_flaky_tests = lambda root: (_ for _ in ()).throw(RuntimeError("db gone"))
        try:
            g._last_candidates = [self._candidate()]
            g._last_fix_results = [self._result()]
            res = g.run_score_select()
            flake = res.data["evidence"]["flake"]
            self.assertIsNone(flake["flaky_count"])
            self.assertIn("error", flake)
        finally:
            flake_mod._detect_flaky_tests = orig
            g.close()


if __name__ == "__main__":
    unittest.main()
