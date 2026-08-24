"""Unit tests for patchi.core.fix.patch"""

import unittest

from patchi.core.fix.patch import (
    FileChange,
    Patch,
    PatchState,
    PatchType,
    compute_confidence,
    compute_risk_score,
)


def _make_change(
    path="src/app.py", original="def foo():\n    pass\n", proposed="def foo():\n    return 1\n"
) -> FileChange:
    return FileChange(path=path, original=original, proposed=proposed)


class TestFileChange(unittest.TestCase):
    def test_diff_computed_on_creation(self):
        c = _make_change()
        self.assertNotEqual(c.diff, "")
        self.assertIn("---", c.diff)
        self.assertIn("+++", c.diff)

    def test_lines_added(self):
        c = _make_change(
            original="def foo():\n    pass\n",
            proposed="def foo():\n    x = 1\n    return x\n",
        )
        self.assertGreater(c.lines_added, 0)

    def test_lines_removed(self):
        c = _make_change(
            original="def foo():\n    old_line = 1\n    pass\n",
            proposed="def foo():\n    pass\n",
        )
        self.assertGreater(c.lines_removed, 0)

    def test_lines_changed_sum(self):
        c = _make_change()
        self.assertEqual(c.lines_changed, c.lines_added + c.lines_removed)

    def test_to_dict_keys(self):
        c = _make_change()
        d = c.to_dict()
        for key in ("path", "diff", "lines_added", "lines_removed"):
            self.assertIn(key, d)

    def test_no_diff_for_identical_content(self):
        same = "def foo():\n    pass\n"
        c = FileChange(path="a.py", original=same, proposed=same)
        self.assertEqual(c.diff.strip(), "")


class TestPatch(unittest.TestCase):
    def _make_patch(self) -> Patch:
        return Patch(
            agent="CodeFixer",
            patch_type=PatchType.BUG_FIX,
            changes=[_make_change()],
            description="Fix null check",
            risk_score=15,
            confidence=90,
        )

    def test_id_auto_generated(self):
        p = self._make_patch()
        self.assertIsNotNone(p.id)
        self.assertEqual(len(p.id), 8)

    def test_proposed_at_set(self):
        p = self._make_patch()
        self.assertNotEqual(p.proposed_at, "")

    def test_state_defaults_to_proposed(self):
        p = self._make_patch()
        self.assertEqual(p.state, PatchState.PROPOSED)

    def test_file_count(self):
        p = self._make_patch()
        self.assertEqual(p.file_count, 1)

    def test_affected_paths(self):
        p = self._make_patch()
        self.assertIn("src/app.py", p.affected_paths)

    def test_risk_level_low(self):
        p = self._make_patch()
        p.risk_score = 15
        self.assertEqual(p.risk_level, "low")

    def test_risk_level_medium(self):
        p = self._make_patch()
        p.risk_score = 45
        self.assertEqual(p.risk_level, "medium")

    def test_risk_level_high(self):
        p = self._make_patch()
        p.risk_score = 75
        self.assertEqual(p.risk_level, "high")

    def test_to_dict_has_required_keys(self):
        p = self._make_patch()
        d = p.to_dict()
        for key in (
            "id",
            "agent",
            "patch_type",
            "risk_score",
            "risk_level",
            "confidence",
            "state",
            "changes",
            "description",
        ):
            self.assertIn(key, d)

    def test_from_dict_roundtrip(self):
        p = self._make_patch()
        d = p.to_dict()
        p2 = Patch.from_dict(d)
        self.assertEqual(p2.id, p.id)
        self.assertEqual(p2.agent, p.agent)
        self.assertEqual(p2.risk_score, p.risk_score)
        self.assertEqual(p2.confidence, p.confidence)
        self.assertEqual(p2.description, p.description)


class TestRiskScorer(unittest.TestCase):
    def _change(self, path="src/app.py", lines=5) -> FileChange:
        orig = "\n".join(f"line_{i} = {i}" for i in range(lines)) + "\n"
        prop = "\n".join(f"line_{i} = {i + 1}" for i in range(lines)) + "\n"
        return FileChange(path=path, original=orig, proposed=prop)

    def test_single_small_change_is_low_risk(self):
        changes = [self._change()]
        score = compute_risk_score(changes)
        self.assertLessEqual(score, 30)

    def test_many_files_increases_risk(self):
        single = compute_risk_score([self._change()])
        multi = compute_risk_score([self._change(f"src/f{i}.py") for i in range(5)])
        self.assertGreater(multi, single)

    def test_auth_path_increases_risk(self):
        safe_score = compute_risk_score([self._change("src/utils.py")])
        auth_score = compute_risk_score([self._change("src/auth/middleware.py")])
        self.assertGreater(auth_score, safe_score)

    def test_payment_path_increases_risk(self):
        score = compute_risk_score([self._change("src/billing/stripe.py")])
        self.assertGreaterEqual(score, 25)

    def test_high_blast_radius_increases_risk(self):
        low_br = compute_risk_score([self._change()], blast_radius=1)
        high_br = compute_risk_score([self._change()], blast_radius=15)
        self.assertGreater(high_br, low_br)

    def test_score_capped_at_100(self):
        huge_changes = [self._change(f"src/auth/f{i}.py", lines=50) for i in range(10)]
        score = compute_risk_score(huge_changes, blast_radius=20)
        self.assertLessEqual(score, 100)

    def test_score_minimum_is_0(self):
        score = compute_risk_score([])
        self.assertGreaterEqual(score, 0)

    def test_migration_path_increases_risk(self):
        score = compute_risk_score([self._change("migrations/0042_add_users.py")])
        self.assertGreaterEqual(score, 20)

    def test_extra_signals(self):
        base = compute_risk_score([self._change()])
        extra = compute_risk_score([self._change()], extra_signals={"touches_contract": True})
        self.assertGreater(extra, base)


class TestConfidenceScorer(unittest.TestCase):
    def _change(self) -> FileChange:
        return _make_change()

    def test_perfect_conditions(self):
        score = compute_confidence([self._change()])
        self.assertEqual(score, 100)

    def test_low_agent_certainty_reduces_score(self):
        high = compute_confidence([self._change()], agent_certainty=1.0)
        low = compute_confidence([self._change()], agent_certainty=0.5)
        self.assertGreater(high, low)

    def test_parse_errors_reduce_score(self):
        clean = compute_confidence([self._change()], has_parse_errors=False)
        errors = compute_confidence([self._change()], has_parse_errors=True)
        self.assertGreater(clean, errors)

    def test_no_test_coverage_reduces_score(self):
        covered = compute_confidence([self._change()], has_test_coverage=True)
        uncovered = compute_confidence([self._change()], has_test_coverage=False)
        self.assertGreater(covered, uncovered)

    def test_multiple_interpretations_reduces_score(self):
        single = compute_confidence([self._change()], multiple_interpretations=False)
        multi = compute_confidence([self._change()], multiple_interpretations=True)
        self.assertGreater(single, multi)

    def test_score_capped_at_100(self):
        score = compute_confidence([self._change()], agent_certainty=2.0)
        self.assertLessEqual(score, 100)

    def test_score_minimum_is_0(self):
        score = compute_confidence(
            [self._change()],
            agent_certainty=0.0,
            has_parse_errors=True,
            has_test_coverage=False,
            multiple_interpretations=True,
        )
        self.assertGreaterEqual(score, 0)


if __name__ == "__main__":
    unittest.main()
