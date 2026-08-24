"""Unit tests for patchi.core.fix.risk_gate"""

import tempfile
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.constants import Mode
from patchi.core.fix.patch import FileChange, Patch, PatchType
from patchi.core.fix.risk_gate import RiskGate


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


def _make_patch(risk_score=10, confidence=90, blast_radius=0, paths=("src/utils.py",)) -> Patch:
    changes = []
    for path in paths:
        changes.append(
            FileChange(
                path=path,
                original="def foo():\n    pass\n",
                proposed="def foo():\n    return 1\n",
            )
        )
    p = Patch(
        agent="CodeFixer",
        patch_type=PatchType.BUG_FIX,
        changes=changes,
        description="Test patch",
        risk_score=risk_score,
        confidence=confidence,
        blast_radius=blast_radius,
    )
    return p


class TestRiskGateBlocked(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_blocks_when_contract_not_locked(self):
        # Brain has no contract_locked flag
        gate = RiskGate(self.root)
        patch = _make_patch()
        result = gate.evaluate(patch)
        self.assertTrue(result.is_blocked)
        self.assertIn("contract", result.reason.lower())

    def test_blocks_no_touch_path(self):
        # Lock contract first
        brain = mem.get_brain(self.root)
        brain["contract_locked"] = True
        mem.save_brain(brain, self.root)

        # Add a no-touch restriction
        cfg.add_restriction(
            "payments/",
            __import__(
                "patchi.core.constants", fromlist=["RestrictionType"]
            ).RestrictionType.NO_TOUCH,
            root=self.root,
        )

        gate = RiskGate(self.root)
        patch = _make_patch(paths=("payments/stripe.py",))
        result = gate.evaluate(patch)
        self.assertTrue(result.is_blocked)
        self.assertTrue(any("restricted" in b.lower() for b in result.blocks))

    def test_blocks_high_risk_without_blast_radius(self):
        brain = mem.get_brain(self.root)
        brain["contract_locked"] = True
        mem.save_brain(brain, self.root)

        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=75, blast_radius=0)  # high risk, no blast data
        result = gate.evaluate(patch)
        self.assertTrue(result.is_blocked)
        self.assertTrue(result.requires_blast_report)

    def test_high_risk_with_blast_radius_not_blocked_by_blast(self):
        brain = mem.get_brain(self.root)
        brain["contract_locked"] = True
        mem.save_brain(brain, self.root)

        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=75, blast_radius=3)  # blast provided
        result = gate.evaluate(patch)
        # Should not be blocked due to missing blast radius
        self.assertFalse(result.requires_blast_report)


class TestRiskGateConfirmMode(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))
        brain = mem.get_brain(self.root)
        brain["contract_locked"] = True
        mem.save_brain(brain, self.root)
        cfg.set_mode(Mode.CONFIRM, self.root)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_confirm_mode_always_requires_review(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=5)  # very low risk
        result = gate.evaluate(patch)
        self.assertFalse(result.is_blocked)
        self.assertTrue(result.needs_review)

    def test_confirm_mode_high_risk_still_review_not_block(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=40, blast_radius=3)
        result = gate.evaluate(patch)
        self.assertFalse(result.is_blocked)
        self.assertTrue(result.needs_review)


class TestRiskGateAutoMode(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))
        brain = mem.get_brain(self.root)
        brain["contract_locked"] = True
        mem.save_brain(brain, self.root)
        cfg.set_mode(Mode.AUTO, self.root)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_auto_low_risk_allows_auto_apply(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=10)
        result = gate.evaluate(patch)
        self.assertFalse(result.is_blocked)
        self.assertTrue(result.is_auto)

    def test_auto_medium_risk_requires_review(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=50, blast_radius=3)
        result = gate.evaluate(patch)
        self.assertFalse(result.is_blocked)
        self.assertTrue(result.needs_review)

    def test_auto_threshold_boundary_low_side(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=30)  # exactly at threshold
        result = gate.evaluate(patch)
        self.assertTrue(result.is_auto)

    def test_auto_threshold_boundary_high_side(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=31, blast_radius=3)  # just over threshold
        result = gate.evaluate(patch)
        self.assertTrue(result.needs_review)


class TestRiskGateAutopilotMode(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))
        brain = mem.get_brain(self.root)
        brain["contract_locked"] = True
        mem.save_brain(brain, self.root)
        cfg.set_mode(Mode.AUTOPILOT, self.root)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_autopilot_always_auto_applies(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=50, blast_radius=3)
        result = gate.evaluate(patch)
        self.assertFalse(result.is_blocked)
        self.assertTrue(result.is_auto)

    def test_autopilot_high_risk_warns(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=80, blast_radius=3)
        result = gate.evaluate(patch)
        self.assertTrue(result.is_auto)
        self.assertTrue(any("AUTOPILOT" in w or "autopilot" in w.lower() for w in result.warnings))


class TestGateResult(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))
        brain = mem.get_brain(self.root)
        brain["contract_locked"] = True
        mem.save_brain(brain, self.root)
        cfg.set_mode(Mode.AUTO, self.root)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_warnings_on_low_confidence(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=10, confidence=50)
        result = gate.evaluate(patch)
        self.assertTrue(any("confidence" in w.lower() for w in result.warnings))

    def test_warnings_on_high_blast_radius(self):
        gate = RiskGate(self.root)
        patch = _make_patch(risk_score=10, blast_radius=15)
        result = gate.evaluate(patch)
        self.assertTrue(any("blast" in w.lower() for w in result.warnings))

    def test_to_dict_keys(self):
        gate = RiskGate(self.root)
        patch = _make_patch()
        result = gate.evaluate(patch)
        d = result.to_dict()
        for key in ("decision", "reason", "patch_id", "risk_score", "risk_level"):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main()
