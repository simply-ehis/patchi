"""Tests for the reconstructed fix verify_loop module."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchi.core.fix.patch import FileChange, Patch
from patchi.core.fix.verify_loop import (
    MAX_RETRIES,
    VerifyOutcome,
    is_test_path,
    run_verify_loop,
    should_flag_for_review,
)


def _patch(paths: list[str]) -> Patch:
    p = Patch(id="t1", agent="test", patch_type="fix")
    p.changes = [FileChange(path=pth, original="", proposed="x") for pth in paths]
    return p


class TestIsTestPath:
    def test_patterns(self):
        assert is_test_path("tests/test_auth.py")
        assert is_test_path("src/auth_test.py")
        assert is_test_path("web/api.spec.ts")
        assert is_test_path("tests/helpers.py")          # dir marker
        assert not is_test_path("src/auth/login.py")
        assert not is_test_path("docs/testing-guide.md")


class TestWeakeningGuard:
    def test_only_test_changes_flagged(self):
        assert should_flag_for_review(_patch(["tests/test_a.py", "tests/test_b.py"]))

    def test_any_source_change_not_flagged(self):
        assert not should_flag_for_review(
            _patch(["tests/test_a.py", "src/auth.py"])
        )

    def test_empty_patch_not_flagged(self):
        assert not should_flag_for_review(_patch([]))


class _FakeResult:
    def __init__(self, success=True, test_passed=True, error=""):
        self.success = success
        self.test_passed = test_passed
        self.error = error


class _FakeApplier:
    def __init__(self, results: list[_FakeResult]):
        self.results = list(results)
        self.calls = 0

    def apply(self, patch):
        self.calls += 1
        return self.results[min(self.calls - 1, len(self.results) - 1)]


class TestRunVerifyLoop:
    def test_review_required_short_circuits(self, tmp_path: Path):
        calls = []

        applier = _FakeApplier([])
        outcome = run_verify_loop(
            _patch(["tests/x.py"]), root=tmp_path,
            applier=applier, log=calls.append,
        )
        assert outcome.review_required and not outcome.applied
        assert applier.calls == 0  # never touched the tree

    def test_verified_first_try(self, tmp_path: Path):
        test_file = tmp_path / "tests" / "test_ok.py"
        test_file.parent.mkdir(parents=True)
        test_file.write_text("def test_ok():\n    assert True\n", encoding="utf-8")

        patch = _patch(["src/mod.py"])
        patch.source_finding = {"type": "test_failure", "file": str(test_file)}
        outcome = run_verify_loop(patch, root=tmp_path, applier=_FakeApplier([_FakeResult()]))
        assert outcome.applied and outcome.verified and outcome.retries_used == 0

    def test_retries_then_honest_failure(self, tmp_path: Path):
        bad = tmp_path / "tests" / "test_bad.py"
        bad.parent.mkdir(parents=True)
        bad.write_text("def test_bad():\n    assert False\n", encoding="utf-8")

        patch = _patch(["src/mod.py"])
        patch.source_finding = {"type": "test_failure", "file": str(bad)}
        outcome = run_verify_loop(
            patch, root=tmp_path, applier=_FakeApplier([_FakeResult()]),
            log=lambda m: None,
        )
        # applied attempts happened but never verified; rolled back honestly
        assert not outcome.verified
        assert outcome.retries_used == MAX_RETRIES
        assert outcome.reason

    def test_apply_error_uses_reason(self, tmp_path: Path):
        patch = _patch(["src/mod.py"])
        patch.source_finding = {}
        outcome = run_verify_loop(
            patch, root=tmp_path,
            applier=_FakeApplier([_FakeResult(success=False, error="boom")]),
        )
        assert not outcome.applied
        assert "boom" in outcome.reason

    def test_no_target_test_falls_back_to_applier_signal(self, tmp_path: Path):
        patch = _patch(["src/mod.py"])
        patch.source_finding = {"type": "bug"}
        outcome = run_verify_loop(
            patch, root=tmp_path,
            applier=_FakeApplier([_FakeResult(test_passed=True)]),
        )
        assert outcome.applied and outcome.verified


class TestOutcomeShape:
    def test_fields_exist_for_cli_contract(self):
        o = VerifyOutcome()
        # fix_cmd.py touches exactly these attributes:
        assert hasattr(o, "review_required")
        assert hasattr(o, "applied")
        assert hasattr(o, "verified")
        assert hasattr(o, "patch")
        assert hasattr(o, "reason")
        assert hasattr(o, "retries_used")
