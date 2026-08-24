"""Tests for the Self-Report Verifier (p verify)."""

from pathlib import Path

from patchi.core.brain.verify import (
    TestRun,
    VerifyReport,
    claim_holds,
    compute_regression,
    verify_project,
)


def _proj(tmp_path: Path) -> Path:
    (tmp_path / ".patchi").mkdir()
    return tmp_path


def test_parse_pytest_output():
    text = (
        "FAILED tests/test_x.py::test_a - assert 1 == 2\n"
        "FAILED tests/test_x.py::test_b - boom\n"
        "===== 2 failed, 12 passed, 1 skipped in 1.23s =====\n"
    )
    run = TestRun()
    # Use the internal parser via run_tests path by calling _parse through module.
    from patchi.core.brain.verify import _parse_pytest_output

    run = _parse_pytest_output(text)
    assert run.passed == 12
    assert run.failed == 2
    assert run.skipped == 1
    assert run.total == 15
    assert "tests/test_x.py::test_a" in run.failed_names
    assert "tests/test_x.py::test_b" in run.failed_names
    assert run.truthful is False


def test_compute_regression_no_baseline():
    run = TestRun(failed_names=["tests/a.py::t1"], exit_ok=False)
    reg = compute_regression(None, run, findings_count=2, charter_violations=0)
    assert reg["has_baseline"] is False
    assert reg["new_failures"] == ["tests/a.py::t1"]
    assert reg["new_findings"] == 2


def test_compute_regression_with_baseline():
    base = {"failed_names": ["tests/a.py::t1"], "findings_count": 1, "charter_violations": 0}
    # t1 resolved, t2 newly failing, 3 findings now (was 1).
    run = TestRun(failed_names=["tests/a.py::t2"], exit_ok=False)
    reg = compute_regression(base, run, findings_count=3, charter_violations=0)
    assert reg["has_baseline"] is True
    assert reg["new_failures"] == ["tests/a.py::t2"]
    assert reg["resolved_failures"] == ["tests/a.py::t1"]
    assert reg["new_findings"] == 2


def test_verify_project_reports_truth_with_stub(tmp_path):
    r = _proj(tmp_path)

    def good_runner(_root):
        return TestRun(command="pytest", passed=5, total=5, exit_ok=True)

    report = verify_project(r, test_runner=good_runner, run_scan=False)
    assert report.truthful is True
    assert "VERIFIED" in report.summary
    # Baseline persisted for next regression check.
    from patchi.core.brain.verify import load_baseline

    assert load_baseline(r) is not None


def test_verify_project_detects_regression(tmp_path):
    r = _proj(tmp_path)

    def good_runner(_root):
        return TestRun(command="pytest", passed=5, total=5, exit_ok=True)

    def bad_runner(_root):
        return TestRun(command="pytest", passed=4, failed=1, total=5, exit_ok=False,
                       failed_names=["tests/x.py::t_fail"])

    # First run establishes a green baseline.
    verify_project(r, test_runner=good_runner, run_scan=False)
    # Second run regresses.
    report = verify_project(r, test_runner=bad_runner, run_scan=False)
    assert report.truthful is False
    assert "tests/x.py::t_fail" in report.regression["new_failures"]
    assert "UNVERIFIED" in report.summary


def test_claim_holds():
    good = TestRun(command="pytest", passed=3, total=3, exit_ok=True)
    report = VerifyReport(test_run=good, truthful=good.truthful)
    assert claim_holds("tests pass", report) is True
    assert claim_holds("this works", report) is True

    bad = TestRun(command="pytest", passed=2, failed=1, total=3, exit_ok=False,
                  failed_names=["t"])
    report2 = VerifyReport(test_run=bad, truthful=bad.truthful)
    assert claim_holds("tests pass", report2) is False

