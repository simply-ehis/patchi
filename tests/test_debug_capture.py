"""Verify that the DAP-based debugger actually captures a real Python failure.

Run:  pytest tests/test_debug_capture.py -v
"""

from __future__ import annotations

from pathlib import Path

from patchi.core.debug import capture_exception

HERE = Path(__file__).parent
FIXTURE = HERE / "fixtures" / "debug_fail_target.py"
PYTEST_FIXTURE = HERE / "fixtures" / "debug_fail_pytest.py"


def test_capture_hits_on_type_error() -> None:
    """The debugger should catch the uncaught TypeError and return structured data."""
    cap = capture_exception(FIXTURE, timeout=30)
    assert cap is not None, "expected a capture (script should crash)"

    assert cap.exception, "capture should include exception description"
    assert cap.frames, "capture should include at least one stack frame"

    # The trigger frame (deepest non-site-packages frame) should be our buggy function
    tf = cap.trigger_frame
    assert tf >= 0 and tf < len(cap.frames), f"trigger_frame index {tf} out of range"


def test_variable_summary_contains_none() -> None:
    """The variable summary should show ``total -> None`` — that's the root cause."""
    cap = capture_exception(FIXTURE, timeout=30)
    assert cap is not None

    summary = cap.variable_summary()
    # One of the frames should show total = None
    assert "total -> None" in summary, (
        f"Expected 'total -> None' in variable summary, got:\n{summary}"
    )
    # process_order should be in the stack
    assert "process_order" in summary


def test_to_dict_structure() -> None:
    """to_dict() returns the expected compact shape."""
    cap = capture_exception(FIXTURE, timeout=30)
    assert cap is not None

    d = cap.to_dict(max_vars=20)
    assert "exception" in d
    assert "trigger_frame" in d
    assert isinstance(d["frames"], list)
    if d["frames"]:
        f0 = d["frames"][0]
        assert "name" in f0
        assert "line" in f0


def test_clean_script_returns_none() -> None:
    """A script that runs without error should return None (no capture)."""
    import tempfile

    tf = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8")
    tf.write("x = 1 + 1\n")
    clean_path = Path(tf.name)
    tf.close()

    try:
        cap = capture_exception(clean_path, timeout=15)
        assert cap is None, f"Expected None for clean script, got: {cap}"
    finally:
        clean_path.unlink(missing_ok=True)


def test_captures_real_pytest_failure() -> None:
    """A real test file that only fails inside a test function must be captured.

    Regression test: the standalone harness returns None for a pytest module
    (it imports cleanly), so the pytest harness is required to reach the
    failure inside ``test_total_is_none``.
    """
    cap = capture_exception(PYTEST_FIXTURE, timeout=60)
    assert cap is not None, (
        "expected a capture for a failing pytest test file (standalone import "
        "would succeed, so the pytest harness must be used)"
    )
    assert "TypeError" in cap.exception, f"expected TypeError, got: {cap.exception}"
    assert "total -> None" in cap.variable_summary(), (
        f"expected 'total -> None' in variable summary, got:\n{cap.variable_summary()}"
    )
