"""Verify that Node debug adapter works correctly.

If Node.js is installed on this system, the test actually runs a JavaScript
file through the harness. If not installed, the real-capture test is skipped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from patchi.core.debug import NodeDebugAdapter, capture_exception
from patchi.core.debug.adapters.node import _find_node

HERE = Path(__file__).parent
JS_SCRIPT = HERE / "fixtures" / "debug_fail_target.js"


def test_node_detection() -> None:
    """_find_node() should either return a path or None — never crash."""
    path = _find_node()
    if path is None:
        print("node not installed — adapter will gracefully skip")
    else:
        print(f"node found at: {path}")
        assert Path(path).is_file()


def test_adapter_available_matches() -> None:
    adapter = NodeDebugAdapter(JS_SCRIPT)
    assert adapter.available() == (_find_node() is not None)


def test_capture_returns_none_when_not_installed() -> None:
    """If node isn't on the system, capture should return None (not crash)."""
    cap = capture_exception(JS_SCRIPT, timeout=10)
    if _find_node() is None:
        assert cap is None


@pytest.mark.skipif(
    _find_node() is None,
    reason="node not installed on this system",
)
def test_capture_node_error_integration() -> None:
    """If node IS installed, this exercises the real harness pipeline."""
    cap = capture_exception(JS_SCRIPT, timeout=60)
    assert cap is not None, "expected a capture (script should error)"
    assert cap.exception, "capture should include exception description"
    assert cap.frames, "capture should include stack frames"
    # The error is a TypeError from calling + on null
    assert "TypeError" in cap.exception or "Cannot read properties of null" in cap.exception, (
        f"expected TypeError, got: {cap.exception}"
    )
    summary = cap.variable_summary()
    print(summary)
    # The trigger frame should be the processOrder function
    assert "processOrder" in summary, "stack should include processOrder"


def test_clean_node_script_returns_none() -> None:
    """A Node script that runs without error should return None."""
    import tempfile

    tf = tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False, encoding="utf-8")
    tf.write("console.log('Hello world');\n")
    clean_path = Path(tf.name)
    tf.close()

    try:
        cap = capture_exception(clean_path, timeout=15)
        assert cap is None, f"Expected None for clean script, got: {cap}"
    finally:
        clean_path.unlink(missing_ok=True)