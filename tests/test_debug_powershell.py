"""Verify that PowerShell debug adapter works correctly.

If pwsh is installed on this system, the test actually runs a PowerShell script
through the harness. If not installed, the real-capture test is skipped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from patchi.core.debug import PowerShellDebugAdapter, capture_powershell_crash
from patchi.core.debug.adapters.powershell import _find_pwsh

HERE = Path(__file__).parent
PS_SCRIPT = HERE / "fixtures" / "debug_fail_target.ps1"


def test_powershell_detection() -> None:
    """_find_pwsh() should either return a path or None — never crash."""
    path = _find_pwsh()
    if path is None:
        print("pwsh not installed — adapter will gracefully skip")
    else:
        print(f"pwsh found at: {path}")
        assert Path(path).is_file()


def test_adapter_available_matches() -> None:
    adapter = PowerShellDebugAdapter(PS_SCRIPT)
    assert adapter.available() == (_find_pwsh() is not None)


def test_capture_returns_none_when_not_installed() -> None:
    """If pwsh isn't on the system, capture should return None (not crash)."""
    if _find_pwsh() is not None:
        pytest.skip("pwsh installed — real-capture path covered by integration test")
    cap = capture_powershell_crash(PS_SCRIPT, timeout=10)
    assert cap is None


@pytest.mark.skipif(
    _find_pwsh() is None,
    reason="pwsh not installed on this system",
)
def test_capture_powershell_error_integration() -> None:
    """If pwsh IS installed, this exercises the real capture pipeline."""
    cap = capture_powershell_crash(PS_SCRIPT, timeout=60)
    assert cap is not None, "expected a capture (script should error)"
    assert cap.exception, "capture should include exception description"
    assert cap.frames, "capture should include stack frames"
    # The error is a RuntimeException from calling .ToString() on $null
    assert "RuntimeException" in cap.exception, (
        f"expected RuntimeException, got: {cap.exception}"
    )
    assert "null-valued expression" in cap.exception, (
        f"expected null-valued expression error, got: {cap.exception}"
    )
    summary = cap.variable_summary()
    print(summary)
    # The trigger frame should be the Process-Order function
    assert "Process-Order" in summary, "stack should include Process-Order"


def test_clean_powershell_script_returns_none() -> None:
    """A PowerShell script that runs without error should return None."""
    import tempfile

    tf = tempfile.NamedTemporaryFile(suffix=".ps1", mode="w", delete=False, encoding="utf-8")
    tf.write("$x = 1 + 1\nWrite-Output $x\n")
    clean_path = Path(tf.name)
    tf.close()

    try:
        cap = capture_powershell_crash(clean_path, timeout=15)
        assert cap is None, f"Expected None for clean script, got: {cap}"
    finally:
        clean_path.unlink(missing_ok=True)
