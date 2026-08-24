"""Verify that codelldb adapter finds the debugger and gracefully handles failures.

If codelldb is installed on this system, the test actually runs a Rust binary
through the debugger.  If not installed, it is skipped explicitly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from patchi.core.debug import CodeLLDBAdapter, capture_rust_crash
from patchi.core.debug.adapters.codelldb import find_codelldb

HERE = Path(__file__).parent
RUST_BINARY = HERE / "fixtures" / "rust-panic" / "target" / "debug" / "rust-panic.exe"
RUST_BINARY_ALT = HERE / "fixtures" / "rust-panic" / "target" / "debug" / "rust-panic"


def test_codelldb_detection() -> None:
    """find_codelldb() should either return a path or None — never crash."""
    path = find_codelldb()
    if path is None:
        print("codelldb not installed — adapter will gracefully skip")
    else:
        print(f"codelldb found at: {path}")
        assert Path(path).is_file()


def test_adapter_available_matches() -> None:
    adapter = CodeLLDBAdapter(RUST_BINARY)
    assert adapter.available() == (find_codelldb() is not None)


@pytest.mark.skipif(
    find_codelldb() is None,
    reason="codelldb not installed on this system",
)
@pytest.mark.skipif(
    not RUST_BINARY.is_file(),
    reason="rust-panic fixture not built — run: cargo build --manifest-path tests/fixtures/rust-panic/Cargo.toml",
)
def test_capture_rust_panic_integration() -> None:
    """If codelldb IS installed, this exercises the real DAP capture pipeline."""
    cap = capture_rust_crash(RUST_BINARY, timeout=60)
    assert cap is not None, "expected a capture (binary should panic)"
    assert cap.exception, "capture should include exception description"
    assert cap.frames, "capture should include stack frames"
    # The crash is a panic/unwrap on None
    assert "panic" in cap.exception.lower() or "unwrap" in cap.exception.lower(), (
        f"expected panic/ unwrap error, got: {cap.exception}"
    )
    summary = cap.variable_summary()
    print(summary)
    assert "process_order" in summary, "stack should include process_order"
