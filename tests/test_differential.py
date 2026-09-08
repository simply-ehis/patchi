"""Differential smoke tests — CLI entrypoints start cleanly.

(Model-classifier differential tests removed with that track's deletion:
untrainable without a labeled corpus, so the whole track was cut.)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_cli_help_is_functional():
    """`p scan --help` and `p --help` exit cleanly."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "patchi.cli.main", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )
    assert result.returncode == 0, f"CLI help failed: {result.stderr}"

    result = subprocess.run(
        [sys.executable, "-m", "patchi.cli.main", "scan", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )
    assert result.returncode == 0, f"Scan help failed: {result.stderr}"
