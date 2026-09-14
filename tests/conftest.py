"""
Shared pytest fixtures for Patchi tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project directory with .patchi/config.json."""
    patchi_dir = tmp_path / ".patchi"
    patchi_dir.mkdir(parents=True)
    config = {
        "mode": "confirm",
        "device_tier": "mid",
        "ai": {"keys": []},
    }
    (patchi_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")
    return tmp_path


@pytest.fixture
def sample_python_file(tmp_project: Path) -> Path:
    """Create a sample Python file for scanning."""
    f = tmp_project / "src" / "app.py"
    f.parent.mkdir(parents=True)
    f.write_text(
        "def hello():\n    print('hello world')\n\nclass App:\n    pass\n",
        encoding="utf-8",
    )
    return f


@pytest.fixture(autouse=True)
def _reset_ai_global_state():
    """Isolate tests from the AI client's process-global state.

    The circuit breaker (and harness stats) accumulate across calls in one
    process: a test that hammers unreachable endpoints trips the breaker
    OPEN, and every later AI-dependent test then sees "unavailable" instead
    of its mocked/real backend — order-dependent green/red. Reset both
    before every test; production behavior is untouched.
    """
    try:
        import patchi.core.ai.client as _client

        _client._circuit_failures = 0
        _client._circuit_open = False
        _client._circuit_skip_count = 0
    except Exception:
        pass
    try:
        import patchi.core.ai.harness as _harness

        _harness.stats.calls = 0
        _harness.stats.grounded = 0
        _harness.stats.hallucinated = 0
        _harness.stats.retried = 0
        _harness.stats.unavailable = 0
    except Exception:
        pass
    yield
    try:
        import patchi.core.ai.client as _client

        _client._circuit_failures = 0
        _client._circuit_open = False
        _client._circuit_skip_count = 0
    except Exception:
        pass
