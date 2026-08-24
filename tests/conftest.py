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
