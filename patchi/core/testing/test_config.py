"""
Test configuration for Patchi.

Reads/writes .patchi/tests.json — project-level test settings.

Config shape:
{
  "base_url": "http://localhost:3000",
  "viewport_widths": [375, 768, 1024, 1440],
  "timeout_per_agent": 120,
  "parallel": false,
  "skip_agents": [],
  "only_agents": [],
  "ai_generate": true,
  "screenshots_dir": ".patchi/screenshots",
  "baselines_dir": ".patchi/baselines",
  "custom_flows": [
    {"name": "login", "url": "/login", "steps": ["fill email", "fill password", "click submit"]}
  ],
  "exclude_paths": ["node_modules", ".venv", "dist"],
  "report_format": "rich"
}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

from ..constants import PATCHI_DIR

TESTS_CONFIG = f"{PATCHI_DIR}/tests.json"

DEFAULT_TEST_CONFIG = {
    "base_url": None,
    "viewport_widths": [375, 768, 1024, 1440],
    "timeout_per_agent": 120,
    "parallel": False,
    "skip_agents": [],
    "only_agents": [],
    "ai_generate": True,
    "screenshots_dir": f"{PATCHI_DIR}/screenshots",
    "baselines_dir": f"{PATCHI_DIR}/baselines",
    "custom_flows": [],
    "exclude_paths": sorted(DEFAULT_IGNORE_DIRS),
    "report_format": "rich",
}


import logging

_log = logging.getLogger("patchi.testing.test_config")

def _config_path(root: Path) -> Path:
    return root / TESTS_CONFIG


def load(root: Path | None = None) -> dict:
    """Load test config, merging with defaults."""
    from ..config import require_project_root

    root = root or require_project_root()
    path = _config_path(root)
    if not path.exists():
        return dict(DEFAULT_TEST_CONFIG)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return {**DEFAULT_TEST_CONFIG, **raw}
    except Exception as e:
        _log.warning("load failed: %s", e)
        return dict(DEFAULT_TEST_CONFIG)


def save(config: dict, root: Path | None = None) -> None:
    """Write test config to disk."""
    from ..config import require_project_root

    root = root or require_project_root()
    path = _config_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def get(key: str, root: Path | None = None) -> Any:
    """Get a single test config value."""
    return load(root).get(key)


def set_value(key: str, value: Any, root: Path | None = None) -> None:
    """Update a single test config key."""
    config = load(root)
    config[key] = value
    save(config, root)


def add_custom_flow(name: str, url: str, steps: list[str], root: Path | None = None) -> None:
    """Add a custom test flow."""
    config = load(root)
    flows = config.get("custom_flows", [])
    flows.append({"name": name, "url": url, "steps": steps})
    config["custom_flows"] = flows
    save(config, root)


def remove_custom_flow(name: str, root: Path | None = None) -> bool:
    """Remove a custom test flow by name."""
    config = load(root)
    flows = config.get("custom_flows", [])
    before = len(flows)
    config["custom_flows"] = [f for f in flows if f.get("name") != name]
    save(config, root)
    return len(config["custom_flows"]) < before


def get_test_history(root: Path | None = None) -> list[dict]:
    """Load test run history from memory."""
    from .. import memory as mem
    from ..config import require_project_root

    root = root or require_project_root()
    brain = mem.get_brain(root)
    return brain.get("test_history", [])


def append_test_history(entry: dict, root: Path | None = None) -> None:
    """Append a test run entry to history."""
    from .. import memory as mem
    from ..config import require_project_root

    root = root or require_project_root()
    brain = mem.get_brain(root)
    history = brain.get("test_history", [])
    history.append(entry)
    # Keep last 50 runs
    if len(history) > 50:
        history = history[-50:]
    brain["test_history"] = history
    mem.save_brain(brain, root)


def get_coverage(root: Path | None = None) -> dict:
    """Get cumulative test coverage data."""
    from .. import memory as mem
    from ..config import require_project_root

    root = root or require_project_root()
    brain = mem.get_brain(root)
    return brain.get(
        "test_coverage",
        {
            "files_tested": [],
            "agents_run": {},
            "total_runs": 0,
            "last_run": None,
        },
    )


def update_coverage(run_result: dict, root: Path | None = None) -> None:
    """Update coverage data after a test run."""
    from .. import memory as mem
    from ..config import require_project_root

    root = root or require_project_root()
    brain = mem.get_brain(root)
    coverage = brain.get(
        "test_coverage",
        {
            "files_tested": [],
            "agents_run": {},
            "total_runs": 0,
            "last_run": None,
        },
    )

    coverage["total_runs"] = coverage.get("total_runs", 0) + 1
    coverage["last_run"] = run_result.get("timestamp")

    # Track which agents have been run
    for agent_name in run_result.get("agents", []):
        counts = coverage.get("agents_run", {})
        counts[agent_name] = counts.get(agent_name, 0) + 1
        coverage["agents_run"] = counts

    # Track files tested
    tested_files = set(coverage.get("files_tested", []))
    for f in run_result.get("files_tested", []):
        tested_files.add(f)
    coverage["files_tested"] = sorted(tested_files)

    brain["test_coverage"] = coverage
    mem.save_brain(brain, root)
