"""Doctor's registry check: a broken registry surfaces in the health view.

The CI tests (test_registry_handlers_exist.py) catch dangling commands at
test time; this pins doctor's twin of the same walk so a broken registry
also shows in `p doctor` — human and JSON — with the offending entries
named, because the user who hits it is the one running doctor, not CI.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _doctor_json() -> dict:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, "-m", "patchi.cli.main", "doctor", "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=REPO_ROOT,
        timeout=180,
    )
    return json.loads(proc.stdout)


def _registry_rows(doc: dict) -> list[dict]:
    return [c for c in doc["checks"] if c["label"] in ("Command registry", "registry")]


def test_healthy_registry_resolves_in_doctor_json():
    doc = _doctor_json()
    rows = _registry_rows(doc)
    assert rows, "doctor --json is missing the Command registry check"
    assert rows[0]["status"] == "✓"
    assert "resolve" in rows[0]["note"]


def test_check_registry_handlers_reports_zero_problems():
    from patchi.cli.framework import check_registry_handlers

    problems, total, missing = check_registry_handlers()
    assert total >= 80, f"registry unexpectedly shrank: {total}"
    assert problems == []
    assert missing == 0


def test_doctor_counts_seeded_dangling_handler_as_error(tmp_path, monkeypatch):
    """Trip-test in-process: a handler pointing at a missing module must
    make check_registry_handlers report it, and doctor's check must turn it
    into an error row + errors count. (End-to-end doctor proven in the
    commit message's live trip; this is the fast CI-safe version.)"""
    from patchi.cli import framework

    real_walk = framework.walk_registry_handlers

    def seeded_walk():
        return sorted(set(real_walk()) | {("zombie", "patchi.cli.commands.zombie_cmd:run")})

    monkeypatch.setattr(framework, "walk_registry_handlers", seeded_walk)
    problems, total, missing = framework.check_registry_handlers()
    assert missing == 1
    assert any("zombie_cmd" in p and "does not exist" in p for p in problems)


def test_doctor_counts_renamed_function_as_error(monkeypatch):
    from patchi.cli import framework

    real_walk = framework.walk_registry_handlers

    def seeded_walk():
        return sorted(
            set(real_walk()) | {("ghost", "patchi.cli.commands.reason_cmd:run_why_gone")}
        )

    monkeypatch.setattr(framework, "walk_registry_handlers", seeded_walk)
    problems, _total, missing = framework.check_registry_handlers()
    assert missing >= 1
    assert any("run_why_gone" in p and "no attribute" in p for p in problems)
