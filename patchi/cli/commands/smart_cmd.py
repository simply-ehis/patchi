"""
`p smart` — goal-driven Smart Agent.

Runs the Patchi SmartAgent: a deterministic planner + the multi-persona Council
decide which *real* tools to call (security scan, live tests, attack simulation,
stress test, ...), then execute them through the tool executor, streaming live
progress. Fully offline — no API key required.
"""

from __future__ import annotations

import sys
from pathlib import Path

from patchi.core.ai.smart import run_smart_agent


def _resolve_root() -> Path:
    # `p smart` analyzes the project you are standing in. We deliberately use
    # the current working directory rather than find_project_root(): a global
    # ~/.patchi (or a stray ancestor .patchi, e.g. the user's home dir) would
    # otherwise pull the *entire* home tree into a tool like run_tests and hang.
    return Path.cwd()


def run(args) -> None:
    """Entry point for `p smart <goal> [--json] [--max-steps N]`."""
    goal_parts = getattr(args, "goal", None) or []
    goal = " ".join(goal_parts).strip()
    if not goal:
        return

    root = _resolve_root()
    max_steps = getattr(args, "max_steps", 6) or 6
    json_output = getattr(args, "json_output", False)

    def on_event(payload: dict) -> None:
        ev = payload.get("event", "")
        data = payload.get("data", {})
        if ev == "security.finding":
            data.get("severity", "?").upper()
        elif ev == "test.suite.completed":
            pass
        elif ev == "test.stress.update":
            pass
        elif ev == "brain.scan.completed":
            pass

    def on_progress(msg: str) -> None:
        if not json_output:
            pass

    try:
        report = run_smart_agent(
            root,
            goal,
            max_steps=max_steps,
            on_event=on_event,
            on_progress=on_progress,
        )
    except Exception:  # surface any failure honestly
        sys.exit(1)

    if json_output:
        return

    for s in report.get("steps_executed", []):
        "OK " if s.get("success") else "FAIL"
