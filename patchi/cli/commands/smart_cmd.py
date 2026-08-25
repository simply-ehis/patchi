"""
`p smart` — goal-driven Smart Agent.

Runs the Patchi SmartAgent: a deterministic planner + the multi-persona Council
decide which *real* tools to call (security scan, live tests, attack simulation,
stress test, ...), then execute them through the tool executor, streaming live
progress. Fully offline — no API key required.
"""

from __future__ import annotations

import json
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
        print("Usage: p smart \"<goal>\"  e.g.  p smart \"audit this project for security vulnerabilities\"")
        print("       p smart \"run the test suite\" --json")
        return

    root = _resolve_root()
    max_steps = getattr(args, "max_steps", 6) or 6
    json_output = getattr(args, "json_output", False)

    def on_event(payload: dict) -> None:
        ev = payload.get("event", "")
        data = payload.get("data", {})
        if ev == "security.finding":
            sev = data.get("severity", "?").upper()
            print(f"   [{sev}] {data.get('description', data.get('type', ''))}"
                  f"  ({data.get('file', '')})")
        elif ev == "test.suite.completed":
            print(f"   tests: passed={data.get('passed')} failed={data.get('failed')}")
        elif ev == "test.stress.update":
            print(f"   stress: {data.get('rps')} rps  p95={data.get('p95')}ms  "
                  f"err={data.get('error_rate')}")
        elif ev == "brain.scan.completed":
            print(f"   brain: {data.get('file_count')} files, "
                  f"{data.get('route_count')} routes")

    def on_progress(msg: str) -> None:
        if not json_output:
            print(f"[smart] {msg}")

    print(f"\n🧠 Patchi SmartAgent — goal: {goal}\n")
    try:
        report = run_smart_agent(
            root, goal, max_steps=max_steps,
            on_event=on_event, on_progress=on_progress,
        )
    except Exception as e:  # surface any failure honestly
        print(f"[smart] FAILED: {e}")
        sys.exit(1)

    if json_output:
        print(json.dumps(report, indent=2, default=str))
        return

    print("\n" + "=" * 64)
    print("SMART AGENT REPORT")
    print("=" * 64)
    print(f"Goal           : {goal}")
    print(f"Plan           : {' -> '.join(report.get('steps_planned', []))}")
    print(f"Live events    : {report.get('events', 0)}")
    print(f"Total findings : {report.get('total_findings', 0)}")
    print("-" * 64)
    for s in report.get("steps_executed", []):
        status = "OK " if s.get("success") else "FAIL"
        print(f"  [{status}] {s['tool']:<22} {s.get('summary', '')}")
    print("=" * 64)
    print("Web live view  : run the agent from the web UI at /smart,")
    print("                 or watch it stream events over the WebSocket.")
