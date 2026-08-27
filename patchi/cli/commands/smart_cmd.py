"""
`p smart` — goal-driven Smart Agent.

Runs the Patchi SmartAgent: a deterministic planner + the multi-persona Council
decide which *real* tools to call (security scan, live tests, attack simulation,
stress test, ...), then execute them through the tool executor, streaming live
progress. Fully offline — no API key required.
"""

from __future__ import annotations

import sys
import time
import threading
from pathlib import Path

from patchi.core.ai.smart import run_smart_agent


class Spinner:
    """Simple spinner for CLI output."""
    def __init__(self, message="", frames=None):
        self.message = message
        self.frames = frames or ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.idx = 0
        self.running = False
        self.thread = None
        self.last_len = 0

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def stop(self, final_msg=""):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.5)
        # Clear the line
        sys.stdout.write('\r' + ' ' * self.last_len + '\r')
        if final_msg:
            sys.stdout.write(final_msg + '\n')
        sys.stdout.flush()

    def _spin(self):
        while self.running:
            frame = self.frames[self.idx % len(self.frames)]
            self.idx += 1
            msg = f"{frame} {self.message}"
            self.last_len = len(msg)
            sys.stdout.write('\r' + msg)
            sys.stdout.flush()
            time.sleep(0.08)


def _resolve_root() -> Path:
    # `p smart` analyzes the project you are standing in. We deliberately use
    # the current working directory rather than find_project_root(): a global
    # ~/.patchi (or a stray ancestor .patchi, e.g. the user's home dir) would
    # otherwise pull the *entire* home tree into a tool like run_tests and hang.
    return Path.cwd()


def _print_tool_status(tool_name, status, details=""):
    """Print a tool status with appropriate icon."""
    icons = {
        'pending': '○',
        'running': '⟳',
        'done': '✓',
        'error': '✗',
    }
    colors = {
        'pending': '\033[90m',      # gray
        'running': '\033[33m',      # yellow
        'done': '\033[32m',         # green
        'error': '\033[31m',        # red
    }
    reset = '\033[0m'
    icon = icons.get(status, '•')
    color = colors.get(status, '')
    details_str = f" {status}" if not details else f" {status} ({details})"
    print(f"  {color}{status.upper():<8}{reset} {icon}  {tool_name}{details_str}")


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

    # Track tool statuses
    tool_statuses = {}
    tool_order = []

    def on_event(payload: dict) -> None:
        ev = payload.get("event", "")
        data = payload.get("data", {})
        if ev == "agent.progress":
            tool = data.get("current_file")
            pct = data.get("progress_pct", 0)
            if tool and tool not in ["planning", "done"]:
                # Update progress for current tool
                pass
        elif ev == "security.finding":
            sev = data.get("severity", "?").upper()
            print(f"\n  [{sev}] {data.get('description', data.get('type', ''))}  ({data.get('file', '')})")
        elif ev == "test.suite.completed":
            print(f"  [TESTS] passed={data.get('passed')} failed={data.get('failed')}")
        elif ev == "test.stress.update":
            print(f"  [STRESS] {data.get('rps')} rps  p95={data.get('p95')}ms  err={data.get('error_rate')}")
        elif ev == "brain.scan.completed":
            print(f"  [BRAIN] {data.get('file_count')} files, {data.get('route_count')} routes")
        elif ev == "agent.completed":
            pass

    def on_progress(msg: str) -> None:
        if msg.startswith("SmartAgent: step"):
            # Extract tool name from message like "SmartAgent: step 1/3 → run_tests"
            parts = msg.split("→")
            if len(parts) > 1:
                tool = parts[1].strip()
                print(f"\n  [STEP] {tool}")
        elif msg.startswith("SmartAgent: plan"):
            print(f"  Plan: {msg.split('=', 1)[1].strip()}")
        elif not msg.startswith("SmartAgent: goal"):
            print(f"  {msg}")

    print(f"\n🧠 Patchi SmartAgent — goal: {goal}\n")

    # Show initial spinner while planning
    plan_spinner = Spinner("Planning agent steps…")
    plan_spinner.start()

    try:
        report = run_smart_agent(
            root, goal, max_steps=max_steps,
            on_event=on_event, on_progress=on_progress,
        )
    except Exception as e:  # surface any failure honestly
        print(f"\n❌ SmartAgent failed: {e}")
        sys.exit(1)
    finally:
        plan_spinner.stop("")

    if json_output:
        import json
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
        status = "OK" if s.get("success") else "FAIL"
        color = "\033[32m" if s.get("success") else "\033[31m"
        reset = "\033[0m"
        print(f"  [{color}{status}{reset}] {s['tool']:<22} {s.get('summary', '')}")
    print("=" * 64)
    print("Web live view  : run the agent from the web UI at /smart,")
    print("                 or watch it stream events over the WebSocket.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("goal", nargs="*")
    parser.add_argument("--json", dest="json_output", action="store_true")
    parser.add_argument("--max-steps", dest="max_steps", type=int, default=6)
    args = parser.parse_args()
    run(args)