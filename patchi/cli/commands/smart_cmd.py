"""
`p smart` — goal-driven Smart Agent.

Runs the Patchi SmartAgent: a deterministic planner + the multi-persona Council
decide which *real* tools to call (security scan, live tests, attack simulation,
stress test, ...), then execute them through the tool executor, streaming live
progress. Fully offline — no API key required.
"""

from __future__ import annotations

import sys
import threading
import time
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
    icons.get(status, '•')
    colors.get(status, '')


def run(args) -> None:
    """Entry point for `p smart <goal> [--json] [--max-steps N]`."""
    goal_parts = getattr(args, "goal", None) or []
    goal = " ".join(goal_parts).strip()
    if not goal:
        return

    root = _resolve_root()
    max_steps = getattr(args, "max_steps", 6) or 6
    json_output = getattr(args, "json_output", False)

    # Track tool statuses

    def on_event(payload: dict) -> None:
        ev = payload.get("event", "")
        data = payload.get("data", {})
        if ev == "agent.progress":
            tool = data.get("current_file")
            data.get("progress_pct", 0)
            if tool and tool not in ["planning", "done"]:
                # Update progress for current tool
                pass
        elif ev == "security.finding":
            data.get("severity", "?").upper()
        elif ev == "test.suite.completed":
            pass
        elif ev == "test.stress.update":
            pass
        elif ev == "brain.scan.completed":
            pass
        elif ev == "agent.completed":
            pass

    def on_progress(msg: str) -> None:
        if msg.startswith("SmartAgent: step"):
            # Extract tool name from message like "SmartAgent: step 1/3 → run_tests"
            parts = msg.split("→")
            if len(parts) > 1:
                parts[1].strip()
        elif msg.startswith("SmartAgent: plan"):
            pass
        elif not msg.startswith("SmartAgent: goal"):
            pass


    # Show initial spinner while planning
    plan_spinner = Spinner("Planning agent steps…")
    plan_spinner.start()

    try:
        report = run_smart_agent(
            root, goal, max_steps=max_steps,
            on_event=on_event, on_progress=on_progress,
        )
    except Exception:  # surface any failure honestly
        sys.exit(1)
    finally:
        plan_spinner.stop("")

    if json_output:
        return

    for s in report.get("steps_executed", []):
        "OK" if s.get("success") else "FAIL"
        "\033[32m" if s.get("success") else "\033[31m"


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("goal", nargs="*")
    parser.add_argument("--json", dest="json_output", action="store_true")
    parser.add_argument("--max-steps", dest="max_steps", type=int, default=6)
    args = parser.parse_args()
    run(args)
