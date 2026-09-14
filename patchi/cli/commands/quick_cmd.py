"""
`p quick` — Fast readiness check with subset of agents.

Usage:
  p quick              — fast readiness check
  p quick --json       — JSON output

Runs a minimal set of agents to quickly check if code is ready:
- Unit tests
- Secret scanning
- Basic security check
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.cli.ux import (
    format_error,
    format_header,
    spinner,
    status_icon,
    status_style,
    summary_panel,
)
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.quick")


def _run_agent_safe(agent_cls, root: Path, brain: dict, config: dict):
    """Run an agent and return results, catching exceptions."""
    from patchi.core.agents.base import AgentInput

    try:
        inp = AgentInput(root=root, scope=[], brain=brain, config=config, extra={})
        return agent_cls().run(inp)
    except Exception as e:
        _log.debug("Agent %s failed: %s", agent_cls.name, e)
        return None


def run(
    json_output: bool = False,
    root: Path | None = None,
) -> None:
    """Entry point for `p quick`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(format_error(str(e)))
        if json_output:
            print(json.dumps({"ready": False, "error": str(e)}))
        sys.exit(1)

    from patchi.core.agents.base import discover_agent_modules

    discover_agent_modules()

    try:
        from patchi.core import config as cfg
        from patchi.core import memory as mem

        brain = mem.get_brain(r)
        config = cfg.load(r)
    except Exception:
        brain, config = {}, {}

    con.print()
    con.print(format_header("Quick Readiness Check", "Fast verification of critical checks"))
    con.print()

    results = {}
    start_time = time.time()

    # Define the quick check agents (subset for speed)
    quick_checks = [
        ("unit_test", "patchi.core.testing.unit_test_agent", "UnitTestAgent"),
        ("secrets", "patchi.core.security.secrets_runtime_agent", "SecretsRuntimeAgent"),
        ("bandit", "patchi.core.agents.scanners.bandit_agent", "BanditAgent"),
    ]

    with spinner("Running quick checks...") as update:
        for i, (name, module_path, class_name) in enumerate(quick_checks, 1):
            update(f"Step {i}/{len(quick_checks)}: Running {name}...")

            try:
                import importlib

                module = importlib.import_module(module_path)
                agent_cls = getattr(module, class_name)
                result = _run_agent_safe(agent_cls, r, brain, config)
                if result:
                    results[name] = {
                        "status": result.status.value,
                        "findings": result.finding_count,
                        "files_scanned": result.files_scanned,
                    }
                else:
                    results[name] = {"status": "error", "findings": 0, "files_scanned": 0}
            except Exception as e:
                _log.debug("Failed to load %s: %s", name, e)
                results[name] = {"status": "error", "findings": 0, "files_scanned": 0}

    elapsed = time.time() - start_time

    # Compute readiness
    is_ready = all(r.get("status") == "done" for r in results.values())
    total_findings = sum(r.get("findings", 0) for r in results.values())

    # Display results
    con.print()

    if json_output:
        output = {
            "ready": is_ready,
            "elapsed_seconds": round(elapsed, 2),
            "total_findings": total_findings,
            "results": results,
        }
        con.print(json.dumps(output, indent=2))
    else:
        # Show results table
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Check", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Findings", justify="right")
        table.add_column("Files", justify="right")

        for name, data in results.items():
            s = data["status"]
            icon = status_icon(s)
            style = status_style(s)
            status_str = f"[{style}]{icon} {s}[/{style}]"

            findings = data["findings"]
            if findings > 0:
                findings_style = f"[red]{findings}[/red]"
            else:
                findings_style = "[green]0[/green]"

            table.add_row(name, status_str, findings_style, str(data["files_scanned"]))

        con.print(table)
        con.print()

        # Summary
        items = {name: data["status"] == "done" for name, data in results.items()}
        con.print(summary_panel("Quick Check", items, elapsed))
        con.print()

    if not is_ready:
        sys.exit(1)
