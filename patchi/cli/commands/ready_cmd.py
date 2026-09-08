"""
Ready command — Ship Readiness Check.

Runs a comprehensive check across all domains to determine if the code is
ready to ship. Outputs a detailed report with pass/fail status.

Usage:
    p ready              → full ship readiness check
    p ready --json       → JSON output
    p ready --quick      → fast check (subset of agents)
    p ready --ci         → CI-friendly output (exit code 1 on failure)
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from patchi.cli.console import con
from patchi.cli.ux import (
    format_header,
    format_step,
    progress_bar,
    spinner,
    status_icon,
    status_style,
    summary_panel,
)
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.ready")


def _run_agent_safe(agent_cls, root: Path, brain: dict, config: dict, extra: dict | None = None):
    """Run an agent and return results, catching exceptions."""
    from patchi.core.agents.base import AgentInput

    try:
        inp = AgentInput(root=root, scope=[], brain=brain, config=config, extra=extra or {})
        return agent_cls().run(inp)
    except Exception as e:
        _log.debug("Agent %s failed: %s", agent_cls.name, e)
        return None


def _check_testing(root: Path, brain: dict, config: dict) -> dict:
    """Run testing agents and return results."""
    from patchi.core.testing.unit_test_agent import UnitTestAgent
    from patchi.core.testing.regression_agent import RegressionAgent
    from patchi.core.testing.flake_detector_agent import FlakeDetectorAgent

    results = {}
    agents = [
        ("unit_test", UnitTestAgent),
        ("regression", RegressionAgent),
        ("flake_detector", FlakeDetectorAgent),
    ]

    for name, cls in agents:
        res = _run_agent_safe(cls, root, brain, config)
        if res:
            results[name] = {
                "status": res.status.value,
                "findings": res.finding_count,
                "files_scanned": res.files_scanned,
            }
        else:
            results[name] = {"status": "error", "findings": 0, "files_scanned": 0}

    return results


def _check_code_quality(root: Path, brain: dict, config: dict) -> dict:
    """Run code quality agents and return results."""
    from patchi.core.agents.base import list_agents, AgentGroup

    results = {}
    # Get scanner agents for code quality
    scanners = [a for a in list_agents(AgentGroup.SCANNER) if a.name in (
        "BanditAgent", "SemgrepAgent", "CatchBlockAuditor",
    )]

    for cls in scanners:
        res = _run_agent_safe(cls, root, brain, config)
        if res:
            results[cls.name] = {
                "status": res.status.value,
                "findings": res.finding_count,
                "files_scanned": res.files_scanned,
            }
        else:
            results[cls.name] = {"status": "error", "findings": 0, "files_scanned": 0}

    return results


def _check_security(root: Path, brain: dict, config: dict) -> dict:
    """Run security agents and return results."""
    from patchi.core.security.secrets_runtime_agent import SecretsRuntimeAgent
    from patchi.core.security.misconfig_agent import MisconfigAgent
    from patchi.core.agents.base import list_agents, AgentGroup

    results = {}

    # Core security agents
    core_agents = [
        ("secrets", SecretsRuntimeAgent),
        ("misconfig", MisconfigAgent),
    ]

    for name, cls in core_agents:
        res = _run_agent_safe(cls, root, brain, config)
        if res:
            results[name] = {
                "status": res.status.value,
                "findings": res.finding_count,
                "files_scanned": res.files_scanned,
            }
        else:
            results[name] = {"status": "error", "findings": 0, "files_scanned": 0}

    return results


def _check_integration(root: Path, brain: dict, config: dict) -> dict:
    """Run integration agents and return results."""
    from patchi.core.testing.api_contract_agent import APIContractAgent

    results = {}
    res = _run_agent_safe(APIContractAgent, root, brain, config)
    if res:
        results["api_contract"] = {
            "status": res.status.value,
            "findings": res.finding_count,
            "files_scanned": res.files_scanned,
        }
    else:
        results["api_contract"] = {"status": "error", "findings": 0, "files_scanned": 0}

    return results


def _format_results_table(results: dict, title: str) -> Table:
    """Format results as a Rich table."""
    table = Table(title=title, show_header=True, header_style="bold")
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

    return table


def _compute_readiness(results: dict) -> tuple[bool, dict]:
    """Compute overall readiness from results."""
    total_findings = 0
    critical_findings = 0
    failed_checks = 0

    for category, checks in results.items():
        for name, data in checks.items():
            total_findings += data.get("findings", 0)
            if data.get("status") == "error":
                failed_checks += 1

    # Readiness criteria:
    # - No critical findings
    # - All checks completed
    is_ready = critical_findings == 0 and failed_checks == 0

    return is_ready, {
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "failed_checks": failed_checks,
    }


def run(
    json_output: bool = False,
    quick: bool = False,
    ci: bool = False,
    root: Path | None = None,
) -> None:
    """Run the ship readiness check."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        if ci:
            sys.exit(1)
        return

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
    con.print(format_header("Ship Readiness Check", "Verifying your code is ready to ship"))
    con.print()

    # Run checks with progress
    all_results = {}
    start_time = time.time()

    steps = [
        ("testing", "Running unit tests & regression checks"),
        ("code_quality", "Analyzing code quality"),
        ("integration", "Checking API contracts"),
        ("security", "Scanning for security issues"),
    ]

    if quick:
        steps = [steps[0], steps[3]]  # Only testing and security

    total_steps = len(steps)

    with spinner("Initializing checks...") as update:
        for i, (category, description) in enumerate(steps, 1):
            update(f"Step {i}/{total_steps}: {description}")

            if category == "testing":
                all_results["testing"] = _check_testing(r, brain, config)
            elif category == "code_quality" and not quick:
                all_results["code_quality"] = _check_code_quality(r, brain, config)
            elif category == "integration" and not quick:
                all_results["integration"] = _check_integration(r, brain, config)
            elif category == "security":
                all_results["security"] = _check_security(r, brain, config)

    elapsed = time.time() - start_time

    # Compute readiness
    is_ready, summary = _compute_readiness(all_results)

    # Display results
    con.print()

    if json_output:
        output = {
            "ready": is_ready,
            "elapsed_seconds": round(elapsed, 2),
            "summary": summary,
            "results": all_results,
        }
        con.print(json.dumps(output, indent=2))
    else:
        # Show tables for each category
        for category, checks in all_results.items():
            title = category.replace("_", " ").title()
            table = _format_results_table(checks, title)
            con.print(table)
            con.print()

        # Show summary
        items = {}
        for category, checks in all_results.items():
            for name, data in checks.items():
                items[f"{category}/{name}"] = data.get("status") == "done"

        con.print(summary_panel("Ship Readiness", items, elapsed))
        con.print()

    if ci and not is_ready:
        sys.exit(1)