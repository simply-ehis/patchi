"""
CLI command: p dev check

Runs the full 3-gate CI check (ruff + pytest + scan) and reports
structured pass/fail with JUnit output for CI integration.

Exit codes:
  0 = all gates passed
  1 = one or more gates failed
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class GateResult:
    name: str
    passed: bool
    duration_s: float = 0.0
    output: str = ""
    detail: str = ""
    kind: str = "normal"  # normal | collection_error | timeout


def _run_gate(cmd: list[str], cwd: str, timeout: int = 300) -> GateResult:
    """Run a gate command and return structured result."""
    name = cmd[0]
    start = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout,
            encoding='utf-8', errors='replace',
        )
        duration = time.time() - start
        output = result.stdout + "\n" + result.stderr

        if result.returncode == 0:
            return GateResult(name=name, passed=True, duration_s=duration, output=output)
        else:
            # Check for pytest collection errors
            if "ERRORS" in output and "no tests ran" in output.lower():
                return GateResult(
                    name=name, passed=False, duration_s=duration,
                    output=output, detail="collection_error",
                    kind="collection_error",
                )
            return GateResult(
                name=name, passed=False, duration_s=duration,
                output=output, detail=f"exit code {result.returncode}",
            )
    except subprocess.TimeoutExpired:
        duration = time.time() - start
        return GateResult(
            name=name, passed=False, duration_s=duration,
            detail="timeout", kind="timeout",
        )
    except Exception as e:
        duration = time.time() - start
        return GateResult(
            name=name, passed=False, duration_s=duration,
            detail=str(e),
        )


def _parse_pytest_junit(xml_path: str) -> dict | None:
    """Parse pytest JUnit XML and return structured counts."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ts = root.find("testsuite") or root
        tests = int(ts.get("tests", 0))
        failures = int(ts.get("failures", 0))
        errors = int(ts.get("errors", 0))
        skipped = int(ts.get("skipped", 0))
        return {
            "tests": tests,
            "failures": failures,
            "errors": errors,
            "skipped": skipped,
            "passed": tests - failures - errors - skipped,
        }
    except Exception:
        return None


def run(action: str = "check", json_output: bool = False) -> None:
    """Entry point for ``p dev check``."""
    try:
        from patchi.core.config import require_project_root
        root = str(require_project_root())
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    results: list[GateResult] = []

    # ── Gate 1: Ruff lint ────────────────────────────────────────────────
    console.print("[bold]Gate 1: Ruff Lint[/bold]")
    gate1 = _run_gate(
        [sys.executable, "-m", "ruff", "check", "patchi/", "--select", "E,F,W", "--ignore", "E402,E501,W291,E741,F821,F401"],
        cwd=root, timeout=120,
    )
    results.append(gate1)
    if gate1.passed:
        console.print("  [green]✓ PASSED[/green]")
    else:
        console.print("  [red]✗ FAILED[/red]")
        console.print(f"  {gate1.detail}")

    # ── Gate 2: Pytest ──────────────────────────────────────────────────
    console.print("\n[bold]Gate 2: Pytest[/bold]")
    junit_path = os.path.join(root, ".patchi", "dev-check-junit.xml")
    os.makedirs(os.path.dirname(junit_path), exist_ok=True)
    gate2 = _run_gate(
        [sys.executable, "-m", "pytest", "tests/", "-x", "-q",
         f"--junitxml={junit_path}", "--timeout=30"],
        cwd=root, timeout=600,
    )
    results.append(gate2)
    junit = _parse_pytest_junit(junit_path)
    if gate2.passed:
        if junit:
            console.print(
                f"  [green]✓ PASSED[/green] — {junit['tests']} tests, "
                f"{junit['passed']} passed, {junit['failures']} failed, "
                f"{junit['skipped']} skipped"
            )
        else:
            console.print("  [green]✓ PASSED[/green]")
    else:
        if junit:
            kind = gate2.kind or "test_failure"
            console.print(
                f"  [red]✗ FAILED ({kind})[/red] — {junit['tests']} tests, "
                f"{junit['failures']} failed, {junit['errors']} errors"
            )
        else:
            console.print(f"  [red]✗ FAILED ({gate2.kind})[/red]")

    # ── Gate 3: Scan (optional) ─────────────────────────────────────────
    console.print("\n[bold]Gate 3: Security Scan (changed files)[/bold]")
    gate3 = _run_gate(
        [sys.executable, "-m", "patchi.cli.main", "scan", "--changed", "--dry-run"],
        cwd=root, timeout=300,
    )
    results.append(gate3)
    if gate3.passed:
        # Extract activated agents from output
        lines = gate3.output.strip().split("\n")
        agent_line = [line for line in lines if "Activated" in line or "agents" in line.lower()]
        if agent_line:
            console.print(f"  [green]✓ PASSED[/green] — {agent_line[0].strip()}")
        else:
            console.print("  [green]✓ PASSED[/green]")
    else:
        console.print(f"  [yellow]⚠ WARN[/yellow] — {gate3.detail}")

    # ── Summary ─────────────────────────────────────────────────────────
    console.print()
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    all_passed = passed == total

    verdict = "ALL PASSED" if all_passed else f"{passed}/{total} PASSED"
    color = "green" if all_passed else "red"
    console.print(f"[bold {color}]Gate Result: {verdict}[/bold {color}]")

    # Summary table
    tbl = Table(title="Gate Summary", box=None)
    tbl.add_column("Gate", style="bold")
    tbl.add_column("Status")
    tbl.add_column("Time")
    tbl.add_column("Kind")
    for r in results:
        status = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
        kind = r.kind if r.kind != "normal" else ""
        tbl.add_row(r.name, status, f"{r.duration_s:.1f}s", kind)
    console.print(tbl)

    # JSON output
    if json_output:
        output = {
            "ok": all_passed,
            "steps": [
                {
                    "name": r.name,
                    "ok": r.passed,
                    "duration_s": round(r.duration_s, 2),
                    "kind": r.kind if r.kind != "normal" else None,
                    "detail": r.detail or None,
                }
                for r in results
            ],
        }
        if junit:
            output["junit"] = junit

    sys.exit(0 if all_passed else 1)
