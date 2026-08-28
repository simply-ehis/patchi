"""
Dev Check API — run p dev check gates from the web UI.

Runs the three gates (ruff lint, pytest, security scan) and returns
structured results for display in the Command Center card.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.templating import Jinja2Templates

router = APIRouter(prefix="/api")

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.post("/dev-check")
async def run_dev_check(request: Request, strict: bool = False) -> JSONResponse:
    """Run p dev check gates and return results.

    Gates:
    1. Ruff lint (fast)
    2. Pytest (may timeout on slow tests)
    3. Security scan (changed files)
    """
    root = request.app.state.root

    results = {"gates": [], "overall": "PASS", "strict": strict}
    overall_pass = True

    # Gate 1: Ruff
    gate1 = await _run_gate(
        "Ruff Lint",
        ["python", "-m", "ruff", "check", "patchi/",
         "--select", "E,F,W", "--ignore", "E501,E402,E741", "--quiet"],
        root,
        timeout=30,
    )
    results["gates"].append(gate1)
    if gate1["status"] != "PASS":
        overall_pass = False

    # Gate 2: Pytest
    gate2 = await _run_gate(
        "Pytest",
        ["python", "-m", "pytest", "tests/",
         "-x", "-q", "--timeout=30", "--tb=no",
         "--ignore=tests/test_differential.py",
         "--ignore=tests/test_gnn_properties.py"],
        root,
        timeout=120,
    )
    results["gates"].append(gate2)
    if gate2["status"] != "PASS":
        overall_pass = False

    # Gate 3: Security Scan (changed files)
    gate3 = await _run_gate(
        "Security Scan",
        ["python", "-m", "patchi.cli.main", "scan",
         "--changed", "--quiet", "--json"],
        root,
        timeout=60,
    )
    results["gates"].append(gate3)
    if gate3["status"] != "PASS":
        overall_pass = False

    results["overall"] = "PASS" if overall_pass else "FAIL"
    results["timestamp"] = time.time()
    results["strict"] = strict

    return JSONResponse(results)


async def _run_gate(
    name: str,
    cmd: list[str],
    cwd: Path,
    timeout: int = 60,
) -> dict:
    """Run a single gate and return structured result."""
    start = time.time()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )

        elapsed = time.time() - start
        output = stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")

        # Parse output for specific gate info
        parsed = _parse_gate_output(name, output)

        return {
            "name": name,
            "status": "PASS" if proc.returncode == 0 else "FAIL",
            "exit_code": proc.returncode,
            "elapsed": round(elapsed, 1),
            "output": output[:2000],  # Truncate long output
            "parsed": parsed,
        }

    except TimeoutError:
        return {
            "name": name,
            "status": "TIMEOUT",
            "exit_code": -1,
            "elapsed": timeout,
            "output": f"Gate timed out after {timeout}s",
            "parsed": {},
        }
    except Exception as e:
        return {
            "name": name,
            "status": "ERROR",
            "exit_code": -1,
            "elapsed": time.time() - start,
            "output": str(e),
            "parsed": {},
        }


def _parse_gate_output(gate_name: str, output: str) -> dict:
    """Parse gate output for specific metrics."""
    parsed = {}

    if gate_name == "Ruff Lint":
        # Count errors
        error_lines = [l for l in output.splitlines() if l.startswith("Found ")]
        if error_lines:
            parts = error_lines[0].split()
            if len(parts) >= 2:
                parsed["error_count"] = int(parts[1])

        # Count by code
        codes = {}
        for line in output.splitlines():
            if " E" in line or " F" in line or " W" in line:
                parts = line.split()
                for p in parts:
                    if len(p) == 4 and p[0] in "EFW":
                        codes[p] = codes.get(p, 0) + 1
        parsed["by_code"] = codes

    elif gate_name == "Pytest":
        # Parse pytest summary
        for line in output.splitlines():
            if "passed" in line or "failed" in line:
                parsed["summary"] = line.strip()
            if "error" in line.lower() and "test" in line.lower():
                parsed["collection_error"] = line.strip()

    elif gate_name == "Security Scan":
        # Try to parse JSON output
        try:
            # Find JSON in output (may have other text before/after)
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    data = json.loads(line)
                    parsed["findings"] = data.get("total_findings", 0)
                    parsed["domains"] = data.get("domains", [])
                    break
        except (json.JSONDecodeError, AttributeError):
            parsed["parse_error"] = "Could not parse JSON output"

    return parsed
