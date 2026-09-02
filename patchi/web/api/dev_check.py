"""
Dev Check API — run p dev check gates from the web UI.

Runs the three gates (ruff lint, pytest, security scan) and returns
structured results for display in the Command Center card.
"""

from __future__ import annotations
import logging

import asyncio
import os
import json
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.templating import Jinja2Templates
_log = logging.getLogger("patchi.web.api.dev_check")


router = APIRouter(prefix="/api")

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.post("/dev-check")
async def run_dev_check(request: Request, strict: bool = False, fast: bool = False) -> JSONResponse:
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

    # Gate 2: Pytest — stable test files only
    _STABLE = [
        "tests/test_config.py", "tests/test_charter.py", "tests/test_contract.py",
        "tests/test_base.py", "tests/test_memory.py",
        "tests/test_web.py", "tests/test_assurance.py",
        "tests/test_risk_gate.py", "tests/test_scanner.py", "tests/test_detector.py",
        "tests/test_secrets.py", "tests/test_security_config.py",
        "tests/test_sigma_engine.py", "tests/test_blast_radius_v2.py",
        "tests/test_chain_engine.py",
        "tests/test_language_support.py", "tests/test_ast_utils.py",
        "tests/test_import_graph.py",
        "tests/test_hosted_mode.py", "tests/test_hosted_tokens.py",
        "tests/test_hosted_audit_log.py", "tests/test_hosted_ip_reputation.py",
        "tests/test_hosted_log_parsers.py", "tests/test_hosted_watchlist.py",
        "tests/test_hosted_anomaly.py",
        "tests/test_new_agents.py", "tests/test_p3_agents.py",
        "tests/test_v2_agent_audit.py", "tests/test_v2_smoke.py",
        "tests/test_attack_agent.py", "tests/test_doc_claim_agent.py",
        "tests/test_fix_agents.py", "tests/test_scanners.py",
        "tests/test_smart_agent.py",
        "tests/test_governor_v2.py", "tests/test_governor_integration.py",
        "tests/test_layered_brain.py", "tests/test_brain_watcher.py",
        "tests/test_rebuilt_modules.py",
        "tests/test_reasoning.py", "tests/test_noise_reduction.py",
        "tests/test_ignore_learner.py", "tests/test_corpus_noise.py",
        "tests/test_ai_client.py", "tests/test_debug_capture.py",
        "tests/test_debug_codelldb.py", "tests/test_debug_node.py",
        "tests/test_debug_powershell.py",
        "tests/test_freshness.py", "tests/test_patch.py",
        "tests/test_proactive.py", "tests/test_proactive_phase5.py",
        "tests/test_snapshot.py", "tests/test_verify.py",
        "tests/test_verify_loop.py", "tests/test_generated_suite.py",
        "tests/test_app_profile.py", "tests/test_audit.py",
        "tests/test_cpg_extractor.py", "tests/test_framework.py",
        "tests/test_new_features.py", "tests/test_route_mapper.py",
        "tests/test_applier.py", "tests/test_dispatcher.py",
        "tests/test_notifications.py", "tests/test_queue.py",
        "tests/test_scheduler.py", "tests/test_domain_loader.py",
    ]
    _CORE = [
        "tests/test_config.py", "tests/test_charter.py", "tests/test_contract.py",
        "tests/test_base.py", "tests/test_memory.py", "tests/test_web.py",
        "tests/test_risk_gate.py", "tests/test_scanner.py", "tests/test_detector.py",
        "tests/test_secrets.py", "tests/test_language_support.py", "tests/test_ast_utils.py",
        "tests/test_import_graph.py", "tests/test_ai_client.py",
        "tests/test_freshness.py", "tests/test_framework.py",
    ]
    _ptests = _CORE if fast else _STABLE
    # Use xdist only on 4+ CPU machines
    _ptargs = ["python", "-m", "pytest"]
    import os as _os
    if _os.cpu_count() and _os.cpu_count() >= 4:
        try:
            import xdist  # noqa: F401
            _ptargs += ["-n", "auto", "--dist", "loadscope"]
        except ImportError:
            pass
    gate2 = await _run_gate(
        "Pytest", _ptargs + _ptests + [
         "-q", "--tb=no"],
         root,
         timeout=360,
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
    results["fast"] = fast

    # Record history for the timing chart
    _record_history(root, results)

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
        # Use temp files to avoid pipe deadlock on Windows when
        # pytest subprocess tests keep pipe handles open.
        import tempfile
        tmp_out = tempfile.NamedTemporaryFile(mode='wb', suffix='.out', delete=False)
        tmp_err = tempfile.NamedTemporaryFile(mode='wb', suffix='.err', delete=False)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(cwd),
                stdout=tmp_out,
                stderr=tmp_err,
            )
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        finally:
            tmp_out.close()
            tmp_err.close()
        elapsed = time.time() - start
        try:
            output = open(tmp_out.name, 'rb').read().decode('utf-8', errors='replace') + open(tmp_err.name, 'rb').read().decode('utf-8', errors='replace')
        except Exception:
            output = ''
        # Cleanup
        try:
            os.unlink(tmp_out.name)
            os.unlink(tmp_err.name)
        except Exception as _exc:
            _log.warning('_run_gate failed: %s', _exc)

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


def _record_history(root: Path, results: dict) -> None:
    """Append gate timing data to history file for the chart."""
    try:
        import json as _json

        history_path = root / ".patchi" / "dev_check_history.json"
        history_path.parent.mkdir(parents=True, exist_ok=True)

        history: list[dict] = []
        if history_path.is_file():
            try:
                history = _json.loads(history_path.read_text(encoding="utf-8"))
            except Exception:
                history = []

        entry = {
            "timestamp": results.get("timestamp", time.time()),
            "overall": results.get("overall", "?"),
            "fast": results.get("fast", False),
            "gates": [],
        }
        for g in results.get("gates", []):
            entry["gates"].append({
                "name": g.get("name", "?"),
                "status": g.get("status", "?"),
                "elapsed": g.get("elapsed", 0),
            })
        entry["total_time"] = sum(g["elapsed"] for g in entry["gates"])

        history.append(entry)

        # Keep last 50 runs
        if len(history) > 50:
            history = history[-50:]

        tmp = history_path.with_suffix(".json.tmp")
        tmp.write_text(_json.dumps(history, indent=2), encoding="utf-8")
        tmp.replace(history_path)
    except Exception as _exc:
        _log.debug("dev_check history write skipped: %s", _exc)


@router.get("/dev-check/history")
async def dev_check_history(request: Request) -> JSONResponse:
    """Return gate execution history for the timing chart."""
    root = request.app.state.root
    import json as _json

    history_path = root / ".patchi" / "dev_check_history.json"
    history: list[dict] = []
    if history_path.is_file():
        try:
            history = _json.loads(history_path.read_text(encoding="utf-8"))
        except Exception:
            history = []

    # Keep last 20 for the chart
    recent = history[-20:]
    return JSONResponse({"ok": True, "runs": recent, "count": len(recent)})


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
