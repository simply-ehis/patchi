from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_log = logging.getLogger("patchi.agents.tool_runner")


def is_tool_available(name: str) -> bool:
    """Return True if an executable `name` is available on PATH."""
    return shutil.which(name) is not None


def _run_process(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Run a subprocess command and return (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout: {str(e)}"
    except Exception as e:
        return 1, "", str(e)


def run_gitleaks(root: Path, timeout: int = 120) -> dict[str, Any]:
    """Run gitleaks detect on `root` and return parsed JSON results.

    Returns a dict with keys:
      - tool: "gitleaks" or "gitleaks_missing"
      - findings: list (empty if none or on error)
      - error: optional error string
      - tool_missing: True when gitleaks is not installed
    """
    if not is_tool_available("gitleaks"):
        return {"tool": "gitleaks_missing", "findings": [], "tool_missing": True}

    with tempfile.NamedTemporaryFile(prefix="gitleaks_report_", suffix=".json", delete=False) as tf:
        report_path = Path(tf.name)

    cmd = [
        "gitleaks",
        "detect",
        "--source",
        str(root),
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--no-git",
    ]
    rc, out, err = _run_process(cmd, timeout=timeout)

    if rc != 0 and not report_path.exists():
        return {"tool": "gitleaks", "findings": [], "error": err or out}

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        findings = data if isinstance(data, list) else data.get("findings", [])
    except Exception as e:
        return {
            "tool": "gitleaks",
            "findings": [],
            "error": f"parse_error: {e}",
        }
    finally:
        try:
            report_path.unlink()
        except Exception as e:
            _log.warning("run_gitleaks failed: %s", e)

    return {"tool": "gitleaks", "findings": findings}


def run_semgrep(root: Path, config: str | None = None, timeout: int = 120) -> dict[str, Any]:
    """Run semgrep on `root` and return parsed JSON output.

    If `config` is provided it will be passed as `--config` value.
    """
    if not is_tool_available("semgrep"):
        return {"tool": "semgrep_missing", "results": [], "tool_missing": True}

    cmd = ["semgrep", "--json"]
    if config:
        cmd.append(f"--config={config}")
    cmd.append(str(root))

    rc, out, err = _run_process(cmd, timeout=timeout)
    if rc != 0:
        # semgrep may still print a partial JSON to stdout; try to parse it
        data_text = out
    else:
        data_text = out

    try:
        parsed = json.loads(data_text) if data_text else {}
    except Exception as e:
        return {"tool": "semgrep", "results": [], "error": f"parse_error: {e}"}

    return {
        "tool": "semgrep",
        "results": parsed.get("results", []) if isinstance(parsed, dict) else parsed,
    }


def run_bandit(root: Path, timeout: int = 180) -> dict[str, Any]:
    """Run bandit on `root` and return parsed JSON results.

    Bandit exit codes: 0 = no issues, 1 = issues found, 2 = tool error.
    Only exit code 2 (or a missing executable) is treated as a failure —
    issues found is the normal, valid outcome.

    Returns a dict with keys:
      - tool: "bandit" or "bandit_missing"
      - findings: list of bandit result dicts (empty if none or on error)
      - error: optional error string
      - tool_missing: True when bandit is not installed
    """
    if not is_tool_available("bandit"):
        return {"tool": "bandit_missing", "findings": [], "tool_missing": True}

    cmd = ["bandit", "-r", str(root), "-f", "json", "-q"]
    rc, out, err = _run_process(cmd, timeout=timeout)

    if rc == 2:
        return {"tool": "bandit", "findings": [], "error": err or out}

    try:
        data = json.loads(out)
        findings = data.get("results", []) if isinstance(data, dict) else []
    except Exception as e:
        return {"tool": "bandit", "findings": [], "error": f"parse_error: {e}"}

    return {"tool": "bandit", "findings": findings}


def run_vulture(root: Path, timeout: int = 60) -> dict[str, Any]:
    """Run vulture as a subprocess and return its JSON output when possible.

    Vulture's CLI supports outputting JSON via `--format json` in newer versions.
    If unavailable, return empty findings and a hint.
    """
    if not is_tool_available("vulture"):
        return {"tool": "vulture_missing", "findings": [], "tool_missing": True}

    cmd = ["vulture", str(root), "--format", "json"]
    rc, out, err = _run_process(cmd, timeout=timeout)
    if rc != 0:
        return {"tool": "vulture", "findings": [], "error": err or out}

    try:
        data = json.loads(out)
    except Exception as e:
        # older vulture versions may not support json — return plain text as single finding
        _log.warning("run_vulture failed: %s", e)
        return {"tool": "vulture", "findings": [], "raw": out}

    return {"tool": "vulture", "findings": data}
