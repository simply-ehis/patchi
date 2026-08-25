"""
Tool Health — three-state probe for external security tooling.

Reconstructed module (referenced by cli/commands/doctor_cmd.py; original
was lost before any commit existed). A tool that is installed but not
runnable must be reported as *broken*, never silently as present-and-fine
or as absent:

    check_tool("bandit") -> {"status": "ok",      "version": "1.7.5", "hint": ""}
                            {"status": "broken",  "version": "",      "hint": "..."}
                            {"status": "missing", "version": "",      "hint": ""}

_TOOLS is the registry of known probeable tools; unknown names fall back
to the caller's own PATH/import check.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

_log = logging.getLogger("patchi.core.agents.tool_health")

_VERSION_TIMEOUT_S = 10

# Tools this module knows how to probe end-to-end.
_TOOLS = frozenset(
    {
        "bandit",
        "semgrep",
        "codeql",
        "pyre",
        "safety",
        "pip-audit",
        "git",
        "node",
        "npm",
        "ollama",
    }
)

# Per-tool run flags: some tools don't answer `--version` nicely.
_VERSION_ARGS: dict[str, list[str]] = {
    "codeql": ["version"],
    "pyre": ["--version"],
}

# Focused hints when a present tool fails to run.
_BROKEN_HINTS: dict[str, str] = {
    "codeql": "codeql binary missing — install the CodeQL CLI and add it to PATH",
    "pyre": "pyre.bin not runnable on this platform — see pyre-check install docs",
}


def _extract_version(output: str, tool: str) -> str:
    """Pull a plausible version token out of a --version blob."""
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.search(r"\d+\.\d+(?:\.\d+)?[a-zA-Z0-9.\-]*", line)
        if m:
            return m.group(0)
        # Fall back to first non-empty line, minus the tool name echo
        lowered = line.lower()
        if tool.lower() not in lowered:
            return line[:40]
    return ""


def check_tool(tool: str) -> dict:
    """Probe one external tool. Never raises."""
    path = shutil.which(tool)
    if path is None:
        return {"status": "missing", "version": "", "hint": ""}

    args = _VERSION_ARGS.get(tool, ["--version"])
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [path, *args],
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        hint = _BROKEN_HINTS.get(tool, f"{tool} did not answer within {_VERSION_TIMEOUT_S}s")
        return {"status": "broken", "version": "", "hint": hint}
    except OSError as exc:
        return {
            "status": "broken",
            "version": "",
            "hint": _BROKEN_HINTS.get(tool, f"cannot execute {path}: {exc}"),
        }

    if proc.returncode != 0:
        hint = _BROKEN_HINTS.get(
            tool,
            f"{tool} exits {proc.returncode} on {args[0]} — reinstall or check its runtime deps",
        )
        return {"status": "broken", "version": "", "hint": hint}

    blob = (proc.stdout or "") + (proc.stderr or "")
    return {
        "status": "ok",
        "version": _extract_version(blob, tool),
        "hint": "",
    }
