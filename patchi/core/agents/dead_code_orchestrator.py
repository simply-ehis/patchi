"""
DeadCodeOrchestrator — sglyon/deadcode wrapper (PATCHI_FEATURE_PLAN §2.1.1).

Orchestrates sglyon/deadcode (Python/JS/TS/Go/Elixir) + falls back to
DeadCodeScanner's per-language dispatch (vulture, knip, cargo-udeps, etc.).
Emits unified JSON {file, line, name, type, message, confidence} for
DeadCodeRemover auto-delete (proposed="" + applier empty==delete + risk_gate).

Usage: registered as AgentGroup.SCANNER, timeout 120s, safe to run even when
`sgyon/deadcode` binary not installed (graceful fallback to existing tools).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
    safe_rglob,
)
from patchi.core.agents.dead_code_scanner import _run_all_tools, _should_skip
from patchi.core.security.tool_adapters import make_tool_finding

_log = logging.getLogger("patchi.agents.dead_code_orchestrator")


def _run_sglyon_deadcode(root: Path) -> list[dict] | None:
    """Run sglyon/deadcode if installed; parses JSON output."""
    # Try binary first, then python -m deadcode
    candidates = []
    if shutil.which("deadcode"):
        candidates.append(["deadcode", "--format", "json", str(root)])
    # sglyon/deadcode also provides `deadcode` entrypoint via pip; fallback to module
    candidates.append([shutil.which("python") or "python", "-m", "deadcode", "--format", "json", str(root)])
    for cmd in candidates:
        if not cmd[0] or (cmd[0] not in ("python", "python3") and not shutil.which(cmd[0])):
            continue
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            if proc.returncode not in (0, 1):
                continue
            raw = proc.stdout.strip() or proc.stderr.strip()
            if not raw:
                continue
            data = json.loads(raw)
            # sglyon/deadcode JSON: [{file, line, symbol, kind}]
            out: list[dict] = []
            for item in data if isinstance(data, list) else data.get("results", []):
                f = item.get("file") or item.get("filename") or ""
                try:
                    rel = Path(f).relative_to(root).as_posix() if f else ""
                except ValueError:
                    rel = f
                if _should_skip(rel):
                    continue
                out.append(
                    {
                        "file": rel or f,
                        "line": int(item.get("line", 0) or 0),
                        "name": item.get("symbol") or item.get("name", ""),
                        "type": item.get("kind") or item.get("type", "deadcode"),
                        "message": f"sglyon/deadcode: {item.get('kind','unused')} {item.get('symbol','')}",
                        "confidence": 90,
                        "code": "",
                    }
                )
            if out:
                return out
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, OSError) as exc:
            _log.debug("sglyon deadcode %s failed: %s", cmd[0], exc)
            continue
    return None


@register
class DeadCodeOrchestrator(BaseAgent):
    """Orchestrator wrapping sglyon/deadcode + DeadCodeScanner per-language tools."""

    group = AgentGroup.SCANNER
    name = "DeadCodeOrchestrator"
    timeout = 120
    description = "Cross-language dead code via sglyon/deadcode orchestrator (py/js/ts/go/elixir) + fallback to vulture/knip/cargo-udeps dispatch"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings: list = []
        # 1. Try sglyon/deadcode first (unified JSON)
        sg = _run_sglyon_deadcode(inp.root)
        if sg:
            for item in sg:
                findings.append(
                    make_tool_finding(
                        agent=self.name,
                        ftype=item.get("type", "deadcode"),
                        raw_severity="low",
                        file=item.get("file", ""),
                        line=item.get("line", 0),
                        message=item.get("message", ""),
                        snippet=item.get("code", ""),
                        confidence_raw=item.get("confidence", 90),
                    )
                )
            result.data["orchestrator"] = "sglyon/deadcode"
            result.data["sglyon_count"] = len(sg)
        else:
            # 2. Fallback: existing per-language dispatch (vulture, ts-prune, cargo-udeps etc.)
            fallback = _run_all_tools(inp.root)
            for item in fallback:
                findings.append(
                    make_tool_finding(
                        agent=self.name,
                        ftype=item.get("type", "deadcode"),
                        raw_severity="low",
                        file=item.get("file", ""),
                        line=item.get("line", 0),
                        message=item.get("message", ""),
                        snippet=item.get("code", ""),
                        confidence_raw=item.get("confidence", 80),
                    )
                )
            result.data["orchestrator"] = "fallback-per-language"
            result.data["fallback_count"] = len(fallback)

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.files_scanned = len(set(f.file for f in findings)) if findings else 0
        result.data["total_findings"] = len(findings)
