"""
`p retest` — verify fixes closed the findings (the billable second pass).

Compares the last scan's findings against a fresh run of the same detector
agents and reports, per finding: FIXED / PERSISTING / NEW. A finding is
never declared fixed when its agent couldn't run — that reports UNKNOWN.

Usage:
  p retest              — retest all findings from the last scan
  p retest --agent InjectionAgent   — only findings from one agent
  p retest --json       — JSON output (CI-friendly)

Records land in .patchi/retests/retest-<timestamp>.json so a client can see
the before/after trail across engagements.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from patchi.cli.console import con, print_json
from patchi.core.config import require_project_root

_LINE_TOLERANCE = 5


def finding_key(finding: dict) -> tuple[str, str]:
    """Identity of a finding across runs: file + type (line drifts)."""
    return (str(finding.get("file", "")), str(finding.get("type", "")))


def match_findings(
    baseline: list[dict], current: list[dict], line_tolerance: int = _LINE_TOLERANCE
) -> dict[str, list[dict]]:
    """Diff two finding lists into fixed / persisting / new.

    A baseline finding persists when a current finding shares file+type
    within line tolerance (fixes shift lines; rewrites change them a lot).
    Pure function — unit-tested, no I/O.
    """
    remaining = list(current)
    persisting: list[dict] = []
    fixed: list[dict] = []
    for old in baseline:
        match = None
        for new in remaining:
            if finding_key(old) != finding_key(new):
                continue
            try:
                if abs(int(old.get("line", 0)) - int(new.get("line", 0))) <= line_tolerance:
                    match = new
                    break
            except (TypeError, ValueError):
                match = new
                break
        if match is None:
            fixed.append(old)
        else:
            persisting.append({"baseline": old, "current": match})
            remaining.remove(match)
    return {"fixed": fixed, "persisting": persisting, "new": remaining}


def _baseline_findings(scans: dict, only_agent: str | None = None) -> dict[str, list[dict]]:
    """{agent_name: [finding, ...]} from stored scan results."""
    out: dict[str, list[dict]] = {}
    for agent_name, scan_data in (scans or {}).items():
        if only_agent and agent_name != only_agent:
            continue
        if not isinstance(scan_data, dict):
            continue
        findings = scan_data.get("findings", []) or []
        if findings:
            out[agent_name] = [dict(f) for f in findings]
    return out


def _rerun_agent(root: Path, agent_name: str) -> tuple[str, list[dict]]:
    """Re-run one detector. Returns (status, findings).

    status: ok | skipped:<reason> | error:<reason>. Anything but ok means
    that agent's baseline findings report UNKNOWN, never FIXED.
    """
    import patchi.core.security.security_agents  # noqa: F401 — registers agents
    from patchi.core.agents.base import AgentInput, AgentStatus, get_agent
    from patchi.core import memory as mem

    cls = get_agent(agent_name)
    if cls is None:
        return f"skipped:unregistered ({agent_name})", []
    try:
        brain = mem.get_brain(root)
    except Exception:
        brain = {}
    inp = AgentInput(root=root, scope=[], brain=brain if isinstance(brain, dict) else {}, config={})
    try:
        res = cls().run(inp)
    except Exception as exc:
        return f"error:{exc}", []
    if res.status == AgentStatus.SKIPPED:
        return f"skipped:{res.data.get('skip_reason', 'no reason')}", []
    out = []
    for f in res.findings or []:
        if isinstance(f, dict):
            out.append(f)
            continue
        out.append(
            {
                "agent": agent_name,
                "type": getattr(f, "type", ""),
                "severity": str(getattr(f, "severity", "")),
                "file": getattr(f, "file", ""),
                "line": getattr(f, "line", getattr(f, "line_start", 0)),
                "message": getattr(f, "message", getattr(f, "title", "")),
                "cwe": getattr(f, "cwe", ""),
            }
        )
    return "ok", out


def run(
    agent: str | None = None,
    json_output: bool = False,
    root: Path | None = None,
) -> int:
    """Entry point for `p retest`."""
    from patchi.core import memory as mem

    r = root or require_project_root()
    scans = mem.get_scan_results(r)
    baseline = _baseline_findings(scans, only_agent=agent)
    if not baseline:
        msg = "No stored findings to retest — run `p scan` first."
        if json_output:
            print_json({"ok": False, "error": msg})
        else:
            con.print(f"[dim]{msg}[/dim]")
        return 1

    per_agent: dict[str, dict] = {}
    totals = {"fixed": 0, "persisting": 0, "new": 0, "unknown": 0}
    for agent_name, old_findings in baseline.items():
        status, current = _rerun_agent(r, agent_name)
        if status != "ok":
            per_agent[agent_name] = {"status": status, "unknown": old_findings}
            totals["unknown"] += len(old_findings)
            continue
        diff = match_findings(old_findings, current)
        per_agent[agent_name] = {"status": "ok", **diff}
        totals["fixed"] += len(diff["fixed"])
        totals["persisting"] += len(diff["persisting"])
        totals["new"] += len(diff["new"])

    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totals": totals,
        "agents": per_agent,
    }
    out_dir = r / ".patchi" / "retests"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"retest-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}.json"
    out_path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")

    if json_output:
        print_json({**record, "path": str(out_path)})
    else:
        con.print()
        con.print(
            f"  [bold]Retest[/bold]  [dim]{totals['fixed']} fixed  "
            f"{totals['persisting']} persisting  {totals['new']} new  "
            f"{totals['unknown']} unknown[/dim]"
        )
        for agent_name, res in per_agent.items():
            if res["status"] != "ok":
                con.print(f"    [dim]{agent_name}: UNKNOWN — {res['status']}[/dim]")
        if totals["persisting"]:
            con.print("  [bold]Still open:[/bold]")
            for agent_name, res in per_agent.items():
                for p in res.get("persisting", [])[:10]:
                    b = p["baseline"]
                    con.print(f"    [dim]{b.get('file', '?')}:{b.get('line', 0)}[/dim] {b.get('message', b.get('type', ''))}")
        con.print(f"  [dim]Record → {out_path}[/dim]")
        con.print()

    failed = totals["persisting"] + totals["new"] + totals["unknown"]
    return 0 if failed == 0 else 1
