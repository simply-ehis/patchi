"""
`p deps` — Supply chain security scan.

Usage:
  p deps                        — run all dependency checks
  p deps --sbom                 — generate SBOM
  p deps --licenses             — check license compliance
  p deps --outdated             — check for outdated packages
  p deps --cve                  — check for known CVEs
"""

from __future__ import annotations

from pathlib import Path

from patchi.cli.console import con
from patchi.cli.display.live_progress import LiveProgress
from patchi.core.agents.base import AgentGroup, AgentInput, list_agents
from patchi.core.config import require_project_root


def run(
    sbom: bool = False,
    licenses: bool = False,
    outdated: bool = False,
    cve: bool = False,
    json_output: bool = False,
    root: Path | None = None,
) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg_mod
    from patchi.core import memory as mem

    brain = mem.get_brain(r)
    config = cfg_mod.load(r)

    all_agents = {a.name: a for a in list_agents(AgentGroup.SECURITY)}
    target_agents = []

    no_flags = not any([sbom, licenses, outdated, cve])
    if cve or no_flags:
        target_agents.append("CVEMonitorAgent")
        target_agents.append("DependencyCVEChecker")
    if sbom or licenses or no_flags:
        target_agents.append("SupplyChainAgent")
    if outdated or no_flags:
        target_agents.append("DependencyVulnerabilityAgent")

    target_agents = list(dict.fromkeys(target_agents))  # dedup

    results = []
    lp = LiveProgress(con, title="Dependency scan")
    lp.start()
    for name in target_agents:
        cls = all_agents.get(name)
        if not cls:
            lp.log(f"  [yellow]Agent {name} not found.[/yellow]")
            lp.update()
            continue
        lp.set_progress(len(results) + 1, len(target_agents), name)
        lp.log(f"  {name}…")
        lp.update()
        inp = AgentInput(root=r, scope=[], brain=brain, config=config, on_message=lambda n, msg, s: (lp.log(f"    {msg}", s), lp.update()))
        try:
            result = cls().run(inp)
            results.append(result)
            total_findings = sum(r.finding_count for r in results)
            lp.set_findings(total_findings)
            lp.log(f"  [#4ADE80]v[/#4ADE80] {result.finding_count} findings", "")
        except Exception as e:
            lp.log(f"  [red]x {name} failed: {e}[/red]", "red")
        lp.update()

    total_findings = sum(r.finding_count for r in results)
    lp.stop(summary=f"{len(results)} agents - {total_findings} findings")

    if json_output:
        import json as _json

        con.print(_json.dumps({
            "agents": [
                {
                    "agent": getattr(res, "agent_name", ""),
                    "status": getattr(getattr(res, "status", None), "value", ""),
                    "findings": [
                        f.to_dict() if hasattr(f, "to_dict") else dict(f)
                        for f in (getattr(res, "findings", []) or [])
                    ],
                }
                for res in results
            ],
            "total_findings": total_findings,
        }, indent=2, default=str))
