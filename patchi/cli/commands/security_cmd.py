"""
Security command — the `security` family default (Part 3 §1).

`p security` runs the full AgentGroup.SECURITY group (not a hardcoded
shortlist) and summarizes: findings by severity, per-agent status including
skipped (gate-blocked / tool-missing) with reasons. Related views live in
the same family: findings, chains, rules, deps, assure, charter, restrict.
"""

from __future__ import annotations

import json

from patchi.cli.console import con
from patchi.core.config import require_project_root


def run(json_output: bool = False, scope: str | None = None) -> int:
    """Entry point for `p security [scope]`."""
    from patchi.core.agents.base import AgentGroup, discover_agent_modules
    from patchi.core.agents.coordinator import Coordinator, merge_results

    try:
        root = require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return 2

    discover_agent_modules()
    coord = Coordinator(root)
    scopes = [scope] if scope else None
    results = coord.run_group(AgentGroup.SECURITY, scope=scopes)
    merged = merge_results(results)

    def _sev(f) -> str:
        s = f.get("severity", "info") if isinstance(f, dict) else getattr(f, "severity", "info")
        return str(getattr(s, "value", s)).lower()

    sev_counts: dict[str, int] = {}
    for f in merged.get("findings", []):
        sev = _sev(f)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    skipped = [
        {
            "agent": r.agent_name,
            # Precedence: explicit skip reason (skip()/skip_for_tool()), then
            # gate blocks, then errors — a bare "skipped" hides why (Part 3 §2.5).
            "reason": (
                r.data.get("skip_reason")
                or r.data.get("gate_reason")
                or (r.errors[0] if r.errors else None)
                or "skipped"
            ),
        }
        for r in results
        if str(getattr(r.status, "value", r.status)) == "skipped"
    ]

    payload = {
        "agents_run": len(results),
        "findings": sum(sev_counts.values()),
        "by_severity": sev_counts,
        "skipped": skipped,
    }
    if json_output:
        print(json.dumps(payload, indent=2, default=str))
        return 0

    con.print()
    con.print("[bold #C8621A]Security group scan[/bold #C8621A]")
    con.print(f"  Agents ran: [bold]{len(results)}[/bold]")
    con.print(f"  Findings: [bold]{payload['findings']}[/bold]")
    if sev_counts:
        con.print("  By severity: " + ", ".join(f"{k}={v}" for k, v in sorted(sev_counts.items())))
    if skipped:
        con.print(f"  [dim]Skipped ({len(skipped)}):[/dim]")
        for s in skipped[:10]:
            con.print(f"    [dim]- {s['agent']}: {str(s['reason'])[:100]}[/dim]")
    con.print("[dim]Family views: p findings · p chains · p rules · p deps · p assure · p charter · p restrict[/dim]")
    return 0
