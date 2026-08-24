"""
`p chain` — Exploit chain analysis over current findings.

Reads the findings already stored in scan memory (never re-scans), links them
into attack narratives, and renders chains + attack trees.

Usage:
    p chain                    — analyze findings, show worst chains + trees
    p chain --json             — machine-readable output
    p chain --min-severity high — only show high/critical chains

Exit codes (findings-aware, mirrors p scan / p security):
    0 — no exploit chains found
    1 — at least one chain found
    2 — no findings to analyze (run `p scan` first)
"""

from __future__ import annotations

import json
import sys

from rich.table import Table

from patchi.cli.console import con
from patchi.core.config import require_project_root


def run(
    min_severity: str = "medium",
    json_output: bool = False,
    max_chains: int = 20,
) -> int:
    """Entry point for `p chain`."""
    try:
        r = require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return 2

    from patchi.core import memory as mem

    stored = mem.load_scan_results(r)
    if not stored:
        con.print("[yellow]No findings in memory. Run `p scan` first.[/yellow]")
        return 2

    # Rehydrate Finding-like objects from stored dicts.
    from patchi.core.agents.base import Finding, Severity

    findings: list[Finding] = []
    for result in stored.values():
        data = result.get("findings") or result if isinstance(result, dict) else {}
        items = data if isinstance(data, list) else (data.get("findings") or [])
        for f in items:
            try:
                findings.append(
                    Finding(
                        agent=f.get("agent", "?"),
                        type=f.get("type", "unknown"),
                        severity=Severity(f.get("severity", "medium")),
                        file=f.get("file", ""),
                        line=int(f.get("line", 0)),
                        message=f.get("message", ""),
                        cwe=f.get("cwe", ""),
                    )
                )
            except (ValueError, KeyError):
                continue

    if not findings:
        con.print("[yellow]No findings in memory. Run `p scan` first.[/yellow]")
        return 2

    from patchi.core.security.attack_tree import build_attack_trees
    from patchi.core.security.chain_analyzer import ChainAnalyzer

    analyzer = ChainAnalyzer(findings)
    chains = analyzer.find_chains(max_chains=max_chains)
    trees = build_attack_trees(chains)

    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    floor = order.get(min_severity.lower(), 2)
    visible = [c for c in chains if order.get(c.severity, 0) >= floor]

    if json_output:
        payload = {
            "chains": [c.to_dict() for c in visible],
            "trees": [t.to_dict() for t in trees],
            "summary": analyzer.summary(),
        }
        sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")
        return 1 if visible else 0

    con.print()
    con.print(
        f"[bold #C8621A]Exploit Chain Analysis[/bold #C8621A]  "
        f"[dim]{len(findings)} findings -> {len(chains)} chains "
        f"({len(visible)} >= {min_severity})[/dim]"
    )
    con.print()

    if not chains:
        con.print("[#4ADE80]No multi-step attack chains detected.[/#4ADE80]")
        con.print("[dim]Individual findings still apply — see `p security`.[/dim]")
        return 0

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("#", width=4)
    table.add_column("Sev", width=9)
    table.add_column("Score", justify="right", width=6)
    table.add_column("Chain")
    for i, c in enumerate(visible, 1):
        color = {"critical": "#FF4D6D", "high": "#FF8C42", "medium": "#FACC15"}.get(
            c.severity, "#B8A898"
        )
        table.add_row(
            str(i),
            f"[{color}]{c.severity}[/{color}]",
            f"{c.score:.0f}",
            c.narrative[:120],
        )
    con.print(table)

    if trees:
        con.print()
        for tree in trees[:3]:
            con.print(f"[dim]{tree.render()}[/dim]")
            con.print()

    con.print("[dim]Full detail: p chain --json | jq '.chains'[/dim]")
    con.print()
    return 1 if visible else 0
