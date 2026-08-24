"""
`p assure` — Assurance campaigns: prove properties, record evidence.

Runs built-in invariant verifiers over the current project state (route
analysis + stored findings), records Evidence into the persistent
AssuranceGraph (.patchi/assurance.json), and reports the assurance status.

The output NEVER claims "secure" — it states exactly which properties are
proved, which are violated, and which remain unproven.

Usage:
    p assure                — run campaigns + show status
    p assure --json         — machine-readable
    p assure --reset        — discard all recorded claims/evidence

Exit codes: 0 = all proved · 1 = at least one disproved/unproven · 2 = no data
"""

from __future__ import annotations

import json
import sys

from rich.table import Table

from patchi.cli.console import con
from patchi.core.config import require_project_root

_VERDICT_STYLE = {
    "proved": ("#4ADE80", "PROVED"),
    "disproved": ("#FF4D6D", "VIOLATED"),
    "not_proved": ("#FACC15", "NOT PROVED"),
    "unproven": ("#B8A898", "UNPROVEN"),
}


def run(json_output: bool = False, reset: bool = False) -> int:
    """Entry point for `p assure`."""
    try:
        r = require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return 2

    from patchi.core.assurance.graph import AssuranceGraph, Evidence, Verdict
    from patchi.core.assurance.invariants import (
        BUILTIN_INVARIANTS,
        verify_invariants,
    )

    graph = AssuranceGraph.load(r)
    if reset:
        graph = AssuranceGraph()
        con.print("[dim]Assurance graph reset.[/dim]")

    # ── Gather project data for verifiers ────────────────────────────────────
    from patchi.core.security.intent_analyzer import IntentAnalyzer

    report = IntentAnalyzer().analyze_root(r)

    findings: list[dict] = []
    try:
        from patchi.core import memory as mem

        stored = mem.load_scan_results(r)
        for result in (stored or {}).values():
            data = result if isinstance(result, dict) else {}
            items = data.get("findings") or []
            findings.extend(items if isinstance(items, list) else [])
    except Exception:
        findings = []

    project_data = {"routes": report, "findings": findings}

    # ── Run campaigns ────────────────────────────────────────────────────────
    results = verify_invariants(BUILTIN_INVARIANTS, project_data)

    for inv, supports, detail, artifact in results:
        claim = graph.upsert_claim(
            inv.id,
            inv.statement,
            domain=inv.domain,
            severity_if_disproved=inv.severity_if_disproved,
        )
        graph.attach_evidence(
            claim.id,
            Evidence(
                source="assure_campaign",
                detail=detail,
                supports=supports,
                artifact={"invariant_type": inv.invariant_type.value, **artifact},
            ),
        )
        # Disproved critical claims enter the repair loop record.
        if claim.verdict == Verdict.DISPROVED:
            already = any(
                rep.get("description") == detail for rep in claim.repairs
            )
            if not already:
                claim.record_repair(detail, outcome="awaiting-fix")

    graph.save(r)

    # ── Report ───────────────────────────────────────────────────────────────
    coverage = graph.coverage()

    if json_output:
        sys.stdout.write(json.dumps(coverage, indent=2, default=str) + "\n")
        has_bad = coverage["by_verdict"].get("disproved", 0) > 0 or (
            coverage["claims_total"] == 0
        )
        return 1 if has_bad else 0

    con.print()
    con.print("[bold #C8621A]Assurance Status[/bold #C8621A]")
    con.print()

    if not graph.claims:
        con.print("[yellow]No claims established.[/yellow]")
        return 2

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Verdict", width=12)
    table.add_column("Property", width=52)
    table.add_column("Domain", style="dim", width=26)
    table.add_column("Evidence", justify="right", width=8)

    for claim in sorted(graph.claims.values(), key=lambda c: c.verdict.value):
        color, label = _VERDICT_STYLE[claim.verdict.value]
        table.add_row(
            f"[{color}]{label}[/{color}]",
            claim.statement[:52],
            claim.domain[:26],
            str(len(claim.evidence)),
        )
    con.print(table)
    con.print()

    disproved = coverage["by_verdict"].get("disproved", 0)
    proved = coverage["by_verdict"].get("proved", 0)
    total = coverage["claims_total"]

    con.print(f"[bold]{coverage['statement']}[/bold]")
    if disproved:
        con.print("[#FF4D6D]Violated properties above need fixes — run `p fix` or `p chain`.[/#FF4D6D]")
    elif proved < total:
        con.print("[dim]Unproved properties have insufficient evidence — scan deeper first.[/dim]")
    con.print()
    con.print(
        "[dim]No evidence currently demonstrates a known violation within "
        f"the {total}-property tested scope.[/dim]" if disproved == 0 else ""
    )
    con.print()

    return 1 if (disproved or total == 0) else 0
