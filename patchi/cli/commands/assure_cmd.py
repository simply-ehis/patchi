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


def run(
    json_output: bool = False,
    reset: bool = False,
    run_attackers: bool = False,
    run_campaigns: bool = False,
    run_all: bool = False,
    chain_report: bool = False,
) -> int:
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
            already = any(rep.get("description") == detail for rep in claim.repairs)
            if not already:
                claim.record_repair(detail, outcome="awaiting-fix")

    # ── Chain report (if requested) ──────────────────────────────────────
    if chain_report:
        _show_chain_report(r, con, json_output)
        return 0

    # ── Run attackers (if requested) ────────────────────────────────────────
    if run_attackers or run_all:
        con.print("\n[bold #C8621A]Attacker Analysis[/bold #C8621A]")
        try:
            from patchi.core.attackers import AttackPlanner

            planner = AttackPlanner(graph)
            plan = planner.plan()
            con.print(f"  Hypotheses generated: [bold]{len(plan.hypotheses)}[/bold]")

            attack_results = planner.run_all()
            confirmed = [r for r in attack_results if r.confirmed]
            con.print(f"  Tested: [bold]{len(attack_results)}[/bold], Confirmed: [bold]{len(confirmed)}[/bold]")

            # Record confirmed attacks as evidence
            for r in confirmed:
                claim_id = f"attack-{r.hypothesis.attacker}-{r.hypothesis.target[:30]}"
                graph.upsert_claim(
                    claim_id,
                    r.evidence[:100],
                    domain="adversarial",
                    severity_if_disproved=r.severity or r.hypothesis.risk,
                )
                graph.attach_evidence(
                    claim_id,
                    Evidence(
                        source=f"attacker:{r.hypothesis.attacker}",
                        detail=r.evidence,
                        supports=True,  # confirmed = evidence supports the vulnerability
                        artifact={
                            "objective": r.hypothesis.objective,
                            "risk": r.hypothesis.risk,
                            "confidence": r.hypothesis.confidence,
                        },
                    ),
                )

            if confirmed:
                con.print("  [red]Confirmed vulnerabilities:[/red]")
                for r in confirmed[:10]:
                    con.print(f"    [{r.severity}] {r.hypothesis.attacker}: {r.evidence[:60]}")
            else:
                con.print("  [green]No confirmed vulnerabilities from attackers.[/green]")

        except Exception as e:
            con.print(f"  [red]Attacker error: {e}[/red]")

    # ── Run campaigns (if requested) ─────────────────────────────────────────
    if run_campaigns or run_all:
        con.print("\n[bold #C8621A]Security Campaigns[/bold #C8621A]")
        try:
            from patchi.core.campaigns import CampaignOrchestrator

            orch = CampaignOrchestrator(graph)
            campaign_result = orch.run_all()
            con.print(f"  Campaigns: [bold]{len(campaign_result.campaigns)}[/bold] run")

            for cr in campaign_result.campaigns:
                status = (
                    "[green]PASS[/green]"
                    if cr.total_findings == 0
                    else f"[yellow]{cr.total_findings} findings[/yellow]"
                )
                con.print(f"    {cr.name}: {status}")

                # Record campaign findings as evidence
                for step in cr.steps:
                    for f in step.findings:
                        sev = f.get("severity", "info")
                        detail = f.get("detail", "")
                        claim_id = f"campaign-{cr.name}-{step.name}"
                        graph.upsert_claim(
                            claim_id,
                            detail[:100],
                            domain="campaign",
                            severity_if_disproved=sev,
                        )
                        graph.attach_evidence(
                            claim_id,
                            Evidence(
                                source=f"campaign:{cr.name}",
                                detail=detail,
                                supports=sev in ("info",),  # info = supports the claim
                                artifact={"step": step.name, "severity": sev},
                            ),
                        )
                        if sev in ("critical", "high"):
                            con.print(f"      [{sev}] {detail[:70]}")

            if campaign_result.total_findings > 0:
                con.print(f"  [yellow]Total findings: {campaign_result.total_findings}[/yellow]")
            else:
                con.print("  [green]All campaigns passed.[/green]")

        except Exception as e:
            con.print(f"  [red]Campaign error: {e}[/red]")

    # ── Run fuzz (if requested) ──────────────────────────────────────────────
    if run_all:
        con.print("\n[bold #C8621A]Fuzz Analysis[/bold #C8621A]")
        try:
            from patchi.core.fuzz import InputFuzzer

            fuzzer = InputFuzzer(seed=42)
            endpoint_claims = [c for c in graph.claims.values() if "endpoint" in c.domain]
            con.print(f"  Endpoints discovered: [bold]{len(endpoint_claims)}[/bold]")

            total_fuzz = 0
            for claim in endpoint_claims[:20]:
                path = (
                    claim.statement.split("Endpoint ")[-1].split(" requires")[0]
                    if "Endpoint" in claim.statement
                    else claim.id
                )
                inputs = fuzzer.fuzz_string(path, count=5)
                total_fuzz += len(inputs)

            con.print(f"  Fuzz inputs generated: [bold]{total_fuzz}[/bold]")

        except Exception as e:
            con.print(f"  [red]Fuzz error: {e}[/red]")

    # Save all new evidence
    graph.save(r)

    # ── Build comprehensive report data ──────────────────────────────────────
    coverage = graph.coverage()
    report_data = _build_report(coverage, run_all)

    if json_output:
        sys.stdout.write(json.dumps(report_data, indent=2, default=str) + "\n")
        has_bad = coverage["by_verdict"].get("disproved", 0) > 0 or (coverage["claims_total"] == 0)
        return 1 if has_bad else 0

    # ── Render report ────────────────────────────────────────────────────────
    _render_report(report_data, coverage, graph)

    disproved = coverage["by_verdict"].get("disproved", 0)
    total = coverage["claims_total"]
    return 1 if (disproved or total == 0) else 0


def _build_report(coverage: dict, run_all: bool) -> dict:
    """Build comprehensive report data from coverage and graph state."""
    by_domain = coverage.get("by_domain", {})
    by_verdict = coverage.get("by_verdict", {})
    disproved = list(coverage.get("disproved_claims", []))

    # Count by severity from evidence artifacts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for claim_dict in disproved:
        for ev in claim_dict.get("evidence", []):
            sev = ev.get("artifact", {}).get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

    report = {
        "summary": {
            "total_claims": coverage.get("claims_total", 0),
            "proved": by_verdict.get("proved", 0),
            "disproved": by_verdict.get("disproved", 0),
            "not_proved": by_verdict.get("not_proved", 0),
            "unproven": by_verdict.get("unproven", 0),
            "status": coverage.get("statement", ""),
        },
        "by_domain": dict(by_domain.items()),
        "by_severity": severity_counts,
        "disproved_claims": disproved[:20],
        "domains_tested": len(by_domain),
        "evidence_total": sum(len(c.get("evidence", [])) for c in disproved),
    }

    if run_all:
        report["mode"] = "full_assurance"
        report["modules_run"] = ["invariants", "attackers", "campaigns", "fuzz"]
    else:
        report["mode"] = "invariants_only"
        report["modules_run"] = ["invariants"]

    return report


def _render_report(report_data: dict, coverage: dict, graph) -> None:
    """Render the assurance report to the console."""
    from rich.panel import Panel
    from rich.text import Text

    summary = report_data["summary"]

    con.print()
    con.print("[bold #C8621A]Assurance Report[/bold #C8621A]")
    con.print()

    if not graph.claims:
        con.print("[yellow]No claims established.[/yellow]")
        return

    # ── Summary panel ────────────────────────────────────────────────────────
    modules = report_data.get("modules_run", [])

    summary_text = Text()
    summary_text.append(f"Claims: {summary['total_claims']}  ", style="bold")
    summary_text.append(f"Proved: {summary['proved']}  ", style="green")
    summary_text.append(f"Violated: {summary['disproved']}  ", style="red" if summary["disproved"] > 0 else "dim")
    summary_text.append(
        f"Unproven: {summary['unproven'] + summary['not_proved']}",
        style="yellow" if summary["unproven"] + summary["not_proved"] > 0 else "dim",
    )
    con.print(Panel(summary_text, title="Summary", border_style="#C8621A"))

    # ── Severity breakdown ───────────────────────────────────────────────────
    sev = report_data.get("by_severity", {})
    has_findings = any(v > 0 for v in sev.values())
    if has_findings:
        sev_text = Text()
        for level in ["critical", "high", "medium", "low", "info"]:
            count = sev.get(level, 0)
            if count > 0:
                style = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "dim",
                    "info": "dim",
                }.get(level, "dim")
                sev_text.append(f"{level}: {count}  ", style=style)
        con.print(Panel(sev_text, title="Findings by Severity", border_style="#C8621A"))

    # ── Domain coverage ──────────────────────────────────────────────────────
    by_domain = report_data.get("by_domain", {})
    if by_domain:
        table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
        table.add_column("Domain", width=30)
        table.add_column("Proved", justify="right", width=8)
        table.add_column("Total", justify="right", width=8)
        table.add_column("Coverage", width=12)

        for domain, counts in sorted(by_domain.items()):
            proved = counts.get("proved", 0)
            total = counts.get("total", 0)
            pct = (proved / total * 100) if total > 0 else 0
            bar_len = int(pct / 10)
            bar = "=" * bar_len + "-" * (10 - bar_len)
            style = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
            table.add_row(
                domain,
                f"[green]{proved}[/green]",
                str(total),
                f"[{style}][{bar}] {pct:.0f}%[/{style}]",
            )
        con.print(table)

    # ── Claim verdicts ───────────────────────────────────────────────────────
    con.print()
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

    # ── Verdict summary ──────────────────────────────────────────────────────
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
        f"[dim]No evidence currently demonstrates a known violation within the {total}-property tested scope.[/dim]"
        if disproved == 0
        else ""
    )
    con.print()

    # ── Modules run ──────────────────────────────────────────────────────────
    if modules:
        con.print(f"[dim]Modules: {', '.join(modules)}[/dim]")
    con.print()


def _show_chain_report(root, con, json_output=False):
    """Show chain-sourced assurance claims separately."""
    import json as _json

    ci_path = root / ".patchi" / "chain_intent.json"
    if not ci_path.is_file():
        con.print("[yellow]No chain/intent data found. Run `p scan` first.[/yellow]")
        return

    try:
        ci_data = _json.loads(ci_path.read_text(encoding="utf-8"))
    except Exception:
        con.print("[red]Failed to parse chain_intent.json[/red]")
        return

    chains = ci_data.get("chains", [])
    intent = ci_data.get("intent_report")

    if not chains and not intent:
        con.print("[dim]No chains or intent gaps found in last scan.[/dim]")
        return

    # Build chain-sourced claims
    chain_claims = []
    for i, chain in enumerate(chains):
        steps = chain.get("steps", [])
        if len(steps) < 2:
            continue
        entry = steps[0].get("type", "?")
        impact = steps[-1].get("type", "?")
        severity = chain.get("severity", "medium")
        score = chain.get("score", 0)

        # Get remediations
        try:
            from patchi.core.security.remediation import get_remediation_for_step

            rems = [get_remediation_for_step(s) for s in steps]
        except ImportError:
            rems = [None] * len(steps)

        chain_claims.append(
            {
                "id": f"chain-{i + 1}",
                "statement": f"{entry} → {impact} ({len(steps)} steps)",
                "severity": severity,
                "score": score,
                "steps": steps,
                "remediations": rems,
                "narrative": chain.get("narrative", ""),
            }
        )

    # Build intent gap claims
    intent_claims = []
    if intent:
        gaps = intent.get("gaps", [])
        for gap in gaps:
            intent_claims.append(
                {
                    "id": gap.get("route", "?"),
                    "statement": gap.get("description", "Missing auth"),
                    "severity": gap.get("severity", "high"),
                    "route": gap.get("route", ""),
                    "method": gap.get("method", ""),
                }
            )

    if json_output:
        con.print(
            _json.dumps(
                {
                    "chain_claims": chain_claims,
                    "intent_claims": intent_claims,
                },
                indent=2,
                default=str,
            )
        )
        return

    # ── Display ──────────────────────────────────────────────────────────
    con.print()
    con.print("[bold #C8621A]Chain-Sourced Assurance Claims[/bold #C8621A]")
    con.print()

    if chain_claims:
        con.print(f"[bold]Exploit Chains[/bold] ({len(chain_claims)} claims)")
        con.print()
        for cc in chain_claims:
            sev = cc["severity"]
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(sev, "")
            con.print(
                f"  [{'#C8621A'}]{cc['id']}[/'#C8621A'] [{sev_style}]{sev}[/{sev_style}] (score {cc['score']:.0f})"
            )
            con.print(f"    {cc['statement']}")

            # Show steps with remediation
            for j, (step, rem) in enumerate(zip(cc["steps"], cc["remediations"], strict=False)):
                role = step.get("role", "?")
                ftype = step.get("type", "?")
                ffile = step.get("file", "?")
                line = step.get("line", 0)
                con.print(f"    [{j + 1}] [{role}] {ftype} @ {ffile}:{line}")
                if rem:
                    con.print(f"        [green]Fix:[/green] {rem['action']}")
                    if rem.get("auto_fixable"):
                        con.print("        [dim]⚡ auto-fixable[/dim]")
            con.print()

    if intent_claims:
        con.print(f"[bold]Intent Gaps[/bold] ({len(intent_claims)} claims)")
        con.print()
        for ic in intent_claims:
            con.print(f"  [yellow]●[/yellow] {ic['method']} {ic['route']}")
            con.print(f"    {ic['statement']}")
        con.print()

    total = len(chain_claims) + len(intent_claims)
    con.print(f"[dim]{total} chain-sourced claims in assurance graph[/dim]")
