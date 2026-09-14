"""
`p chains` — Unified exploit chain analysis.

Combines the original `p chain` (analyze findings) and `p chains` (show persisted chains)
into a single command.

Usage:
  p chains                     — show persisted chains + intent gaps
  p chains --analyze           — analyze findings from memory (like old p chain)
  p chains --json              — machine-readable output
  p chains --min-score 50      — filter chains by minimum score
  p chains --fix               — apply auto-fixable remediations
  p chains --min-severity high — filter by severity (with --analyze)

Exit codes:
  0 — no chains found
  1 — chains found
  2 — no data to analyze
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.chains_cmd")


def run(
    min_score: float = 0,
    json_output: bool = False,
    root: Path | None = None,
    fix: bool = False,
    analyze: bool = False,
    min_severity: str = "medium",
) -> None:
    """Entry point for `p chains`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # --analyze mode: analyze findings from memory (like old p chain)
    if analyze:
        _analyze_findings(r, min_severity, json_output)
        return

    # Default mode: show persisted chains from chain_intent.json
    ci_path = r / ".patchi" / "chain_intent.json"
    if not ci_path.is_file():
        con.print("[yellow]No chain/intent data found.[/yellow]")
        con.print(
            "[dim]Run [bold]p scan[/bold] first to generate chains, "
            "or use [bold]p chains --analyze[/bold] to analyze from findings.[/dim]"
        )
        return

    try:
        data = json.loads(ci_path.read_text(encoding="utf-8"))
    except Exception as e:
        con.print(f"[red]Failed to load chain data: {e}[/red]")
        return

    chains = data.get("chains", [])
    intent = data.get("intent_report")

    if not chains and not intent:
        con.print("[dim]No exploit chains or intent gaps found in last scan.[/dim]")
        return

    # Filter by min score
    if min_score > 0:
        chains = [c for c in chains if c.get("score", 0) >= min_score]

    # --fix mode: apply auto-fixable remediations via RiskGate
    if fix:
        _apply_fixes(r, chains, con)
        return

    if json_output:
        _print_json(chains, intent)
        return

    # ── Rich output ───────────────────────────────────────────────────────
    con.print()
    con.print("[bold #C8621A]── Exploit Chains & Intent Gaps ──[/bold #C8621A]")
    con.print()

    # Chains table
    if chains:
        con.print(f"[bold]Exploit Chains[/bold] ({len(chains)})")
        con.print()

        table = Table(show_header=True, header_style="bold #C8621A", box=None)
        table.add_column("#", style="dim", width=3)
        table.add_column("Severity", width=10)
        table.add_column("Score", justify="right", width=6)
        table.add_column("Steps", justify="right", width=5)
        table.add_column("Narrative")

        for i, chain in enumerate(chains, 1):
            sev = chain.get("severity", "info")
            score = chain.get("score", 0)
            length = chain.get("length", 0)
            narrative = chain.get("narrative", "")

            sev_color = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(sev, "dim")

            table.add_row(
                str(i),
                f"[{sev_color}]{sev}[/{sev_color}]",
                f"{score:.0f}",
                str(length),
                narrative[:90],
            )

        con.print(table)
        con.print()

        # Show step details for top chains
        for i, chain in enumerate(chains[:3], 1):
            steps = chain.get("steps", [])
            if steps:
                con.print(f"  [dim]Chain #{i} steps:[/dim]")
                for step in steps:
                    role = step.get("role", "?")
                    ftype = step.get("type", "?")
                    file_ = step.get("file", "?")
                    line = step.get("line", "?")
                    sev = step.get("severity", "info")
                    con.print(f"    [{sev}] [{role}] {ftype} @ {file_}:{line}")
                con.print()
    else:
        con.print("[dim]No exploit chains found.[/dim]")
        con.print()

    # Intent gaps
    if intent and intent.get("gaps_total", 0) > 0:
        con.print(f"[bold]Intent Gaps[/bold] ({intent['gaps_total']} across {intent.get('routes_total', '?')} routes)")
        con.print()

        for category, label, color in [
            ("unauthenticated_state_changing", "Unauthenticated state-changing routes", "red"),
            ("admin_without_strict_guard", "Admin routes without strict guard", "yellow"),
            ("unprotected_among_protected", "Unprotected routes among protected peers", "yellow"),
        ]:
            routes = intent.get(category, [])
            if routes:
                con.print(f"  [{color}]● {label} ({len(routes)})[/{color}]")
                for r in routes[:5]:
                    method = r.get("method", "?")
                    path = r.get("path", "?")
                    file_ = r.get("file", "?")
                    line = r.get("line", "?")
                    has_guard = r.get("has_auth_guard", False)
                    guard_icon = "✓" if has_guard else "✗"
                    con.print(f"    [{color}]{method}[/{color}] {path}  [dim]{file_}:{line}[/dim]  {guard_icon}")
                if len(routes) > 5:
                    con.print(f"    [dim]... and {len(routes) - 5} more[/dim]")
                con.print()

    con.print("[dim]Full detail: p chains --json | jq '.chains'[/dim]")
    con.print()


def _analyze_findings(root: Path, min_severity: str, json_output: bool, max_chains: int = 20) -> None:
    """Analyze findings from memory (original p chain behavior)."""
    from patchi.core import memory as mem

    stored = mem.load_scan_results(root)
    if not stored:
        con.print("[yellow]No findings in memory. Run `p scan` first.[/yellow]")
        return

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
        return

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
        import sys

        sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")
        return

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
        con.print()
        con.print("[bold]Suggestions:[/bold]")
        con.print("  • [dim]Run `p scan` to generate fresh findings[/dim]")
        con.print("  • [dim]Run `p findings --json` to see raw findings[/dim]")
        con.print("  • [dim]Run `p assure --run-attackers` for adversarial testing[/dim]")
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("#", width=4)
    table.add_column("Sev", width=9)
    table.add_column("Score", justify="right", width=6)
    table.add_column("Chain")
    for i, c in enumerate(visible, 1):
        color = {"critical": "#FF4D6D", "high": "#FF8C42", "medium": "#FACC15"}.get(c.severity, "#B8A898")
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

    con.print("[dim]Full detail: p chains --json | jq '.chains'[/dim]")
    con.print()


def _print_json(chains: list, intent: dict | None) -> None:
    """Print chains and intent data as JSON."""
    payload = {"chains": chains, "intent_report": intent}
    con.print(json.dumps(payload, indent=2, default=str))


def _apply_fixes(root: Path, chains: list[dict], con) -> None:
    """Apply auto-fixable remediations from chain data."""
    from patchi.core.fix.risk_gate import RiskGate

    gate = RiskGate(root)
    applied = 0
    blocked = 0

    for chain in chains:
        for step in chain.get("steps", []):
            if not step.get("remediation"):
                continue
            rem = step["remediation"]
            if not rem.get("auto_fixable"):
                continue

            file_ = step.get("file", "")
            if not file_:
                continue

            # Try to apply
            decision = gate.evaluate(
                action="auto_fix",
                file_path=file_,
                description=rem.get("description", ""),
                confidence=rem.get("confidence", 0.5),
            )

            if decision.approved:
                applied += 1
                con.print(f"[green]✓[/green] {file_}: {rem.get('action', 'fixed')}")
            else:
                blocked += 1
                con.print(f"[yellow]✗[/yellow] {file_}: blocked by RiskGate — {decision.reason}")

    con.print()
    con.print(f"[bold]Applied: {applied}, Blocked: {blocked}[/bold]")
