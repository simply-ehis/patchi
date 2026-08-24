"""
`p health` — Deep-dive health report with per-component breakdown.

Shows the full health score computed from brain memory and agent scan results:
  - Security posture      (35%)
  - Test coverage         (25%)
  - Dead code ratio       (20%)
  - Dependency health     (10%)
  - App contract          (10%)

This is the detailed version of the one-line health shown in `p status`.
"""

from __future__ import annotations

from pathlib import Path

from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core import health as hm
from patchi.core import memory as mem
from patchi.core.config import require_project_root


import logging
_log = logging.getLogger("patchi.cli.health_cmd")

def run(root: Path | None = None) -> None:
    """Entry point for `p health`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    brain = mem.get_brain(r)
    if not brain or not brain.get("file_count"):
        con.print("[yellow]No scan data yet. Run 'p scan' first.[/yellow]")
        return

    score = hm.compute(r)
    _show_health(score, brain, r)

def _show_health(score: hm.HealthScore, brain: dict, root: Path) -> None:
    breakdown = score.breakdown or {}
    components = score.to_dict().get("components", {})

    con.print()
    con.print(f"[bold #C8621A]Project Health[/bold #C8621A]  "
              f"[dim]grade {score.grade} · {score.total}/100[/dim]")

    # ── Score bar ─────────────────────────────────────────────────────────────
    bar_width = 40
    filled = int(score.total / 100 * bar_width)
    empty = bar_width - filled
    bar_fill = "█" * filled
    bar_empty = "░" * empty
    con.print(f"  [{score.color}]{bar_fill}[/{score.color}][dim]{bar_empty}[/dim]")
    con.print()

    # ── Component scores ──────────────────────────────────────────────────────
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Component", style="bold #F2EDD6", width=20)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Weight", justify="right", width=8)
    table.add_column("Weighted", justify="right", width=10)
    table.add_column("Detail", style="dim", width=50)

    weight_map = {"security": 0.35, "test_coverage": 0.25, "dead_code": 0.20, "dependency": 0.10, "contract": 0.10}

    for comp_key, raw_score in components.items():
        comp_label = comp_key.replace("_", " ").title()
        w = weight_map.get(comp_key, 0)
        weighted = round(raw_score * w, 1)

        color = "#4ADE80" if raw_score >= 80 else ("#FACC15" if raw_score >= 50 else "#FF4D6D")
        detail = _detail_for(comp_key, breakdown)

        table.add_row(
            comp_label,
            Text(f"{raw_score:.0f}", style=color),
            f"{w*100:.0f}%",
            Text(f"{weighted:.1f}", style="dim"),
            detail,
        )

    con.print(table)
    con.print()

    # ── Security breakdown (if available) ───────────────────────────────────
    scans = breakdown.get("agents_run", [])
    if scans:
        file_count = breakdown.get("file_count", 0)
        route_count = breakdown.get("route_count", 0)
        fw = breakdown.get("framework", "Unknown")
        circular = breakdown.get("circular_deps", 0)
        patches = breakdown.get("patches_applied", 0)
        test_pct = breakdown.get("test_coverage_pct", 0)

        con.print("[bold]Project snapshot[/bold]")
        con.print(f"  [dim]Files:[/dim] {file_count}  [dim]Routes:[/dim] {route_count}  "
                         f"[dim]Framework:[/dim] {fw}")
        con.print(f"  [dim]Circular deps:[/dim] {circular}  [dim]Tests:[/dim] {test_pct:.0f}% coverage  "
                         f"[dim]Patches:[/dim] {patches}")
        con.print()

    # ── Active security domains ───────────────────────────────────────────────
    active_domains = brain.get("active_security_domains", [])
    if active_domains:
        con.print("[bold]Active Security Domains[/bold]")
        con.print(f"  [dim]{', '.join(active_domains)}[/dim]")
        con.print()

    # ── Findings summary from scan results ────────────────────────────────────
    scans = _get_scan_results_summary(root)
    if scans["total"] > 0:
        con.print("[bold #FF4D6D]Recent Scan Findings[/bold #FF4D6D]")
        con.print(f"  [dim]{scans['total']} total, "
                         f"{scans['critical']} critical, {scans['high']} high, "
                         f"{scans['medium']} medium, {scans['low']} low[/dim]")
        con.print()

    # ── Grade scale ────────────────────────────────────────────────────────
    con.print("[dim]Grade scale:  [bold #4ADE80]A[/bold #4ADE80] 90–100  "
                   "[bold #86EFAC]B[/bold #86EFAC] 70–89  [bold #FACC15]C[/bold #FACC15] 50–69  "
                   "[bold #FB923C]D[/bold #FB923C] 30–49  [bold #FF4D6D]F[/bold #FF4D6D] 0–29[/dim]")
    con.print()

    # ── Actions ────────────────────────────────────────────────────────────────
    actions = []
    if components.get("security", 100) < 70:
        actions.append("[dim]→ Run [bold]p security[/bold] to scan for vulnerabilities[/dim]")
    if components.get("test_coverage", 100) < 50:
        actions.append("[dim]→ Run [bold]p test[/bold] to check test coverage[/dim]")
    if components.get("dead_code", 100) < 70:
        actions.append("[dim]→ Run [bold]p fix[/bold] to remove dead code[/dim]")
    if components.get("contract", 100) < 60:
        actions.append("[dim]→ Run [bold]p scan[/bold] then [bold]p contract confirm[/bold] to confirm flows[/dim]")

    if actions:
        con.print("[bold]Suggested Actions[/bold]")
        for a in actions:
            con.print(f"  {a}")
        con.print()

def _detail_for(component: str, breakdown: dict) -> str:
    """Return a detail string for a health component."""
    def _count(v):
        return v if isinstance(v, int) else len(v or [])

    details = {
        "security": f"{breakdown.get('file_count', 0)} files, route scan active",
        "test_coverage": f"{breakdown.get('test_coverage_pct', 0):.0f}% of source files have tests",
        "dead_code": f"{_count(breakdown.get('circular_deps', 0))} circular chains",
        "dependency": f"{_count(breakdown.get('patches_applied', 0))} applied patches" if _count(breakdown.get("patches_applied", 0)) else "dependency scan active",
        "contract": f"{_count(breakdown.get('agents_run', []))} agents available",
    }
    return details.get(component, "")

def _get_scan_results_summary(root: Path) -> dict:
    """Aggregate finding counts from scan results memory."""
    try:
        scans = mem.get_scan_results(root)
    except Exception as e:
        _log.warning("_get_scan_results_summary failed: %s", e)
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    total = critical = high = medium = low = 0
    for agent_name, data in scans.items():
        findings = data.get("findings", [])
        total += len(findings)
        for f in findings:
            sev = f.get("severity", "info")
            if sev == "critical":
                critical += 1
            elif sev == "high":
                high += 1
            elif sev == "medium":
                medium += 1
            elif sev == "low":
                low += 1

    return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low}