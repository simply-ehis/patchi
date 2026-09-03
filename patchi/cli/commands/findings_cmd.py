"""p findings — view and manage security findings.

Subcommands:
  p findings             — show all findings from last scan
  p findings --summary   — per-agent before/after counts (repeatable)
  p findings --json      — machine-readable output
  p findings --save-baseline  — snapshot current counts as baseline
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table

_log = logging.getLogger("patchi.cli.commands.findings_cmd")



def run(args) -> None:
    con = Console()
    root = Path.cwd()

    if getattr(args, "save_baseline", False):
        _save_baseline(root, con)
        return

    if getattr(args, "summary", False):
        _show_summary(root, con, json_output=getattr(args, "json_output", False))
        return

    _show_findings(root, con, json_output=getattr(args, "json_output", False))


def _load_scan_results(root: Path) -> dict:
    """Load scan results from .patchi/."""
    results_path = root / ".patchi" / "memory" / "scan_results.json"
    if not results_path.exists():
        return {}
    try:
        return json.loads(results_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _show_findings(root: Path, con: Console, json_output: bool = False) -> None:
    """Show all findings from last scan."""
    results = _load_scan_results(root)
    if not results:
        con.print("[yellow]No scan results found. Run `p scan` first.[/yellow]")
        return

    all_findings = []
    for agent_name, data in results.items():
        for f in data.get("findings", []):
            f["agent"] = agent_name
            all_findings.append(f)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    if json_output:
        con.print(
            json.dumps(
                {"total": len(all_findings), "findings": all_findings}, indent=2, default=str
            )
        )
        return

    # Summary
    by_sev = {}
    for f in all_findings:
        s = f.get("severity", "info")
        by_sev[s] = by_sev.get(s, 0) + 1
    sev_parts = ", ".join(f"{s}: {c}" for s, c in sorted(by_sev.items()))
    con.print(f"\n[bold]Findings[/bold] ({len(all_findings)} total: {sev_parts})\n")

    # Table
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=4)
    table.add_column("Sev", width=8)
    table.add_column("Type", width=20)
    table.add_column("File", width=30)
    table.add_column("Line", width=6)
    table.add_column("Agent", width=16)
    table.add_column("Message", max_width=40)

    for i, f in enumerate(all_findings, 1):
        sev = f.get("severity", "info")
        sev_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
            "info": "dim",
        }.get(sev, "")
        table.add_row(
            str(i),
            f"[{sev_style}]{sev}[/{sev_style}]",
            f.get("type", "?"),
            f.get("file", "?")[-30:],
            str(f.get("line", 0)),
            f.get("agent", "?"),
            (f.get("message", "")[:80]),
        )

    con.print(table)


def _show_summary(root: Path, con: Console, json_output: bool = False) -> None:
    """Show per-agent finding counts with before/after comparison."""
    results = _load_scan_results(root)
    baseline_path = root / ".patchi" / "findings_baseline.json"
    baseline = {}
    if baseline_path.exists():
        try:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        except Exception as _exc:
            _log.warning('_show_summary failed: %s', _exc)

    # Current counts
    agent_counts = {}
    total = 0
    for agent_name, data in results.items():
        count = len(data.get("findings", []))
        agent_counts[agent_name] = count
        total += count

    if json_output:
        rows = []
        for agent, count in sorted(agent_counts.items()):
            prev = baseline.get(agent, count)
            rows.append(
                {
                    "agent": agent,
                    "current": count,
                    "baseline": prev,
                    "delta": count - prev,
                }
            )
        con.print(json.dumps({"total": total, "agents": rows}, indent=2))
        return

    con.print(
        f"\n[bold]Finding Counts Summary[/bold] — {len(agent_counts)} agents, {total} total findings\n"
    )

    table = Table(show_header=True, header_style="bold")
    table.add_column("Agent", width=28)
    table.add_column("Current", justify="right", width=8)
    table.add_column("Baseline", justify="right", width=8)
    table.add_column("Delta", justify="right", width=8)

    for agent, count in sorted(agent_counts.items()):
        prev = baseline.get(agent, count)
        delta = count - prev
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        delta_style = "red" if delta > 0 else ("green" if delta < 0 else "dim")
        table.add_row(
            agent,
            str(count),
            str(prev),
            f"[{delta_style}]{delta_str}[/{delta_style}]",
        )

    con.print(table)

    if not baseline:
        con.print("\n[dim]No baseline set. Run `p findings --save-baseline` to create one.[/dim]")


def _save_baseline(root: Path, con: Console) -> None:
    """Snapshot current finding counts as baseline."""
    results = _load_scan_results(root)
    baseline = {}
    for agent_name, data in results.items():
        baseline[agent_name] = len(data.get("findings", []))

    baseline_path = root / ".patchi" / "findings_baseline.json"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    con.print(
        f"[green]Baseline saved: {len(baseline)} agents, {sum(baseline.values())} total findings[/green]"
    )
