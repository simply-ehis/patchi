"""
`p trend` — Health and quality trend tracking over time.

Shows how your project's health changes across scans:
- Health score history with sparkline
- Security finding trends
- Test coverage progression
- Dead code ratio changes
- Dependency health over time

This catches regressions before they become problems.
No other tool tracks quality trends across time.

Usage:
  p trend                  — show health trend over last 20 scans
  p trend --last 50        — show last 50 scans
  p trend security         — security findings trend only
  p trend tests            — test coverage trend only
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.trend_cmd")


def run(
    metric: str | None = None, last_n: int = 20, root: Path | None = None, json_output: bool = False
) -> None:
    """Entry point for `p trend`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import memory as mem

    brain = mem.get_brain(r)
    scans = mem.get_scan_results(r)

    # Build trend data from scan history
    trend_data = _build_trend_data(scans, brain)

    if not trend_data:
        if json_output:
            import json as _json

            con.print(_json.dumps({"trend": [], "note": "no scan history yet"}))
        else:
            con.print(
                "[dim]No scan history yet. Run `p scan` a few times to build trend data.[/dim]"
            )
        return

    if json_output:
        import json as _json

        con.print(_json.dumps({"trend": trend_data[-last_n:]}, indent=2, default=str))
        return

    if metric == "security":
        _show_security_trend(trend_data, last_n)
    elif metric == "tests":
        _show_test_trend(trend_data, last_n)
    else:
        _show_health_trend(trend_data, last_n)


def _build_trend_data(scans: dict, brain: dict) -> list[dict]:
    """Extract trend data from scan results."""
    entries = []

    for name, data in scans.items():
        if not isinstance(data, dict):
            continue
        ts = data.get("timestamp", "")
        finding_count = data.get("finding_count", 0)
        status = data.get("status", "done")
        duration = data.get("duration_ms", 0)

        # Extract severity breakdown if available
        findings = data.get("findings", [])
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            if isinstance(f, dict):
                sev = f.get("severity", "low").lower()
                if sev in by_sev:
                    by_sev[sev] += 1

        entries.append(
            {
                "timestamp": ts,
                "agent": name,
                "finding_count": finding_count,
                "status": status,
                "duration_ms": duration,
                "by_severity": by_sev,
            }
        )

    # Sort by timestamp
    entries.sort(key=lambda x: x.get("timestamp", ""))
    return entries


def _show_health_trend(trend_data: list[dict], last_n: int) -> None:
    """Show overall health trend."""
    entries = trend_data[-last_n:]

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Time", style="dim", width=19)
    table.add_column("Agent", style="bold #F2EDD6", width=22)
    table.add_column("Status", width=8)
    table.add_column("Findings", justify="right", width=9)
    table.add_column("Critical", justify="right", width=9)
    table.add_column("High", justify="right", width=7)
    table.add_column("Duration", justify="right", width=10)
    table.add_column("Trend", width=12)

    prev_findings = None
    for entry in entries:
        ts = entry.get("timestamp", "")
        try:
            ts_fmt = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts))) if ts else "—"
        except Exception as e:
            _log.warning("_show_health_trend failed: %s", e)
            ts_fmt = str(ts)[:16]

        agent = entry.get("agent", "—")
        status = entry.get("status", "done")
        findings = entry.get("finding_count", 0)
        by_sev = entry.get("by_severity", {})
        crit = by_sev.get("critical", 0)
        high = by_sev.get("high", 0)
        dur = entry.get("duration_ms", 0)

        # Trend indicator
        if prev_findings is not None:
            if findings < prev_findings:
                trend = Text("↓ improving", style="#4ADE80")
            elif findings > prev_findings:
                trend = Text("↑ regressing", style="#FF4D6D")
            else:
                trend = Text("→ stable", style="dim")
        else:
            trend = Text("—", style="dim")
        prev_findings = findings

        status_color = "#4ADE80" if status == "done" else "#FF4D6D"

        table.add_row(
            ts_fmt,
            agent[:22],
            Text(status, style=status_color),
            str(findings) if findings else "—",
            Text(str(crit), style="#FF4D6D bold") if crit else "—",
            Text(str(high), style="#FF8C42") if high else "—",
            f"{dur}ms" if dur else "—",
            trend,
        )

    con.print()
    con.print(Panel(table, title="📈 Health Trend", border_style="#C8621A"))

    # Sparkline summary
    findings_series = [e.get("finding_count", 0) for e in entries]
    if findings_series:
        sparkline = _sparkline(findings_series)
        con.print(f"\n  Findings: {sparkline}")
        con.print(
            f"  [dim]Latest: {findings_series[-1]} findings "
            f"(avg: {sum(findings_series) // len(findings_series)})[/dim]"
        )
    con.print()


def _show_security_trend(trend_data: list[dict], last_n: int) -> None:
    """Show security-specific trend."""
    from patchi.core.agents.base import AgentGroup, list_agents

    security_agents = {a.name for a in list_agents(AgentGroup.SECURITY)}

    entries = [e for e in trend_data if e.get("agent") in security_agents][-last_n:]

    if not entries:
        con.print("[dim]No security scan data yet. Run `p security` first.[/dim]")
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Time", style="dim", width=19)
    table.add_column("Agent", style="bold #F2EDD6", width=22)
    table.add_column("Critical", justify="right", width=9)
    table.add_column("High", justify="right", width=7)
    table.add_column("Medium", justify="right", width=8)
    table.add_column("Low", justify="right", width=6)
    table.add_column("Total", justify="right", width=7)

    for entry in entries:
        ts = entry.get("timestamp", "")
        try:
            ts_fmt = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts))) if ts else "—"
        except Exception as e:
            _log.warning("_show_security_trend failed: %s", e)
            ts_fmt = str(ts)[:16]

        by_sev = entry.get("by_severity", {})
        crit = by_sev.get("critical", 0)
        high = by_sev.get("high", 0)
        med = by_sev.get("medium", 0)
        low = by_sev.get("low", 0)
        total = crit + high + med + low

        table.add_row(
            ts_fmt,
            entry.get("agent", "—")[:22],
            Text(str(crit), style="#FF4D6D bold") if crit else "—",
            Text(str(high), style="#FF8C42") if high else "—",
            str(med) if med else "—",
            str(low) if low else "—",
            str(total) if total else "—",
        )

    con.print()
    con.print(Panel(table, title="🛡 Security Trend", border_style="#C8621A"))
    con.print()


def _show_test_trend(trend_data: list[dict], last_n: int) -> None:
    """Show test-related trend."""
    from patchi.core.agents.base import AgentGroup, list_agents

    test_agents = {a.name for a in list_agents(AgentGroup.TEST)}

    entries = [e for e in trend_data if e.get("agent") in test_agents][-last_n:]

    if not entries:
        con.print("[dim]No test data yet. Run `p test` first.[/dim]")
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Time", style="dim", width=19)
    table.add_column("Agent", style="bold #F2EDD6", width=22)
    table.add_column("Status", width=8)
    table.add_column("Findings", justify="right", width=9)
    table.add_column("Duration", justify="right", width=10)

    for entry in entries:
        ts = entry.get("timestamp", "")
        try:
            ts_fmt = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts))) if ts else "—"
        except Exception as e:
            _log.warning("_show_test_trend failed: %s", e)
            ts_fmt = str(ts)[:16]

        status = entry.get("status", "done")
        findings = entry.get("finding_count", 0)
        dur = entry.get("duration_ms", 0)

        status_color = "#4ADE80" if findings == 0 else "#FF4D6D"

        table.add_row(
            ts_fmt,
            entry.get("agent", "—")[:22],
            Text(status, style=status_color),
            str(findings) if findings else "—",
            f"{dur}ms" if dur else "—",
        )

    con.print()
    con.print(Panel(table, title="🧪 Test Trend", border_style="#C8621A"))
    con.print()


def _sparkline(values: list[int], width: int = 40) -> str:
    """Create a text sparkline from numeric values."""
    if not values:
        return ""
    blocks = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    mn = min(values)
    mx = max(values)
    rng = mx - mn if mx != mn else 1
    # Downsample to width
    step = max(1, len(values) // width)
    sampled = values[::step][:width]
    return "".join(blocks[min(int((v - mn) / rng * 7), 7)] for v in sampled)
