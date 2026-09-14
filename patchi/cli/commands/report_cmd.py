"""
`p report` — Generate a structured analysis report for the current project.

Usage:
  p report                 — Print full report to terminal
  p report export          — Write report to .patchi/report.md
  p report export --format json  — Write JSON report to .patchi/report.json

Report sections:
  1. Project summary (name, framework, file count, last scan)
  2. Health score breakdown (A–F grade + component scores)
  3. Open issues (by severity)
  4. Security findings
  5. Test results (last run)
  6. Recent patches applied
  7. Recommendations (top 5 actionable items)

All data comes from brain memory — no re-scan is triggered.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path

from rich.panel import Panel
from rich.rule import Rule

from patchi.cli.console import con
from patchi.core.config import require_project_root

# ── Entry point ────────────────────────────────────────────────────────────────


def run(
    report_cmd: str | None = None,
    export: bool = False,
    fmt: str = "markdown",
    weekly: bool = False,
    root: Path | None = None,
) -> None:
    """Entry point for `p report [export|weekly]`."""
    if report_cmd == "export":
        export = True
    elif report_cmd == "weekly":
        weekly = True
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import health
    from patchi.core import memory as mem

    if weekly:
        _send_weekly(r)
        return

    brain = mem.get_brain(r)
    scans = mem.get_scan_results(r)
    patches = mem.list_patches(r)
    score = health.compute(r)

    report_data = _build_report(r, brain, scans, patches, score)

    if export:
        _export_report(r, report_data, fmt)
    else:
        _print_report(report_data, score)


# ── Report builder ─────────────────────────────────────────────────────────────


def _build_report(
    root: Path,
    brain: dict,
    scans: dict,
    patches: list,
    score,
) -> dict:
    """Build the structured report dict from in-memory data."""
    now = datetime.now(UTC).isoformat(timespec="seconds") + "Z"

    framework = brain.get("framework", "Unknown")
    file_count = brain.get("file_count", 0)
    route_count = brain.get("route_count", 0)
    last_scan = brain.get("last_scan", "Never")

    # Aggregate all findings from recent scans
    findings_by_severity: dict[str, list[dict]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    for agent_name, scan_data in scans.items():
        for finding in scan_data.get("findings", []):
            sev = finding.get("severity", "low").lower()
            if sev in findings_by_severity:
                findings_by_severity[sev].append(
                    {
                        **finding,
                        "agent": agent_name,
                    }
                )

    # Top recommendations
    recommendations = _build_recommendations(score, findings_by_severity, brain, scans)

    # Recent patches (last 10)
    recent_patches = [
        {
            "id": p.get("id", "?"),
            "file": p.get("file", "?"),
            "status": p.get("status", "?"),
            "created": p.get("created_at", ""),
        }
        for p in patches[-10:]
    ]

    return {
        "generated_at": now,
        "project": {
            "root": str(root),
            "framework": framework,
            "file_count": file_count,
            "route_count": route_count,
            "last_scan": last_scan,
        },
        "health": score.to_dict(),
        "findings": findings_by_severity,
        "finding_totals": {k: len(v) for k, v in findings_by_severity.items()},
        "patches": recent_patches,
        "recommendations": recommendations,
    }


def _build_recommendations(score, findings_by_severity: dict, brain: dict, scans: dict) -> list[str]:
    recs: list[str] = []

    # Security
    if findings_by_severity["critical"]:
        recs.append(
            f"Fix {len(findings_by_severity['critical'])} CRITICAL security findings immediately — "
            "these are active vulnerabilities."
        )
    if findings_by_severity["high"]:
        recs.append(f"Address {len(findings_by_severity['high'])} HIGH severity findings before next release.")

    # Test coverage
    if score.test_coverage < 50:
        recs.append(
            "Test coverage is below 50%. Add unit tests for business-critical paths — run `p test unit` to see gaps."
        )

    # Dead code
    if score.dead_code < 60:
        recs.append("Dead code ratio is high. Run `p scan` then review `p fix` suggestions to remove unused modules.")

    # Dependency health
    if score.dependency < 70:
        recs.append(
            "Vulnerable dependencies detected. Run `p security deps` for details and upgrade affected packages."
        )

    # Circular deps
    circular = len(brain.get("circular_deps", []))
    if circular > 0:
        recs.append(
            f"{circular} circular dependency cycle(s) detected. These make the codebase "
            "brittle — refactor to break the cycle."
        )

    # All green
    if not recs:
        recs.append("Project health looks good. Keep running `p scan` on every PR.")

    return recs[:5]


# ── Terminal renderer ──────────────────────────────────────────────────────────


def _print_report(data: dict, score) -> None:
    con.print()
    con.print(Rule("[bold #C8621A]Patchi Analysis Report[/bold #C8621A]", style="#C8621A"))
    con.print(f"  [dim]Generated: {data['generated_at']}[/dim]")
    con.print()

    # Project summary
    proj = data["project"]
    con.print(f"  [bold]Project[/bold]    {proj['root']}")
    con.print(f"  [bold]Framework[/bold]  {proj['framework']}")
    con.print(f"  [bold]Files[/bold]      {proj['file_count']}  |  [bold]Routes[/bold] {proj['route_count']}")
    con.print(f"  [bold]Last scan[/bold]  {proj['last_scan']}")
    con.print()

    # Health score
    h = data["health"]
    color = score.color
    con.print(
        Panel(
            f"[bold {color}]Score: {h['total']}/100   Grade: {h['grade']}[/bold {color}]\n"
            f"[dim]"
            f"Security {h['components']['security']:.0f}   "
            f"Tests {h['components']['test_coverage']:.0f}   "
            f"Dead-code {h['components']['dead_code']:.0f}   "
            f"Deps {h['components']['dependency']:.0f}   "
            f"Contract {h['components']['contract']:.0f}"
            f"[/dim]",
            title="Health Score",
            border_style=color,
            padding=(0, 1),
        )
    )
    con.print()

    # Findings
    totals = data["finding_totals"]
    if any(totals.values()):
        con.print("  [bold #F2EDD6]Findings[/bold #F2EDD6]")
        sev_colors = {
            "critical": "#FF4D6D",
            "high": "#FF8C42",
            "medium": "#FACC15",
            "low": "#4ADE80",
        }
        for sev in ("critical", "high", "medium", "low"):
            count = totals[sev]
            if count:
                color = sev_colors[sev]
                con.print(f"    [{color}]●[/{color}] {sev.upper():<10} {count}")
                for finding in data["findings"][sev][:3]:
                    msg = finding.get("message", "")[:70]
                    con.print(f"      [dim]→ {msg}[/dim]")
        con.print()

    # Patches
    if data["patches"]:
        con.print(f"  [bold #F2EDD6]Recent Patches[/bold #F2EDD6]  [dim](last {len(data['patches'])})[/dim]")
        for p in data["patches"][-5:]:
            status_color = "#4ADE80" if p["status"] == "applied" else "#6B7280"
            con.print(
                f"    [{status_color}]·[/{status_color}] "
                f"[dim]{p['id'][:8]}[/dim]  {p['file'][:50]}  [dim]{p['status']}[/dim]"
            )
        con.print()

    # Recommendations
    con.print("  [bold #F2EDD6]Recommendations[/bold #F2EDD6]")
    for i, rec in enumerate(data["recommendations"], 1):
        con.print(f"    [dim]{i}.[/dim] {rec}")
    con.print()
    con.print(Rule(style="dim"))
    con.print("  [dim]Run `p report export` to save this as a Markdown file.[/dim]")
    con.print()


# ── Export ────────────────────────────────────────────────────────────────────


def _export_report(root: Path, data: dict, fmt: str) -> None:
    report_dir = root / ".patchi"
    report_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        out_path = report_dir / "report.json"
        out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elif fmt == "sarif":
        from patchi.core import ci_bundle

        findings = []
        for sev_list in data.get("findings", {}).values():
            findings.extend(sev_list)
        out_path = report_dir / "report.sarif.json"
        out_path.write_text(ci_bundle.render_findings(findings, "sarif"), encoding="utf-8")
    else:
        out_path = report_dir / "report.md"
        out_path.write_text(_render_markdown(data), encoding="utf-8")

    con.print()
    con.print(f"[#4ADE80]✓[/#4ADE80] Report saved → [bold]{out_path}[/bold]")
    con.print()


def _render_markdown(data: dict) -> str:
    lines: list[str] = []
    h = data["health"]
    proj = data["project"]

    lines.append("# Patchi Analysis Report")
    lines.append("")
    lines.append(f"**Generated:** {data['generated_at']}  ")
    lines.append(f"**Project:** `{proj['root']}`  ")
    lines.append(f"**Framework:** {proj['framework']}  ")
    lines.append(f"**Files:** {proj['file_count']}  |  **Routes:** {proj['route_count']}  ")
    lines.append(f"**Last scan:** {proj['last_scan']}  ")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"## Health Score: {h['total']}/100 (Grade {h['grade']})")
    lines.append("")
    lines.append("| Component | Score |")
    lines.append("|-----------|-------|")
    for comp, val in h["components"].items():
        lines.append(f"| {comp.replace('_', ' ').title()} | {val:.0f} |")
    lines.append("")

    totals = data["finding_totals"]
    if any(totals.values()):
        lines.append("## Findings")
        lines.append("")
        sev_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        for sev in ("critical", "high", "medium", "low"):
            count = totals[sev]
            if count:
                lines.append(f"### {sev_map[sev]} {sev.title()} ({count})")
                lines.append("")
                for finding in data["findings"][sev][:10]:
                    msg = finding.get("message", "")
                    file = finding.get("file", "")
                    lines.append(f"- `{file}` — {msg}")
                lines.append("")

    if data["patches"]:
        lines.append("## Recent Patches")
        lines.append("")
        lines.append("| ID | File | Status |")
        lines.append("|----|------|--------|")
        for p in data["patches"]:
            lines.append(f"| `{p['id'][:8]}` | `{p['file']}` | {p['status']} |")
        lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    for i, rec in enumerate(data["recommendations"], 1):
        lines.append(f"{i}. {rec}")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by Patchi — https://patchi.dev*")
    lines.append("")

    return "\n".join(lines)


def _send_weekly(root: Path) -> None:
    """Generate and send weekly health report (MISS-09)."""
    from datetime import datetime

    from patchi.core import config as cfg
    from patchi.core import health
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    scans = mem.get_scan_results(root)
    patches = mem.list_patches(root)
    score = health.compute(root)
    config = cfg.load(root)

    report_data = _build_report(root, brain, scans, patches, score)
    markdown = _render_markdown(report_data)
    out_path = root / ".patchi" / f"weekly_report_{datetime.now(UTC).strftime('%Y%m%d')}.md"
    out_path.write_text(markdown, encoding="utf-8")

    con.print()
    con.print(f"[#4ADE80]✓[/#4ADE80] Weekly report saved → [bold]{out_path}[/bold]")

    # Send via email if a notification channel is configured
    notifications = config.get("notifications", [])
    email_channels = [n for n in notifications if n.get("type") == "email" or n.get("channel_type") == "email"]
    if email_channels:
        try:
            from patchi.core.notifications.digest import DigestQueue

            digest = DigestQueue(root)
            digest._queue = [
                {
                    "event": "weekly_report",
                    "title": f"Patchi Weekly Report — {datetime.now(UTC).strftime('%Y-%m-%d')}",
                    "body": markdown[:10000],
                    "severity": "info",
                    "timestamp": time.time(),
                }
            ]
            digest.flush(channels=email_channels)
            con.print(f"[#4ADE80]✓[/#4ADE80] Report sent to [bold]{len(email_channels)}[/bold] email channel(s)")
        except Exception as e:
            con.print(f"[yellow]Could not send via email: {e}[/yellow]")
    else:
        con.print("[dim]No email channel configured. Set up notifications in config to auto-send.[/dim]")
    con.print()
