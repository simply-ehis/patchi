"""
`p audit` — Full project audit + Plan-vs-Built Drift Detector (Dream Assistant spec).

This command existed as a "full project audit (scan + security + test + report)"
and the Dream Assistant spec's Audit Mode maps directly onto it. We keep that
contract and add the Drift Detector:

  p audit --plan [--intent "..."]   snapshot current state as the agreed Plan
  p audit --plan-file PATH          audit the built state against a plan/spec file
  p audit [--quick] [--no-scan]     full audit + drift vs the saved Plan (if any)
  p audit --html PATH               write a self-contained HTML report (Playwright-viewable)

The full audit re-runs the real test suite and the Brain scan (never trusting a
self-report) and, if a Plan exists, reports the gap between Plan and Built.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.panel import Panel

from patchi.cli.console import con
from patchi.core.brain.audit import (
    compute_drift,
    drift_vs_plan_file,
    load_plan,
    save_plan,
)
from patchi.core.brain.secrets import scan_secrets
from patchi.core.brain.verify import detect_test_command, run_tests
from patchi.core.config import require_project_root


def run(
    quick: bool = False,
    json_output: bool = False,
    plan: bool = False,
    plan_file: str | None = None,
    intent: str | None = None,
    no_scan: bool = False,
    html: str | None = None,
    root: Path | None = None,
) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # ── Plan mode: snapshot the agreed Plan, no scans ──────────────────────────
    if plan:
        saved = save_plan(r, intent=intent)
        con.print(
            f"[#4ADE80]Plan saved[/#4ADE80] at {saved['saved_at']}"
            + (f" — intent: {saved['intent']}" if saved.get("intent") else "")
            + "."
        )
        con.print(
            f"  Findings at plan time: {saved['total_findings']}; "
            f"charter violations: {saved['charter_violations']}"
        )
        con.print("[dim]Now build. Later run [bold]p audit[/bold] to detect drift.[/dim]")
        return

    # ── Plan-file mode: diff the built state against a supplied plan ───────────
    if plan_file:
        drift = drift_vs_plan_file(r, plan_file)
        _print_drift(drift)
        return

    # ── Full audit ─────────────────────────────────────────────────────────────
    report: dict = {"audit": "full"}
    scan_error = None
    if not no_scan:
        try:
            from patchi.core.brain.brain import Brain

            Brain(r).scan()
        except Exception as e:
            scan_error = str(e)
    report["scan_error"] = scan_error

    test_run = None
    if not quick:
        cmd = detect_test_command(r)
        if cmd:
            test_run = run_tests(r, cmd)
            report["tests"] = {
                "command": cmd,
                "passed": test_run.passed,
                "failed": test_run.failed,
                "error": test_run.error,
                "skipped": test_run.skipped,
                "truthful": test_run.truthful,
                "duration_seconds": test_run.duration_seconds,
            }

    # Secrets sanity (lightweight; deep scanning is via `p security`/`p deps`).
    secrets = scan_secrets(r)
    report["secret_hits"] = [str(s) for s in secrets]

    # Drift vs the saved Plan (if one exists).
    plan_state = load_plan(r)
    if plan_state:
        drift = compute_drift(r)
        report["drift"] = {
            k: drift[k]
            for k in (
                "has_plan",
                "clean",
                "new_findings",
                "new_charter_violations",
                "layers_added",
                "layers_removed",
                "scope_diff",
            )
        }
    else:
        report["drift"] = {"has_plan": False}

    if json_output:
        con.print(json.dumps(report, indent=2, default=str))
        return
    if html:
        _write_html(Path(html), report)
        con.print(f"[#4ADE80]HTML report written to {html}[/#4ADE80]")
        return

    _print_full_audit(report, test_run)


def _print_full_audit(report: dict, test_run) -> None:
    con.print()
    lines = ["[bold #C8621A]Full Project Audit[/bold #C8621A]"]
    if report.get("scan_error"):
        lines.append(f"[red]scan could not run:[/red] {report['scan_error']}")
    tests = report.get("tests")
    if tests:
        state = "[#4ADE80]GREEN[/#4ADE80]" if tests["truthful"] else "[#FACC15]RED[/#FACC15]"
        lines.append(
            f"Tests: {state} — {tests['passed']} passed"
            + (f", {tests['failed']} failed" if tests["failed"] else "")
            + (f", {tests['error']} error" if tests["error"] else "")
            + (f" ({tests['duration_seconds']}s)" if tests.get("duration_seconds") else "")
        )
    secrets = report.get("secret_hits") or []
    if secrets:
        lines.append(f"[#FACC15]Possible secrets found ({len(secrets)}):[/#FACC15]")
        for s in secrets[:10]:
            lines.append(f"  • {s}")
    else:
        lines.append("Secrets: none detected in a quick sweep (run `p security` for depth).")

    drift = report.get("drift") or {}
    if drift.get("has_plan"):
        status = "ON PLAN ✅" if drift.get("clean") else "DRIFT DETECTED ⚠️"
        lines.append(
            f"Plan-vs-Built: {status}"
            + (
                f" — {drift.get('new_findings', 0)} new findings"
                if drift.get("new_findings")
                else ""
            )
            + (
                f", {drift.get('new_charter_violations', 0)} new charter violations"
                if drift.get("new_charter_violations")
                else ""
            )
        )
        if drift.get("layers_added"):
            lines.append(f"  + beyond plan: {', '.join(drift['layers_added'])}")
        if drift.get("layers_removed"):
            lines.append(f"  - missing vs plan: {', '.join(drift['layers_removed'])}")
        sd = drift.get("scope_diff") or {}
        if sd.get("added_files"):
            lines.append(
                f"  + files added ({sd['added_count']}): "
                + ", ".join(f for f in sd["added_files"][:8])
            )
        if sd.get("removed_files"):
            lines.append(
                f"  - files removed ({sd['removed_count']}): "
                + ", ".join(f for f in sd["removed_files"][:8])
            )
        if sd.get("modified_files"):
            lines.append(f"  ~ files changed ({sd['modified_count']}):")
            for m in sd["modified_files"][:8]:
                bits = []
                if m["symbols_added"]:
                    bits.append(f"+{len(m['symbols_added'])} sym")
                if m["symbols_removed"]:
                    bits.append(f"-{len(m['symbols_removed'])} sym")
                if not bits:
                    bits.append("content changed")
                lines.append(f"      • {m['file']}  ({', '.join(bits)})")
    else:
        lines.append(
            "[dim]Tip: run [bold]p audit --plan[/bold] to set a baseline, then re-audit for drift.[/dim]"
        )

    con.print(
        Panel("\n".join(lines), title="[bold #C8621A]Audit[/bold #C8621A]", border_style="#2A3D28")
    )
    con.print()


def _write_html(path: Path, report: dict) -> None:
    def _esc(s) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows = []
    tests = report.get("tests")
    if tests:
        state = "GREEN" if tests["truthful"] else "RED"
        rows.append(
            f"<tr><td>Tests</td><td>{state}</td>"
            f"<td>{tests['passed']} passed / {tests['failed']} failed"
            f"{('/ ' + str(tests['error']) + ' error') if tests['error'] else ''}</td></tr>"
        )
    secrets = report.get("secret_hits") or []
    rows.append(
        f"<tr><td>Secrets</td><td>{'FOUND' if secrets else 'none'}</td>"
        f"<td>{_esc('; '.join(str(s) for s in secrets[:10]) or 'none detected')}</td></tr>"
    )
    drift = report.get("drift") or {}
    if drift.get("has_plan"):
        status = "ON PLAN" if drift.get("clean") else "DRIFT"
        extra = []
        if drift.get("new_findings"):
            extra.append(f"{drift['new_findings']} new findings")
        if drift.get("new_charter_violations"):
            extra.append(f"{drift['new_charter_violations']} new charter violations")
        if drift.get("layers_added"):
            extra.append("beyond plan: " + ", ".join(drift["layers_added"]))
        if drift.get("layers_removed"):
            extra.append("missing: " + ", ".join(drift["layers_removed"]))
        rows.append(
            f"<tr><td>Plan-vs-Built</td><td>{status}</td>"
            f"<td>{_esc('; '.join(extra) or 'no drift')}</td></tr>"
        )
    else:
        rows.append(
            "<tr><td>Plan-vs-Built</td><td>n/a</td>"
            "<td>run <code>p audit --plan</code> to set a baseline</td></tr>"
        )

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Patchi — Audit Report</title>
<style>
 body {{ font-family: ui-monospace, Menlo, Consolas, monospace; background:#1a1714; color:#f2edd6; margin:2rem; }}
 h1 {{ color:#c8621a; }}
 table {{ border-collapse:collapse; width:100%; }}
 th,td {{ text-align:left; padding:.5rem .7rem; border-bottom:1px solid #2a3d28; }}
 th {{ color:#c8621a; }}
 .muted {{ color:#b8a898; }}
</style></head>
<body>
<h1>Patchi — Full Project Audit</h1>
<p class="muted">scan_error: {_esc(report.get("scan_error") or "none")}</p>
<table>
<tr><th>Section</th><th>Status</th><th>Detail</th></tr>
{"".join(rows)}
</table>
</body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def _print_drift(drift: dict) -> None:
    con.print()
    if not drift.get("has_plan"):
        msg = drift.get("error") or "No usable plan."
        con.print(f"[red]{msg}[/red]")
        return
    border = "#4ADE80" if drift.get("clean") else "#FACC15"
    con.print(
        Panel(
            drift["summary"],
            title="[bold #C8621A]Plan-vs-Built[/bold #C8621A]",
            border_style=border,
        )
    )
    con.print()
