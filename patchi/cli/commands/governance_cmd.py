"""
`p governance` — CLI surface for the GUARD infrastructure agents (Part 3 §1).

Every subcommand here is a thin, honest wrapper over an existing core module
that previously had no CLI consumer:

- `actions`  → governance.patchi_get_actions   (the audit trail, previously write-only)
- `policy`   → governance.patchi_policy_gate / _load_policy
- `history`  → history.patchi_get_history      (scan history analytics)
- `verify`   → history.patchi_verify_finding   (findings lifecycle)
- `impact`   → blast_radius.patchi_blast_radius (symbol reference counting)
- `triage`   → detector.triage.TriageAgent     (EventBus anomaly daemon / stats)
- `generate` → CICDGeneratorAgent templates    (CI configs actually written to disk)

Honesty rules (Part 2/3): a subcommand with no data says so; destructive or
over-broad operations (verify --force) require an explicit flag and say what
they actually did; `generate` never overwrites an existing CI file unless
told to; the triage daemon prints its real stats on shutdown.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.table import Table

from patchi.cli.console import con


def _root_or_fail() -> Path | None:
    try:
        from patchi.core.config import require_project_root

        return require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return None


def _emit(payload: dict, json_output: bool) -> None:
    if json_output:
        # Plain print, NOT the rich console: con.print word-wraps at console
        # width, which injects raw newlines inside JSON string values and
        # corrupts machine parsing.
        print(json.dumps(payload, indent=2, default=str))


def _cmd_actions(root: Path, limit: int, json_output: bool) -> int:
    from patchi.core.security.governance import patchi_get_actions

    actions = patchi_get_actions(root, limit=limit)
    if not actions:
        if json_output:
            _emit({"actions": [], "count": 0}, True)
        else:
            con.print(
                "[dim]No actions logged yet. The audit trail fills up as agents,"
                " fixes, and governance checks run (`p scan`, `p fix`, ...).[/dim]"
            )
        return 0

    _emit({"actions": actions, "count": len(actions)}, json_output)
    if json_output:
        return 0

    table = Table(title=f"Governance action log (last {len(actions)})")
    table.add_column("Timestamp", style="dim")
    table.add_column("Action", style="#C8621A")
    table.add_column("Target", max_width=40)
    table.add_column("Agent", style="dim")
    table.add_column("Status")
    for a in actions:
        status = a.get("status", "")
        style = "green" if status == "ok" else ("red" if status == "error" else "yellow")
        table.add_row(
            str(a.get("timestamp", "")),
            str(a.get("action", "")),
            str(a.get("target", "")),
            str(a.get("agent", "")),
            f"[{style}]{status}[/{style}]",
        )
    con.print(table)
    return 0


def _cmd_policy(root: Path, target: str | None, severity: str, json_output: bool) -> int:
    from patchi.core.security.governance import _load_policy, patchi_action_log, patchi_policy_gate

    policy = _load_policy(root)
    checks: list[dict] = []
    if target:
        allowed, reason = patchi_policy_gate(root, "cli_check", target, severity)
        checks.append({"target": target, "severity": severity, "allowed": allowed, "reason": reason})
        # Policy checks are themselves auditable actions.
        patchi_action_log(
            root,
            "policy_check",
            target,
            agent="p governance",
            detail=reason,
            status="ok" if allowed else "blocked",
        )

    _emit({"policy": policy, "checks": checks}, json_output)
    if json_output:
        return 0

    con.print("[bold #C8621A]Governance policy[/bold #C8621A]")
    con.print(f"  never_touch patterns: [bold]{len(policy.get('never_touch', []))}[/bold]")
    for p in policy.get("never_touch", [])[:10]:
        con.print(f"    - {p}")
    con.print(f"  auto_apply_max_severity: [bold]{policy.get('auto_apply_max_severity', '?')}[/bold]")
    con.print(f"  require_confirmation_above: [bold]{policy.get('require_confirmation_above', '?')}[/bold]")
    con.print("[dim]Source: .patchi/policies/default.yaml (or built-in defaults)[/dim]")
    for c in checks:
        style = "green" if c["allowed"] else "red"
        con.print(f"  [{style}]{'ALLOWED' if c['allowed'] else 'BLOCKED'}[/{style}] {c['target']} — {c['reason']}")
    return 0


def _cmd_history(root: Path, limit: int, json_output: bool) -> int:
    from patchi.core.security.history import patchi_get_analytics, patchi_get_history

    history = patchi_get_history(root, limit=limit)
    analytics = patchi_get_analytics(root)
    if not history:
        if json_output:
            _emit({"history": [], "analytics": analytics, "count": 0}, True)
        else:
            con.print(
                "[dim]No scan history yet. Run `p scan` or `p security` — every scan"
                " is recorded here with severity breakdown and health score.[/dim]"
            )
        return 0

    _emit({"history": history, "analytics": analytics, "count": len(history)}, json_output)
    if json_output:
        return 0

    table = Table(title=f"Scan history (last {len(history)} of {analytics['total_scans']})")
    table.add_column("Timestamp", style="dim")
    table.add_column("Tool")
    table.add_column("Findings", justify="right")
    table.add_column("Health", justify="right")
    table.add_column("Duration", justify="right", style="dim")
    for h in history:
        table.add_row(
            str(h.get("timestamp", "")),
            str(h.get("tool", "")),
            str(h.get("findings_count", 0)),
            str(h.get("health_score", 0)),
            f"{h.get('duration_ms', 0)}ms",
        )
    con.print(table)
    by_status = analytics.get("findings_by_status", {})
    if by_status:
        con.print("  Findings lifecycle: " + ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())))
    return 0


def _cmd_verify(root: Path, finding_id: str, force: bool, json_output: bool) -> int:
    import sqlite3

    from patchi.core.security import history as hist
    from patchi.core.security.history import patchi_verify_finding

    db_path = root / ".patchi" / hist._DB_NAME
    if not db_path.exists():
        con.print("[red]No findings database yet — run a scan first.[/red]")
        return 1

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT finding_id, status, file, severity FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        con.print(f"[red]Finding '{finding_id}' not found in the history database.[/red]")
        return 1

    current_status = row[1]
    if current_status != "open" and not force:
        _emit(
            {
                "finding_id": finding_id,
                "verified": False,
                "status": current_status,
                "note": "not open — use --force to transition anyway",
            },
            json_output,
        )
        if not json_output:
            con.print(
                f"[yellow]Finding is '{current_status}', not 'open'[/yellow] — verify only"
                f" transitions open findings. Use [bold]--force[/bold] to override."
            )
        return 1

    patchi_verify_finding(root, finding_id)
    _emit({"finding_id": finding_id, "verified": True, "previous_status": current_status}, json_output)
    if not json_output:
        con.print(f"[green]Verified[/green] {finding_id} ({row[3]} in {row[2] or '—'})")
    return 0


def _cmd_impact(root: Path, symbol: str, json_output: bool) -> int:
    from patchi.core.security.blast_radius import patchi_blast_radius

    result = patchi_blast_radius(symbol, root)
    _emit(result, json_output)
    if json_output:
        return 0

    level = result["blast_level"]
    style = {"low": "green", "medium": "yellow", "high": "red"}.get(level, "white")
    con.print(f"[bold #C8621A]Blast radius:[/bold #C8621A] [{style}]{level}[/{style}]")
    con.print(f"  Symbol: {result['symbol']}")
    con.print(f"  References: {result['reference_count']}")
    for f in result["referencing_files"][:15]:
        con.print(f"    - {f}")
    if result["reference_count"] > 15:
        con.print(f"    ... and {result['reference_count'] - 15} more")
    return 0


def _cmd_triage(root: Path, start: bool, json_output: bool) -> int:
    from patchi.core.detector.triage import TriageAgent

    agent = TriageAgent()
    if not start:
        stats = agent.get_stats()
        _emit({**stats, "hint": "run `p governance triage --start` to subscribe to the live event stream"}, json_output)
        if json_output:
            return 0
        if stats["total_events"] == 0:
            con.print(
                "[dim]Triage has not observed any events in this process. The agent"
                " holds state in memory while subscribed — run"
                " `p governance triage --start` to attach it to the live EventBus.[/dim]"
            )
            return 0
        _print_stats(stats)
        return 0

    # Live daemon: subscribe to the EventBus, print anomalies as they fire,
    # Ctrl+C detaches cleanly. The periodic silence check rides the same loop.
    import asyncio

    from patchi.core.detector.bus import EventBus

    async def _serve() -> None:
        bus = EventBus()
        await agent.run_detached(bus)
        con.print("[green]TriageAgent subscribed — listening for events (Ctrl+C to detach)[/green]")
        try:
            while True:
                await asyncio.sleep(60)
                for f in agent.check_silence():
                    con.print(f"[yellow]SILENCE[/yellow] {f.message}")
        except asyncio.CancelledError:
            raise
        finally:
            agent.stop()

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass
    stats = agent.get_stats()
    _emit({"detached": True, **stats}, json_output)
    if not json_output:
        con.print("[dim]Detached. Session statistics:[/dim]")
        _print_stats(stats)
    return 0


def _print_stats(stats: dict) -> None:
    con.print(f"  Sources tracked: {stats['sources_tracked']}  |  Total events: {stats['total_events']}")
    for key, s in list(stats.get("sources", {}).items())[:10]:
        con.print(
            f"    - {key}: {s['event_count']} events, mean rate {s['mean_rate']:.2f}/s,"
            f" last seen {s['last_seen_ago']:.0f}s ago"
        )


def _cmd_generate(root: Path, write: bool, force: bool, json_output: bool) -> int:
    from patchi.core.agents.cicd_generator import (
        _GITHUB_ACTIONS_WORKFLOW,
        _GITLAB_CI_TEMPLATE,
        _PRE_COMMIT_CONFIG,
    )
    from patchi.core.security.governance import patchi_action_log

    targets = [
        (root / ".pre-commit-config.yaml", _PRE_COMMIT_CONFIG),
        (root / ".github" / "workflows" / "patchi-ci.yml", _GITHUB_ACTIONS_WORKFLOW),
        (root / ".gitlab-ci.yml", _GITLAB_CI_TEMPLATE),
    ]

    written: list[str] = []
    present: list[str] = []
    if write:
        for path, template in targets:
            rel = path.relative_to(root).as_posix()
            if path.exists() and not force:
                present.append(rel)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(template, encoding="utf-8")
            written.append(rel)
        patchi_action_log(
            root,
            "governance_ci_generate",
            ",".join(written) or "(nothing written)",
            detail=f"written={written} present={present}",
        )

    payload = {
        "written": written,
        "present": present,
        "manual": ["CODEOWNERS (team knowledge — GitHub/GitLab settings, not generated)"],
        "mode": "write" if write else "preview",
    }
    _emit(payload, json_output)
    if json_output:
        return 0

    con.print("[bold #C8621A]CI/CD configuration[/bold #C8621A]")
    if not write:
        con.print("[dim]Preview mode — add [bold]--write[/bold] to create missing files.[/dim]")
    for path, _ in targets:
        rel = path.relative_to(root).as_posix()
        if rel in written:
            con.print(f"  [green]✓ written[/green]  {rel}")
        elif rel in present:
            con.print(f"  [yellow]• present[/yellow]  {rel} (use --force to overwrite)")
        else:
            con.print(f"  [green]✓[/green] {rel} (missing — would be generated)")
    con.print("  [dim]• CODEOWNERS: manual — set up branch protection in GitHub/GitLab settings[/dim]")
    return 0


def run(args: argparse.Namespace) -> int:
    """Self-routing entry point for `p governance` (namespace handler)."""
    root = _root_or_fail()
    if root is None:
        return 1

    sub = getattr(args, "governance_cmd", None)
    json_output = bool(getattr(args, "json_output", False))

    if sub == "actions":
        return _cmd_actions(root, int(getattr(args, "limit", 50) or 50), json_output)
    if sub == "policy":
        sev = getattr(args, "severity", "medium") or "medium"
        return _cmd_policy(root, getattr(args, "target", None), sev, json_output)
    if sub == "history":
        return _cmd_history(root, int(getattr(args, "limit", 20) or 20), json_output)
    if sub == "verify":
        return _cmd_verify(
            root,
            getattr(args, "finding_id", "") or "",
            bool(getattr(args, "force", False)),
            json_output,
        )
    if sub == "impact":
        symbol = getattr(args, "symbol", None)
        if not symbol:
            con.print("[red]Provide a symbol or package: p governance impact <name>[/red]")
            return 1
        return _cmd_impact(root, symbol, json_output)
    if sub == "triage":
        return _cmd_triage(root, bool(getattr(args, "start", False)), json_output)
    if sub == "generate":
        return _cmd_generate(
            root,
            bool(getattr(args, "write", False)),
            bool(getattr(args, "force", False)),
            json_output,
        )

    # Bare `p governance` — an honest overview of what this surface owns.
    con.print("[bold #C8621A]p governance[/bold #C8621A] — GUARD infrastructure surface")
    con.print("  actions   Audit trail: what agents/fixes/gates actually did")
    con.print("  policy    Show (or test) the never-touch / severity policy")
    con.print("  history   Scan history + findings lifecycle analytics")
    con.print("  verify    Mark a finding's fix as verified")
    con.print("  impact    Blast radius of a symbol or package")
    con.print("  triage    Event-stream anomaly daemon (stats / --start)")
    con.print("  generate  Generate CI configs (--write to create files)")
    con.print("[dim]All subcommands accept --json for machine-readable output.[/dim]")
    return 0
