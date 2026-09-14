"""
`p scan` — Run the full Patchi pipeline on the project.

Usage:
  p scan               — full project pipeline (structural + security + scoring)
  p scan src/auth      — targeted scan of a specific area
  p scan --dry-run     — show what would be scanned without parsing

There is ONE pipeline (spec §1 merge): the Governor's 7-phase state machine
wraps the Brain's structural pass and dispatches both the generic scanner
agents and the AgentGroup.SECURITY agents by default. `--governor` was removed
— it used to select the only implementation that ran the security agents,
undocumented, while every documented entry point silently ran a thin path that
never touched them. `p scan` is read-only: fix candidates are generated,
sandbox-verified and SCORED, but never applied — `p fix` / `p auto` are the
apply paths.

Shows:
  - Rich multi-bar progress display (one bar per phase)
  - Live file discovery feed
  - Per-phase evidence and summary tables after completion
  - Contract confirmation if new critical flows are found
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import UTC
from pathlib import Path
from typing import Any

from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.agents.base import AgentGroup, list_agents
from patchi.core.brain.brain import BrainReport, ScanProgress
from patchi.core.brain.freshness import check_freshness
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.scan_cmd")


def run(
    area: str | None = None,
    dry_run: bool = False,
    force: bool = False,
    quiet: bool = False,
    no_logo: bool = False,
    deep: bool = False,
    file_path: str | None = None,
    contract: bool = False,
    all_flows: bool = False,
    offline: bool = False,
    json_output: bool = False,
    side: bool = True,
    pipeline: bool = False,
    daemon: bool = False,
    with_attackers: bool = False,
    with_campaigns: bool = False,
    with_fuzz: bool = False,
    red_team: bool = False,
    dast: bool = False,
    changed: bool = False,
    changed_commits: int = 1,
    since: str | None = None,
    fail_on: str | None = None,
    root: Path | None = None,
    with_license: bool = False,
    with_extended: bool = False,
) -> int:
    """Entry point for `p scan [area]`. Returns process exit code."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return 2

    # If area is an absolute path, treat it as the project root
    if area and Path(area).is_absolute():
        r = Path(area)
        area = None

    # ── Set tenant context so profiler records the correct project root ────
    from patchi.core.tenant import get_tenant_manager, tenant_context

    try:
        mgr = get_tenant_manager()
        mgr.register_project(r)
        mgr.switch_project(r)
    except Exception as _exc:
        _log.debug("tenant registration skipped: %s", _exc)

    with tenant_context(r):
        return _run_scan_inner(
            r,
            area,
            dry_run,
            force,
            quiet,
            no_logo,
            deep,
            file_path,
            contract,
            all_flows,
            offline,
            json_output,
            side,
            pipeline,
            daemon,
            with_attackers,
            with_campaigns,
            with_fuzz,
            red_team,
            dast,
            changed,
            changed_commits,
            since,
            fail_on,
            with_license,
            with_extended,
        )


def _run_scan_inner(
    r: Path,
    area: str | None = None,
    dry_run: bool = False,
    force: bool = False,
    quiet: bool = False,
    no_logo: bool = False,
    deep: bool = False,
    file_path: str | None = None,
    contract: bool = False,
    all_flows: bool = False,
    offline: bool = False,
    json_output: bool = False,
    side: bool = True,
    pipeline: bool = False,
    daemon: bool = False,
    with_attackers: bool = False,
    with_campaigns: bool = False,
    with_fuzz: bool = False,
    red_team: bool = False,
    dast: bool = False,
    changed: bool = False,
    changed_commits: int = 1,
    since: str | None = None,
    fail_on: str | None = None,
    with_license: bool = False,
    with_extended: bool = False,
) -> int:
    """Inner scan logic — runs inside tenant_context. Returns process exit code."""

    # ── Contract review mode ──────────────────────────────────────────────────
    if contract:
        _run_contract_review(r, all_flows=all_flows)
        return 0

    # ── Offline mode ──────────────────────────────────────────────────────────
    if offline:
        import os

        os.environ["PATCHI_OFFLINE"] = "1"
        if not quiet:
            con.print(
                "[bold #C8621A]OFFLINE MODE[/bold #C8621A] — Static analysis only. Zero API calls."
            )
            con.print(
                "[dim]Findings will have no AI explanations. Run without --offline to add them.[/dim]"
            )
            con.print()

    # ── Dry run ───────────────────────────────────────────────────────────────
    if dry_run and not changed:
        _show_dry_run(r, area)
        return 0

    # ── Changed dry-run mode ──────────────────────────────────────────────
    if changed and dry_run:
        _show_changed_dry_run(r, changed_commits)
        return 0

    # ── Handle file-specific deep scan ────────────────────────────────────────
    if file_path:
        _run_file_scan(r, file_path, deep)
        return 0

    # ── Check freshness first ─────────────────────────────────────────────────
    freshness = check_freshness(r)
    if (
        not freshness["is_stale"]
        and freshness["last_recorded"]
        and not area
        and not force
        and not deep
        and not contract
    ):
        con.print()
        con.print(
            "[dim]Brain is already fresh.[/dim] "
            f"[dim]Last scan: {_fmt_time(freshness['last_recorded'])}[/dim]"
        )
        con.print("[dim]Run [bold]p scan --force[/bold] to re-scan anyway.[/dim]")
        con.print()
        # Still show current status
        _show_summary_from_memory(r)
        return 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    con.print()
    area_label = f" [dim]→ {area}[/dim]" if area else ""
    scan_type = "Deep" if deep else "Scanning"
    con.print(f"[bold #C8621A]{scan_type}{area_label}[/bold #C8621A]")
    con.print()

    # Chain progress display
    from patchi.cli.ux import format_step, status_icon, status_style

    scan_phases = [
        "File discovery",
        "Stack detection",
        "Source parsing",
        "Route mapping",
        "Import graph",
        "Contract inference",
        "Agent dispatch",
        "Scoring phases",
    ]
    total_steps = len(scan_phases)
    current_step = 0

    def show_scan_step(step_name: str, status: str = "running"):
        nonlocal current_step
        current_step += 1
        icon = status_icon(status)
        style = status_style(status)
        con.print(format_step(current_step, total_steps, f"[{style}]{icon} {step_name}[/{style}]"))

    # Show initial chain steps (first 6 are brain phases inside Governor.SCAN)
    for phase_name in scan_phases[:6]:
        show_scan_step(phase_name, "done")

    _scan_start = time.monotonic()  # wall clock for entire scan

    progress = _build_progress()
    tasks: dict[str, Any] = {}

    phases = {
        "discovery": "Discovering files",
        "stack_detect": "Detecting stack",
        "parsing": "Parsing source files",
        "routes": "Mapping routes",
        "graph": "Building import graph",
        "contract": "Inferring app contract",
    }

    for phase, label in phases.items():
        tasks[phase] = progress.add_task(
            f"[dim]{label}[/dim]",
            total=None,  # indeterminate until we know file count
        )
    tasks["agents"] = progress.add_task("[dim]Security & scanner agents[/dim]", total=None)

    last_phase = [None]

    def on_progress(sp: ScanProgress) -> None:
        # The Governor pipes BOTH Brain (ScanProgress) and agent-dispatch
        # (CoordinatorProgress) events here; only Brain phases map to bars.
        phase = getattr(sp, "phase", None)
        if phase is None:
            # CoordinatorProgress: live agent activity on the agents bar.
            agent_task = tasks.get("agents")
            name = getattr(sp, "agent_name", "")
            if agent_task is not None and name:
                progress.update(
                    agent_task,
                    description=f"[dim]{name} - {getattr(sp, 'finding_count', 0)} findings[/dim]",
                )
            return
        task_id = tasks.get(phase)
        if task_id is None:
            return

        # Advance completed previous phase
        if last_phase[0] and last_phase[0] != sp.phase:
            prev_id = tasks.get(last_phase[0])
            if prev_id is not None:
                progress.update(prev_id, completed=100, total=100)
        last_phase[0] = sp.phase

        if sp.total:
            progress.update(
                task_id,
                total=sp.total,
                completed=sp.current,
                description=f"[dim]{sp.message[:60]}[/dim]",
            )
        else:
            progress.update(task_id, description=f"[dim]{sp.message[:60]}[/dim]", total=None)

    report: BrainReport | None = None
    agent_results: list | None = None
    error: str | None = None

    _is_tty = con.is_terminal

    # ── Pre-load DomainLoader in background (saves ~5-10s) ──────────────
    # Auto-detect component types first (cheap), then load scoped taxonomy
    # in a background thread while the main scan runs.
    _ctypes = []
    try:
        _root = Path(str(r))
        if any((_root / d).exists() for d in ("templates", "static", "public")):
            _ctypes.append("frontend-web")
        if any((_root / f).exists() for f in ("requirements.txt", "pyproject.toml", "setup.py")):
            _ctypes.append("backend-api")
        if any((_root / d).exists() for d in ("docker", "k8s", "kubernetes", ".github")) or (_root / "Dockerfile").exists():
            _ctypes.append("infra")
    except Exception as _exc:
        _log.debug("component type detect skipped: %s", _exc)
    _domain_loader_future = None
    try:
        import concurrent.futures as _cf

        from patchi.core.security.domain_loader import DomainLoader as _DL
        _loader_pool = _cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="dl-preload")
        def _preload_loader() -> _DL:
            # Construct + force the (lazy) load so YAML parsing happens in
            # this background thread, not on first use in the main thread.
            _ldr = _DL(r, component_types=_ctypes if _ctypes else None)
            _ldr.list_domains()  # public force-load; parses + caches taxonomy
            return _ldr

        _domain_loader_future = _loader_pool.submit(_preload_loader)
        _loader_pool.shutdown(wait=False)
    except Exception as _exc:
        _log.debug('suppressed: %s', _exc)

    def _run_scan() -> None:
        nonlocal report, agent_results, error
        try:
            # ── ONE pipeline: the Governor IS `p scan` (spec §1 merge) ─────
            # The former thin path (Brain + SCANNER group only) and the
            # undocumented --governor fork are collapsed into this single
            # implementation. Governor.run_scan() delegates the Brain's
            # structural pass (file discovery → stack detection → parsing →
            # routes → import graph → contract) and then dispatches BOTH the
            # generic scanners and AgentGroup.SECURITY by default. Later
            # phases (graph update, graph-scoped test generation, fix
            # candidate scoring) run with dry_run=True: p scan is read-only —
            # candidates are scored and routed, never applied; p fix / p auto
            # remain the apply paths.
            from patchi.core.agents.governor import Governor

            gov = Governor(r, on_progress=on_progress)
            gov.brain_on_progress = on_progress  # feed Brain phases to the bars

            # ── On-demand domain activation from git diff (pre-dispatch) ─
            if changed:
                try:
                    from patchi.core.security.git_diff_activator import (
                        activate_from_diff,
                    )

                    diff_result = activate_from_diff(r, commits=changed_commits)
                    if diff_result.activated_domains:
                        con.print(
                            f"  [dim]Changed files: {len(diff_result.changed_files)}[/dim]"
                        )
                        dom_str = ", ".join(
                            f"{d} ({s:.1f})"
                            for d, s in list(diff_result.activated_domains.items())[:8]
                        )
                        con.print(f"  [dim]Activated domains: {dom_str}[/dim]")
                        gov.coordinator.set_active_domains(
                            list(diff_result.activated_domains.keys())
                        )
                    else:
                        con.print(
                            "  [dim]No domain-relevant changes detected — running full scan[/dim]"
                        )
                except Exception as e:
                    _log.debug("Git-diff activation failed: %s", e)

            # Run the full pipeline (see Governor.run_scan for the Brain
            # delegation and the default SECURITY dispatch).
            phase_results = gov.run_full_pipeline_v2(scope=None, dry_run=True, area=area)

            # ── Surface per-phase evidence (§8: verdicts carry evidence) ──
            con.print()
            con.print("[bold #C8621A]─ Pipeline Phases ─[/bold #C8621A]")
            for pr in phase_results:
                status_style = "#4ADE80" if pr.passed else "#FF4D6D"
                con.print(
                    f"  {pr.phase.value}: [bold {status_style}]{pr.status.value}[/bold {status_style}]"
                    f"  [dim]{pr.duration_ms}ms  {pr.findings_count} findings  {pr.agents_run} agents[/dim]"
                )
                ev = (pr.data or {}).get("evidence") or {}
                verdict = (pr.data or {}).get("verdict", "?")
                if ev:
                    partial = ""
                    if verdict == "partial":
                        reasons = ev.get("partial_reasons", [])
                        partial = f"  [yellow]partial: {'; '.join(reasons[:2])}[/yellow]"
                    con.print(
                        f"    [dim]verdict={verdict}"
                        + (
                            f"  eval_acc={ev['eval'].get('routing_accuracy')}"
                            if isinstance(ev.get("eval"), dict)
                            and ev["eval"].get("routing_accuracy") is not None
                            else ""
                        )
                        + (f"  tests={ev['test_totals']}" if ev.get("test_totals") else "")
                        + "[/dim]"
                        + partial
                    )
                if pr.errors:
                    for err in pr.errors[:3]:
                        con.print(f"    [dim]  {err}[/dim]")

            # Any failed phase is a failed scan for exit-code purposes; the
            # summary still renders below so the user sees the evidence.
            failed_phases = [pr for pr in phase_results if not pr.passed]
            if failed_phases:
                error = "; ".join(
                    f"{pr.phase.value}: {'; '.join(pr.errors[:1]) or pr.status.value}"
                    for pr in failed_phases
                )

            # ── Collect report + agent results from the pipeline itself ───
            # The BrainReport rides on the SCAN phase result ( Governor
            # stashes it there); agent results are the union of every phase
            # that dispatched agents.
            for pr in phase_results:
                rep = (pr.data or {}).get("brain_report")
                if rep is not None:
                    report = rep
                    break
            # Collect each agent's CANONICAL result: the first phase that ran
            # it (SCAN for scanners/security, TEST_EXECUTION for test agents).
            # Later phases (SANDBOX_REVERIFY re-runs whole groups) would
            # otherwise duplicate every row and every finding in the summary.
            agent_results = []
            _seen_agents: set[str] = set()
            for pr in phase_results:
                for ar in getattr(pr, "results", []) or []:
                    _name = getattr(ar, "agent_name", "")
                    if _name in _seen_agents:
                        continue
                    _seen_agents.add(_name)
                    agent_results.append(ar)

            show_scan_step("Agent dispatch", "done")
            show_scan_step("Scoring phases", "done" if not failed_phases else "error")

            # Mark all tasks complete
            for tid in tasks.values():
                progress.update(tid, completed=100, total=100)

        except Exception as e:
            import traceback

            error = f"{e}\n{traceback.format_exc()}"

    if _is_tty:
        with Live(progress, console=con, refresh_per_second=10):
            _run_scan()
    else:
        _run_scan()

    if error:
        # Phase failures already printed their evidence above; only a hard
        # crash (traceback) prints here.
        if "\n" in error:
            con.print(f"\n[red]Scan failed:[/red] {error}")
            return 2
        if not quiet:
            con.print(f"\n[yellow]Scan completed with phase failures:[/yellow] {error}")

    # ── Deep scan processing ──────────────────────────────────────────────────
    if deep:
        _run_deep_scan_analysis(r, report, agent_results)

    if report is None:
        con.print("\n[red]Scan returned no results.[/red]")
        return 2

    # ── Results summary ───────────────────────────────────────────────────────
    con.print()
    _scan_elapsed = time.monotonic() - _scan_start
    _show_report_summary(report, agent_results, wall_time=_scan_elapsed, root=r)

    # ── Threat Model Generation (auto-updated from findings) ────────────────
    try:
        from patchi.core.agents.coordinator import merge_results as _mr
        from patchi.core.security.threat_model_updater import update_threat_model

        _findings_for_tm = _mr(agent_results).get("findings", []) if agent_results else []
        threat_model = update_threat_model(r, _findings_for_tm)
        if threat_model.applicable_scenarios > 0:
            con.print()
            con.print("[bold #C8621A]─ Threat Model ─[/bold #C8621A]")
            con.print(
                f"  Scenarios: [bold]{threat_model.applicable_scenarios}[/bold] applicable "
                f"out of {threat_model.total_scenarios} total"
            )
            if threat_model.by_severity:
                sev_str = ", ".join(f"{k}={v}" for k, v in sorted(threat_model.by_severity.items()))
                con.print(f"  By severity: {sev_str}")
            if threat_model.recommendations:
                for rec in threat_model.recommendations[:3]:
                    con.print(f"  [dim]• {rec}[/dim]")
            # Persist for web UI and assurance
            tm_path = r / ".patchi" / "threat_model.json"
            tm_path.parent.mkdir(parents=True, exist_ok=True)
            import json as _json

            tm_path.write_text(_json.dumps(threat_model.to_dict(), indent=2), encoding="utf-8")
    except Exception as e:
        _log.debug("Threat model generation failed: %s", e)

    # ── Chain & Intent Analysis ─────────────────────────────────────────────
    try:
        from patchi.core.agents.base import list_agents as _la

        _sec_names = {a.name for a in _la(AgentGroup.SECURITY)}
        _sec_agents = [
            a for a in (agent_results or []) if getattr(a, "agent_name", "") in _sec_names
        ]
        if _sec_agents:
            from patchi.core.security.orchestrator import SecurityOrchestrator

            _sec_report = SecurityOrchestrator().correlate(_sec_agents)

            # ── Exploit Chains ──────────────────────────────────────
            if _sec_report.chains:
                con.print()
                con.print("[bold #C8621A]─ Exploit Chains ─[/bold #C8621A]")
                con.print(
                    f"  [bold]{len(_sec_report.chains)}[/bold] cross-file attack paths discovered"
                )
                for chain in _sec_report.chains[:5]:
                    sev_color = {"critical": "red", "high": "red", "medium": "yellow"}.get(
                        chain.severity, "dim"
                    )
                    con.print(
                        f"    [{sev_color}]●[{chain.severity}] score={chain.score:.0f} "
                        f"length={chain.length}[/{sev_color}]"
                    )
                    con.print(f"      [dim]{chain.narrative[:100]}[/dim]")
                if len(_sec_report.chains) > 5:
                    con.print(f"    [dim]… and {len(_sec_report.chains) - 5} more[/dim]")

            # ── Intent Gaps ─────────────────────────────────────────
            intent = _sec_report.intent_report
            if intent and intent.gap_count > 0:
                con.print()
                con.print("[bold #C8621A]─ Intent Gaps ─[/bold #C8621A]")
                con.print(
                    f"  [bold]{intent.gap_count}[/bold] logic gaps across "
                    f"[bold]{len(intent.routes)}[/bold] routes"
                )
                if intent.unauthenticated_state_changing:
                    con.print(
                        f"    [red]● {len(intent.unauthenticated_state_changing)}[/red] "
                        f"state-changing routes without auth"
                    )
                    for _rt in intent.unauthenticated_state_changing[:3]:
                        con.print(f"      [dim]{_rt.method} {_rt.path} @ {_rt.file}:{_rt.line}[/dim]")
                if intent.admin_without_strict_guard:
                    con.print(
                        f"    [yellow]● {len(intent.admin_without_strict_guard)}[/yellow] "
                        f"admin routes without strict guard"
                    )
                    for _rt in intent.admin_without_strict_guard[:3]:
                        con.print(f"      [dim]{_rt.method} {_rt.path} @ {_rt.file}:{_rt.line}[/dim]")
                if intent.unprotected_among_protected:
                    con.print(
                        f"    [yellow]● {len(intent.unprotected_among_protected)}[/yellow] "
                        f"unprotected routes among protected peers"
                    )
                    for _rt in intent.unprotected_among_protected[:3]:
                        con.print(f"      [dim]{_rt.method} {_rt.path} @ {_rt.file}:{_rt.line}[/dim]")

            if _sec_report.charter_violations:
                con.print(
                    f"  [bold]{len(_sec_report.charter_violations)}[/bold] "
                    f"[yellow]charter violation(s)[/yellow]"
                )
                for cv in _sec_report.charter_violations[:5]:
                    sev = cv.get("severity", "medium")
                    con.print(
                        f"    [yellow]● [{sev}] {cv.get('rule_id', '?')}[/yellow]: "
                        f"{cv.get('message', '')}"
                    )
                    if cv.get("suggestion"):
                        con.print(f"      [dim]→ {cv['suggestion']}[/dim]")
                if len(_sec_report.charter_violations) > 5:
                    con.print(
                        f"    [dim]… and {len(_sec_report.charter_violations) - 5} more[/dim]"
                    )

            # Persist for web UI
            import json as _cjson

            _ci_path = r / ".patchi" / "chain_intent.json"
            _ci_path.parent.mkdir(parents=True, exist_ok=True)
            _ci_path.write_text(_cjson.dumps(_sec_report.to_dict(), indent=2), encoding="utf-8")

            # ── Feed chains + intent into assurance graph ──────────────
            try:
                from patchi.core.security.chain_to_assurance import feed_chains_to_graph

                _fed = feed_chains_to_graph(r)
                if _fed:
                    con.print(f"  [dim]Fed {_fed} evidence items into assurance graph[/dim]")
            except Exception as e:
                _log.debug("Chain-to-assurance bridge failed: %s", e)

    except Exception as e:
        _log.debug("Chain/intent analysis failed: %s", e)

    # ── Assurance analysis (attackers, campaigns, fuzz) ─────────────────────
    if with_attackers or with_campaigns or with_fuzz:
        con.print()
        con.print("[bold #C8621A]─ Assurance Analysis ─[/bold #C8621A]")
        try:
            from patchi.core.assurance.graph import AssuranceGraph

            agraph = AssuranceGraph.load(r)
            if not agraph.claims:
                con.print(
                    "  [dim]No assurance graph found — run 'p scan' first to build one.[/dim]"
                )
            else:
                con.print(f"  [dim]Loaded assurance graph: {len(agraph.claims)} claims[/dim]")

                # ── Campaigns ────────────────────────────────────────────
                if with_campaigns:
                    from patchi.core.campaigns import CampaignOrchestrator

                    orch = CampaignOrchestrator(agraph)
                    campaign_result = orch.run_all()
                    con.print(f"  Campaigns: [bold]{len(campaign_result.campaigns)}[/bold] run")
                    for cr in campaign_result.campaigns:
                        status = (
                            "[green]PASS[/green]"
                            if cr.total_findings == 0
                            else f"[yellow]{cr.total_findings} findings[/yellow]"
                        )
                        con.print(f"    {cr.name}: {status}")
                        for step in cr.steps:
                            if step.findings:
                                for f in step.findings:
                                    sev = f.get("severity", "info")
                                    con.print(f"      [{sev}] {f.get('detail', '')[:80]}")

                # ── Attackers ────────────────────────────────────────────
                if with_attackers:
                    from patchi.core.attackers import AttackPlanner

                    planner = AttackPlanner(agraph)
                    attack_results = planner.run_all()
                    confirmed = [r for r in attack_results if r.confirmed]
                    con.print(
                        f"  Attackers: [bold]{len(attack_results)}[/bold] hypotheses tested, "
                        f"[bold]{len(confirmed)}[/bold] confirmed"
                    )
                    for r in confirmed[:10]:
                        con.print(f"    [red]●[/red] {r.hypothesis.attacker}: {r.evidence[:70]}")

                # ── Fuzz ─────────────────────────────────────────────────
                if with_fuzz:
                    from patchi.core.fuzz import InputFuzzer

                    fuzzer = InputFuzzer(seed=42)
                    # Fuzz route parameters
                    route_finds = 0
                    for claim in agraph.claims.values():
                        if "endpoint" in claim.domain:
                            route_finds += 1
                    con.print(f"  Fuzz: [bold]{route_finds}[/bold] endpoints available for fuzzing")
                    if route_finds > 0:
                        sample = fuzzer.fuzz_string("test", count=5)
                        con.print(f"    Generated {len(sample)} sample mutations")

        except Exception as e:
            import traceback

            con.print(f"  [red]Assurance analysis error: {e}[/red]")
            con.print(traceback.format_exc())

    # ── Red Team Engine (live attack simulation) ─────────────────────────────
    if red_team:
        con.print()
        con.print("[bold #C8621A]─ Red Team Engine ─[/bold #C8621A]")
        try:
            from patchi.core.security.red_team_engine import RedTeamEngine

            # Launcher-provided base_url first (config port, then dev ports)
            target_url = None
            try:
                from patchi.core.testing._browser import find_server

                target_url = find_server(r, {}, None)
            except Exception as exc:  # noqa: BLE001
                _log.debug("red-team target resolve failed: %s", exc)
            if target_url:
                con.print(f"  [dim]Target: {target_url} (detected running server)[/dim]")
            else:
                con.print("  [dim]No running web server detected — running code-only attacks[/dim]")

            engine = RedTeamEngine(
                root=r,
                target_url=target_url,
                safe_mode=True,
                on_progress=lambda msg: con.print(f"  [dim]{msg}[/dim]"),
            )
            import asyncio

            report = asyncio.run(
                engine.run_assessment(
                    scope="full",
                    intensity="standard",
                )
            )
            con.print(f"  Scenarios run: [bold]{len(report.scenarios_run)}[/bold]")
            con.print(f"  Findings: [bold]{report.total_findings}[/bold]")
            if report.by_severity:
                sev_str = ", ".join(f"{k}={v}" for k, v in sorted(report.by_severity.items()))
                con.print(f"  By severity: {sev_str}")
            if report.remediation_playbooks:
                con.print(f"  Playbooks: [bold]{len(report.remediation_playbooks)}[/bold]")

            # Auto-fix confirmed findings
            if report.total_findings > 0:
                con.print("\n  [dim]Generating fixes for confirmed findings...[/dim]")
                from patchi.core.security.auto_fixer import AutoFixer

                fixer = AutoFixer(
                    r, cfg.load(r), on_progress=lambda msg: con.print(f"  [dim]{msg}[/dim]")
                )
                for scenario in report.scenarios_run:
                    for finding in scenario.findings:
                        import asyncio

                        result = asyncio.run(
                            fixer.fix_finding(finding, strategy="auto", apply=False, verify=False)
                        )
                        if result.get("success"):
                            con.print(
                                f"    [green]Fixed[/green] {finding.type} → patch {result['patch_id']}"
                            )

        except Exception as e:
            import traceback

            con.print(f"  [red]Red team error: {e}[/red]")
            con.print(traceback.format_exc())

    # ── DAST (Dynamic Application Security Testing) ──────────────────────────
    # Part 3 linking: the old DastScanner module was deleted — this flag now
    # runs DASTAgent (the real implementation). P-Check gating applies: with
    # no serving app the agent idles with instructions instead of probing.
    if dast:
        con.print()
        con.print("[bold #C8621A]─ DAST Scanner ─[/bold #C8621A]")
        try:
            from patchi.core.agents.base import AgentInput
            from patchi.core.security.dast_agent import DASTAgent

            try:
                from patchi.core import config as _cfg_mod
                from patchi.core import memory as _mem_mod

                _dconfig = _cfg_mod.load(r)
            except Exception:
                _dconfig = {}
                _mem_mod = None
            _dbrain: dict = {}
            if _mem_mod is not None:
                try:
                    _dbrain = _mem_mod.get_brain(r) or {}
                except Exception:
                    _dbrain = {}
            _dres = DASTAgent().run(
                AgentInput(root=r, scope=[], brain=_dbrain, config=_dconfig)
            )
            if _dres.data.get("gate_blocked"):
                con.print(f"  [yellow]{_dres.data.get('gate_reason')}[/yellow]")
            else:
                con.print(f"  [dim]Target: {_dres.data.get('target_url', '?')}[/dim]")
                con.print(f"  Tests run: [bold]{_dres.data.get('tests_run', 0)}[/bold]")
                con.print(f"  Findings: [bold]{_dres.finding_count}[/bold]")

                if _dres.findings:
                    sev_counts = {}
                    for f in _dres.findings:
                        _sev = getattr(f.severity, "value", f.severity)
                        sev_counts[_sev] = sev_counts.get(_sev, 0) + 1
                    sev_str = ", ".join(f"{k}={v}" for k, v in sorted(sev_counts.items()))
                    con.print(f"  By severity: {sev_str}")
                    con.print()
                    for f in _dres.findings[:10]:
                        _sev = getattr(f.severity, "value", f.severity)
                        sev_color = {
                            "critical": "red",
                            "high": "red",
                            "medium": "yellow",
                            "low": "dim",
                        }.get(_sev, "dim")
                        con.print(
                            f"    [{sev_color}] [{_sev}] {f.type}: {(f.message or '')[:60]}[/{sev_color}]"
                        )
                else:
                    con.print("  [green]No security issues found.[/green]")

                if _dres.errors:
                    con.print(f"  [dim]Errors: {len(_dres.errors)}[/dim]")

        except Exception as e:
            import traceback

            con.print(f"  [red]DAST error: {e}[/red]")
            con.print(traceback.format_exc())

    # ── Domain enrichment (always runs) ────────────────────────────────────
    try:
        from patchi.core.security.domain_loader import DomainLoader
        # Use pre-loaded DomainLoader if available, else create new
        _dl = None
        if _domain_loader_future is not None:
            try:
                _dl = _domain_loader_future.result(timeout=0)
            except Exception as _exc:
                _log.debug('suppressed: %s', _exc)
        if _dl is None:
            _dl = DomainLoader(r, component_types=_ctypes if _ctypes else None)
        _SEC_AGENTS = {
            "EnvScanner", "SideFileScanner", "CoreScanner",
            "DependencyScanner", "RouteGraphScanner", "SBOMGeneratorAgent",
            "CommentScanner", "DeadCodeScanner", "DeadCodeHygieneAgent",
        }
        for _ar in (agent_results or []):
            _aname = getattr(_ar, "agent_name", "") or ""
            for _f in getattr(_ar, "findings", []):
                # Skip enrichment for agents that never produce security findings
                _fagent = getattr(_f, "agent", "") or _aname
                if _fagent not in _SEC_AGENTS:
                    continue
                _msg = getattr(_f, "message", "") or ""
                _file = getattr(_f, "file", "") or ""
                _type = getattr(_f, "type", "") or _fagent
                _ctrls = _dl.match_finding_to_controls(_type, _file, _msg)
                if _ctrls:
                    _f.extra["domain_controls"] = [
                        {"control_id": c.control_id, "name": c.name, "severity": c.severity}
                        for c in _ctrls[:5]
                    ]
                    _pb = _dl.get_playbook(_ctrls[0].control_id)
                    if _pb:
                        _f.extra["playbook_ref"] = _pb.control_id
                        _f.extra["fix_strategy"] = _pb.fix_strategy
    except Exception as _e:
        import logging
        logging.getLogger("patchi.scan").debug("Domain enrichment skipped: %s", _e)

    # ── Pipeline / defense mode ───────────────────────────────────────────────
    if pipeline:
        con.print()
        con.print("[bold #C8621A]─ Defense Pipeline ─[/bold #C8621A]")
        try:
            from patchi.core.security.defenders import ADAPTER_REGISTRY, DefenseAction, get_adapter
            from patchi.core.security.defense_layer import DefenseLayer
            from patchi.core.security.detection_pipeline import DetectionPipeline
            from patchi.core.security.orchestrator import SecurityOrchestrator

            con.print(f"  [dim]Adapter registry: {len(ADAPTER_REGISTRY)} adapters loaded[/dim]")

            sec_group_names = {a.name for a in list_agents(AgentGroup.SECURITY)}
            sec_group_names.update(
                {
                    "DependencyScanner",
                    "EnvScanner",
                    "SideFileScanner",
                }
            )
            sec_agents = [
                a for a in agent_results if getattr(a, "agent_name", "") in sec_group_names
            ]
            report_sec = SecurityOrchestrator().correlate(sec_agents)
            pipeline_inst = DetectionPipeline(r, cfg.load(r))
            gated = pipeline_inst.process(report_sec)
            con.print(
                f"  Findings gated: [bold]{len(gated.findings)}[/bold] "
                f"(defend={len(gated.defend)}, "
                f"ai_analyze={len(gated.ai_analyze)}, "
                f"human_review={len(gated.human_review)}, "
                f"discarded={len(gated.discarded)})"
            )
            noise_stats = gated.stats.get("noise")
            if noise_stats:
                cats = ", ".join(
                    f"{k}={v}" for k, v in sorted(noise_stats.get("by_category", {}).items())
                )
                con.print(
                    f"  Noise muted: [bold]{noise_stats.get('capped', 0)}[/bold] capped, "
                    f"[bold]{noise_stats.get('discarded', 0)}[/bold] discarded"
                    + (f" ({cats})" if cats else "")
                )
            if gated.defend:
                # Use adapter registry directly for each finding
                from patchi.core.fix.risk_gate import RiskGate

                risk_gate = RiskGate(r)
                results = []
                action_counts = {"applied": 0, "queued": 0, "blocked": 0, "skipped": 0}
                for gf in gated.defend:
                    f = gf.finding
                    ftype = f.type.lower()
                    # Map finding type to action type
                    action_type = None
                    for key, val in DefenseLayer._finding_to_action_map().items():
                        if key in ftype or ftype in key:
                            action_type = val
                            break
                    if action_type is None:
                        action_type = "escalate"

                    target = f.file
                    if action_type == "block_ip":
                        target = (
                            f.extra.get("ip", "")
                            if hasattr(f, "extra") and isinstance(f.extra, dict)
                            else ""
                        )

                    action = DefenseAction(
                        type=action_type,
                        target=target,
                        finding=f,
                        severity=f.severity.value
                        if hasattr(f.severity, "value")
                        else str(f.severity),
                        fix_code=f.suggestion or "",
                    )
                    adapter = get_adapter(action_type, root=r, risk_gate=risk_gate)
                    result = adapter.execute(action)
                    results.append(result)
                    action_counts[result.action] = action_counts.get(result.action, 0) + 1

                con.print(
                    f"  Defense actions: [bold]{action_counts['applied']}[/bold] applied, "
                    f"[bold]{action_counts['queued']}[/bold] queued, "
                    f"[bold]{action_counts['blocked']}[/bold] blocked, "
                    f"[bold]{action_counts['skipped']}[/bold] skipped"
                )
                for d in results:
                    if d.action == "applied":
                        adapter_name = type(d.defense_action).__name__ if d.defense_action else "?"
                        con.print(
                            f"    [green]✓[/green] {d.defense_action.type} → {d.defense_action.target} (via {adapter_name})"
                        )
                    elif d.action == "queued":
                        con.print(
                            f"    [yellow]⏳[/yellow] {d.defense_action.type} → queued for review"
                        )
            else:
                con.print("  [dim]No actionable defense findings.[/dim]")
        except Exception as e:
            import traceback

            con.print(f"  [red]Pipeline error: {e}[/red]")
            con.print(traceback.format_exc())

    # ── Daemon mode ───────────────────────────────────────────────────────────
    if daemon:
        con.print()
        con.print("[bold #C8621A]─ Scan Scheduler Daemon ─[/bold #C8621A]")
        try:
            from patchi.core.security.scheduler import ScanScheduler

            scheduler = ScanScheduler(r, cfg.load(r), on_result=lambda res: None)
            scheduler.start()
            if scheduler.is_running:
                con.print(
                    f"  [green]✓[/green] Scheduler started with {len(scheduler._agents)} security agents"
                )
                con.print(
                    f"  [dim]Default interval: {cfg.load(r).get('pipeline', {}).get('scheduler', {}).get('intervals', {}).get('default', '1h')}[/dim]"
                )
                con.print(
                    "  [dim]Use [bold]p hosted daemon[/bold] for production daemon mode[/dim]"
                )
            else:
                con.print(
                    "  [yellow]Scheduler not enabled (pipeline.scheduler.enabled=false)[/yellow]"
                )
        except Exception as e:
            import traceback

            con.print(f"  [red]Daemon error: {e}[/red]")
            con.print(traceback.format_exc())

    # ── Contract confirmation ─────────────────────────────────────────────────
    import sys

    is_interactive = sys.stdin.isatty() if hasattr(sys.stdin, "isatty") else False

    if contract and is_interactive and report.inferred_flows:
        _run_contract_confirmation(r, report, all_flows=all_flows)

    elif report.inferred_flows:
        # New flows inferred that aren't yet confirmed
        new_flows = [
            f for f in report.inferred_flows if f.id not in {cf.id for cf in report.confirmed_flows}
        ]
        if new_flows:
            con.print()
            con.print(
                f"[yellow]![/yellow] [dim]{len(new_flows)} new potential critical flow(s) found.[/dim]"
            )
            con.print("[dim]Run [bold]p scan --contract[/bold] to review and confirm.[/dim]")

    # ── Doc validation ────────────────────────────────────────────────────────
    dv = report.doc_validation or {}
    if dv.get("total_claims", 0) > 0:
        stale = len(dv.get("stale_claims", []))
        validated = len(dv.get("validated_claims", []))
        total = dv["total_claims"]
        doc_files = len(dv.get("doc_files_found", []))
        if stale > 0:
            con.print(
                f"[yellow]![/yellow] [dim]{stale}/{total} doc claim(s) stale — "
                f"docs say it but code doesn't have it[/dim]"
            )
        else:
            con.print(
                f"[dim]{validated}/{total} doc claim(s) verified across {doc_files} file(s)[/dim]"
            )

    # ── Health score ──────────────────────────────────────────────────────────
    health_score = None
    try:
        from patchi.core.health import compute as compute_health

        hs = compute_health(r)
        health_score = hs.total
        con.print()
        con.print(
            f"[bold {hs.color}]● Health: {hs.total}/100 ({hs.grade})[/bold {hs.color}]  "
            f"[dim]security {hs.security:.0f}  tests {hs.test_coverage:.0f}  "
            f"dead code {hs.dead_code:.0f}  deps {hs.dependency:.0f}  "
            f"contract {hs.contract:.0f}[/dim]"
        )
    except Exception as e:
        con.print(f"[dim]Health score unavailable: {e}[/dim]")

    # ── Auto-update BRAIN.md ──────────────────────────────────────────────────
    try:
        _brain_path = r / ".patchi" / "BRAIN.md"
        if _brain_path.exists():
            import time as _t
            if _t.time() - _brain_path.stat().st_mtime > 300:
                con.print("[dim]BRAIN.md is stale. Run p scan to regenerate.[/dim]")
    except Exception as e:
        con.print(f"[dim]BRAIN.md auto-update failed: {e}[/dim]")

    # ── JSON output ──────────────────────────────────────────────────────────
    if json_output:
        import json

        from patchi.core.agents.coordinator import merge_results

        merged = (
            merge_results(agent_results) if agent_results else {"findings": [], "total_findings": 0}
        )

        findings = []
        for f in merged["findings"]:
            entry = {
                "severity": f.get("severity", "info"),
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "message": f.get("message", ""),
                "agent": f.get("agent", ""),
            }
            # Include domain classification if present
            if f.get("domain_controls"):
                entry["domain_controls"] = f["domain_controls"]
            if f.get("playbook_ref"):
                entry["playbook_ref"] = f["playbook_ref"]
            if f.get("fix_strategy"):
                entry["fix_strategy"] = f["fix_strategy"]
            findings.append(entry)

        dead_files = [str(df) for df in (report.dead_files or [])]
        circular_deps = [cd.short_label for cd in (report.circular_dependencies or [])]
        languages = dict(report.language_breakdown) if report.language_breakdown else {}

        result = {
            "file_count": report.file_count,
            "route_count": report.route_count,
            "health_score": health_score,
            "findings": findings,
            "languages": languages,
            "dead_files": dead_files,
            "circular_deps": circular_deps,
        }
        con.print(json.dumps(result, indent=2))
        from patchi.core import ci_bundle as _ci

        return _ci.exit_code_for(findings, fail_on)

    # ── Exit-code contract: --fail-on gates CI (plain scan always 0) ──
    from patchi.core import ci_bundle as _ci

    _tail_dicts = [f.to_dict() for ar in (agent_results or []) for f in getattr(ar, "findings", [])]
    _exit = _ci.exit_code_for(_tail_dicts, fail_on)
    if fail_on:
        _n_fail = sum(
            1
            for f in _tail_dicts
            if _ci._SEV_ORDER.get(str(f.get("severity", "info")).lower(), 5)
            <= _ci._SEV_ORDER[fail_on.lower()]
        )
        con.print(
            f"[dim] --fail-on {fail_on}: {_n_fail}/{len(_tail_dicts)} findings "
            f"at/above threshold (exit {_exit})[/dim]"
        )
    con.print()
    return _exit


def _run_contract_review(root: Path, all_flows: bool = False) -> None:
    """Run contract review mode."""
    con.print("[bold #C8621A]Contract Review Mode[/bold #C8621A]")
    con.print()

    # Load brain data to get contract information
    brain_data = mem.get_brain(root)
    inferred_flows = brain_data.get("inferred_flows", [])
    confirmed_flows = brain_data.get("confirmed_flows", [])

    if not inferred_flows:
        con.print("[dim]No inferred contract flows found. Run a full scan first.[/dim]")
        return

    # Filter: when --all-flows, show everything; otherwise hide suggested
    if not all_flows:
        visible = [f for f in inferred_flows if not f.get("suggested", False)]
    else:
        visible = inferred_flows

    # Show unconfirmed flows for review
    confirmed_ids = {cf.get("id") for cf in confirmed_flows}
    unconfirmed_flows = [f for f in visible if f.get("id") not in confirmed_ids]
    hidden_count = len(inferred_flows) - len(visible)

    if not unconfirmed_flows:
        label = f"[green]✓[/green] All {len(visible)} contract flows confirmed!"
        if hidden_count:
            label += f" ({hidden_count} low-confidence flows hidden — use --all-flows to see)"
        con.print(label)
        return

    label = f"[yellow]Found {len(unconfirmed_flows)} unconfirmed flow(s) to review:[/yellow]"
    if hidden_count:
        label += f" [dim]({hidden_count} low-confidence hidden — use --all-flows to see all)[/dim]"
    con.print(label)

    for i, flow in enumerate(unconfirmed_flows, 1):
        conf = flow.get("confidence", "medium")
        conf_tag = ""
        if conf == "low":
            conf_tag = " [dim](low confidence)[/dim]"
        elif conf == "high":
            conf_tag = " [dim](high)[/dim]"
        con.print(f"  {i}. [bold]{flow.get('name', 'Unknown flow')}[/bold]{conf_tag}")
        con.print(f"     [dim]{flow.get('description', 'No description')}[/dim]")
        routes = flow.get("routes", [])
        if routes:
            con.print(f"     [dim]Routes: {', '.join(routes[:3])}[/dim]")

    con.print()
    con.print("[dim]Run a full scan to confirm these flows.[/dim]")


def _run_file_scan(root: Path, file_path: str, deep: bool = False) -> None:
    """Run deep analysis on a specific file."""
    con.print(f"[bold #C8621A]Deep analysis of {file_path}[/bold #C8621A]")

    file_abs_path = root / file_path
    if not file_abs_path.exists():
        con.print(f"[red]File does not exist: {file_path}[/red]")
        return

    if deep:  # Only do deep AI analysis when --deep flag is explicitly passed
        try:
            import patchi.core.config as config_mod
            from patchi.core.ai.client import call_ai
            from patchi.core.ai.prompts import SYSTEM_PROMPTS, Skill

            config = config_mod.load(root)
            content = file_abs_path.read_text(encoding="utf-8")
            lang = "python" if file_path.endswith(".py") else "javascript"

            system_prompt = SYSTEM_PROMPTS.get(Skill.DEEP_ANALYSIS, "You are a code analyst.")
            user_prompt = f"Analyse this {lang} file:\n\nFILE: {file_path}\n\n```\n{content[:6000]}\n```\n\nReturn a JSON object with: purpose, functions (with issues), issues (with line numbers), and architecture notes."

            result = call_ai(config, system_prompt, user_prompt, max_tokens=2000)
            if result:
                con.print(f"[#4ADE80]✓[/#4ADE80] AI analysis for {file_path}:")
                con.print()
                # Try to format JSON response
                import json

                try:
                    analysis = json.loads(
                        result.strip().removeprefix("```json").removesuffix("```").strip()
                    )
                    for key, val in analysis.items():
                        if isinstance(val, str):
                            con.print(f"  [bold]{key}:[/bold] {val}")
                        elif isinstance(val, list):
                            con.print(f"  [bold]{key}:[/bold]")
                            for item in val[:10]:
                                if isinstance(item, dict):
                                    line = item.get("line", "")
                                    name = item.get("name", item.get("function", ""))
                                    issue = item.get("issue", item.get("description", ""))
                                    con.print(
                                        f"    L{line} {name}: {issue}"
                                        if line
                                        else f"    {name}: {issue}"
                                    )
                                else:
                                    con.print(f"    {item}")
                except (json.JSONDecodeError, ValueError):
                    # Not JSON — print raw
                    for line in result.strip().splitlines()[:30]:
                        con.print(f"  {line}")
            else:
                con.print("[yellow]AI returned no response — showing file structure only.[/yellow]")
                lines = content.splitlines()
                con.print(
                    f"[dim]File has {len(lines)} lines · {file_abs_path.stat().st_size} bytes[/dim]"
                )

        except Exception as e:
            con.print(f"[red]Error analyzing file: {e}[/red]")
    else:
        con.print(f"[dim]Basic scan of {file_path}[/dim]")


def _run_deep_scan_analysis(root: Path, report: BrainReport, agent_results: list) -> None:
    """Run deep AI analysis on changed files since last deep scan."""
    try:
        import patchi.core.config as config_mod
        from patchi.core.ai.client import call_ai_structured
        from patchi.core.ai.prompts import Skill, build_prompt, get_system_prompt

        config = config_mod.load(root)

        # Quick AI availability check
        test = call_ai_structured(config, "Say OK", 'Reply with JSON: {"ok": true}')
        if test is None:
            con.print(
                "[yellow]No AI available — skipping deep analysis (run without --offline to use AI).[/yellow]"
            )
            return

        brain_data = mem.get_brain(root)
        last_hashes = brain_data.get("deep_scan_hashes", {})

        tokens_used = 0
        files_analyzed = 0
        findings: list[dict] = []

        source_exts = (".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb", ".php")
        all_files = [p for p in root.rglob("*") if p.suffix in source_exts]

        for file_path in all_files:
            rel_path = file_path.relative_to(root).as_posix()
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                _log.warning("_run_deep_scan_analysis failed: %s", e)
                continue

            current_hash = hashlib.sha256(content.encode()).hexdigest()
            if last_hashes.get(rel_path) == current_hash:
                continue

            con.print(f"[dim]Deep analyzing {rel_path}...[/dim]")

            system = get_system_prompt(Skill.DEEP_ANALYSIS)
            user_prompt = build_prompt(
                Skill.DEEP_ANALYSIS,
                {
                    "file_path": rel_path,
                    "file_content": content[:6000],
                    "language": rel_path.split(".")[-1],
                },
            )

            result = call_ai_structured(config, system, user_prompt, max_tokens=3000)
            if result is None:
                continue

            analysis_entry = {
                "file": rel_path,
                "hash": current_hash,
                "analysis": result,
            }
            brain_data.setdefault("deep_analyses", {})[rel_path] = analysis_entry
            last_hashes[rel_path] = current_hash

            tokens_used += len(content.split())
            files_analyzed += 1

            # Collect issues for the summary
            for issue in result.get("issues") or []:
                findings.append(
                    {
                        "file": rel_path,
                        "type": issue.get("type", "unknown"),
                        "severity": issue.get("severity", "low"),
                        "line": issue.get("line", 0),
                        "message": issue.get("description", ""),
                    }
                )

        # Persist
        brain_data["deep_scan_hashes"] = last_hashes
        mem.save_brain(brain_data, root)

        # Summary
        con.print(f"[dim]Deep scan: {files_analyzed} files analyzed, ~{tokens_used} tokens[/dim]")
        if findings:
            by_sev: dict[str, int] = {}
            for f in findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            parts = "  ".join(
                f"[{_SEV_COLORS.get(s, '#B8A898')}]{c} {s}[/{_SEV_COLORS.get(s, '#B8A898')}]"
                for s, c in sorted(by_sev.items())
            )
            con.print(f"[bold #F2EDD6]Deep Analysis Issues:[/bold #F2EDD6]  {parts}")
            for f in findings[:8]:
                loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
                con.print(f"  [dim]{loc}[/dim] — {f['message'][:100]}")

    except Exception as e:
        import traceback

        con.print(f"[red]Error during deep scan: {e}[/red]")
        con.print(f"[dim]{traceback.format_exc()}[/dim]")


_SEV_COLORS = {
    "critical": "#FF4D6D",
    "high": "#FF8C42",
    "medium": "#FACC15",
    "low": "#4ADE80",
    "info": "#B8A898",
}


def _show_report_summary(
    report: BrainReport,
    agent_results: list | None = None,
    wall_time: float | None = None,
    root: Path | None = None,
) -> None:
    """Print the post-scan results table."""
    if wall_time is not None:
        duration = f"{wall_time:.1f}s"
    else:
        duration = f"{report.duration_seconds:.1f}s"

    # Stats table
    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 3))
    table.add_column("Label", style="bold #F2EDD6", width=22)
    table.add_column("Value", style="#B8A898")

    table.add_row("Files scanned", str(report.file_count))

    if report.language_breakdown:
        lang_str = "  ".join(
            f"{lang}: {cnt}" for lang, cnt in list(report.language_breakdown.items())[:4]
        )
        table.add_row("Languages", lang_str)

    if report.stack and report.stack.frameworks:
        fw_str = ", ".join(f.name for f in report.stack.frameworks[:3])
        table.add_row("Framework", fw_str)

    table.add_row("Routes found", str(report.route_count))
    table.add_row(
        "Import graph", f"{len(report.import_graph.nodes)} nodes" if report.import_graph else "—"
    )

    if report.circular_dependencies:
        circ_text = Text(f"{len(report.circular_dependencies)} circular deps found", style="yellow")
        table.add_row("Circular deps", circ_text)
    else:
        table.add_row("Circular deps", Text("None ✓", style="#4ADE80"))

    if report.dead_files:
        dead_text = Text(f"{len(report.dead_files)} unreachable files", style="dim")
        table.add_row("Dead code", dead_text)
    else:
        table.add_row("Dead code", Text("None found ✓", style="#4ADE80"))

    if report.errors:
        err_text = Text(f"{len(report.errors)} parse error(s)", style="yellow")
        table.add_row("Parse errors", err_text)

    table.add_row("Scan duration", duration)

    con.print(
        Panel(
            table,
            title="[bold #C8621A]Brain Scan Complete[/bold #C8621A]",
            border_style="#2A3D28",
        )
    )

    # Circular dep details
    if report.circular_dependencies:
        con.print()
        con.print("[yellow]Circular dependencies:[/yellow]")
        for cd in report.circular_dependencies[:5]:
            con.print(f"  [dim]→[/dim] {cd.short_label}")
        if len(report.circular_dependencies) > 5:
            con.print(f"  [dim]… and {len(report.circular_dependencies) - 5} more[/dim]")

    # Dead files
    if report.dead_files:
        con.print()
        con.print(f"[dim]Dead files ({len(report.dead_files)}):[/dim]")
        for df in report.dead_files[:8]:
            con.print(f"  [dim]○ {df}[/dim]")
        if len(report.dead_files) > 8:
            con.print(f"  [dim]… and {len(report.dead_files) - 8} more[/dim]")

    # Agent findings summary
    if agent_results:
        _show_agent_findings_summary(agent_results, root=root)


def _show_agent_findings_summary(agent_results: list, root: Path | None = None) -> None:
    """Show a condensed findings table from all scanner agents.

    Headline counts run through the NoiseFilter first: findings from
    tests/lockfiles/generated/docs are severity-caps (or discarded) so
    the summary reflects signal, not fixture noise.

    Noisy scanners (TypeScanner, DeadCodeScanner, TestScanner, UIScanner,
    ContractDiff) produce thousands of low-value medium/low/info findings
    that drown real issues. Their findings are stored in memory for
    drill-down but excluded from the summary table by default.
    (DuplicateScanner was deleted — function-level clone detection never
    produced signal worth its noise.)
    """
    from patchi.core.agents.coordinator import merge_results

    merged = merge_results(agent_results)
    findings = merged["findings"]

    # Noise filter (non-fatal): cap or drop fixture/lockfile/bundle noise
    noise_line = ""
    if root is not None:
        try:
            from patchi.core.security.noise_filter import NoiseFilter

            try:
                config = cfg.load(root)
            except Exception:  # noqa: BLE001 — config optional for filtering
                config = None
            nf = NoiseFilter(root, config if isinstance(config, dict) else None)
            if nf.enabled and findings:
                kept, nfr = nf.apply(findings)
                if nfr.capped or nfr.discarded:
                    cats = ", ".join(
                        f"{k}={v}" for k, v in sorted(nfr.to_dict()["by_category"].items())
                    )
                    noise_line = (
                        f"  [dim]Noise muted: {nfr.capped} capped, "
                        f"{nfr.discarded} discarded" + (f" ({cats})" if cats else "") + "[/dim]"
                    )
                findings = kept
        except Exception as _exc:  # noqa: BLE001 — display must never crash on filter bugs
            _log.warning('_show_agent_findings_summary failed: %s', _exc)

    # ── Suppress noisy scanner medium/low/info findings ──────────────────
    # These agents produce thousands of low-value findings. Keep their
    # data in memory for `p findings --json` but exclude from the summary.
    _NOISY_AGENTS = {
        "TypeScanner", "DeadCodeScanner", "TestScanner",
        "UIScanner", "ContractDiff", "RefactoringAgent", "DeadCodeHygieneAgent",
        "SideFileScanner", "CommentScanner", "CoreScanner",
    }
    _suppressed = 0
    _kept_findings = []
    for f in findings:
        agent = f.get("agent", "")
        sev = f.get("severity", "info")
        # Only suppress low-value (medium/low/info) from noisy agents
        # Keep high/critical from ALL agents always
        if agent in _NOISY_AGENTS and sev in ("medium", "low", "info"):
            _suppressed += 1
            continue
        _kept_findings.append(f)
    findings = _kept_findings
    if _suppressed:
        noise_line = (
            (noise_line + "  " if noise_line else "  ")
            + f"[dim]Suppressed {_suppressed} low-value findings from noisy scanners[/dim]"
        )

    merged["findings"] = findings
    total = len(findings)

    if total == 0:
        con.print()
        con.print(Text("✓ No issues found by scanner agents.", style="#4ADE80"))
        if noise_line:
            con.print(noise_line)
        return

    # Count by severity
    by_sev: dict[str, int] = {}
    for f in merged["findings"]:
        sev = f.get("severity", "info")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    con.print()
    # Show severity summary — only high/critical by default (the rest are noise)
    _ALL_SEVS = ("critical", "high", "medium", "low", "info")
    _ACTIONABLE_SEVS = ("critical", "high")
    _COLORS = {
        "critical": "#FF4D6D",
        "high": "#FF8C42",
        "medium": "#FACC15",
        "low": "#4ADE80",
        "info": "#B8A898",
    }
    _actionable = [(sev, by_sev.get(sev, 0)) for sev in _ACTIONABLE_SEVS if by_sev.get(sev, 0)]
    _noise = [(sev, by_sev.get(sev, 0)) for sev in _ALL_SEVS[2:] if by_sev.get(sev, 0)]

    sev_parts: list[str] = []
    for sev, count in _actionable:
        sev_parts.append(f"[{_COLORS[sev]}]{count} {sev}[/{_COLORS[sev]}]")
    # Dim the rest — they're noise
    if _noise:
        noise_counts = " + ".join(f"{count} {sev}" for sev, count in _noise)
        sev_parts.append(f"[dim]{noise_counts}[/dim]")

    sev_str = "  ".join(sev_parts)
    con.print(f"[bold #F2EDD6]Agent Findings:[/bold #F2EDD6]  {sev_str}")
    if noise_line:
        con.print(noise_line)

    # Show agent-by-agent summary (hide noisy scanners, show only useful agents)
    con.print()
    table = Table(show_header=True, header_style="dim", box=None, pad_edge=False)
    table.add_column("Agent", style="bold #F2EDD6", width=26)
    table.add_column("Findings", justify="right", width=10)
    table.add_column("Status", width=10)
    table.add_column("ms", justify="right", width=8)

    _NOISY_AGENTS_TABLE = {
        "TypeScanner", "DeadCodeScanner", "TestScanner",
        "UIScanner", "ContractDiff", "RefactoringAgent", "DeadCodeHygieneAgent",
        "SideFileScanner", "CommentScanner", "CoreScanner",
    }
    for r in sorted(agent_results, key=lambda x: -x.finding_count):
        # Skip noisy agents with 0 findings after filtering
        if r.agent_name in _NOISY_AGENTS_TABLE and (r.finding_count or 0) == 0:
            continue
        status_colors = {
            "done": "#4ADE80",
            "failed": "#FF4D6D",
            "skipped": "dim",
            "running": "#C8621A",
        }
        color = status_colors.get(r.status.value, "dim")
        # Dim the noisy agents' finding counts
        finding_style = "dim" if r.agent_name in _NOISY_AGENTS_TABLE else ""
        ftext = Text(str(r.finding_count) if r.finding_count else "—", style=finding_style)
        table.add_row(
            r.agent_name,
            ftext,
            Text(r.status.value, style=color),
            str(r.duration_ms),
        )

    con.print(table)

    # Show top critical/high findings
    top = [f for f in merged["findings"] if f.get("severity") in ("critical", "high")][:5]
    if top:
        con.print()
        con.print("[bold #FF4D6D]Critical / High findings:[/bold #FF4D6D]")
        for f in top:
            sev = f.get("severity", "info")
            color = "#FF4D6D" if sev == "critical" else "#FF8C42"
            fpath = f.get("file", "")
            line = f.get("line", 0)
            loc = f"{fpath}:{line}" if line else fpath
            con.print(f"  [{color}]●[/{color}] [dim]{loc}[/dim]")
            con.print(f"    {f.get('message', '')[:80]}")


def _run_contract_confirmation(root: Path, report: BrainReport, all_flows: bool = False) -> None:
    """Interactive contract confirmation flow."""
    from rich.prompt import Confirm, Prompt

    from patchi.core.brain.contract import ContractBuilder, confirm_flows

    builder = ContractBuilder(
        report.routes, report.file_infos, report.dead_files, report.circular_dependencies
    )

    # Filter flows: hide suggested unless --all-flows
    shown_flows = report.inferred_flows
    hidden_count = 0
    if not all_flows:
        shown_flows = [f for f in report.inferred_flows if not f.suggested]
        hidden_count = len(report.inferred_flows) - len(shown_flows)

    msg = builder.build_confirmation_message(shown_flows, all_flows=all_flows)

    con.print()
    sub = (
        f" ({hidden_count} low-confidence flows hidden — use --all-flows to see)"
        if hidden_count
        else ""
    )
    con.print(
        Panel(
            f"[bold #F2EDD6]App Contract[/bold #F2EDD6]\n\n[dim]{msg}[/dim]{sub}",
            border_style="#C8621A",
        )
    )
    con.print()

    # Show each inferred flow and ask Y/N
    confirmed_ids: set[str] = set()
    for flow in shown_flows:
        conf_tag = ""
        if flow.confidence == "high":
            conf_tag = " [dim](high confidence)[/dim]"
        elif flow.confidence == "low":
            conf_tag = " [dim](low confidence)[/dim]"
        con.print(f"  [bold]{flow.name}[/bold]{conf_tag}  [dim]{flow.description}[/dim]")
        if flow.routes:
            route_str = ", ".join(flow.routes[:3])
            con.print(f"  [dim]Routes: {route_str}[/dim]")
        yn = Confirm.ask(f"  Include [bold]{flow.name}[/bold] in contract?", default=True)
        if yn:
            confirmed_ids.add(flow.id)
        con.print()

    # Any additional flows?
    user_flows: list[dict] = []
    if Confirm.ask("Add any flows I didn't detect?", default=False):
        while True:
            name = Prompt.ask("  Flow name (or Enter to finish)")
            if not name:
                break
            desc = Prompt.ask("  One-sentence description")
            user_flows.append({"name": name, "description": desc})

    confirmed = confirm_flows(report.inferred_flows, confirmed_ids, user_flows)

    # Save to brain memory
    brain_mem = mem.get_brain(root)
    brain_mem["confirmed_flows"] = [f.to_dict() for f in confirmed]
    brain_mem["contract_locked"] = True  # p fix checks this before running
    mem.save_brain(brain_mem, root)

    con.print()
    con.print(
        f"[#4ADE80]✓[/#4ADE80] App contract locked: "
        f"[bold]{len(confirmed)}[/bold] flow(s) protected."
    )
    con.print("[dim]Every fix will check against this contract before applying.[/dim]")


def _show_changed_dry_run(root: Path, commits: int) -> None:
    """Show what --changed would activate without actually scanning."""
    from patchi.core.security.domain_activator_v2 import DomainActivatorV2
    from patchi.core.security.git_diff_activator import activate_from_diff

    con.print()
    con.print("[bold #C8621A]── Changed Dry-Run ──[/bold #C8621A]")
    con.print()

    # 1. Show changed files
    diff_result = activate_from_diff(root, commits=commits)
    if diff_result.error:
        con.print(f"  [yellow]{diff_result.error}[/yellow]")
        return

    con.print(
        f"  [bold]Changed files:[/bold] {len(diff_result.changed_files)} (from last {commits} commit{'s' if commits > 1 else ''})"
    )
    con.print()

    # Group changed files by extension
    ext_groups: dict[str, list[str]] = {}
    for fp in diff_result.changed_files:
        ext = Path(fp).suffix or "(no ext)"
        ext_groups.setdefault(ext, []).append(fp)
    for ext in sorted(ext_groups, key=lambda e: -len(ext_groups[e])):
        con.print(f"    [dim]{ext}:[/dim] {len(ext_groups[ext])} files")
    con.print()

    # 2. Show activated domains
    if diff_result.activated_domains:
        con.print(f"  [bold]Activated domains:[/bold] {len(diff_result.activated_domains)}")
        con.print()
        table = Table(show_header=True, header_style="bold #C8621A", box=None)
        table.add_column("Domain")
        table.add_column("Score", justify="right")
        table.add_column("Agents", style="dim")
        for domain, score in sorted(diff_result.activated_domains.items(), key=lambda x: -x[1]):
            try:
                activator = DomainActivatorV2(root)
                agents = activator.get_relevant_agents([domain])
                agent_str = ", ".join(agents[:4])
                if len(agents) > 4:
                    agent_str += f" +{len(agents) - 4}"
            except Exception:
                agent_str = "(unknown)"
            score_color = "red" if score >= 0.8 else "yellow" if score >= 0.5 else "dim"
            table.add_row(domain, f"[{score_color}]{score:.1f}[/{score_color}]", agent_str)
        con.print(table)
    else:
        con.print("  [dim]No domain-relevant changes detected.[/dim]")
    con.print()

    # 3. Show total agent count
    from patchi.core.agents.base import list_agents as _la
    all_scanner_agents = _la(AgentGroup.SCANNER)
    if diff_result.activated_domains:
        try:
            activator = DomainActivatorV2(root)
            relevant = activator.get_relevant_agents(list(diff_result.activated_domains.keys()))
            relevant.extend(["PreCheckAgent", "PlanAuditorAgent"])
            relevant = list(dict.fromkeys(relevant))  # dedupe preserving order
            would_run = [a for a in all_scanner_agents if getattr(a, "name", "") in relevant]
            skipped = len(all_scanner_agents) - len(would_run)
            con.print(
                f"  [bold]Would run:[/bold] {len(would_run)} agents [dim](skipping {skipped})[/dim]"
            )
            con.print()
            con.print("  [dim]Run without --dry-run to execute the scan.[/dim]")
        except Exception:
            con.print(
                f"  [dim]Would run all {len(all_scanner_agents)} agents (activation failed)[/dim]"
            )
    else:
        con.print(f"  [dim]Would run all {len(all_scanner_agents)} agents (no diff match)[/dim]")
    con.print()


def _show_dry_run(root: Path, area: str | None) -> None:
    """Show what would be scanned without actually scanning."""
    from patchi.core import config as cfg
    from patchi.core.brain.scanner import FileScanner

    try:
        config = cfg.load(root)
    except Exception as e:
        con.print(f"[dim]Config load error: {e}[/dim]")
        config = {}

    scanner = FileScanner(
        root=root,
        ignore_paths=config.get("ignore_paths", []),
    )
    paths = scanner.discover(area)

    con.print()
    con.print(f"[dim]--dry-run: would scan {len(paths)} files[/dim]")
    con.print()

    from patchi.core.brain.languages import detect_language

    by_lang: dict = {}
    for p in paths:
        lang = detect_language(p).value
        by_lang[lang] = by_lang.get(lang, 0) + 1

    table = Table(show_header=True, header_style="bold #C8621A", box=None)
    table.add_column("Language")
    table.add_column("Files", justify="right")
    for lang, count in sorted(by_lang.items(), key=lambda x: x[1], reverse=True):
        table.add_row(lang, str(count))
    con.print(table)
    con.print()


def _show_summary_from_memory(root: Path) -> None:
    """Show last scan summary from brain memory."""
    brain = mem.get_brain(root)
    if not brain:
        return
    con.print(
        f"[dim]Last scan:[/dim] {brain.get('file_count', '?')} files · "
        f"{brain.get('route_count', '?')} routes · "
        f"{brain.get('framework', '?')} detected"
    )
    con.print()


def _build_progress() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=24),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        transient=False,
    )


def _fmt_time(iso: str) -> str:
    """Format ISO timestamp as human-readable."""
    try:
        from datetime import datetime

        dt = datetime.fromisoformat(iso)
        now = datetime.now(UTC)
        diff = now - dt
        secs = diff.total_seconds()
        if secs < 60:
            return "just now"
        if secs < 3600:
            return f"{int(secs // 60)}m ago"
        if secs < 86400:
            return f"{int(secs // 3600)}h ago"
        return f"{int(secs // 86400)}d ago"
    except Exception as e:
        _log.warning("_fmt_time failed: %s", e)
        return iso
