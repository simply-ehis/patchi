"""
`p fix` — Propose and apply fixes for all detected issues.

Usage:
  p fix                  — fix entire project
  p fix src/auth         — fix specific area
  p fix --dry-run        — preview what would be fixed, touch nothing
  p fix --safe-all       — apply every non-blocked patch, not just AUTO

Flow:
  1. Check contract_locked (hard block if not confirmed)
  2. Load findings from last scan (from memory)
  3. Run relevant fix agents (sequentially — spec mandates non-parallel)
  4. Collect proposed patches
  5. For each patch: run through risk gate
     - BLOCK        → skip, explain why
     - AUTO         → apply immediately (AUTO/AUTOPILOT mode, low risk)
     - REQUIRE_REVIEW → queue for `p review`
  6. Show summary: applied / queued / blocked
"""

from __future__ import annotations

from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.cli.display.live_progress import LiveProgress
from patchi.core import memory as mem
from patchi.core.config import require_project_root
from patchi.core.fix.applier import PatchApplier
from patchi.core.fix.patch import Patch, PatchState
from patchi.core.fix.risk_gate import RiskGate
from patchi.core.fix.verify_loop import run_verify_loop, should_flag_for_review


def run(
    area: str | None = None,
    dry_run: bool = False,
    preview: bool = False,
    safe_all: bool = False,
    root: Path | None = None,
) -> None:
    """Entry point for `p fix [area]`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # ── 1. Contract lock check ─────────────────────────────────────────────────
    brain = mem.get_brain(r)
    if not brain.get("contract_locked"):
        con.print()
        con.print(
            Panel(
                "[bold yellow]App contract not yet formed.[/bold yellow]\n\n"
                "[dim]Run [bold]p scan[/bold] first to understand your project,\n"
                "then [bold]p fix[/bold] will work automatically.[/dim]\n",
                border_style="yellow",
            )
        )
        con.print()
        return

    # ── 2. Load findings from last scan ───────────────────────────────────────
    scan_results = mem.get_scan_results(r)
    all_findings = _collect_findings(scan_results, area)

    # Annotate findings with framework info for multi-framework awareness
    _annotate_findings_with_framework(all_findings, brain)

    if not all_findings:
        con.print()
        con.print("[dim]No findings from last scan. Run [bold]p scan[/bold] first.[/dim]")
        con.print()
        return

    fixable = [f for f in all_findings if f.get("fix_agent")]
    if not fixable:
        con.print()
        con.print("[#4ADE80]✓[/#4ADE80] [dim]No fixable issues found.[/dim]")
        con.print()
        return

    con.print()
    area_label = f" [dim]→ {area}[/dim]" if area else ""
    con.print(
        f"[bold #C8621A]Fixing{area_label}[/bold #C8621A]  "
        f"[dim]{len(fixable)} fixable finding(s)[/dim]"
    )
    con.print()

    if dry_run or preview:
        _show_dry_run(fixable, r, preview=preview)
        return

    # ── 3. Run fix agents sequentially ────────────────────────────────────────
    from patchi.cli.ux import format_step, status_icon, status_style

    fix_phases = [
        "Finding analysis",
        "Fix agent execution",
        "Risk gate evaluation",
        "Patch application",
    ]
    total_steps = len(fix_phases)
    current_step = 0

    def show_fix_step(step_name: str, status: str = "running"):
        nonlocal current_step
        current_step += 1
        icon = status_icon(status)
        style = status_style(status)
        con.print(format_step(current_step, total_steps, f"[{style}]{icon} {step_name}[/{style}]"))

    show_fix_step("Finding analysis", "done")
    show_fix_step("Fix agent execution")

    patches = _run_fix_agents(fixable, r)

    if not patches:
        show_fix_step("Fix agent execution", "failed")
        con.print("[dim]Fix agents produced no patches.[/dim]")
        con.print(
            "[dim]This may be because no AI key is configured. "
            "Run [bold]p key add[/bold] to add one.[/dim]"
        )
        con.print()
        return

    show_fix_step("Fix agent execution", "done")
    show_fix_step("Risk gate evaluation")

    # ── 4. Risk gate + apply/queue ────────────────────────────────────────────
    gate = RiskGate(r)
    applier = PatchApplier(r)

    try:
        from patchi.core import config as cfg

        config = cfg.load(r)
    except Exception as e:
        con.print(f"[dim]Config load warning: {e}[/dim]")
        config = {}
    brain = mem.get_brain(r)

    # Sort patches by blast radius (smallest first) to minimize risk
    patches.sort(key=lambda p: p.blast_radius or 0)

    applied: list[Patch] = []
    queued: list[Patch] = []
    blocked: list[tuple[Patch, str]] = []

    for patch in patches:
        # Test-weakening guard: a fix that only changes test files must go to
        # human review, never auto-apply — flag it before the gate so even
        # AUTOPILOT mode queues it.
        if should_flag_for_review(patch):
            patch.requires_review = True

        gate_result = gate.evaluate(patch)

        if gate_result.is_blocked:
            blocked.append((patch, gate_result.reason))
            continue

        # --safe-all: apply everything the gate didn't block, except
        # test-weakening edits (requires_review set above) which still queue.
        if gate_result.is_auto or (
            safe_all and gate_result.needs_review and not patch.requires_review
        ):
            if (patch.source_finding or {}).get("type") == "test_failure":
                # fix → verify → retry loop: apply, re-run the failing test,
                # feed the failure back (up to 2 retries), never weaken tests.
                outcome = run_verify_loop(
                    patch,
                    root=r,
                    config=config,
                    brain=brain,
                    applier=applier,
                    log=lambda msg: con.print(f"[dim]{msg}[/dim]"),
                )
                if outcome.review_required:
                    patch.state = PatchState.PENDING
                    _save_patch(outcome.patch or patch, r)
                    queued.append(outcome.patch or patch)
                    con.print(
                        f"[yellow]⚠[/yellow] Patch {patch.id} only changes test file(s) — "
                        "queued for human review (test-weakening edits are never "
                        "auto-applied)."
                    )
                elif outcome.applied:
                    applied.append(outcome.patch or patch)
                    if outcome.verified:
                        con.print(
                            f"[#4ADE80]✓[/#4ADE80] Patch {patch.id} verified — failing test passes."
                        )
                    else:
                        con.print(
                            f"[yellow]⚠[/yellow] Patch {patch.id} applied but could not "
                            f"be re-verified: {outcome.reason}"
                        )
                else:
                    con.print(
                        f"[yellow]⚠[/yellow] Patch {patch.id} not applied after "
                        f"{outcome.retries_used} retr{'y' if outcome.retries_used == 1 else 'ies'} — "
                        f"rolled back. {outcome.reason}"
                    )
            else:
                # Save patch to memory first
                _save_patch(patch, r)
                result = applier.apply(patch)
                if result.success:
                    applied.append(patch)
                else:
                    con.print(
                        f"[yellow]⚠[/yellow] Patch {patch.id} applied but tests failed — "
                        f"rolled back. {result.error}"
                    )
        else:
            # Queue for review
            patch.state = PatchState.PENDING
            _save_patch(patch, r)
            queued.append(patch)

    # ── 5. Record fix patterns for learning ───────────────────────────────────
    try:
        from patchi.core.brain.learning import record_fix_pattern

        for patch in applied:
            if patch.findings:
                finding_type = patch.findings[0].get("type", "unknown")
                file_pattern = patch.findings[0].get("file", "")
                record_fix_pattern(
                    finding_type=finding_type,
                    file_pattern=file_pattern,
                    fix_strategy=patch.strategy,
                    fix_summary=patch.message[:200],
                    root=r,
                )
    except Exception as e:
        con.print(f"[dim]Could not record fix pattern: {e}[/dim]")

    show_fix_step("Risk gate evaluation", "done")
    show_fix_step("Patch application", "done")

    # ── 6. Summary ────────────────────────────────────────────────────────────
    _show_summary(applied, queued, blocked)

    # ── 7. Interactive review prompt ──────────────────────────────────────────
    if queued and not dry_run:
        from patchi.cli.ux import confirm
        con.print()
        if confirm("Review queued patches interactively?", default=False):
            from patchi.cli.commands.fix_review_cmd import run as review_run
            review_run(root=r)


# ── Fix agents runner ──────────────────────────────────────────────────────────


def _run_fix_agents(findings: list[dict], root: Path) -> list[Patch]:
    """Run relevant fix agents sequentially. Returns all proposed patches."""
    import patchi.core.fix.fix_agents  # noqa: F401 — trigger registration
    from patchi.core import config as cfg
    from patchi.core.agents.base import AgentGroup, AgentInput, list_agents

    try:
        config = cfg.load(root)
    except Exception as e:
        con.print(f"[dim]Config load warning: {e}[/dim]")
        config = {}

    brain = mem.get_brain(root)

    # Load brain report to include blast radius information
    brain_report = None
    try:
        brain_data = mem.get_brain(root)
        brain_report = type(
            "BrainReport",
            (),
            {
                "blast_radius_map": brain_data.get("blast_radius_map", {}),
                "routes": brain_data.get("routes", []),
                "file_infos": brain_data.get("file_infos", []),
            },
        )()
    except Exception as e:
        con.print(f"[dim]Could not build brain report: {e}[/dim]")
        brain_report = None

    # Build import graph for fix context
    import_graph = None
    try:
        from patchi.core.brain.import_graph import build_import_graph

        import_graph = build_import_graph(root)
        # Enrich each finding with import graph context
        for f in findings:
            fpath = f.get("file", "")
            if fpath and import_graph and fpath in import_graph.nodes:
                f["import_context"] = import_graph.format_fix_context(fpath)
                f["transitive_dependents"] = list(import_graph.get_transitive_dependents(fpath))
    except Exception as e:
        con.print(f"[dim]Import graph enrichment error: {e}[/dim]")

    inp = AgentInput(
        root=root,
        scope=[],
        brain=brain,
        config=config,
        extra={"findings": findings, "brain_report": brain_report}
        if brain_report
        else {"findings": findings},
    )

    fix_agent_classes = list_agents(AgentGroup.FIX)
    all_patches: list[Patch] = []

    lp = LiveProgress(con, title="Fix")
    lp.start()
    for agent_cls in fix_agent_classes:
        # Only run agents that have relevant findings
        relevant = [f for f in findings if f.get("fix_agent") == agent_cls.name]
        if not relevant and agent_cls.name not in ("EnvFixer",):
            continue

        short_name = agent_cls.name.replace("Agent", "").replace("Fixer", "")
        lp.set_progress(len(all_patches) + 1, len(fix_agent_classes), short_name)
        lp.log(f"  {short_name}…")
        lp.update()

        def ai_progress(msg: str):
            lp.log(f"    [dim]{msg}[/dim]", "dim")
            lp.update()

        inp_with_cb = AgentInput(
            root=inp.root,
            scope=inp.scope,
            brain=inp.brain,
            config=inp.config,
            extra=inp.extra,
            on_message=lambda n, msg, s: (lp.log(f"    {msg}", s), lp.update()),
            on_ai_progress=ai_progress,
        )
        result = agent_cls().run(inp_with_cb)
        patch_count = len(result.data.get("patches", []))
        lp.log(f"  [{patch_count}] patches from {short_name}", "")

        # Extract patches from result
        for patch_dict in result.data.get("patches", []):
            try:
                patch = Patch.from_dict(patch_dict)
                all_patches.append(patch)
            except Exception as e:
                lp.log(f"  [dim]Skipping invalid patch: {e}[/dim]", "dim")

        lp.update()

    lp.stop(summary=f"{len(all_patches)} patch(es) from {len(fix_agent_classes)} agent(s)")
    return all_patches


# ── Dry run display ────────────────────────────────────────────────────────────


def _show_dry_run(findings: list[dict], root: Path, preview: bool = False) -> None:
    """Show what would be fixed without doing anything.

    If preview=True, also show the actual before/after code diff for each patch.
    """
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Fix Agent", style="bold #F2EDD6", width=20)
    table.add_column("File", style="dim", width=34)
    table.add_column("Issue", width=40)
    table.add_column("Sev", width=8)

    sev_colors = {
        "critical": "#FF4D6D",
        "high": "#FF8C42",
        "medium": "#FACC15",
        "low": "#4ADE80",
        "info": "dim",
    }
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.get("severity", "info"), 99)):
        sev = f.get("severity", "info")
        table.add_row(
            f.get("fix_agent", "?"),
            f.get("file", "?")[:34],
            f.get("message", "?")[:40],
            Text(sev, style=sev_colors.get(sev, "white")),
        )

    con.print(
        Panel(
            table,
            title="[bold #C8621A]--dry-run: Would fix[/bold #C8621A]",
            border_style="#2A3D28",
        )
    )
    con.print()
    con.print(f"[dim]{len(findings)} finding(s) would be sent to fix agents.[/dim]")

    # Run fix agents to generate proposed patches (without applying)
    patches = _run_fix_agents(findings, root)

    if patches:
        gate = RiskGate(root)
        con.print()
        risk_table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
        risk_table.add_column("File", style="dim", width=34)
        risk_table.add_column("Risk", justify="right", width=8)
        risk_table.add_column("Confidence", justify="right", width=10)
        risk_table.add_column("Action", width=16)
        risk_table.add_column("Description", width=40)

        files_changed: set[str] = set()
        for patch in sorted(patches, key=lambda p: p.blast_radius or 0):
            gate_result = gate.evaluate(patch)
            action = (
                "BLOCKED"
                if gate_result.is_blocked
                else ("AUTO-APPLY" if gate_result.is_auto else "QUEUE")
            )
            action_color = (
                "#FF4D6D"
                if gate_result.is_blocked
                else ("#4ADE80" if gate_result.is_auto else "#FACC15")
            )
            for fp in patch.affected_paths:
                files_changed.add(fp)
            file_label = patch.affected_paths[0] if patch.affected_paths else "(multiple)"
            risk_table.add_row(
                file_label[:34],
                f"{patch.risk_score:.0f}",
                f"{patch.confidence:.0f}%",
                Text(action, style=action_color),
                (patch.description or "")[:40],
            )

        con.print(
            Panel(
                risk_table,
                title="[bold #C8621A]--dry-run: Proposed patches[/bold #C8621A]",
                border_style="#2A3D28",
            )
        )
        con.print()
        con.print(
            f"[dim]{len(patches)} patch(es) across {len(files_changed)} file(s) would be generated.[/dim]"
        )
    else:
        con.print("[dim]No patches would be generated by fix agents.[/dim]")

    # --preview: show before/after code diffs
    if preview and patches:
        _show_preview_diffs(patches, root)

    hint = "Remove --preview or --dry-run to apply fixes."
    con.print(f"[dim]{hint}[/dim]")
    con.print()


# ── Preview Diffs ──────────────────────────────────────────────────────────────


def _show_preview_diffs(patches: list[Patch], root: Path) -> None:
    """Show before/after code diffs for each proposed patch."""
    con.print()
    con.print("[bold #C8621A]── Preview: Before / After ──[/bold #C8621A]")
    con.print()

    for i, patch in enumerate(patches, 1):
        file_label = patch.affected_paths[0] if patch.affected_paths else "(unknown)"
        con.print(
            f"[bold]#{i} {file_label}[/bold]  "
            f"[dim]{patch.description[:60] if patch.description else ''}[/dim]"
        )

        # Try to read the current file content and show relevant lines
        for change in (patch.changes or []):
            file_path = change.get("path", "")
            if not file_path:
                continue

            full_path = root / file_path
            if not full_path.is_file():
                continue

            # Get line range from the change
            start_line = change.get("line_start", change.get("line", 0))
            end_line = change.get("line_end", start_line)
            new_content = change.get("content", change.get("new_content", ""))

            if not new_content and not start_line:
                continue

            try:
                lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue

            # Show context: 3 lines before, the changed area, 3 lines after
            ctx_start = max(0, (start_line or 1) - 4)
            ctx_end = min(len(lines), (end_line or start_line or len(lines)) + 3)

            if start_line and end_line:
                # Show the diff
                con.print(f"  [dim]Lines {start_line}-{end_line}:[/dim]")
                for ln in range(ctx_start, ctx_end):
                    line_num = ln + 1
                    marker = "-" if start_line <= line_num <= end_line else " "
                    color = "red" if marker == "-" else "dim"
                    con.print(f"  [{color}]{marker} {line_num:4d} │ {lines[ln][:80]}[/{color}]")

                if new_content:
                    con.print("  [green]+ After:[/green]")
                    for new_line in new_content.splitlines()[:10]:
                        con.print(f"  [green]+       │ {new_line[:80]}[/green]")
            elif new_content:
                # New file or block
                con.print("  [green]+ New content:[/green]")
                for new_line in new_content.splitlines()[:15]:
                    con.print(f"  [green]+       │ {new_line[:80]}[/green]")

        con.print()


# ── Summary ────────────────────────────────────────────────────────────────────


def _show_summary(
    applied: list[Patch],
    queued: list[Patch],
    blocked: list[tuple[Patch, str]],
) -> None:
    con.print()

    if applied:
        con.print(
            f"[#4ADE80]✓ Applied:[/#4ADE80] {len(applied)} fix(es) passed tests and are live."
        )
        for p in applied:
            con.print(f"  [dim]● {p.id}[/dim] {p.description[:60]}")

    if queued:
        con.print()
        con.print(
            f"[yellow]● Queued for review:[/yellow] {len(queued)} fix(es) need your approval."
        )
        con.print("  [dim]Run [bold]p review[/bold] to see diffs and approve or reject.[/dim]")

    if blocked:
        con.print()
        con.print(f"[red]✗ Blocked:[/red] {len(blocked)} fix(es) could not proceed.")
        for _, reason in blocked[:3]:
            con.print(f"  [dim]{reason[:80]}[/dim]")

    if not applied and not queued and not blocked:
        con.print("[dim]No patches were generated.[/dim]")

    con.print()


# ── Multi-framework annotation ─────────────────────────────────────────────────


def _build_file_framework_map(brain: dict) -> dict[str, str]:
    """Build a file path → framework name map from brain routes and framework list.

    Routes carry a ``framework`` field (set by RouteMapper).  For files that
    appear in no route we fall back to the first detected framework for that
    file's language.
    """
    mapping: dict[str, str] = {}

    # 1. Route-based mapping (most precise — per-file per-route)
    for route in brain.get("routes", []):
        if isinstance(route, dict):
            fw = route.get("framework", "") or ""
            fp = route.get("file", "") or ""
        else:
            fw = getattr(route, "framework", "") or ""
            fp = getattr(route, "file", "") or ""
        if fw and fp:
            mapping[fp] = fw

    # 2. Language-based fallback for files without routes
    detected_frameworks = brain.get("frameworks", [])
    if not mapping and detected_frameworks:
        first_fw = ""
        if isinstance(detected_frameworks[0], dict):
            first_fw = detected_frameworks[0].get("name", "")
        elif isinstance(detected_frameworks[0], str):
            first_fw = detected_frameworks[0]
        if first_fw:
            for fi in brain.get("file_infos", []):
                fp = (
                    fi.path
                    if hasattr(fi, "path")
                    else (fi.get("path") if isinstance(fi, dict) else "")
                )
                if fp and fp not in mapping:
                    mapping[fp] = first_fw

    return mapping


def _annotate_findings_with_framework(findings: list[dict], brain: dict) -> None:
    """Annotate each finding with the ``framework`` key so fix agents can
    produce framework-aware prompts."""
    fw_map = _build_file_framework_map(brain)
    for f in findings:
        fp = f.get("file", "")
        if fp in fw_map:
            f["framework"] = fw_map[fp]


# ── Helpers ────────────────────────────────────────────────────────────────────


def _collect_findings(scan_results: dict, area: str | None) -> list[dict]:
    """Collect all findings from the last agent scan results."""
    all_findings: list[dict] = []
    for agent_name, data in scan_results.items():
        if agent_name == "Brain":
            continue
        findings = data.get("findings", [])
        for f in findings:
            if area and not f.get("file", "").startswith(area):
                continue
            all_findings.append(f)
    return all_findings


def _save_patch(patch: Patch, root: Path) -> None:
    """Save a patch to memory."""
    try:
        mem.save_patch(patch.to_dict(), root)
    except Exception as e:
        con.print(f"[dim]Could not save patch {patch.id}: {e}[/dim]")
