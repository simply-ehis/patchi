"""
`p test` — Run tests, generate suites, view history, manage config.

Usage:
  p test                          — run default tests (unit + regression)
  p test unit                     — unit tests only
  p test smoke                    — smoke tests (buttons + layout + a11y)
  p test full                     — all test agents
  p test <type> [area]            — specific test type, optional scope

  p test generate                 — AI generates a full test suite
  p test generate unit            — AI generates unit tests only
  p test generate e2e             — AI generates E2E tests only

  p test report                   — show test run history
  p test report --last 10         — show last 10 runs

  p test config show              — show current test configuration
  p test config set <key> <value> — update a config value
  p test config flows add         — add a custom test flow (interactive)
  p test config flows remove <n>  — remove a custom test flow
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.cli.display.live_progress import LiveProgress
from patchi.core import memory as mem
from patchi.core.config import require_project_root

_MAPS_DIR = Path(__file__).resolve().parent


_log = logging.getLogger("patchi.cli.test_cmd")


def _load_test_type_map() -> dict[str, list[str]]:
    """Load test type mapping from external JSON config."""
    maps_file = _MAPS_DIR / "agent_maps.json"
    try:
        data = json.loads(maps_file.read_text(encoding="utf-8"))
        return data["test"]["test_types"]
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        con.print(f"[yellow]Warning: could not load agent_maps.json: {e}[/yellow]")
        return {}


TEST_TYPE_MAP = _load_test_type_map()
VALID_TYPES = sorted(TEST_TYPE_MAP.keys())


def run(
    test_type: str | None = None,
    area: str | None = None,
    root: Path | None = None,
    action: str | None = None,
    config_action: str | None = None,
    key: str | None = None,
    value: str | None = None,
    last_n: int = 20,
    attack: bool = False,
) -> None:
    """Entry point for `p test [type] [area]` and subcommands."""
    # Route to subcommands
    if action == "generate":
        run_generate(test_type=test_type, root=root)
        return
    if action == "report":
        run_report(last_n=last_n, root=root)
        return
    if action == "config":
        run_config(action=config_action, key=key, value=value, root=root)
        return

    # ── Attack mode ─────────────────────────────────────────────────────────
    if attack:
        _run_attack(root)
        return

    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # Import all test agents (triggers registration)
    _import_all_agents()

    from patchi.core import config as cfg
    from patchi.core.agents.base import AgentGroup, AgentInput, list_agents

    try:
        config = cfg.load(r)
    except Exception as e:
        _log.warning("run failed: %s", e)
        config = {}

    brain = mem.get_brain(r)
    scope = _scope_from_area(r, area)

    # Determine which agents to run
    all_test_agents = list_agents(AgentGroup.TEST)
    agent_map = {a.name: a for a in all_test_agents}

    if test_type is None:
        # Default: unit + regression
        to_run_names = ["UnitTestAgent", "RegressionAgent"]
    else:
        to_run_names = TEST_TYPE_MAP.get(test_type.lower(), [])
        if not to_run_names:
            # Try direct agent name match
            if test_type in agent_map:
                to_run_names = [test_type]
            else:
                con.print(f"[red]Unknown test type: {test_type!r}[/red]")
                con.print(f"[dim]Valid types: {' · '.join(VALID_TYPES)}[/dim]")
                con.print(f"[dim]Or an agent name: {' · '.join(sorted(agent_map))}[/dim]")
                return

    to_run = [agent_map[n] for n in to_run_names if n in agent_map]
    if not to_run:
        con.print("[red]No matching test agents found.[/red]")
        return

    # ConsoleLoggingAgent rides along on browser-family runs (§11: auto when
    # p test is active). Fail-open inside the agent if no server/playwright.
    _browser_family = {
        "BrowserTestAgent", "UIButtonAgent", "UILayoutAgent", "UIAccessibilityAgent",
        "VisualRegressionAgent", "E2EFlowAgent", "ConsoleLoggingAgent",
    }
    if "ConsoleLoggingAgent" in agent_map and any(n in _browser_family for n in to_run_names):
        if all(a.name != "ConsoleLoggingAgent" for a in to_run):
            to_run.append(agent_map["ConsoleLoggingAgent"])
            to_run_names = [*to_run_names, "ConsoleLoggingAgent"]

    # Chain: Check → Run → Test/Attack (Run relies on Check green, Test relies on Run)
    _launcher_url = None
    needs_launcher = any(n in ("BrowserTestAgent", "UIButtonAgent", "UILayoutAgent", "UIAccessibilityAgent", "VisualRegressionAgent", "E2EFlowAgent", "ConsoleLoggingAgent") for n in to_run_names) or test_type in ("browser", "e2e", "visual", "full")
    needs_run = needs_launcher or any(n in ("RedTeamAgent", "DastAgent", "ApiFuzzerAgent") for n in to_run_names)
    if needs_run:
        # 1. Check must be green — gate via .patchi/p_check_status.json
        try:
            from patchi.core.testing.gate import require_ready

            ready, url, st = require_ready(r)
            if not ready:
                con.print(f"[yellow]P-Check not READY_TO_SERVE — running p check first[/yellow] [dim]({st.get('status') if st else 'no status'})[/dim]")
                # Run P-Check side agents inline (install/build/format)
                try:
                    from patchi.cli.commands.check_cmd import run as check_run

                    check_run(root=r)
                    ready, url, st = require_ready(r)
                    if not ready:
                        con.print(f"[red]P-Check still BLOCKED: {st.get('error') if st else 'unknown'} — aborting test (fix via p check --fix)[/red]")
                        return
                except Exception as exc:  # noqa: BLE001
                    _log.debug("p check inline failed: %s", exc)
        except Exception as exc:  # noqa: BLE001
            _log.debug("gate check failed: %s", exc)
        # 2. Run — start app after Check green
        try:
            from patchi.core.agents.base import AgentInput as _AI
            from patchi.core.agents.run_agent import RunAgent

            run_inp = _AI(root=r, scope=[], brain=brain, config=config, extra={})
            run_res = RunAgent().run(run_inp)
            if run_res.status.value == "done" and run_res.data.get("base_url"):
                _launcher_url = run_res.data["base_url"]
                con.print(f"[dim]RunAgent: app at {_launcher_url} — P-Check was green[/dim]")
            else:
                _log.debug("RunAgent %s: %s", run_res.status, run_res.data.get("gate_reason") or run_res.errors)
                if run_res.data.get("gate_blocked"):
                    con.print(f"[red]Run blocked: {run_res.data.get('gate_reason')}[/red]")
                    return
                # Fallback to direct launcher if RunAgent failed but Check was green
                from patchi.core.testing.app_launcher import ensure_running

                _launcher_url = ensure_running(r, config, {})
                if _launcher_url:
                    con.print(f"[dim]App running at {_launcher_url} — launcher fallback[/dim]")
        except Exception as exc:  # noqa: BLE001
            _log.debug("RunAgent failed: %s", exc)
            # Fallback direct
            try:
                from patchi.core.testing.app_launcher import ensure_running

                _launcher_url = ensure_running(r, config, {})
            except Exception as _exc:
                _log.debug('suppressed: %s', _exc)

    con.print()
    label = f" [dim]→ {area}[/dim]" if area else ""
    con.print(
        f"[bold #C8621A]Testing{label}[/bold #C8621A]  "
        f"[dim]{', '.join(a.name.replace('Agent', '') for a in to_run)}[/dim]"
    )
    con.print()

    # Chain progress display
    from patchi.cli.ux import format_step, status_icon, status_style

    total_steps = len(to_run) + (2 if needs_run else 0)  # +2 for check and run if needed
    current_step = 0

    def show_step(step_name: str, status: str = "running"):
        nonlocal current_step
        current_step += 1
        icon = status_icon(status)
        style = status_style(status)
        con.print(format_step(current_step, total_steps, f"[{style}]{icon} {step_name}[/{style}]"))

    # Show chain steps
    if needs_run:
        show_step("P-Check gate verification", "done")
        show_step("RunAgent — starting app", "done")

    # Run via coordinator (sequential for tests — order matters)
    results = []
    agent_names = ", ".join(a.name.replace("Agent", "") for a in to_run)
    lp = LiveProgress(con, title=f"Tests ({agent_names})")
    lp.start()
    for agent_cls in to_run:
        short_name = agent_cls.name.replace("Agent", "")
        show_step(f"Running {short_name}")
        lp.set_progress(len(results) + 1, len(to_run), short_name)
        lp.log(f"  {short_name}…")
        lp.update()

        extra = {}
        if _launcher_url:
            extra["base_url"] = _launcher_url
            extra["live_probe"] = True
        inp = AgentInput(
            root=r,
            scope=scope,
            brain=brain,
            config=config,
            extra=extra,
            on_message=lambda n, msg, s: (lp.log(f"    {msg}", s), lp.update()),
        )
        result = agent_cls().run(inp)
        results.append(result)

        # Per-test result lines
        suite = result.data.get("suite", {})
        for t in suite.get("cases", []):
            label = t.get("name", t.get("label", "?"))
            passed = t.get("passed", t.get("status")) in (True, "passed", "ok")
            icon = "[#4ADE80]v[/#4ADE80]" if passed else "[#FF4D6D]x[/#FF4D6D]"
            lp.log(f"  {icon} {label}", "green" if passed else "red")

        lp.update()

        # Save to scan results so memory tracks test runs
        try:
            mem.save_scan_result(
                agent_cls.name,
                {
                    "status": result.status.value,
                    "duration_ms": result.duration_ms,
                    "finding_count": result.finding_count,
                    **result.data,
                },
                r,
            )
        except Exception as e:
            _log.warning("run failed: %s", e)

    total_tests = sum(r.data.get("suite", {}).get("total", 0) for r in results)
    total_passed = sum(r.data.get("suite", {}).get("passed", 0) for r in results)
    total_failed = sum(r.data.get("suite", {}).get("failed", 0) for r in results)
    lp.stop(summary=f"{total_tests} tests - {total_passed} passed, {total_failed} failed")
    # Launcher teardown
    if _launcher_url:
        try:
            from patchi.core.testing.app_launcher import stop

            stop()
            con.print(f"[dim]Launcher: app at {_launcher_url} stopped[/dim]")
        except Exception as exc:  # noqa: BLE001
            _log.debug("launcher stop failed: %s", exc)
    _show_results(results)

    # Merge TEST findings through the UI verification gate before memory —
    # only findings whose file/line check out against the codebase are saved.
    try:
        from patchi.core.brain.verify import verify_ui_findings

        ui_dicts: list[dict] = []
        for res in results:
            for f in res.findings:
                ui_dicts.append(f.to_dict() if hasattr(f, "to_dict") else dict(f))
        kept, dropped = verify_ui_findings(r, ui_dicts)
        mem.save_scan_result(
            "UI",
            {
                "status": "ok",
                "finding_count": len(kept),
                "dropped_unverifiable": len(dropped),
                "findings": kept,
            },
            r,
        )
        if dropped:
            con.print(
                f"[dim]UI gate: kept {len(kept)}, dropped {len(dropped)} unverifiable[/dim]"
            )
    except Exception as e:
        _log.warning("UI merge failed: %s", e)

    # Save to test history
    _save_to_history(results, test_type or "default", area, r)


def run_test(args) -> None:
    """Namespace-shaped entry for the CLI registry (self-routing).

    The framework passes the whole parsed Namespace; this replicates the exact
    routing the legacy main.py ladder did before the migration, so `p test`
    keeps the same behavior for every `type` value.
    """
    test_type = getattr(args, "type", None)
    if test_type == "generate":
        run(action="generate", test_type=getattr(args, "area", None))
    elif test_type == "report":
        run(action="report", last_n=getattr(args, "last", 20))
    elif test_type == "config":
        run(
            action="config",
            config_action=getattr(args, "area", None),
            key=getattr(args, "config_key", None),
            value=getattr(args, "config_value", None),
        )
    else:
        run(
            test_type=test_type,
            area=getattr(args, "area", None),
            attack=getattr(args, "attack", False),
        )


def run_generate(test_type: str | None = None, root: Path | None = None) -> None:
    """Entry point for `p test generate [type]`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg

    try:
        config = cfg.load(r)
    except Exception as e:
        _log.warning("run_generate failed: %s", e)
        config = {}

    # Contract tests are deterministic (static route extraction) — no AI needed.
    if (test_type or "").lower() == "contract":
        from patchi.core.testing.api_contract_agent import generate_contract_tests
        from patchi.core.testing.gate import require_ready

        base = None
        try:
            ready, url, _st = require_ready(r)
            if ready and url:
                base = url
        except Exception as e:
            _log.debug("contract generate gate check failed: %s", e)
        summary = generate_contract_tests(r, base)
        if not summary["written"]:
            con.print("[yellow]No static routes detected — nothing to generate.[/yellow]")
            return
        con.print(
            f"[green]Generated {summary['routes']} contract smoke tests → "
            f"{summary['path']}[/green]"
        )
        con.print(f"[dim]Base URL: {summary['base_url']} (override with PATCHI_CONTRACT_BASE_URL)[/dim]")
        con.print(f"[dim]Run: pytest {summary['path']} (needs the app serving)[/dim]")
        return

    from patchi.core.ai.client import call_ai

    # Quick availability check
    test_response = call_ai(config, "Reply with OK", "test", max_tokens=5)
    if not test_response:
        con.print("[yellow]No AI configured. Set up a key with `p key add` or use Ollama.[/yellow]")
        con.print("[dim]Tip: `p ai status` to see what's available.[/dim]")
        return

    con.print()
    con.print("[bold #C8621A]Generating tests with AI…[/bold #C8621A]")
    con.print()

    # Patchi decides — not user configured: Understander + coverage gap
    try:
        from patchi.core.ai.tools.realize import generate_tests as _realize_gen

        # Let Patchi auto-pick untested core files (Understander + body_tags)
        auto_res = _realize_gen(r, ["auto"], test_type or "unit")
        # auto_res already wrote .patchi/generated_tests/test_*.py
        # Now also do AI skeleton for deeper tests on same auto-picked files
        auto_files = [c.get("source", "") for c in auto_res.get("created", []) if c.get("status") == "created"]
        if auto_files:
            project_files = [p.replace(str(r) + "/", "").replace("\\", "/") for p in auto_files]
        else:
            # fallback to Understander core
            from patchi.core.brain.body_tags import load_body_tags
            from patchi.core.brain.file_corpus import FileCorpus
            from patchi.core.brain.understander import Understander

            tags = load_body_tags(r)
            corpus = FileCorpus(r)
            class _FI:
                def __init__(self, p: str):
                    self.path = p

            fis = [_FI(e.path) for e in corpus.files()]
            if tags:
                u = Understander(r, fis, tags, {}, [])
                core = u.core_files(limit=8)
                project_files = [c["path"] for c in core if not (r / f"tests/test_{Path(c['path']).stem}.py").exists()]
                if not project_files:
                    project_files = [c["path"] for c in core[:3]]
            else:
                project_files = _discover_project_files(r)[:8]
    except Exception as e:
        _log.debug("Patchi auto-pick failed, fallback: %s", e)
        project_files = _discover_project_files(r)[:8]
        top_files = project_files
    if not project_files:
        con.print("[yellow]Patchi found no untested core files to generate for.[/yellow]")
        con.print("[dim]Patchi decides coverage gap: all core files already have tests or no core detected[/dim]")
        return
    con.print(f"[dim]Patchi auto-picked {len(project_files)} untested core files: {', '.join(project_files[:3])}{' …' if len(project_files)>3 else ''}[/dim]")
    scope_msg = f" for {test_type} tests" if test_type else " — Patchi decided"
    top_files = project_files  # Patchi decides, not user

    # Extract AST skeletons — guaranteed real names, no hallucination
    skeletons = []
    for fp in top_files:
        full = r / fp
        try:
            skeleton = _extract_skeleton(str(full))
            if skeleton.strip():
                skeletons.append(f"### {fp}\n{skeleton}")
        except Exception as e:
            _log.warning("run_generate failed: %s", e)
            continue

    if not skeletons:
        con.print("[yellow]Could not extract skeletons from any files.[/yellow]")
        return

    skeletons_text = "\n\n".join(skeletons)

    # Smarter context: mutation survived, branch gaps, coverage, fuzz boundaries
    extra_context = []
    try:
        from patchi.core import memory as _mem2

        scans = _mem2.get_scan_results(r) or {}
        mut = scans.get("MutationAgent", {}).get("findings", [])
        if mut:
            mut_lines = [f"- {f.get('file')}:{f.get('line')} {f.get('message','')[:80]}" for f in mut[:5]]
            extra_context.append("MUTATION SURVIVED (must kill):\n" + "\n".join(mut_lines))
    except Exception as _exc:
        _log.debug('suppressed: %s', _exc)
    try:
        # Branch gaps: heuristic from FileCorpus
        from patchi.core.brain.file_corpus import FileCorpus

        corpus = FileCorpus(r)
        branch_gaps = []
        for fp in top_files:
            try:
                txt = (r / fp).read_text(encoding="utf-8", errors="replace")
                branches = txt.count(" if ") + txt.count(" else") + txt.count(" ? ")
                if branches > 6:
                    branch_gaps.append(f"- {fp}: {branches} branches")
            except OSError:
                pass
        if branch_gaps:
            extra_context.append("BRANCH GAPS (cover each if/else):\n" + "\n".join(branch_gaps[:5]))
    except Exception as _exc:
        _log.debug('suppressed: %s', _exc)
    try:
        from patchi.core.fuzz.input_fuzzer import InputFuzzer

        fz = InputFuzzer(seed=42)
        fuzz_samples = [f.to_dict() for f in fz.fuzz_string("test", count=5)]
        extra_context.append("FUZZ BOUNDARIES (test these):\n" + "\n".join(f"- {s['label']}: {s['value']!r} ({s['strategy']})" for s in fuzz_samples[:4]))
    except Exception as _exc:
        _log.debug('suppressed: %s', _exc)
    extra_block = "\n\n".join(extra_context) if extra_context else "No extra gap data — cover happy path + one edge per function."
    if extra_block:
        extra_block = f"\n\nSMART CONTEXT — Patchi decided what to catch:\n{extra_block}\n"

    prompt = f"""Generate a pytest test file{scope_msg} for these Python modules.

MODULE SKELETONS (these are real — use ONLY these names):
{skeletons_text}
{extra_block}
Rules:
1. Import from the exact paths shown (e.g. from patchi.core.agents.base import ...)
2. Use ONLY the function/class names listed above — do not invent new ones
3. Mock call_ai, HTTP, and file I/O
4. Keep under 250 lines
5. Return ONE test file in a ```python block
6. NEVER use module-level `with patch(...)` blocks — use @patch decorators on test methods only
7. NEVER import the module under test at the top level — import inside each test method
8. Keep all imports inside test functions/methods to avoid side effects at collection time
9. SMART: For each function, add one happy path + one boundary/branch test + one mutation-killing test (use extra context above). For security-sensitive fns, add injection/encoding payload test from FUZZ BOUNDARIES.
10. Prioritize covering MUTATION SURVIVED and BRANCH GAPS listed — those are Patchi's priority catch list."""

    from patchi.core.ai.prompts import SYSTEM_PROMPTS, Skill

    system_prompt = SYSTEM_PROMPTS.get(Skill.TEST_GENERATE, "You are a test generator.")

    lp = LiveProgress(con, title="Generate tests")
    lp.start()
    lp.log("  Generating tests via AI…")
    lp.update()
    try:
        response_text = call_ai(config, system_prompt, prompt, max_tokens=4000)

        if response_text:
            code = response_text
            if "```python" in code:
                code = code.split("```python")[1].split("```")[0]
            elif "```" in code:
                code = code.split("```")[1].split("```")[0]

            # Determine output path
            if test_type:
                out_path = r / "tests" / f"test_{test_type}_generated.py"
            else:
                out_path = r / "tests" / "test_generated_suite.py"

            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(code.strip(), encoding="utf-8")

            # Quick verify — no second AI call, just check if it compiles
            err = _verify_test(code, r)
            if err:
                lp.log(f"  [yellow]Tests written but may have issues: {err[:100]}[/yellow]")
                lp.stop(summary="Tests generated with warnings")
                con.print(f"[yellow]⚠ Tests written but may have issues: {err[:100]}[/yellow]")
            else:
                lp.log("  Tests verified and written")
                lp.stop(summary="Tests generated and verified")
                con.print(
                    f"[#4ADE80]✓[/#4ADE80] Tests verified and written to [bold]{out_path.relative_to(r)}[/bold]"
                )
            con.print("[dim]Run with: p test unit[/dim]")
        else:
            lp.stop(summary="AI returned empty response")
            con.print("[yellow]AI returned empty response. Try again or check your key.[/yellow]")

    except Exception as e:
        lp.stop(summary=f"Failed: {e}")
        con.print(f"[red]Generation failed: {e}[/red]")


def run_report(last_n: int = 20, root: Path | None = None) -> None:
    """Entry point for `p test report`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core.testing.test_config import get_test_history

    history = get_test_history(r)

    if not history:
        con.print("[dim]No test runs recorded yet. Run `p test` first.[/dim]")
        return

    runs = history[-last_n:]

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Time", style="dim", width=19)
    table.add_column("Type", style="bold #F2EDD6", width=12)
    table.add_column("Status", width=8)
    table.add_column("Passed", justify="right", width=7)
    table.add_column("Failed", justify="right", width=7)
    table.add_column("Duration", justify="right", width=10)
    table.add_column("Agents", style="dim", width=30)

    for entry in reversed(runs):
        ts = entry.get("timestamp", "")
        try:
            ts_fmt = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"
        except Exception as e:
            _log.warning("run_report failed: %s", e)
            ts_fmt = str(ts)[:16]

        status = entry.get("status", "unknown")
        passed = entry.get("passed", 0)
        failed = entry.get("failed", 0)
        dur = entry.get("duration_ms", 0)
        agents = entry.get("agents", [])
        test_type = entry.get("test_type", "—")

        if status == "passed" or (passed > 0 and failed == 0):
            status_text = Text("PASS", style="#4ADE80 bold")
        elif status == "failed" or failed > 0:
            status_text = Text("FAIL", style="#FF4D6D bold")
        else:
            status_text = Text(status, style="dim")

        table.add_row(
            ts_fmt,
            test_type,
            status_text,
            str(passed) if passed else "—",
            Text(str(failed), style="#FF4D6D") if failed else "—",
            f"{dur}ms" if dur else "—",
            ", ".join(a.replace("Agent", "") for a in agents[:4])
            + ("…" if len(agents) > 4 else ""),
        )

    con.print()
    con.print(Panel(table, title=f"Test History (last {len(runs)} runs)", border_style="#C8621A"))
    con.print()

    # Coverage summary
    from patchi.core.testing.test_config import get_coverage

    cov = get_coverage(r)
    total_runs = cov.get("total_runs", 0)
    agents_run = cov.get("agents_run", {})
    if total_runs:
        con.print(f"[dim]Total runs: {total_runs}[/dim]")
        if agents_run:
            con.print(
                f"[dim]Agents exercised: {', '.join(f'{k}({v})' for k, v in sorted(agents_run.items(), key=lambda x: -x[1]))}[/dim]"
            )
    con.print()


def run_config(
    action: str | None = None,
    key: str | None = None,
    value: str | None = None,
    root: Path | None = None,
) -> None:
    """Entry point for `p test config`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core.testing import test_config as tc

    if action is None or action == "show":
        config = tc.load(r)
        con.print()
        con.print(
            Panel(
                json.dumps(config, indent=2),
                title="Test Configuration",
                border_style="#C8621A",
                subtitle=f"{tc.TESTS_CONFIG}",
            )
        )
        con.print()
        return

    if action == "set":
        if not key:
            con.print("[red]Usage: p test config set <key> <value>[/red]")
            return
        # Try to parse as JSON for non-string values
        parsed_value = value
        if value:
            try:
                parsed_value = json.loads(value)
            except (json.JSONDecodeError, ValueError):
                pass
        tc.set_value(key, parsed_value, r)
        con.print(f"[#4ADE80]✓[/#4ADE80] [bold]{key}[/bold] = {parsed_value}")
        return

    if action == "flows":
        _manage_flows(key, value, r)
        return

    con.print(f"[yellow]Unknown config action: {action!r}[/yellow]")
    con.print("[dim]Valid: show, set, flows[/dim]")


def _manage_flows(sub_action: str | None, name: str | None, root: Path) -> None:
    """Manage custom test flows."""
    from patchi.core.testing import test_config as tc

    if sub_action == "add":
        con.print("[dim]Add a custom test flow:[/dim]")
        flow_name = name or input("  Flow name: ").strip()
        if not flow_name:
            con.print("[red]Name required.[/red]")
            return
        url = input("  URL path (e.g. /login): ").strip()
        steps_raw = input("  Steps (comma-separated): ").strip()
        steps = [s.strip() for s in steps_raw.split(",") if s.strip()]
        tc.add_custom_flow(flow_name, url, steps, root)
        con.print(f"[#4ADE80]✓[/#4ADE80] Flow [bold]{flow_name}[/bold] added.")

    elif sub_action == "remove":
        if not name:
            con.print("[red]Usage: p test config flows remove <name>[/red]")
            return
        removed = tc.remove_custom_flow(name, root)
        if removed:
            con.print(f"[#4ADE80]✓[/#4ADE80] Flow [bold]{name}[/bold] removed.")
        else:
            con.print(f"[yellow]Flow {name!r} not found.[/yellow]")

    elif sub_action == "list" or sub_action is None:
        config = tc.load(root)
        flows = config.get("custom_flows", [])
        if not flows:
            con.print("[dim]No custom flows configured.[/dim]")
            con.print("[dim]Add one with: p test config flows add[/dim]")
            return
        for f in flows:
            con.print(f"  [bold]{f['name']}[/bold]  [dim]{f['url']}[/dim]")
            if f.get("steps"):
                con.print(f"    [dim]Steps: {' → '.join(f['steps'])}[/dim]")

    else:
        con.print(f"[yellow]Unknown flows action: {sub_action!r}[/yellow]")
        con.print("[dim]Valid: add, remove, list[/dim]")


# ── Helpers ────────────────────────────────────────────────────────────────────


def _import_all_agents():
    """Import all agent modules to trigger registration (never hand-list)."""
    from patchi.core.agents.base import discover_agent_modules

    failures = discover_agent_modules()
    for failure in failures:
        _log.debug("agent discovery: %s", failure)


def _extract_skeleton(filepath: str) -> str:
    """Extract function/class signatures and imports — no bodies, no hallucination."""
    import ast

    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            tree = ast.parse(f.read())
    except (SyntaxError, OSError):
        return ""

    lines = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef):
            args = [a.arg for a in node.args.args if a.arg != "self"]
            lines.append(f"def {node.name}({', '.join(args)}): ...")
        elif isinstance(node, ast.AsyncFunctionDef):
            args = [a.arg for a in node.args.args if a.arg != "self"]
            lines.append(f"async def {node.name}({', '.join(args)}): ...")
        elif isinstance(node, ast.ClassDef):
            bases = [ast.unparse(b) for b in node.bases]
            base_str = f"({', '.join(bases)})" if bases else ""
            lines.append(f"class {node.name}{base_str}:")
            for item in ast.iter_child_nodes(node):
                if isinstance(item, ast.FunctionDef):
                    margs = [a.arg for a in item.args.args if a.arg != "self"]
                    lines.append(f"    def {item.name}({', '.join(margs)}): ...")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            lines.append(ast.unparse(node))

    return "\n".join(lines)


def _verify_test(test_code: str, root: Path) -> str | None:
    """Try to compile+import the test. Returns error string or None if OK."""
    import importlib.util
    import tempfile

    try:
        tmp = Path(tempfile.mktemp(suffix=".py"))
        tmp.write_text(test_code, encoding="utf-8")
        spec = importlib.util.spec_from_file_location("_test_check", str(tmp))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tmp.unlink(missing_ok=True)
        return None
    except (ImportError, AttributeError, SyntaxError) as e:
        try:
            tmp.unlink(missing_ok=True)
        except Exception as e:
            _log.warning("_verify_test failed: %s", e)
        return str(e)


def _discover_project_files(root: Path) -> list[str]:
    """Discover Python source files in the project."""
    from patchi.core.agents.base import safe_rglob

    files = []
    for p in safe_rglob(root, "*.py"):
        rel = str(p.relative_to(root))
        if rel.startswith("tests/") or rel.startswith("test_"):
            continue
        if "__pycache__" in rel:
            continue
        files.append(rel)
    return sorted(files)[:50]


def _save_to_history(results: list, test_type: str, area: str | None, root: Path) -> None:
    """Save test run to history for reporting."""
    from patchi.core.agents.base import AgentStatus
    from patchi.core.testing.test_config import append_test_history, update_coverage

    passed = sum(1 for r in results if r.finding_count == 0 and r.status != AgentStatus.SKIPPED)
    failed = sum(1 for r in results if r.finding_count > 0 or r.status == AgentStatus.FAILED)
    total_dur = sum(r.duration_ms for r in results)
    agent_names = [r.agent_name for r in results]

    entry = {
        "timestamp": time.time(),
        "test_type": test_type,
        "area": area,
        "status": "passed" if failed == 0 else "failed",
        "passed": passed,
        "failed": failed,
        "duration_ms": total_dur,
        "agents": agent_names,
    }

    append_test_history(entry, root)
    update_coverage(entry, root)


# ── Results display ────────────────────────────────────────────────────────────


def _show_results(results: list) -> None:
    from patchi.core.agents.base import AgentStatus

    all_passed = all(r.finding_count == 0 for r in results if r.status != AgentStatus.SKIPPED)

    con.print()

    if all_passed and results:
        con.print(
            Panel(
                "[bold #4ADE80]All tests passed.[/bold #4ADE80]",
                border_style="#4ADE80",
                padding=(0, 1),
            )
        )
        for r in results:
            suite = r.data.get("suite", {})
            if suite:
                con.print(
                    f"  [dim]✓ {r.agent_name.replace('Agent', '')}:[/dim] "
                    f"[dim]{suite.get('passed', 0)} passed in "
                    f"{suite.get('duration_ms', r.duration_ms)}ms[/dim]"
                )
        con.print()
        return

    # Show per-agent results
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Agent", style="bold #F2EDD6", width=20)
    table.add_column("Status", width=10)
    table.add_column("Passed", justify="right", width=8)
    table.add_column("Failed", justify="right", width=8)
    table.add_column("Duration", justify="right", width=10)
    table.add_column("Note", style="dim", width=30)

    for r in results:
        suite = r.data.get("suite", {})
        passed = suite.get("passed", r.data.get("passed", 0))
        failed = suite.get("failed", r.data.get("failed", r.finding_count))
        dur_ms = suite.get("duration_ms", r.duration_ms)

        if r.status == AgentStatus.SKIPPED:
            status_text = Text("skipped", style="dim")
        elif failed > 0 or r.finding_count > 0:
            status_text = Text("failed", style="#FF4D6D bold")
        else:
            status_text = Text("passed", style="#4ADE80 bold")

        note = r.data.get("message", "")[:30]

        table.add_row(
            r.agent_name.replace("Agent", ""),
            status_text,
            str(passed) if passed else "—",
            Text(str(failed), style="#FF4D6D") if failed else "—",
            f"{dur_ms}ms",
            note,
        )

    con.print(table)

    # Show individual failures
    sev_colors = {
        "critical": "#FF4D6D",
        "high": "#FF8C42",
        "medium": "#FACC15",
        "low": "#4ADE80",
    }
    for r in results:
        if r.findings:
            con.print()
            con.print(f"[bold #F2EDD6]{r.agent_name.replace('Agent', '')} failures:[/bold #F2EDD6]")
            for finding in r.findings[:8]:
                sev = finding.severity.value
                color = sev_colors.get(sev, "white")
                con.print(f"  [{color}]●[/{color}] {finding.message[:80]}")
                if finding.detail:
                    for line in finding.detail.splitlines()[:3]:
                        con.print(f"    [dim]{line[:80]}[/dim]")

    con.print()


# ── Attack mode ────────────────────────────────────────────────────────────────


def _run_attack(root: Path | None) -> None:
    """Run the AttackAgent (Metasploit auxiliary/scanner probe)."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg
    from patchi.core import memory as mem
    from patchi.core.agents.attack_agent import AttackAgent
    from patchi.core.agents.base import AgentInput

    try:
        config = cfg.load(r)
    except Exception as e:
        _log.warning("_run_attack failed: %s", e)
        config = {}

    brain = mem.get_brain(r)

    con.print()
    con.print(
        "[bold #C8621A]Attack Scan[/bold #C8621A]  [dim]Metasploit auxiliary/scanner probes against localhost[/dim]"
    )
    con.print()

    inp = AgentInput(
        root=r,
        scope=[],
        brain=brain,
        config=config,
        extra={"msf_password": config.get("msf", {}).get("password", "")},
    )

    msf_target = config.get("msf", {}).get("target", "127.0.0.1:8000")
    inp.extra["msf_target"] = msf_target

    lp = LiveProgress(con, title="Attack probes")
    lp.start()
    lp.log("  Running attack probes…")
    lp.update()
    result = AttackAgent().run(inp)
    lp.stop(summary=f"{result.finding_count} findings")
    _show_attack_results(result, msf_target)


def _show_attack_results(result, default_target: str = "127.0.0.1:8000") -> None:
    """Display Metasploit attack scan results."""
    from patchi.core.agents.base import AgentStatus

    con.print()
    if result.status == AgentStatus.SKIPPED or result.status == AgentStatus.FAILED:
        for err in result.errors:
            con.print(f"  [yellow]![/yellow] [dim]{err}[/dim]")
        con.print()
        return

    target = result.data.get("target", default_target)
    frameworks = result.data.get("frameworks", [])
    modules_run = result.data.get("modules_selected", [])

    # Info panel
    con.print(
        Panel(
            f"[bold #F2EDD6]Target:[/bold #F2EDD6]  [dim]{target}[/dim]\n"
            + (
                f"[bold #F2EDD6]Framework:[/bold #F2EDD6]  [dim]{', '.join(frameworks)}[/dim]\n"
                if frameworks
                else ""
            )
            + f"[bold #F2EDD6]Modules:[/bold #F2EDD6]  [dim]{len(modules_run)} probe(s)[/dim]\n"
            + f"[bold #F2EDD6]Findings:[/bold #F2EDD6]  [dim]{result.finding_count}[/dim]",
            border_style="#C8621A",
        )
    )
    con.print()

    if not result.findings and not result.errors:
        con.print("[dim]No findings from Metasploit probes.[/dim]")
        con.print()
        return

    # Module results table
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Module", style="bold #F2EDD6", width=32)
    table.add_column("Severity", width=10)
    table.add_column("Detail", style="dim", width=60)

    for f in result.findings:
        sev_colors = {
            "critical": "#FF4D6D",
            "high": "#FF8C42",
            "medium": "#FACC15",
            "low": "#4ADE80",
            "info": "#B8A898",
        }
        sev = f.severity.value
        color = sev_colors.get(sev, "white")
        mod_name = f.extra.get("module", f.type)
        detail_preview = f.detail[:60].replace("\n", " ") if f.detail else "—"
        table.add_row(
            mod_name,
            Text(sev, style=color),
            detail_preview,
        )

    con.print(table)
    con.print()

    # Show any errors
    if result.errors:
        con.print("[yellow]Probe errors:[/yellow]")
        for err in result.errors:
            con.print(f"  [dim]— {err}[/dim]")
        con.print()


# ── Scope helper ───────────────────────────────────────────────────────────────


def _scope_from_area(root: Path, area: str | None) -> list[str]:
    if not area:
        return []
    area_path = root / area
    if area_path.is_file():
        return [area]
    if area_path.is_dir():
        return [str(p.relative_to(root)) for p in area_path.rglob("*.py")]
    # Treat as prefix filter
    return [
        str(p.relative_to(root))
        for p in root.rglob("*.py")
        if str(p.relative_to(root)).startswith(area)
    ]
