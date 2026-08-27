"""
`p status` — unified status, health, and doctor command.

Shows: Brain health · Current mode · Queue depth · AI key status

Flags:
  --deep      Show detailed health breakdown (was p health)
  --validate  Run system validation checks (was p doctor)
  --verbose   Show detailed output
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con

if TYPE_CHECKING:
    pass

_log = logging.getLogger("patchi.cli.status_cmd")


def _health_bar(score: int, width: int = 20) -> str:
    """Build a visual health bar: [████████░░░░░░░░░░░░] 80/100."""
    filled = int(score / 100 * width)
    empty = width - filled
    if score >= 80:
        color = "#4ADE80"
    elif score >= 50:
        color = "#FACC15"
    elif score >= 25:
        color = "#FF8C42"
    else:
        color = "#FF4D6D"
    bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"
    return f"{bar} {score}/100"


def run(
    root: Path | None = None,
    json_output: bool = False,
    deep: bool = False,
    validate: bool = False,
    verbose: bool = False,
) -> None:
    """p status — unified command for status, health, and doctor."""
    from patchi.core import config as cfg

    try:
        r = root or cfg.find_project_root()
        if not r:
            if json_output:
                import json as _json
                con.print(_json.dumps({"error": "no project root found"}))
            else:
                con.print("[yellow]No project root found. Run 'p init' first.[/yellow]")
            return
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if validate:
        _run_doctor(r, json_output=json_output, verbose=verbose)
        return

    if deep:
        _run_health(r, json_output=json_output)
        return

    # Default: status view
    _run_status(r, json_output=json_output)


def _run_status(root: Path, json_output: bool) -> None:
    """Original status view: Brain health, mode, queue state, AI keys."""
    from patchi.core import config as cfg
    from patchi.core import memory as mem
    from patchi.core import queue as q

    try:
        config = cfg.load(root)
        brain = mem.get_brain(root)
        qstats = q.stats(root)
        mode = cfg.get_mode(root)
        qmode = cfg.get_queue_mode(root)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if json_output:
        import json as _json

        health_score = brain.get("health_score", {}) if brain else {}
        stack = (brain or {}).get("stack", {}) or {}
        con.print(
            _json.dumps(
                {
                    "mode": mode,
                    "queue_mode": qmode,
                    "queue": qstats,
                    "health_score": health_score,
                    "brain": {
                        "ready": bool(brain and not brain.get("stale") and not brain.get("error")),
                        "stale": bool((brain or {}).get("stale")),
                        "file_count": (brain or {}).get("file_count", 0),
                        "route_count": (brain or {}).get("route_count", 0),
                        "frameworks": [f.get("name", "") for f in stack.get("frameworks", [])[:3]],
                    },
                },
                indent=2,
                default=str,
            )
        )
        return

    con.print()

    # ── Build info sections ────────────────────────────────────────────────────

    # Health score
    health_score = brain.get("health_score", {})
    health_total = health_score.get("total")
    health_grade = health_score.get("grade", "")

    if health_total is not None:
        health_bar = _health_bar(health_total)
        comps = health_score.get("components", {})
        health_detail = (
            f"security {comps.get('security', 0):.0f}  "
            f"tests {comps.get('test_coverage', 0):.0f}  "
            f"dead {comps.get('dead_code', 0):.0f}  "
            f"deps {comps.get('dependency', 0):.0f}  "
            f"contract {comps.get('contract', 0):.0f}"
        )
    else:
        health_bar = "[dim]No scan yet[/dim]"
        health_detail = "Run [bold]p scan[/bold] to compute"

    # Brain
    if not brain:
        brain_line = "[dim]No scan yet — run [bold]p scan[/bold][/dim]"
    elif brain.get("stale"):
        reason = brain.get("stale_reason", "Files changed since last scan")
        brain_line = f"[yellow]Stale[/yellow] — {reason}"
    elif brain.get("error"):
        brain_line = f"[red]Error:[/red] {brain.get('error', '')}"
    else:
        fc = brain.get("file_count", 0)
        rc = brain.get("route_count", 0)
        fw = ""
        stack = brain.get("stack", {})
        if stack and stack.get("frameworks"):
            fw_names = [f.get("name", "") for f in stack["frameworks"][:3]]
            fw = f"  ·  {', '.join(fw_names)}"
        brain_line = f"[#4ADE80]Ready[/#4ADE80] — {fc} files · {rc} routes{fw}"

    # Mode
    mode_colors = {"confirm": "#60A5FA", "auto": "#FACC15", "autopilot": "#4ADE80"}
    mode_icons = {"confirm": "🔒", "auto": "⚡", "autopilot": "🤖"}
    mc = mode_colors.get(mode.value, "dim")
    mi = mode_icons.get(mode.value, "")
    mode_line = f"[bold {mc}]{mi} {mode.label()}[/bold {mc}]"
    mode_desc = {
        "confirm": "Every fix requires your approval",
        "auto": "Low-risk auto-applied, risky ones ask",
        "autopilot": "Full trust — Patchi decides",
    }.get(mode.value, "")

    # Queue
    queue_paused = qstats.get("paused", False)
    queue_waiting = qstats.get("waiting", 0)
    queue_active = qstats.get("active", 0)

    if queue_paused:
        queue_line = "[yellow]Paused[/yellow]"
    elif queue_active:
        queue_line = f"[#C8621A]{queue_active} active[/#C8621A]"
    elif queue_waiting:
        queue_line = f"{queue_waiting} waiting"
    else:
        queue_line = "[dim]Empty[/dim]"
    queue_detail = f"mode: {qmode.value}"

    # AI
    ai_config = config.get("ai", {})
    local_model = ai_config.get("local_model_name")
    keys = ai_config.get("keys", [])
    horde_fallback = ai_config.get("horde_fallback", False)

    if local_model:
        ai_line = f"[#4ADE80]Local:[/#4ADE80] {local_model}"
        ai_detail = "Offline · zero cost"
    elif keys:
        working = [k for k in keys if k.get("status") != "error"]
        if working:
            ai_line = f"[#4ADE80]{len(working)}/{len(keys)} keys active[/#4ADE80]"
        else:
            ai_line = f"[red]0/{len(keys)} keys active[/red]"
        ai_detail = "  ".join(k.get("nickname", "?") for k in keys[:4])
        if len(keys) > 4:
            ai_detail += f" +{len(keys) - 4} more"
    elif horde_fallback:
        ai_line = "[yellow]Community fallback[/yellow]"
        ai_detail = "AI Horde · slower but always works"
    else:
        ai_line = "[yellow]Not configured[/yellow]"
        ai_detail = "Run [bold]p key add[/bold] or [bold]p init[/bold]"

    # ── Render ─────────────────────────────────────────────────────────────────

    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 2))
    table.add_column("Key", style="bold #F2EDD6", width=14)
    table.add_column("Value", min_width=30)
    table.add_column("Detail", style="dim")

    table.add_row("Health", Text.from_markup(health_bar), health_detail)
    table.add_row("Brain", Text.from_markup(brain_line), "")
    table.add_row("Mode", Text.from_markup(mode_line), mode_desc)
    table.add_row("Queue", Text.from_markup(queue_line), queue_detail)
    table.add_row("AI", Text.from_markup(ai_line), ai_detail)

    panel_title = "[bold #C8621A]Patchi Status[/bold #C8621A]"
    if health_grade:
        panel_title += f"  [dim]{health_grade}[/dim]"

    con.print(
        Panel(
            table,
            title=panel_title,
            border_style="#2A3D28",
            padding=(0, 1),
        )
    )
    con.print()


def _run_health(root: Path, json_output: bool) -> None:
    """Detailed health breakdown (was p health)."""
    from patchi.core import health as hm
    from patchi.core import memory as mem

    brain = mem.get_brain(root)
    if not brain or not brain.get("file_count"):
        if json_output:
            import json as _json
            con.print(_json.dumps({"error": "no scan data yet"}))
        else:
            con.print("[yellow]No scan data yet. Run 'p scan' first.[/yellow]")
        return

    score = hm.compute(root)
    if json_output:
        import json as _json
        from dataclasses import asdict, is_dataclass

        payload = (
            asdict(score)
            if is_dataclass(score)
            else (score.__dict__ if hasattr(score, "__dict__") else {"score": str(score)})
        )
        con.print(_json.dumps(payload, indent=2, default=str))
        return

    _show_health(score, brain, root)


def _show_health(score, brain: dict, root: Path) -> None:
    """Render the detailed health breakdown."""
    breakdown = score.breakdown or {}
    components = score.to_dict().get("components", {})

    con.print()
    con.print(
        f"[bold #C8621A]Project Health[/bold #C8621A]  "
        f"[dim]grade {score.grade} · {score.total}/100[/dim]"
    )

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

    weight_map = {
        "security": 0.35,
        "test_coverage": 0.25,
        "dead_code": 0.20,
        "dependency": 0.10,
        "contract": 0.10,
    }

    for comp_key, raw_score in components.items():
        comp_label = comp_key.replace("_", " ").title()
        w = weight_map.get(comp_key, 0)
        weighted = round(raw_score * w, 1)

        color = "#4ADE80" if raw_score >= 80 else ("#FACC15" if raw_score >= 50 else "#FF4D6D")
        detail = _detail_for(comp_key, breakdown)

        table.add_row(
            comp_label,
            Text(f"{raw_score:.0f}", style=color),
            f"{w * 100:.0f}%",
            Text(f"{weighted:.1f}", style="dim"),
            detail,
        )

    con.print(table)
    con.print()

    # ── Project snapshot ───────────────────────────────────────────────────────
    scans = breakdown.get("agents_run", [])
    if scans:
        file_count = breakdown.get("file_count", 0)
        route_count = breakdown.get("route_count", 0)
        fw = breakdown.get("framework", "Unknown")
        circular = breakdown.get("circular_deps", 0)
        patches = breakdown.get("patches_applied", 0)
        test_pct = breakdown.get("test_coverage_pct", 0)

        con.print("[bold]Project snapshot[/bold]")
        con.print(
            f"  [dim]Files:[/dim] {file_count}  [dim]Routes:[/dim] {route_count}  "
            f"[dim]Framework:[/dim] {fw}"
        )
        con.print(
            f"  [dim]Circular deps:[/dim] {circular}  [dim]Tests:[/dim] {test_pct:.0f}% coverage  "
            f"[dim]Patches:[/dim] {patches}"
        )
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
        con.print(
            f"  [dim]{scans['total']} total, "
            f"{scans['critical']} critical, {scans['high']} high, "
            f"{scans['medium']} medium, {scans['low']} low[/dim]"
        )
        con.print()

    # ── Grade scale ────────────────────────────────────────────────────────
    con.print(
        "[dim]Grade scale:  [bold #4ADE80]A[/bold #4ADE80] 90–100  "
        "[bold #86EFAC]B[/bold #86EFAC] 70–89  [bold #FACC15]C[/bold #FACC15] 50–69  "
        "[bold #FB923C]D[/bold #FB923C] 30–49  [bold #FF4D6D]F[/bold #FF4D6D] 0–29[/dim]"
    )
    con.print()

    # ── Actions ────────────────────────────────────────────────────────────────
    actions = []
    if components.get("security", 100) < 70:
        actions.append("[dim]→ Run [bold]p scan[/bold] to scan for vulnerabilities[/dim]")
    if components.get("test_coverage", 100) < 50:
        actions.append("[dim]→ Run [bold]p test[/bold] to check test coverage[/dim]")
    if components.get("dead_code", 100) < 70:
        actions.append("[dim]→ Run [bold]p fix[/bold] to remove dead code[/dim]")
    if components.get("contract", 100) < 60:
        actions.append(
            "[dim]→ Run [bold]p scan[/bold] then [bold]p contract confirm[/bold]"
            " to confirm flows[/dim]"
        )

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
        "dependency": f"{_count(breakdown.get('patches_applied', 0))} applied patches"
        if _count(breakdown.get("patches_applied", 0))
        else "dependency scan active",
        "contract": f"{_count(breakdown.get('agents_run', []))} agents available",
    }
    return details.get(component, "")


def _get_scan_results_summary(root: Path) -> dict:
    """Aggregate finding counts from scan results memory."""
    from patchi.core import memory as mem

    try:
        scans = mem.get_scan_results(root)
    except Exception as e:
        _log.warning("_get_scan_results_summary failed: %s", e)
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    total = critical = high = medium = low = 0
    for _agent_name, data in scans.items():
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


def _run_doctor(root: Path, json_output: bool = False, verbose: bool = False) -> None:
    """System validation checks (was p doctor)."""
    import importlib
    import shutil
    import sys

    if not json_output:
        con.print()
        con.print("[bold #C8621A]Patchi Doctor[/bold #C8621A]  [dim]system health check[/dim]")
        con.print()

    checks: list[tuple[str, str, str, str]] = []  # (label, status, note, color)
    warnings = 0
    errors = 0

    # ── 1. Python version ─────────────────────────────────────────────────────
    pyver = sys.version_info
    if pyver >= (3, 11):
        checks.append(("Python", "✓", f"{pyver.major}.{pyver.minor}.{pyver.micro}", "#4ADE80"))
    else:
        checks.append(("Python", "✗", f"{pyver.major}.{pyver.minor} — requires ≥ 3.11", "#FF4D6D"))
        errors += 1

    # ── 2. Required dependencies ──────────────────────────────────────────────
    _REQUIRED = [
        ("rich", "rich", "Terminal UI rendering"),
        ("watchfiles", "watchfiles", "File watcher (p watch)"),
        ("vulture", "vulture", "Dead code detection"),
        ("httpx", "httpx", "HTTP client (AI requests)"),
        ("fastapi", "fastapi", "Web dashboard backend"),
        ("uvicorn", "uvicorn", "Web dashboard ASGI server"),
        ("psutil", "psutil", "Process + system metrics"),
        ("yaml", "pyyaml", "YAML config parsing"),
        ("loguru", "loguru", "Structured logging"),
    ]

    for import_name, pip_name, desc in _REQUIRED:
        try:
            importlib.import_module(import_name)
            checks.append((f"dep: {pip_name}", "✓", desc, "#4ADE80"))
        except ImportError:
            checks.append((f"dep: {pip_name}", "✗", f"Missing — pip install {pip_name}", "#FF4D6D"))
            errors += 1

    # ── 3. Project root ───────────────────────────────────────────────────────
    from patchi.core.config import find_project_root

    root_found = find_project_root()
    if root_found:
        checks.append(("Project root", "✓", str(root_found), "#4ADE80"))
    else:
        checks.append(("Project root", "⚠", "Not found — run 'p init' first", "#FACC15"))
        warnings += 1

    # ── 4. API keys ───────────────────────────────────────────────────────────
    try:
        from patchi.core import config as cfg

        config = cfg.load(root)
        ai_keys = config.get("ai", {}).get("keys", [])
        if ai_keys:
            checks.append(("API keys", "✓", f"{len(ai_keys)} key(s) configured", "#4ADE80"))
        else:
            checks.append(("API keys", "⚠", "No keys — run 'p key add'", "#FACC15"))
            warnings += 1
    except Exception as e:
        checks.append(("API keys", "✗", str(e)[:60], "#FF4D6D"))
        errors += 1

    # ── 5. Local model (Ollama) ───────────────────────────────────────────────
    try:
        from patchi.core import config as cfg

        local_model = cfg.load(root).get("ai", {}).get("local_model_name")
        if local_model:
            checks.append((f"Ollama: {local_model}", "✓", "Configured", "#4ADE80"))
        else:
            checks.append(("Ollama", "—", "No local model configured (optional)", "#6B7280"))
    except Exception:
        pass

    # ── 6. Optional: test tooling ─────────────────────────────────────────────
    con.print()
    _OPTIONAL_TEST = [
        ("pytest", "pytest", "pytest", "Unit test runner"),
        ("npx", "", "node/npm", "Playwright host"),
        ("locust", "locust", "locust", "Stress test runner"),
    ]
    for cmd, import_name, pip_name, desc in _OPTIONAL_TEST:
        try:
            on_path = shutil.which(cmd) is not None
            importable = import_name and importlib.import_module(import_name)
            present = on_path or bool(importable)
        except ImportError:
            present = False
        status = "✓" if present else "—"
        color = "#4ADE80" if present else "#6B7280"
        note = desc if present else f"Optional — {pip_name}"
        checks.append((f"[dim]opt:[/dim] {cmd}", status, note, color))

    # ── 7. Optional: security tooling ────────────────────────────────────────
    try:
        from patchi.core.agents.tool_health import check_tool

        _OPTIONAL_SECURITY = [
            ("bandit", "bandit", "bandit", "Python security linter"),
            ("semgrep", "", "semgrep", "Multi-language SAST scanner"),
        ]
        for cmd, _import_name, pip_name, desc in _OPTIONAL_SECURITY:
            try:
                st = check_tool(cmd)
                if st["status"] == "ok":
                    note = f"{desc} ({st['version']})"
                    checks.append((
                        f"[dim]opt:[/dim] {cmd}", "✓", note, "#4ADE80"
                    ))
                elif st["status"] == "broken":
                    hint = st["hint"]
                    checks.append((
                        f"[dim]opt:[/dim] {cmd}", "✗", f"Broken: {hint}", "#FF4D6D"
                    ))
                    errors += 1
                else:
                    note = f"Optional — {pip_name}"
                    checks.append((
                        f"[dim]opt:[/dim] {cmd}", "—", note, "#6B7280"
                    ))
            except Exception:
                note = f"Optional — {pip_name}"
                checks.append((
                    f"[dim]opt:[/dim] {cmd}", "—", note, "#6B7280"
                ))
    except ImportError:
        pass

    # ── 8. .patchi/ size warning ─────────────────────────────────────────────
    try:
        from patchi.cli.commands.cleanup_cmd import get_patchi_size

        size_info = get_patchi_size(root)
        total_bytes = size_info["total_bytes"]
        total_files = size_info["total_files"]

        mb = total_bytes / (1024 * 1024)
        if total_bytes > 50 * 1024 * 1024:
            size_str = f"{mb:.1f} MB"
            warn_msg = f"{size_str} ({total_files} files) — consider 'p cleanup'"
            checks.append((".patchi/ size", "⚠", warn_msg, "#FACC15"))
            warnings += 1
        else:
            if total_bytes >= 1024 * 1024:
                size_str = f"{mb:.1f} MB"
            else:
                size_str = f"{total_bytes / 1024:.1f} KB"
            info_msg = f"{size_str} ({total_files} files)"
            checks.append((".patchi/ size", "✓", info_msg, "#4ADE80"))
    except Exception:
        pass

    # ── 9. Stale commands check ────────────────────────────────────────────────
    try:
        from patchi.cli.registry import COMMANDS

        stale_commands = {
            "brain": "Merged into 'p agents list --brain'",
            "smart": "Merged into 'p chat --stream'",
            "health": "Merged into 'p status --deep'",
            "doctor": "Merged into 'p status --validate'",
            "security": "Merged into 'p scan'",
            "ignore": "Merged into 'p memory ignore'",
        }

        cmd_names = [cmd.name for cmd in COMMANDS]
        for name, suggestion in stale_commands.items():
            if name not in cmd_names:
                checks.append((f"stale: {name}", "⚠", f"Removed — {suggestion}", "#FACC15"))
                warnings += 1

        if not any(name not in cmd_names for name in stale_commands):
            checks.append(("command hygiene", "✓", "No stale commands found", "#4ADE80"))
    except Exception:
        pass

    # ── Render results ────────────────────────────────────────────────────────
    if json_output:
        import json as _json

        con.print(
            _json.dumps(
                {
                    "ok": errors == 0,
                    "errors": errors,
                    "warnings": warnings,
                    "checks": [
                        {"label": label, "status": status.strip(), "note": note}
                        for label, status, note, _color in checks
                    ],
                },
                indent=2,
            )
        )
        return

    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
    table.add_column("Status", width=4)
    table.add_column("Check", style="bold #F2EDD6", width=28)
    table.add_column("Note", style="dim", width=55)

    for label, status, note, color in checks:
        table.add_row(Text(status, style=color), label, note)

    con.print(table)

    # ── Summary ───────────────────────────────────────────────────────────────
    con.print()
    if errors == 0 and warnings == 0:
        con.print(
            Panel(
                "[bold #4ADE80]All checks passed. Patchi is ready.[/bold #4ADE80]",
                border_style="#4ADE80",
                padding=(0, 1),
            )
        )
    elif errors == 0:
        con.print(
            Panel(
                f"[bold #FACC15]{warnings} warning(s). Core functionality OK.[/bold #FACC15]",
                border_style="#FACC15",
                padding=(0, 1),
            )
        )
    else:
        con.print(
            Panel(
                f"[bold #FF4D6D]{errors} error(s), {warnings} warning(s)"
                f". Fix errors above.[/bold #FF4D6D]",
                border_style="#FF4D6D",
                padding=(0, 1),
            )
        )
    con.print()
