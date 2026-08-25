"""
`p dev` — Developer utilities, testing docs, and diagnostics.

Usage:
  p dev                        — show all development info
  p dev info                   — show project health, config, security status
  p dev test                   — show testing tool documentation
  p dev playwright             — show Playwright/browser testing docs
  p dev security               — show security pipeline status
  p dev docs                   — show all CLI commands reference
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from patchi.cli.console import con
from patchi.core import config as cfg
from patchi.core.agents.base import AgentGroup, list_agents

_log = logging.getLogger("patchi.cli.dev_cmd")

def run(action: str | None = None, verbose: bool = False) -> None:

    if action == "test":
        _show_test_docs(con)
    elif action == "playwright":
        _show_playwright_docs(con)
    elif action == "security":
        _show_security_status(con)
    elif action == "docs":
        _show_cli_reference(con)
    else:
        _show_dev_overview(con, verbose)

def _show_dev_overview(con: Console, verbose: bool) -> None:
    con.print()
    con.print(Panel.fit("[bold cyan]Patchi Developer Console[/bold cyan]", border_style="cyan"))
    con.print()

    try:
        root = cfg.require_project_root()
        config = cfg.load(root)
    except Exception as e:
        _log.warning("_show_dev_overview failed: %s", e)
        root = None
        config = {}

    info = Table.grid(padding=(0, 2))
    info.add_column()
    info.add_column()

    info.add_row("[bold]Project Root:[/bold]", str(root or "Not initialized"))
    mode = config.get("mode", "unknown")
    info.add_row("[bold]Mode:[/bold]", mode)
    pipeline_enabled = config.get("pipeline", {}).get("enabled", False)
    info.add_row("[bold]Security Pipeline:[/bold]", "ENABLED" if pipeline_enabled else "DISABLED")
    interceptor_enabled = config.get("pipeline", {}).get("interceptor", {}).get("enabled", False)
    info.add_row("[bold]Request Interceptor:[/bold]", "ENABLED" if interceptor_enabled else "DISABLED")
    ai_keys = config.get("ai", {}).get("keys", [])
    info.add_row("[bold]AI Keys:[/bold]", f"{len(ai_keys)} configured")
    info.add_row("[bold]Agent Queue:[/bold]", config.get("queue_mode", "single"))
    info.add_row("[bold]Version:[/bold]", _get_version())
    con.print(info)
    con.print()

    _show_quick_commands(con)
    con.print()
    con.print("[dim]Run [bold]p dev test[/bold] for testing docs, [bold]p dev security[/bold] for security status, [bold]p dev docs[/bold] for all commands[/dim]")

def _show_quick_commands(con: Console) -> None:
    t = Table(title="Quick Reference", box=None)
    t.add_column("Command", style="cyan")
    t.add_column("Description")
    t.add_row("p dev test", "Show all testing tools and commands")
    t.add_row("p dev playwright", "Show Playwright/browser testing docs")
    t.add_row("p dev security", "Show security pipeline status")
    t.add_row("p dev docs", "Show all CLI commands reference")
    t.add_row("p scan", "Run a full scan")
    t.add_row("p scan --pipeline", "Run scan with full security pipeline")
    t.add_row("p security all", "Run all 34 security agents")
    t.add_row("p test full", "Run all test agents")
    t.add_row("p test smoke", "Quick smoke test (buttons + layout + a11y)")
    t.add_row("p test e2e", "AI-generated Playwright E2E tests")
    t.add_row("p web", "Launch the Patchi web dashboard")
    t.add_row("p doctor", "Validate setup and dependencies")
    t.add_row("p audit", "Full project audit in one shot")
    con.print(t)

def _show_test_docs(con: Console) -> None:
    con.print()
    con.print(Panel.fit("[bold yellow]Testing Tools Reference[/bold yellow]", border_style="yellow"))
    con.print()

    t = Table(title="Test Commands")
    t.add_column("Command", style="cyan")
    t.add_column("Type")
    t.add_column("Description")

    t.add_row("p test", "default", "Run unit + regression tests")
    t.add_row("p test unit", "unit", "Run pytest/unittest/jest/mocha tests via UnitTestAgent")
    t.add_row("p test browser", "browser", "Run Playwright critical-flow tests via BrowserTestAgent")
    t.add_row("p test e2e", "e2e", "AI-generated end-to-end Playwright tests via E2EFlowAgent")
    t.add_row("p test buttons", "buttons", "Button/form/interaction tests via UIButtonAgent")
    t.add_row("p test layout", "layout", "Responsive layout tests at 320/768/1024/1440px via UILayoutAgent")
    t.add_row("p test accessibility", "accessibility", "WCAG a11y via axe-core injection via UIAccessibilityAgent")
    t.add_row("p test visual", "visual", "Screenshot comparison at 3 viewports via VisualRegressionAgent")
    t.add_row("p test api", "api", "OpenAPI/JSON Schema contract tests via APIContractAgent")
    t.add_row("p test stress", "stress", "Locust load testing via StressTestAgent")
    t.add_row("p test security", "security", "Route-specific security pytest generation via SecurityTestAgent")
    t.add_row("p test regression", "regression", "Snapshot-based regression tests via RegressionAgent")
    t.add_row("p test smoke", "smoke", "Quick smoke: buttons + layout + accessibility")
    t.add_row("p test full", "full", f"ALL test agents ({len(list_agents(AgentGroup.TEST))} agents)")
    t.add_row("p test generate", "generate", "AI generates a full test suite")
    t.add_row("p test report", "report", "Show test run history (last 50)")
    t.add_row("p test config show", "config", "Show test configuration")
    t.add_row("p test config set <k> <v>", "config", "Set a config value")
    t.add_row("p security browsertest", "security", "Security-focused Playwright browser tests")

    con.print(t)
    con.print()

    t2 = Table(title="Test Agents (12 total)")
    t2.add_column("Agent", style="green")
    t2.add_column("File")
    t2.add_column("Framework")

    t2.add_row("UnitTestAgent", "unit_test_agent.py", "pytest / jest / mocha")
    t2.add_row("BrowserTestAgent", "browser_test_agent.py", "Playwright")
    t2.add_row("E2EFlowAgent", "e2e_flow_agent.py", "Playwright + AI")
    t2.add_row("UIButtonAgent", "ui_button_agent.py", "Playwright")
    t2.add_row("UILayoutAgent", "ui_layout_agent.py", "Playwright")
    t2.add_row("UIAccessibilityAgent", "ui_accessibility_agent.py", "Playwright + axe-core")
    t2.add_row("VisualRegressionAgent", "visual_regression_agent.py", "Playwright screenshots")
    t2.add_row("AccessibilityAgent", "accessibility_agent.py", "Playwright + axe-core")
    t2.add_row("APIContractAgent", "api_contract_agent.py", "OpenAPI / JSON Schema")
    t2.add_row("RegressionAgent", "regression_agent.py", "Snapshot baselines")
    t2.add_row("StressTestAgent", "stress_test_agent.py", "Locust")
    t2.add_row("SecurityTestAgent", "security_test_agent.py", "pytest generation")

    con.print(t2)
    con.print()

    t3 = Table(title="Security Tester", box=None)
    t3.add_column("Tool", style="red")
    t3.add_column("Description")
    t3.add_row("BrowserTesterAgent (security)", "Playwright auth bypass / XSS / SQLi testing")
    con.print(t3)

def _show_playwright_docs(con: Console) -> None:
    con.print()
    con.print(Panel.fit("[bold magenta]Playwright / Browser Testing Reference[/bold magenta]", border_style="magenta"))
    con.print()

    t = Table(title="Playwright Test Types")
    t.add_column("Command", style="cyan")
    t.add_column("What It Tests")
    t.add_column("Viewports")

    t.add_row("p test browser", "Critical flows: login, forms, navigation, API calls", "N/A")
    t.add_row("p test e2e", "AI-generated full user flows", "N/A")
    t.add_row("p test buttons", "Buttons, forms, hover/focus, keyboard, disabled states", "N/A")
    t.add_row("p test layout", "Responsive design, overflow, overlap, touch targets", "320 / 768 / 1024 / 1440")
    t.add_row("p test accessibility", "WCAG: contrast, alt text, labels, ARIA, landmarks", "N/A")
    t.add_row("p test visual", "Screenshot diff detection", "375 / 768 / 1440")
    t.add_row("p security browsertest", "Auth bypass, XSS injection, SQLi injection", "N/A")

    con.print(t)
    con.print()

    con.print("[bold]Playwright Browsers:[/bold]")
    con.print("  Playwright is a core dependency (playwright>=1.40 in pyproject.toml)")
    con.print("  Browser binaries must be installed separately:")
    con.print()
    con.print("  [bold]p npm playwright install chromium[/bold]   — or —")
    con.print("  [bold]playwright install chromium[/bold]          — in activated venv")
    con.print()
    con.print("[dim]All Playwright agents gracefully skip if Playwright is not installed.[/dim]")
    con.print()

    con.print("[bold]Web UI Events for Test Agents:[/bold]")
    con.print("  test.suite.started    — When a test run begins")
    con.print("  test.case.passed      — Individual test passed")
    con.print("  test.case.failed      — Individual test failed (screenshot on fail)")
    con.print("  test.browser.flow_started  — Browser flow started")
    con.print("  test.browser.step_passed   — Browser step passed")
    con.print("  test.browser.step_failed   — Browser step failed")
    con.print("  test.stress.update         — Load test stats")
    con.print("  test.stress.break_found    — Load test breakpoint")
    con.print()
    con.print("[dim]Open [bold]p web[/bold] and watch the dashboard while tests run![/dim]")

def _show_security_status(con: Console) -> None:
    con.print()
    con.print(Panel.fit("[bold red]Security Pipeline Status[/bold red]", border_style="red"))
    con.print()

    try:
        root = cfg.require_project_root()
        config = cfg.load(root)
    except Exception as e:
        _log.warning("_show_security_status failed: %s", e)
        root = None
        config = {}

    pipeline = config.get("pipeline", {})
    interceptor = pipeline.get("interceptor", {})
    ai_keys = config.get("ai", {}).get("keys", [])

    t = Table(box=None)
    t.add_column("Component", style="cyan")
    t.add_column("Status")
    t.add_column("Detail")

    t.add_row("Security Pipeline", "ENABLED" if pipeline.get("enabled") else "DISABLED", "DetectionPipeline + ConfidenceGate + Layer2Orchestrator + DefenseLayer")
    t.add_row("Request Interceptor", "ENABLED" if interceptor.get("enabled") else "DISABLED", f"ASGI middleware, threshold={interceptor.get('block_threshold', 0.7)}, rate={interceptor.get('rate_limit', 100)}/min")
    t.add_row("Security Agents", f"{len(list_agents(AgentGroup.SECURITY))} agents", "All registered via @register decorator")
    t.add_row("ConfidenceGate", "Active", "Routes findings: defend / ai_analyze / human_review / discard")
    t.add_row("Layer2 AI", "Active" if ai_keys else "No AI keys", "Batches medium-confidence findings for AI confirmation")
    t.add_row("DefenseLayer", "Active", "Creates patches / blocks IPs / rotates secrets / escalates")
    t.add_row("RiskGate", "Always active", "Enforces mode, no-touch paths, quiet hours, secrets gate")
    t.add_row("Sigma Engine", "Standby", "Loaded from .patchi/sigma/ (if rules exist)")
    t.add_row("SecretsGuard", "Always active", "Gate-checks proposed code for secrets before apply")

    con.print(t)
    con.print()

    con.print("[bold]Security Commands:[/bold]")
    con.print("  p security all            — Run all 34 security scanners")
    con.print("  p security <type>         — Run specific security scan (sqli, xss, jwt, crypto, etc.)")
    con.print("  p security report         — Show correlated security report")
    con.print("  p security browsertest    — Run Playwright security browser tests")
    con.print("  p scan --pipeline         — Full scan + security pipeline + auto-defense")
    con.print("  p audit                   — Full project audit in one shot")
    con.print()
    con.print("[bold]Defense Actions:[/bold]")
    con.print("  fix_code         — Creates Patch, passes RiskGate, applies if allowed")
    con.print("  update_dependency — Runs pip/npm update + patches manifest")
    con.print("  block_ip         — Persists to .patchi/blocked_ips.json + iptables")
    con.print("  rotate_secret    — Generates 256-bit secret, replaces in .env")
    con.print("  patch_config     — Edits config files with known-good values")
    con.print("  auth_middleware  — Adds auth middleware/decorator templates")
    con.print("  invalidate_session — Queues to .patchi/invalidate_sessions.json")
    con.print("  suspend_account  — Queues to .patchi/suspend_accounts.json")
    con.print("  block_ws_origin  — Persists to .patchi/blocked_ws_origins.json")

def _show_cli_reference(con: Console) -> None:
    con.print()
    con.print(Panel.fit("[bold green]Patchi CLI Reference — All Commands[/bold green]", border_style="green"))
    con.print()

    t = Table(box=None)
    t.add_column("Command", style="cyan", width=20)
    t.add_column("Description")
    t.add_column("File")

    cmds = [
        ("p init", "Initialize .patchi in a project", "init.py (436 lines)"),
        ("p scan", "Run scanner agents", "scan_cmd.py (947 lines)"),
        ("p status", "Show project health overview", "status_cmd.py (167 lines)"),
        ("p watch", "Watch mode — auto-rescan on file changes", "watch_cmd.py (109 lines)"),
        ("p doctor", "Validate setup, check deps, test AI", "doctor_cmd.py (386 lines)"),
        ("p fix", "Auto-fix findings", "fix_cmd.py (374 lines)"),
        ("p review", "Review pending patches", "review_cmd.py (225 lines)"),
        ("p patch", "Manage patches (list/show/apply/reject)", "patch_cmd.py (215 lines)"),
        ("p undo / redo / rollback", "Undo/redo/rollback patches", "undo_cmd.py (233 lines)"),
        ("p test", f"Run test agents ({len(list_agents(AgentGroup.TEST))} types)", "test_cmd.py (699 lines)"),
        ("p security", f"Run security agents ({len(list_agents(AgentGroup.SECURITY))} types)", "security_cmd.py (538 lines)"),
        ("p memory", "Show/manage brain memory", "memory_cmd.py (219 lines)"),
        ("p queue", "Manage agent queue", "queue_cmd.py (154 lines)"),
        ("p mode", "Set confirm/auto/autopilot mode", "mode_cmd.py (78 lines)"),
        ("p restrict", "Add/remove path restrictions", "restrict_cmd.py (128 lines)"),
        ("p settings", "Show/edit settings", "inline in main.py"),
        ("p key", "Manage API keys (10 providers)", "key_cmd.py (505 lines)"),
        ("p ai", "AI status, test, horde management", "ai_cmd.py (205 lines)"),
        ("p model", "Set/list AI models", "model_cmd.py (205 lines)"),
        ("p access", "Manage dev access tokens", "inline in main.py"),
        ("p notify", "Notification channels", "notify_cmd.py (213 lines)"),
        ("p agents", "List/status/reset agents", "agents_cmd.py (185 lines)"),
        ("p hosted", "Hosted mode management", "hosted_cmd.py (957 lines)"),
        ("p report", "Export reports (JSON/HTML/markdown)", "report_cmd.py (414 lines)"),
        ("p chat", "Interactive AI chat", "chat_cmd.py (134 lines)"),
        ("p web", "Launch web dashboard", "web_cmd.py (102 lines)"),
        ("p explain", "Explain a finding", "explain_cmd.py (330 lines)"),
        ("p blast", "Blast radius analysis", "blast_cmd.py (318 lines)"),
        ("p brain", "Generate BRAIN.md knowledge file", "brain_cmd.py (305 lines)"),
        ("p trend", "Health quality trends", "trend_cmd.py (298 lines)"),
        ("p blame", "Git blame for a file", "blame_cmd.py (52 lines)"),
        ("p log", "Git changelog", "log_cmd.py (59 lines)"),
        ("p deps", "Supply chain security scan", "deps_cmd.py (79 lines)"),
        ("p audit", "Full project audit in one shot", "audit_cmd.py (381 lines)"),
        ("p learn", "Learn project conventions", "learn_cmd.py (375 lines)"),
        ("p dev", "Developer utilities (this command)", "dev_cmd.py"),
    ]

    for cmd, desc, src in cmds:
        t.add_row(cmd, desc, src)

    con.print(t)

def _get_version() -> str:
    try:
        from patchi import __version__
        return __version__
    except Exception as e:
        _log.warning("_get_version failed: %s", e)
        return "unknown"
