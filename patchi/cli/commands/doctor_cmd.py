"""
`p doctor` — System health check and stale command detection.

Checks:
  1. Stale/removed commands that should be migrated
  2. Missing dependencies
  3. API key configuration
  4. .patchi/ size warnings
  5. Config validation
"""

from __future__ import annotations

import importlib
import shutil
import sys
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con


def run(verbose: bool = False, json_output: bool = False) -> None:
    """Entry point for `p doctor`."""
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
    try:
        from patchi.core.config import find_project_root

        root = find_project_root()
        if root:
            checks.append(("Project root", "✓", str(root), "#4ADE80"))
        else:
            checks.append(("Project root", "⚠", "Not found — run 'p init' first", "#FACC15"))
            warnings += 1
    except Exception as e:
        checks.append(("Project root", "✗", str(e)[:60], "#FF4D6D"))
        errors += 1
        root = None

    # ── 4. Stale commands check ────────────────────────────────────────────────
    try:
        from patchi.cli.registry import COMMANDS

        stale_commands = {
            "brain": {
                "replacement": "p agents list --brain",
                "reason": "Merged into agents command",
            },
            "smart": {
                "replacement": "p chat --stream",
                "reason": "Merged into chat command",
            },
            "health": {
                "replacement": "p status --deep",
                "reason": "Merged into status command",
            },
            "doctor": {
                "replacement": "p status --validate",
                "reason": "Merged into status command (this command is the standalone check)",
            },
            "security": {
                "replacement": "p scan",
                "reason": "Merged into scan command",
            },
            "ignore": {
                "replacement": "p memory ignore",
                "reason": "Merged into memory command",
            },
            "explain": {
                "replacement": "p chat 'explain <type>'",
                "reason": "Merged into chat command",
            },
            "profile": {
                "replacement": "p agent-stats",
                "reason": "Merged into agent-stats command",
            },
            "learning": {
                "replacement": "p agent-stats --learning",
                "reason": "Merged into agent-stats command",
            },
            "ask": {
                "replacement": "p chat",
                "reason": "Alias — chat is the unified interface",
            },
        }

        cmd_names = [cmd.name for cmd in COMMANDS]
        found_stale = []
        for name, info in stale_commands.items():
            if name not in cmd_names:
                found_stale.append((name, info))

        if found_stale:
            con.print("[bold]Stale Commands Detected[/bold]")
            con.print("[dim]These commands have been merged or removed. Update your scripts:[/dim]")
            con.print()

            table = Table(show_header=True, header_style="bold #C8621A", box=None)
            table.add_column("Command", style="red", width=15)
            table.add_column("Replacement", style="green", width=25)
            table.add_column("Reason", style="dim")

            for name, info in found_stale:
                table.add_row(
                    f"p {name}",
                    info["replacement"],
                    info["reason"],
                )
                warnings += 1

            con.print(table)
            con.print()
        else:
            checks.append(("Stale commands", "✓", "No stale commands found", "#4ADE80"))
    except Exception as e:
        _log.warning("Stale command check failed: %s", e)

    # ── 5. API keys ───────────────────────────────────────────────────────────
    if root:
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

    # ── 6. Optional: test tooling ─────────────────────────────────────────────
    con.print()
    _OPTIONAL_TEST = [
        ("pytest", "pytest", "pytest", "Unit test runner"),
        ("npx", "", "node/npm", "Playwright host"),
        ("locust", "locust", "locust", "Stress test runner"),
    ]
    for cmd, import_name, pip_name, desc in _OPTIONAL_TEST:
        try:
            present = (shutil.which(cmd) is not None) or (
                import_name and importlib.import_module(import_name)
            )
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
                    checks.append((f"[dim]opt:[/dim] {cmd}", "✓", note, "#4ADE80"))
                elif st["status"] == "broken":
                    hint = st["hint"]
                    checks.append(
                        (f"[dim]opt:[/dim] {cmd}", "✗", f"Broken: {hint}", "#FF4D6D")
                    )
                    errors += 1
                else:
                    note = f"Optional — {pip_name}"
                    checks.append((f"[dim]opt:[/dim] {cmd}", "—", note, "#6B7280"))
            except Exception:
                note = f"Optional — {pip_name}"
                checks.append((f"[dim]opt:[/dim] {cmd}", "—", note, "#6B7280"))
    except ImportError:
        pass

    # ── 8. .patchi/ size warning ─────────────────────────────────────────────
    if root:
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
                f"[bold #FF4D6D]{errors} error(s), {warnings} warning(s). Fix errors above.[/bold #FF4D6D]",
                border_style="#FF4D6D",
                padding=(0, 1),
            )
        )
    con.print()
