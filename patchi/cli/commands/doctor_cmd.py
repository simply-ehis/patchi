"""
`p doctor` — System health check and stale command detection.

Checks:
  1. Stale/removed commands that should be migrated
  2. Missing dependencies
  3. API key configuration
  4. .patchi/ size warnings
  5. Config validation
  6. External security tooling — the full unified registry (Part 3 §2),
     every tool any agent may use, present/broken/missing with the exact
     install command. `p doctor --install` attempts the pip/npm-installable
     ones automatically and prints the manual command for the rest.
"""

from __future__ import annotations

import importlib
import logging
import pathlib
import re
import shutil
import subprocess
import sys

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con

_log = logging.getLogger("patchi.cli.doctor")

# ── Tool installer (Part 3 §2.4) ─────────────────────────────────────────────

_AUTO_TIMEOUT_S = 600  # pip/npm/go installs can be slow; go builds slower still


def _run_installer(cmd: list[str]) -> tuple[bool, str]:
    """Run one install command. Returns (ok, tail-of-output). Never raises."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=_AUTO_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {_AUTO_TIMEOUT_S}s"
    except OSError as e:
        return False, str(e)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    tail = "\n".join(out.splitlines()[-3:]) if out else ""
    return proc.returncode == 0, tail


def _auto_install_tools(only: str | None = None) -> int:
    """`p doctor --install [--only GROUP]` — attempt the installable tools,
    print the rest.

    With ``only`` set, the pass is scoped to one tool group (sast, dast,
    secrets, supply-chain, ...) so CI can install just the tier it needs.
    Group names are validated against the tool registry.

    Returns a process exit code: 0 = everything available afterwards,
    1 = some tools still missing/broken (each with its manual command).
    """
    from patchi.core.agents.tool_health import check_tool, list_tools, tool_groups

    _groups = tool_groups()
    if only is not None and only not in _groups:
        con.print(f"[red]Unknown tool group: {only!r}[/red]")
        con.print(f"[dim]Valid groups: {', '.join(_groups)}[/dim]")
        return 2

    scope_label = f" — [bold]{only}[/bold] tools only" if only else ""
    still_manual: list[tuple[str, str]] = []  # (tool, manual command)
    attempted = 0
    installed = 0

    con.print()
    con.print(
        f"[bold #C8621A]Tooling install{scope_label}[/bold #C8621A]"
        f"  [dim]auto-install what I can, print the rest[/dim]"
    )
    con.print()

    for tool in list_tools(only):
        st = check_tool(tool["name"])
        if st["status"] == "ok":
            ver = f" ({st['version']})" if st["version"] else ""
            con.print(f"  [#4ADE80]✓[/#4ADE80] {tool['name']}[dim]{ver} — already present[/dim]")
            continue

        how = tool.get("auto")
        _pkg = tool.get("pkg") or tool.get("go_pkg") or tool["name"]
        # Windows: npm/go are .cmd shims — spawn fails with WinError 2 unless
        # resolved to their full path via shutil.which. And when the installer
        # itself is absent (no Go toolchain), classify as manual instead of
        # attempting a spawn that can only fail.
        _npm = shutil.which("npm")
        _go = shutil.which("go")
        _pw_module = importlib.util.find_spec("playwright") is not None
        _installer_present = {
            "pip": True,  # always available via sys.executable -m pip
            "npm": _npm is not None,
            "go": _go is not None,
            "playwright": _pw_module,  # browser binaries need the pip package
        }.get(how or "", False)
        cmd_map = {
            "pip": [sys.executable, "-m", "pip", "install", _pkg],
            "npm": [(_npm or "npm"), "install", "-g", _pkg],
            "go": [(_go or "go"), "install", tool["go_pkg"]] if tool.get("go_pkg") else None,
            "playwright": [sys.executable, "-m", "playwright", "install", "chromium"],
        }
        cmd = cmd_map.get(how) if how else None
        if cmd is not None and not _installer_present:
            still_manual.append((tool["name"], tool["install"]))
            _why = {
                "npm": "npm not found",
                "go": "Go toolchain not found",
                "playwright": "playwright package not installed",
            }.get(how or "", "installer unavailable")
            con.print(f"  [dim]— {tool['name']}: manual ({_why}) — {tool['install']}[/dim]")
            continue

        if cmd is None:
            still_manual.append((tool["name"], tool["install"]))
            con.print(f"  [dim]— {tool['name']}: manual — {tool['install']}[/dim]")
            continue

        attempted += 1
        con.print(f"  [#C8621A]…[/#C8621A] installing [bold]{tool['name']}[/bold] [dim]({' '.join(cmd)})[/dim]")
        ok, tail = _run_installer(cmd)
        if ok and check_tool(tool["name"])["status"] == "ok":
            installed += 1
            con.print(f"  [#4ADE80]✓[/#4ADE80] {tool['name']} installed")
        else:
            still_manual.append((tool["name"], tool["install"]))
            _fail_note = " — " + tail if tail else ""
            con.print(f"  [#FF4D6D]✗[/#FF4D6D] {tool['name']} failed{_fail_note}")
            con.print(f"      [dim]try manually: {tool['install']}[/dim]")

    # Playwright browser binaries when the package is present but browsers are not
    pw = check_tool("playwright")
    if pw["status"] == "broken" and "binaries missing" in pw["hint"]:
        attempted += 1
        con.print(
            "  [#C8621A]…[/#C8621A] installing [bold]playwright browser binaries[/bold] (playwright install chromium)"
        )
        ok, tail = _run_installer([sys.executable, "-m", "playwright", "install", "chromium"])
        if ok and check_tool("playwright")["status"] == "ok":
            installed += 1
            con.print("  [#4ADE80]✓[/#4ADE80] playwright browser binaries installed")
        else:
            _pw_fail_note = " — " + tail if tail else ""
            con.print(f"  [#FF4D6D]✗[/#FF4D6D] playwright browsers failed{_pw_fail_note}")
            con.print("      [dim]try manually: playwright install chromium[/dim]")

    con.print()
    if attempted:
        con.print(f"  Attempted [bold]{attempted}[/bold] auto-install(s); [bold]{installed}[/bold] succeeded.")
    if still_manual:
        con.print(
            f"  [#FACC15]{len(still_manual)} tool(s) need manual installation"
            f"{' in ' + only if only else ''}:[/#FACC15]"
        )
        for name, hint in still_manual:
            con.print(f"    · {name}: [dim]{hint}[/dim]")
        return 1
    con.print("[#4ADE80]All registered tools available.[/#4ADE80]")
    return 0


# ── Stale reference auto-fixer ───────────────────────────────────────

# Patterns to search: "p <old>" as a shell command in any text file
# We match whole-word to avoid false positives (e.g. "p status" shouldn't match "p status --deep")


def _build_replacement_patterns(
    found_stale: list[tuple[str, dict]],
) -> list[tuple[re.Pattern, str]]:
    """Build regex patterns for each stale command."""
    patterns = []
    for name, info in found_stale:
        replacement = info["replacement"]
        # Match: p <old> as a standalone command (word boundary after)
        # Handles: "p brain", "p brain ", "p brain\n", "p brain'"
        # Also handles: "patchi brain", "python -m patchi brain"
        pat = re.compile(
            r"(\b)(?:p|patchi|python\s+-m\s+patchi)\s+" + re.escape(name) + r"(\s|\'|\"|$)",
            re.MULTILINE,
        )
        patterns.append((pat, replacement))
    return patterns


def _fix_stale_references(
    root: pathlib.Path | None,
    found_stale: list[tuple[str, dict]],
) -> None:
    """Scan scripts/ and common locations for stale command references and fix them."""
    if not root or not root.exists():
        con.print("[yellow]No project root — skipping auto-fix.[/yellow]")
        return

    patterns = _build_replacement_patterns(found_stale)

    # Directories to scan
    scan_dirs = []
    for d in ["scripts", ".github", ".gitlab", ".circleci", "ci", "bin"]:
        p = root / d
        if p.is_dir():
            scan_dirs.append(p)

    # Also scan root-level shell scripts and config files
    scan_files = list(root.glob("*.sh")) + list(root.glob("*.bash")) + list(root.glob("*.zsh"))
    scan_files += list(root.glob("Makefile")) + list(root.glob("*.mk"))
    scan_files += list(root.glob("*.yml")) + list(root.glob("*.yaml"))
    scan_files += list(root.glob("*.toml")) + list(root.glob("*.cfg"))
    scan_files += list(root.glob("*.ini"))
    scan_files += list(root.glob("docker*"))
    scan_files += list(root.glob("*.bat")) + list(root.glob("*.cmd")) + list(root.glob("*.ps1"))

    total_fixed = 0
    fixed_files = []

    # Scan directories recursively
    for scan_dir in scan_dirs:
        for fpath in scan_dir.rglob("*"):
            if fpath.is_file() and _is_text_file(fpath):
                fixed = _fix_file(fpath, patterns)
                if fixed > 0:
                    total_fixed += fixed
                    fixed_files.append((fpath, fixed))

    # Scan root-level files
    for fpath in scan_files:
        if fpath.is_file() and _is_text_file(fpath):
            fixed = _fix_file(fpath, patterns)
            if fixed > 0:
                total_fixed += fixed
                fixed_files.append((fpath, fixed))

    # Report results
    if total_fixed == 0:
        con.print("[green]✓ No stale references found in scripts/.[/green]")
    else:
        con.print(f"\n[bold green]✓ Fixed {total_fixed} stale reference(s) in {len(fixed_files)} file(s):[/bold green]")
        con.print()
        for fpath, count in fixed_files:
            rel = fpath.relative_to(root) if fpath.is_relative_to(root) else fpath
            con.print(f"  [cyan]{rel}[/cyan] — {count} replacement(s)")
        con.print()
        con.print("[dim]Review the changes with `git diff` before committing.[/dim]")


def _is_text_file(fpath: pathlib.Path) -> bool:
    """Check if a file is likely a text file (not binary)."""
    text_exts = {
        ".sh",
        ".bash",
        ".zsh",
        ".bat",
        ".cmd",
        ".ps1",
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".yml",
        ".yaml",
        ".toml",
        ".cfg",
        ".ini",
        ".conf",
        ".md",
        ".rst",
        ".txt",
        "Makefile",
        "Dockerfile",
        ".dockerfile",
        ".mk",
        ".cmake",
    }
    if fpath.name in text_exts or fpath.suffix in text_exts:
        return True
    # Check if it has no extension but is small (likely a script)
    if not fpath.suffix and fpath.stat().st_size < 100_000:
        try:
            fpath.read_text(encoding="utf-8")[:100]
            return True
        except (UnicodeDecodeError, OSError):
            return False
    return False


def _fix_file(fpath: pathlib.Path, patterns: list[tuple[re.Pattern, str]]) -> int:
    """Replace stale references in a file. Returns number of replacements."""
    try:
        text = fpath.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return 0

    new_text = text
    total = 0
    for pat, replacement in patterns:
        new_text, n = pat.subn(replacement, new_text)
        total += n

    if total > 0 and new_text != text:
        fpath.write_text(new_text, encoding="utf-8")
    return total


def run(
    verbose: bool = False,
    json_output: bool = False,
    fix: bool = False,
    install: bool = False,
    only: str | None = None,
) -> None:
    """Entry point for `p doctor`."""
    if install:
        # §2.4: the real install path — attempts pip/npm/go/playwright
        # installs, prints manual commands for the rest, exits non-zero when
        # anything is still missing so agents/CI can react. --only scopes the
        # pass to one tool group so CI installs just the tier it needs.
        raise SystemExit(_auto_install_tools(only))
    if only:
        con.print("[yellow]--only has no effect without --install[/yellow]")
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
            "reason": "Merged into status command",
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
        "chain": {
            "replacement": "p chains",
            "reason": "Merged into chains command (plural)",
        },
        "mode": {
            "replacement": "p settings mode",
            "reason": "Merged into settings command",
        },
        "reason": {
            "replacement": "p chat 'reason about <topic>'",
            "reason": "Merged into chat command",
        },
        "blast": {
            "replacement": "p impact",
            "reason": "Renamed to impact command",
        },
    }

    try:
        from patchi.cli.registry import COMMANDS

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

            # ── --fix: auto-update stale references in scripts/ ──
            if fix:
                _fix_stale_references(root, found_stale)
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
            present = (shutil.which(cmd) is not None) or (import_name and importlib.import_module(import_name))
        except ImportError:
            present = False
        status = "✓" if present else "—"
        color = "#4ADE80" if present else "#6B7280"
        note = desc if present else f"Optional — {pip_name}"
        checks.append((f"[dim]opt:[/dim] {cmd}", status, note, color))

    # ── 7. Security tooling: full registry (Part 3 §2) ─────────────────────
    # Every tool any agent may use, whether present, and the exact install
    # command when missing — not just the two that happened to be checked.
    try:
        from patchi.core.agents.tool_health import check_tool, list_tools

        _last_group = ""
        _tools = sorted(
            (t for t in list_tools() if t["group"] not in ("platform", "ai")),
            key=lambda t: (t["group"], t["name"]),
        )
        for tool in _tools:
            if tool["group"] != _last_group:
                _last_group = tool["group"]
                checks.append((f"[bold]— {tool['group']} —[/bold]", "", "", "#6B7280"))
            try:
                st = check_tool(tool["name"])
                if st["status"] == "ok":
                    ver = f" ({st['version']})" if st["version"] else ""
                    checks.append((f"[dim]opt:[/dim] {tool['name']}", "✓", f"{tool['desc']}{ver}", "#4ADE80"))
                elif st["status"] == "broken":
                    checks.append((f"[dim]opt:[/dim] {tool['name']}", "✗", f"Broken: {st['hint']}", "#FF4D6D"))
                    errors += 1
                else:
                    checks.append((f"[dim]opt:[/dim] {tool['name']}", "—", tool["install"], "#6B7280"))
            except Exception:
                checks.append((f"[dim]opt:[/dim] {tool['name']}", "—", tool["install"], "#6B7280"))
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
        except Exception as _exc:
            _log.warning("run failed: %s", _exc)

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
