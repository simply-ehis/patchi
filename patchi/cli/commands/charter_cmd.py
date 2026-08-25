from patchi.cli.console import con

"""
`p charter` — view and enforce the project's guard-rail charter (Pillar 2).

Subcommands:
  p charter                         — show the current charter (alias for `show`)
  p charter set "<sentence>"       — parse a natural-language charter and save it
  p charter set "<sentence>" --ai  — parse with the LLM for richer semantics
  p charter show                   — show the current saved charter
  p charter check [--rebuild]      — check the live codebase against the charter
  p charter hooks [--install]      — generate a git pre-commit hook that enforces the charter
"""

import logging
from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.brain.charter import (
    Charter,
    check_charter,
    load_charter,
    parse_charter,
    parse_charter_with_ai,
    save_charter,
)
from patchi.core.config import require_project_root

_log = logging.getLogger("patchi.cli.charter_cmd")


def run_show(root: Path | None = None) -> None:
    """p charter show — display the current charter."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    charter = load_charter(r)
    if charter is None:
        con.print()
        con.print(
            "[dim]No charter set yet. Define guard rails with:[/dim]\n"
            '  [bold]p charter set "Frontend must not import from backend"[/bold]'
        )
        con.print()
        return

    _print_charter(charter)


def run_set(text: str, use_ai: bool = False, root: Path | None = None) -> None:
    """p charter set "<sentence>" — parse and persist a charter."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if not text or not text.strip():
        con.print(
            "[red]Provide a charter sentence, e.g.[/red] "
            '[bold]p charter set "Backend must not import from tests"[/bold]'
        )
        return

    con.print()
    if use_ai:
        con.print("[dim]Parsing charter with AI…[/dim]")
        try:
            config = cfg.load(r)
        except RuntimeError:
            config = {}
        charter = parse_charter_with_ai(text, config)
        if charter is None:
            con.print("[yellow]AI parser unavailable — using heuristic parser.[/yellow]")
            charter = parse_charter(text)
    else:
        charter = parse_charter(text)

    save_charter(charter, r)
    con.print("[#4ADE80]✓[/#4ADE80] Charter saved.")
    con.print()
    _print_charter(charter)
    con.print()
    con.print(
        "[dim]Run [bold]p scan[/bold] to let Patchi enforce these guard rails, "
        "then [bold]p charter check[/bold] to see any drift.[/dim]"
    )
    con.print()


def run_check(rebuild: bool = False, root: Path | None = None) -> None:
    """p charter check — verify the codebase against the saved charter."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    charter = load_charter(r)
    if charter is None:
        con.print(
            '[yellow]No charter set.[/yellow] Define one with [bold]p charter set "…"[/bold] first.'
        )
        return

    if rebuild:
        con.print("[dim]Rebuilding layered brain from current code…[/dim]")
        from patchi.core.brain.brain import Brain

        report = Brain(r).scan()
        layers = {n: l.to_dict() for n, l in report.layers.items()}
    else:
        layers = mem.get_layers(r)

    if not layers:
        con.print(
            "[yellow]No layered brain available.[/yellow] Run [bold]p scan[/bold] "
            "(or [bold]p charter check --rebuild[/bold]) to build it."
        )
        return

    detected_fw = []
    try:
        brain_mem = mem.read(mem.MemoryCategory.BRAIN, r) or {}
        detected_fw = [
            f.get("name")
            for f in brain_mem.get("frameworks", [])
            if isinstance(f, dict) and f.get("name")
        ]
    except Exception as e:
        _log.warning("run_check failed: %s", e)

    violations = check_charter(
        charter,
        layers,
        detected_frameworks=detected_fw,
    )

    con.print()
    if not violations:
        con.print(
            Panel(
                "[#4ADE80]✓ No charter violations.[/#4ADE80]\n"
                "[dim]Project structure respects all defined guard rails.[/dim]",
                title="[bold #C8621A]Charter Check[/bold #C8621A]",
                border_style="#2A3D28",
            )
        )
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", width=28)
    table.add_column("Detail")
    for v in violations:
        color = {"high": "#FF4D6D", "medium": "#F2C14E", "low": "dim"}.get(v.severity, "white")
        table.add_row(
            f"[{color}]{v.severity.upper()}[/{color}]",
            v.rule,
            v.message,
        )
    con.print(
        Panel(
            table,
            title=f"[bold #C8621A]Charter Violations ({len(violations)})[/bold #C8621A]",
            border_style="#FF4D6D",
        )
    )
    con.print()


def run_hooks(install: bool = False, root: Path | None = None) -> None:
    """p charter hooks — generate a git pre-commit hook that enforces the charter."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    git_dir = r / ".git"
    if not git_dir.exists():
        con.print("[red]Not a git repository (no .git directory found).[/red]")
        return

    hook_path = git_dir / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)

    script = (
        "#!/bin/sh\n"
        "# Patchi charter guard — generated by `p charter hooks`.\n"
        "# Fails the commit if the codebase violates the project charter.\n"
        'echo "🔍 Patchi: checking project charter…"\n'
        "patchi charter check\n"
        "if [ $? -ne 0 ]; then\n"
        '  echo "❌ Commit blocked: charter violation(s) detected."\n'
        '  echo "   Review with: patchi charter check"\n'
        "  exit 1\n"
        "fi\n"
        'echo "✓ Charter OK"\n'
    )
    hook_path.write_text(script, encoding="utf-8")
    try:
        hook_path.chmod(0o755)
    except Exception as e:
        _log.warning("run_hooks failed: %s", e)

    con.print()
    con.print(f"[#4ADE80]✓[/#4ADE80] Pre-commit hook written to [bold]{hook_path}[/bold]")
    con.print(
        "[dim]It runs [bold]patchi charter check[/bold] on every commit. "
        "Run [bold]p scan[/bold] first so the layered brain is current.[/dim]"
    )
    con.print()


# ── Helpers ────────────────────────────────────────────────────────────────────


def _print_charter(charter: Charter) -> None:
    lines = []
    if charter.raw_text:
        lines.append(f'[dim italic]"{charter.raw_text}"[/dim italic]')
        lines.append("")
    if charter.boundaries:
        lines.append("[bold #F2EDD6]Boundaries (guard rails):[/bold #F2EDD6]")
        for b in charter.boundaries:
            src = b.get("from", "?")
            tgt = b.get("to", "?")
            lines.append(f"  • [high]high[/high]  {src} must not import {tgt}")
        lines.append("")
    if charter.stack.get("frameworks") or charter.stack.get("languages"):
        lines.append("[bold #F2EDD6]Stack (expected):[/bold #F2EDD6]")
        if charter.stack.get("frameworks"):
            lines.append("  • frameworks: " + ", ".join(charter.stack["frameworks"]))
        if charter.stack.get("languages"):
            lines.append("  • languages: " + ", ".join(charter.stack["languages"]))
        lines.append("")
    if charter.security:
        lines.append("[bold #F2EDD6]Security rules:[/bold #F2EDD6]")
        for s in charter.security:
            lines.append(f"  • {s}")
        lines.append("")
    if charter.conventions:
        lines.append("[bold #F2EDD6]Conventions:[/bold #F2EDD6]")
        for k, v in charter.conventions.items():
            lines.append(f"  • {k}: {v}")
        lines.append("")
    if charter.notes:
        lines.append("[bold #F2EDD6]Notes:[/bold #F2EDD6]")
        for n in charter.notes:
            lines.append(f"  • {n}")
        lines.append("")

    if len(lines) == 1:
        lines.append("[dim]No specific rules parsed. The raw sentence is kept as intent.[/dim]")

    con.print()
    con.print(
        Panel(
            "\n".join(lines).rstrip(),
            title="[bold #C8621A]Project Charter[/bold #C8621A]",
            border_style="#2A3D28",
        )
    )
    con.print()
