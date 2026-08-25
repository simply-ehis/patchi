"""
`p access` — Manage dev access tokens.
add [--env-var VAR] <name> | list | remove <name>
"""

from __future__ import annotations

from pathlib import Path

from patchi.cli.console import con
from patchi.core import memory as mem


def run(
    access_cmd: str | None = None,
    name: str | None = None,
    env_var: str | None = None,
    root: Path | None = None,
) -> None:
    if access_cmd == "add":
        run_add(name, env_var, root)
    elif access_cmd == "list":
        run_list(root)
    elif access_cmd == "remove":
        run_remove(name, root)


def run_add(name: str | None = None, env_var: str | None = None, root: Path | None = None) -> None:
    if not name:
        con.print("[red]Usage: p access add <name> [--env-var VAR][/red]")
        return
    r = root or _require_root()
    mem.save_token(name, env_var or name.upper(), r)  # type: ignore[arg-type]
    con.print(f"[#4ADE80]✓[/#4ADE80] Token [bold]{name}[/bold] saved.")


def run_list(root: Path | None = None) -> None:
    r = root or _require_root()
    tokens = mem.list_tokens(r)
    if not tokens:
        con.print("[dim]No dev access tokens configured.[/dim]")
    for t in tokens:
        con.print(f"  [bold]{t['name']}[/bold]  [dim]env: {t['env_var']}[/dim]")


def run_remove(name: str | None, root: Path | None = None) -> None:
    if not name:
        con.print("[red]Usage: p access remove <name>[/red]")
        return
    r = root or _require_root()
    ok = mem.remove_token(name, r)
    if ok:
        con.print(f"[#4ADE80]✓[/#4ADE80] Token [bold]{name}[/bold] removed.")
    else:
        con.print(f"[yellow]Token {name!r} not found.[/yellow]")


def _require_root() -> Path:
    try:
        from patchi.core.config import require_project_root

        return require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        raise SystemExit(1)
