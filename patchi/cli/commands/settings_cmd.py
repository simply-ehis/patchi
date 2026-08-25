"""
`p settings` — View or modify Patchi configuration.
show | set <key> <value>
"""

from __future__ import annotations

from pathlib import Path

from patchi.cli.console import con
from patchi.core import config as cfg


def run(
    settings_cmd: str | None = None,
    key: str | None = None,
    value: str | None = None,
    root: Path | None = None,
) -> None:
    if settings_cmd == "show":
        run_show(root)
    elif settings_cmd == "set":
        run_set(key, value, root)


def run_show(root: Path | None = None) -> None:
    r = root or _require_root()
    con.print_json(data=cfg.load(r))


def run_set(key: str | None, value: str | None, root: Path | None = None) -> None:
    if not key or value is None:
        con.print("[red]Usage: p settings set <key> <value>[/red]")
        return
    r = root or _require_root()
    cfg.set_value(key, value, r)
    con.print(f"[#4ADE80]✓[/#4ADE80] [bold]{key}[/bold] = {value}")


def _require_root() -> Path:
    try:
        return cfg.require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        raise SystemExit(1)
