"""
p link — hybrid linking for non-monorepo (auto discovery tag + manual).

  p link status   — show linking config + suggestion
  p link add --frontend ./ --backend ../backend --frontend-url http://localhost:3000 --backend-url http://localhost:5000
  p link confirm  — confirm auto suggestion
  p link remove   — remove linking
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.panel import Panel

from patchi.cli.console import con
from patchi.core.config import require_project_root

_CFG = ".patchi/config.json"
_SUG = ".patchi/linking_suggestion.json"


def _load_cfg(root: Path) -> dict:
    p = root / _CFG
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_cfg(root: Path, cfg: dict) -> None:
    p = root / _CFG
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    tmp.replace(p)


def run(action: str | None = None, root: Path | None = None, **kwargs) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if action in (None, "status"):
        cfg = _load_cfg(r)
        link = cfg.get("linking")
        sug_path = r / _SUG
        if link:
            con.print(Panel(f"[bold]Linking:[/bold] {link}", border_style="#4ADE80"))
        elif sug_path.exists():
            try:
                sug = json.loads(sug_path.read_text(encoding="utf-8"))
                con.print(Panel(f"[yellow]Suggestion:[/yellow] frontend {sug.get('frontend')} ↔ backend {sug.get('backend')}\nRun [bold]p link confirm[/bold] to activate", border_style="#FF8C42"))
            except Exception:
                con.print("[dim]No linking suggestion[/dim]")
        else:
            con.print("[dim]No linking configured — monorepo auto-detected or run p link add[/dim]")
        return

    if action == "add":
        import argparse

        # Called via registry: kwargs has frontend, backend, frontend_url, backend_url
        front = kwargs.get("frontend") or "./"
        back = kwargs.get("backend")
        furl = kwargs.get("frontend_url") or "http://localhost:3000"
        burl = kwargs.get("backend_url") or "http://localhost:5000"
        if not back:
            con.print("[red]--backend required (e.g. ../backend)[/red]")
            return
        cfg = _load_cfg(r)
        cfg["linking"] = {"mode": "separate", "frontend": front, "backend": back, "frontend_url": furl, "backend_url": burl, "confirmed": True}
        _save_cfg(r, cfg)
        con.print(f"[green]Linking added:[/green] {front} ↔ {back}")
        return

    if action == "confirm":
        sug_path = r / _SUG
        if not sug_path.exists():
            con.print("[yellow]No suggestion to confirm — run p scan first or p link add[/yellow]")
            return
        try:
            sug = json.loads(sug_path.read_text(encoding="utf-8"))
            cfg = _load_cfg(r)
            cfg["linking"] = {**sug, "mode": "separate", "confirmed": True}
            _save_cfg(r, cfg)
            sug_path.unlink(missing_ok=True)
            con.print(f"[green]Link confirmed:[/green] {sug}")
        except Exception as e:
            con.print(f"[red]Confirm failed: {e}[/red]")
        return

    if action == "remove":
        cfg = _load_cfg(r)
        cfg.pop("linking", None)
        _save_cfg(r, cfg)
        con.print("[dim]Linking removed[/dim]")
        return

    con.print(f"[yellow]Unknown link action {action!r}[/yellow]")
