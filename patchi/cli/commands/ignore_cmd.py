"""
`p ignore` — manage Patchi's self-learned ignore list.

Patchi learns which files/dirs to skip (static rules, .gitignore,
false-positive history, tool-data composition). These commands let the
user inspect and correct that list; user entries always win over
learned ones in both directions.

Usage:
  p ignore                     — show learned + user entries
  p ignore add <path>          — never scan <path> (user override)
  p ignore remove <path>       — stop ignoring (removes user + learned)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core.config import require_project_root

_STORE = ".patchi/memory/learned_ignores.json"


def _load(root: Path) -> list[dict]:
    path = root / _STORE
    if not path.is_file():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — corrupt store: start clean
        return []


def _save(root: Path, entries: list[dict]) -> None:
    path = root / _STORE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    tmp.replace(path)


def run_list(json_output: bool = False, **_kw) -> None:
    """Show every ignore entry with provenance."""
    root = require_project_root()
    entries = _load(root)

    # Merge what the learner would derive right now, for visibility
    try:
        import json as _json

        from patchi.core.security.ignore_learner import IgnoreLearner

        fp_path = root / ".patchi/memory/known_false_positives.json"
        fps = _json.loads(fp_path.read_text(encoding="utf-8")) if fp_path.is_file() else []
        learner = IgnoreLearner(root)
        learner.build(known_fps=fps or None)
        stored_patterns = {e.get("pattern") for e in entries}
        for e in learner.entries:
            if e.pattern not in stored_patterns:
                entries.append({
                    "pattern": e.pattern,
                    "category": e.category,
                    "source": e.source,
                    "reason": f"{e.reason} (derived, not stored)",
                    "confidence": e.confidence,
                })
    except Exception:  # noqa: BLE001 — listing must work even if learner fails
        pass

    if json_output:
        import json as _json

        con.print(_json.dumps({"ignores": entries}, indent=2))
        return

    if not entries:
        con.print(Text("No ignore entries yet. Patchi learns as you scan.", style="#4ADE80"))
        return

    table = Table(show_header=True, header_style="bold #F2EDD6", box=None, pad_edge=False)
    table.add_column("Pattern", style="#F2EDD6", width=34)
    table.add_column("Category", width=12)
    table.add_column("Source", width=11)
    table.add_column("Conf", justify="right", width=5)
    table.add_column("Reason", style="dim")

    order = {"user": "#4ADE80", "fp_stats": "#FF8C42", "composition": "#FACC15",
             "git": "#B8A898", "static": "dim"}
    for e in sorted(entries, key=lambda x: (x.get("source") != "user", -x.get("confidence", 0))):
        src = e.get("source", "?")
        color = order.get(src, "dim")
        table.add_row(
            e.get("pattern", "?"),
            e.get("category", "?"),
            Text(src, style=color),
            f"{e.get('confidence', 0):.2f}",
            (e.get("reason", "") or "")[:60],
        )

    con.print(table)
    user_n = sum(1 for e in entries if e.get("source") == "user")
    con.print(f"\n[dim]{len(entries)} entries ({user_n} user overrides). "
              f"User entries always win over learned ones.[/dim]")


def run_add(path: str, **_kw) -> None:
    """Add a user ignore rule; wins over everything."""
    root = require_project_root()
    pattern = path.replace("\\", "/").strip("/")
    if not pattern:
        con.print("[red]Empty path.[/red]")
        return
    if not any(ch in pattern for ch in "*/") and (root / pattern).is_dir():
        pattern = f"{pattern}/**"

    entries = [e for e in _load(root) if e.get("source") == "user"]
    if any(e.get("pattern") == pattern for e in entries):
        con.print(f"[yellow]Already ignored:[/yellow] {pattern}")
        return
    entries.append({
        "pattern": pattern,
        "category": "user",
        "source": "user",
        "reason": "added via p ignore add",
        "confidence": 1.0,
        "added_at": time.time(),
    })
    # also drop conflicting learned rows so the override is durable on disk
    base = pattern.removesuffix("/**")
    kept_learned = [
        e for e in _load(root) if e.get("source") != "user"
        and not e.get("pattern", "").startswith(base)
    ]
    _save(root, kept_learned + entries)
    con.print(f"[green]✓ Never scanning[/green] {pattern} [dim](user override)[/dim]")


def run_remove(path: str, **_kw) -> None:
    """Remove an ignore rule (user or learned); path becomes scannable again."""
    root = require_project_root()
    pattern = path.replace("\\", "/").strip("/")
    base = pattern.removesuffix("/**")

    before = _load(root)
    after = [
        e for e in before
        if e.get("pattern", "").removesuffix("/**") != base
        and not e.get("pattern", "").startswith(base + "/**")
    ]
    removed = len(before) - len(after)
    if removed == 0:
        con.print(f"[yellow]No ignore entry matches[/yellow] {pattern}")
        return
    _save(root, after)
    con.print(f"[green]✓ Removed {removed} entr{'y' if removed == 1 else 'ies'}[/green] — "
              f"{pattern} will be scanned again.")
