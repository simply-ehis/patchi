"""
`p plan` — Prioritized Fix List (Dream Assistant spec).

A standalone, ranked view of "here's what to fix first" across the project
(or a given area). Fixes are ranked by priority (charter/contract breaches and
breaking changes above cosmetic cleanups) and safe fixes are listed before the
ones that need human review.

  p plan                       — ranked fix list for the whole project
  p plan src/api              — ranked fix list for one area
  p plan --format             — also include formatter fixes
  p plan --json               — machine-readable output
  p plan --html report.html   — write a self-contained HTML report (Playwright-viewable)
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.core.brain.proactive import _FIX_PRIORITY, build_fix_list
from patchi.core.config import require_project_root

_PRIORITY_LABEL = {
    1: "contract",
    2: "breaking",
    3: "missing-import",
    4: "dead-code",
    5: "unused-import",
    6: "format",
}


def run(
    area: str | None = None,
    include_format: bool = False,
    include_missing_import: bool = False,
    json_output: bool = False,
    html: str | None = None,
    root: Path | None = None,
) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    fixes = build_fix_list(
        r,
        area=area,
        include_format=include_format,
        include_missing_import=include_missing_import,
    )

    if json_output:
        con.print(json.dumps([f.to_dict() for f in fixes], indent=2))
        return
    if html:
        _write_html(Path(html), fixes)
        con.print(f"[#4ADE80]HTML report written to {html}[/#4ADE80]")
        return

    con.print()
    if not fixes:
        con.print("[#4ADE80]✓[/#4ADE80] No prioritized fixes proposed.")
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("#", width=4)
    table.add_column("Priority", width=14)
    table.add_column("Safe", width=8)
    table.add_column("Type", width=18)
    table.add_column("File", width=36)
    table.add_column("Fix")
    for i, f in enumerate(fixes, 1):
        pri = _FIX_PRIORITY.get(f.fix_type, 9)
        label = _PRIORITY_LABEL.get(pri, "other")
        safe = "[#4ADE80]safe[/#4ADE80]" if f.safe else "[#FACC15]review[/#FACC15]"
        table.add_row(str(i), label, safe, f.fix_type, f.file, f.description)
    con.print(
        f"[bold #C8621A]Prioritized Fix List[/bold #C8621A]  [dim]({len(fixes)} item(s))[/dim]"
    )
    con.print(table)
    con.print()


def _write_html(path: Path, fixes) -> None:
    rows = []
    for i, f in enumerate(fixes, 1):
        pri = _FIX_PRIORITY.get(f.fix_type, 9)
        label = _PRIORITY_LABEL.get(pri, "other")
        safe = "safe" if f.safe else "needs-review"
        rows.append(
            f"<tr class='{safe}'><td>{i}</td><td>{label}</td>"
            f"<td>{safe}</td><td>{f.fix_type}</td><td>{f.file}</td>"
            f"<td>{_esc(f.description)}</td></tr>"
        )
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Patchi — Prioritized Fix List</title>
<style>
 body {{ font-family: ui-monospace, Menlo, Consolas, monospace; background:#1a1714; color:#f2edd6; margin:2rem; }}
 h1 {{ color:#c8621a; }}
 table {{ border-collapse:collapse; width:100%; }}
 th,td {{ text-align:left; padding:.4rem .6rem; border-bottom:1px solid #2a3d28; }}
 th {{ color:#c8621a; }}
 tr.safe td {{ color:#9be8a0; }}
 tr.needs-review td {{ color:#facc15; }}
 .muted {{ color:#b8a898; }}
</style></head>
<body>
<h1>Patchi — Prioritized Fix List</h1>
<p class="muted">{len(fixes)} item(s) ranked by priority.</p>
<table>
<tr><th>#</th><th>Priority</th><th>Safe</th><th>Type</th><th>File</th><th>Fix</th></tr>
{"".join(rows)}
</table>
</body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
