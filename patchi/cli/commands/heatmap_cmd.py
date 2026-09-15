"""
p heatmap — Risk Heatmap §9.1.3 color-coded file map of bug-prone hotspots.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from patchi.cli.console import con, print_json
from patchi.core.config import require_project_root


def run(json_output: bool = False, root: Path | None = None) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return
    from patchi.core.brain.heatmap import build_heatmap

    data = build_heatmap(r)
    if json_output:
        print_json(data)
        return
    hotspots = data.get("hotspots", [])
    if not hotspots:
        con.print("[dim]No hotspots — run `p scan` first.[/dim]")
        return
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("File", style="bold #F2EDD6", width=50)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Findings", justify="right", width=9)
    for h in hotspots[:15]:
        sev = h.get("severity", "low")
        color = {
            "critical": "#FF4D6D",
            "high": "#FF8C42",
            "medium": "#FACC15",
            "low": "#4ADE80",
        }.get(sev, "dim")
        table.add_row(
            h["file"][:50],
            f"{h['score']:.1f}",
            f"[{color}]{sev}[/{color}]",
            str(next((c for c in data["tree"]["children"] if False), "")),
        )
    # findings count per hotspot already in score, show directly
    # rebuild with findings
    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("File", style="bold #F2EDD6")
    table.add_column("Score", justify="right")
    table.add_column("Severity")
    for h in hotspots[:15]:
        sev = h.get("severity", "low")
        color = {
            "critical": "#FF4D6D",
            "high": "#FF8C42",
            "medium": "#FACC15",
            "low": "#4ADE80",
        }.get(sev, "dim")
        table.add_row(h["file"], f"{h['score']:.1f}", f"[{color}]{sev}[/{color}]")
    con.print()
    con.print(
        Panel(
            table,
            title="🔥 Risk Heatmap — bug-prone hotspots (score = findings×10 + churn×2 + size/10)",
            border_style="#C8621A",
        )
    )
    con.print(
        f"\n[dim]Total files with findings: {data.get('total_files', 0)} — tree stored for web D3 treemap at"
        f" .patchi/heatmap.json[/dim]"
    )
    # persist for web
    try:
        out = r / ".patchi" / "heatmap.json"
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as _exc:
        logging.getLogger("patchi").debug("suppressed: %s", _exc)
    con.print()
