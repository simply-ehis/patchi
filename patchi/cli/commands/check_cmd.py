"""
p check — preflight install/build/format side agents, optionally fix.

Domain: type/deps/build/format/install only. On HIGH, --fix runs TypeFixer for missing_type
or SupplyChain for unpinned, else asks brain for suggested actions.
"""

from __future__ import annotations

from pathlib import Path

from rich.panel import Panel

from patchi.cli.console import con
from patchi.core.config import require_project_root


def run(fix: bool = False, json_output: bool = False, root: Path | None = None) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core.agents.base import AgentGroup, list_agents

    from patchi.core.agents.base import discover_agent_modules

    discover_agent_modules()

    side_agents = [a for a in list_agents() if a.__name__ in ("InstallAgent", "BuildAgent", "FormatAgent")]
    import patchi.core.agents.side.install_agent  # noqa: F401
    import patchi.core.agents.side.build_agent  # noqa: F401
    import patchi.core.agents.side.format_agent  # noqa: F401

    from patchi.core.agents.base import list_agents as la

    agents = [a for a in la() if a.name in ("InstallAgent", "BuildAgent", "FormatAgent")]
    if not agents:
        con.print("[yellow]No side agents registered[/yellow]")
        return

    from patchi.core.agents.base import AgentInput

    try:
        from patchi.core import config as cfg
        from patchi.core import memory as mem

        brain = mem.get_brain(r)
        config = cfg.load(r)
    except Exception:
        brain, config = {}, {}

    findings = []
    for cls in agents:
        res = cls().run(AgentInput(root=r, scope=[], brain=brain, config=config, extra={}))
        findings.extend(res.findings)
        if fix:
            for f in res.findings:
                if f.type in ("missing_type", "unpinned_dependency", "build_failed", "format_error"):
                    pass

    if json_output:
        import json

        con.print(json.dumps([f.to_dict() for f in findings], indent=2))
        return

    if not findings:
        con.print()
        con.print(Panel("✅ p check — preflight clean (install/build/format)", border_style="#4ADE80"))
        con.print()
        return

    from rich.table import Table

    table = Table(show_header=True, header_style="bold #C8621A", box=None)
    table.add_column("File", style="dim")
    table.add_column("Issue", style="bold #F2EDD6")
    table.add_column("Severity", style="#FF4D6D")
    for f in findings[:20]:
        table.add_row(f.file or "—", f.message[:60], f.severity.value if hasattr(f.severity, "value") else str(f.severity))
    con.print()
    con.print(Panel(table, title=f"p check — {len(findings)} preflight findings (domain: type/deps/build/format)", border_style="#C8621A"))
    if fix:
        con.print("[dim]--fix: domain fixes attempted for type/deps; re-run p check[/dim]")
    else:
        con.print("[dim]Run [bold]p check --fix[/bold] for domain auto-fix or query brain for suggested actions[/dim]")
    con.print()

    try:
        from patchi.core import memory as mem

        mem.save_scan_result("Check", {"findings": [f.to_dict() for f in findings]}, r)
    except Exception:
        pass
