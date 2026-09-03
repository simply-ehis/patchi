"""p rules — view and validate security rule packs.

Subcommands:
  p rules               — list all shipped rule packs with per-language sinks
  p rules --validate    — validate all rule packs (semgrep, bandit, presence)
  p rules --which <id>  — map a finding control id back to its rule pack
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table

_log = logging.getLogger("patchi.cli.commands.rules_cmd")



def run(args) -> None:
    con = Console()
    root = Path.cwd()

    if getattr(args, "validate", False):
        _validate_rules(root, con)
        return

    which_id = getattr(args, "which", None)
    if which_id:
        _which_rule(root, con, which_id)
        return

    _list_rules(root, con)


def _find_rules_dir(root: Path) -> Path | None:
    """Find the rules directory (could be in patchi/ or rules/)."""
    candidates = [
        root / "patchi" / "core" / "security" / "rules",
        root / "rules",
        root / "patchi" / "rules",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def _list_rules(root: Path, con: Console) -> None:
    """List all rule packs."""
    rules_dir = _find_rules_dir(root)
    if not rules_dir:
        con.print("[yellow]No rules directory found. Rule packs are embedded in agents.[/yellow]")
        _list_agent_patterns(root, con)
        return

    con.print(f"\n[bold]Rule Packs[/bold] — {rules_dir}\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Pack", width=24)
    table.add_column("Language", width=12)
    table.add_column("Rules", justify="right", width=6)
    table.add_column("Sinks", max_width=40)

    for pack_file in sorted(rules_dir.glob("*.yaml")):
        try:
            import yaml

            data = yaml.safe_load(pack_file.read_text(encoding="utf-8"))
            name = data.get("name", pack_file.stem)
            lang = data.get("language", "all")
            rules = data.get("rules", [])
            sinks = []
            for rule in rules:
                sinks.extend(rule.get("sinks", [])[:3])
            table.add_row(
                name,
                lang,
                str(len(rules)),
                ", ".join(sinks[:5]) or "(pattern-based)",
            )
        except Exception:
            table.add_row(pack_file.stem, "?", "?", "(parse error)")

    con.print(table)

    # Also show semgrep rules if present
    semgrep_dir = rules_dir / "semgrep"
    if semgrep_dir.is_dir():
        count = len(list(semgrep_dir.glob("*.yaml")))
        if count:
            con.print(f"\n  [dim]Semgrep rules: {count} files in {semgrep_dir}[/dim]")

    # Bandit config
    bandit_cfg = root / ".bandit" if (root / ".bandit").exists() else None
    if bandit_cfg:
        con.print(f"  [dim]Bandit config: {bandit_cfg}[/dim]")


def _list_agent_patterns(root: Path, con: Console) -> None:
    """List pattern-based detection from agents."""
    con.print("\n[bold]Agent Detection Patterns[/bold]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Agent", width=24)
    table.add_column("Group", width=12)
    table.add_column("Detection", max_width=50)

    try:
        from patchi.core.agents.base import AgentGroup, list_agents

        agents = list_agents(AgentGroup.SECURITY)
        for agent_cls in agents:
            table.add_row(
                agent_cls.name,
                "security",
                agent_cls.description[:50] if hasattr(agent_cls, "description") else "",
            )
    except Exception:
        con.print("[dim]Could not enumerate agents[/dim]")

    con.print(table)


def _validate_rules(root: Path, con: Console) -> None:
    """Validate all rule packs."""
    con.print("\n[bold]Validating Rule Packs[/bold]\n")

    # Try the existing validator
    validator_path = root / "tools" / "validate_rule_packs.py"
    if validator_path.exists():
        con.print(f"  Running: python {validator_path}")
        import subprocess

        result = subprocess.run(
            ["python", str(validator_path)],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(root),
        )
        con.print(result.stdout)
        if result.returncode != 0:
            con.print(f"[red]Validation failed (exit {result.returncode})[/red]")
            if result.stderr:
                con.print(f"[dim]{result.stderr[:500]}[/dim]")
        else:
            con.print("[green]All rule packs valid[/green]")
        return

    # Manual validation
    rules_dir = _find_rules_dir(root)
    if not rules_dir:
        con.print("[yellow]No rules directory found.[/yellow]")
        return

    errors = 0
    for pack_file in sorted(rules_dir.glob("*.yaml")):
        try:
            import yaml

            data = yaml.safe_load(pack_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                con.print(f"  [red]✗ {pack_file.name}: not a dict[/red]")
                errors += 1
                continue
            rules = data.get("rules", [])
            for rule in rules:
                if not rule.get("id"):
                    con.print(f"  [red]✗ {pack_file.name}: rule missing 'id'[/red]")
                    errors += 1
        except Exception as e:
            con.print(f"  [red]✗ {pack_file.name}: {e}[/red]")
            errors += 1

    if errors == 0:
        con.print("[green]All rule packs valid[/green]")
    else:
        con.print(f"\n[red]{errors} error(s) found[/red]")


def _which_rule(root: Path, con: Console, finding_id: str) -> None:
    """Map a finding control id to its rule pack and keywords."""
    con.print(f"\n[bold]Rule Lookup: {finding_id}[/bold]\n")

    # Search in all YAML rule packs
    rules_dir = _find_rules_dir(root)
    if rules_dir:
        for pack_file in sorted(rules_dir.rglob("*.yaml")):
            try:
                import yaml

                data = yaml.safe_load(pack_file.read_text(encoding="utf-8"))
                rules = data.get("rules", []) if isinstance(data, dict) else []
                for rule in rules:
                    rid = rule.get("id", "")
                    if finding_id.upper() in rid.upper():
                        con.print(f"  [green]Found in:[/green] {pack_file.name}")
                        con.print(f"    Rule ID: {rid}")
                        con.print(f"    Message: {rule.get('message', '')[:100]}")
                        sinks = rule.get("sinks", [])
                        if sinks:
                            con.print(f"    Sinks: {', '.join(sinks[:10])}")
                        keywords = rule.get("keywords", [])
                        if keywords:
                            con.print(f"    Keywords: {', '.join(keywords[:10])}")
                        severity = rule.get("severity", "")
                        if severity:
                            con.print(f"    Severity: {severity}")
                        con.print()
            except Exception:
                continue

    # Also search in agent pattern loaders
    try:
        from patchi.core.security.pattern_loader import load_patterns

        patterns = load_patterns()
        for section, rules in patterns.items():
            if isinstance(rules, list):
                for rule in rules:
                    if isinstance(rule, dict):
                        rid = rule.get("id", rule.get("name", ""))
                        if finding_id.upper() in str(rid).upper():
                            con.print(f"  [green]Found in patterns:[/green] {section}")
                            con.print(f"    {json.dumps(rule, indent=2)[:300]}")
                            con.print()
    except Exception as _exc:
        _log.warning('_which_rule failed: %s', _exc)

    con.print("[dim]Search complete.[/dim]")
