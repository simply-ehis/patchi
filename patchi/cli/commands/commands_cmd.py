"""
Commands command — shows command families and their subcommands.

Usage:
    p commands                    → lists all families with descriptions
    p commands --flat             → alphabetical list of all commands
    p commands --search <q>       → search commands by name/description
    p <family> commands           → shows subcommands in that family
"""

from __future__ import annotations

import sys

from rich.table import Table

from patchi.cli.command_families import (
    FAMILIES,
    format_all_families,
    format_family_help,
    get_family,
    list_families,
)
from patchi.cli.console import con
from patchi.cli.ux import format_header, colored_status


def run(args=None, flat: bool = False, search: str | None = None, **_kwargs):
    """Handle the commands command."""
    if args is None:
        args = sys.argv[1:]

    # Parse arguments (fallback for direct CLI invocation)
    if not flat:
        flat = "--flat" in args
    if not search:
        for i, arg in enumerate(args):
            if arg == "--search" and i + 1 < len(args):
                search = args[i + 1]
                break

    if flat:
        _print_flat_commands()
    elif search:
        _search_commands(search)
    else:
        _print_families()


def _print_families():
    """Print all families with descriptions."""
    con.print()
    con.print(format_header("Patchi Command Families"))
    con.print()

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Family", style="cyan", ratio=1)
    table.add_column("Description", ratio=3)
    table.add_column("Subcommands", ratio=2)

    for family in list_families():
        cmds = ", ".join(family.commands[:5]) if family.commands else "—"
        if len(family.commands) > 5:
            cmds += f" (+{len(family.commands) - 5} more)"
        table.add_row(
            f"p {family.name}",
            family.description,
            f"[dim]{cmds}[/dim]",
        )

    con.print(table)
    con.print()
    con.print("[dim]Use 'p <family> commands' to see all subcommands in a family.[/dim]")
    con.print()


def _print_flat_commands():
    """Print all commands in alphabetical order."""
    all_commands = []
    for family in list_families():
        all_commands.append((family.name, family.description))
        for cmd in family.commands:
            all_commands.append((f"{family.name} {cmd}", family.description))

    all_commands.sort(key=lambda x: x[0])

    con.print()
    con.print(format_header("All Patchi Commands"))
    con.print()

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Command", style="cyan", ratio=1)
    table.add_column("Description", ratio=3)

    for cmd, desc in all_commands:
        table.add_row(f"p {cmd}", desc)

    con.print(table)
    con.print()


def _search_commands(query: str):
    """Search commands by name or description."""
    query = query.lower()
    results = []

    for family in list_families():
        # Check family name and description
        if query in family.name.lower() or query in family.description.lower():
            results.append((family.name, family.description, "family"))

        # Check subcommands
        for cmd in family.commands:
            if query in cmd.lower():
                results.append((f"{family.name} {cmd}", family.description, "subcommand"))

    con.print()
    if results:
        con.print(format_header(f"Commands matching '{query}'"))
        con.print()

        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Command", style="cyan", ratio=1)
        table.add_column("Description", ratio=2)
        table.add_column("Type", ratio=1)

        for cmd, desc, cmd_type in results:
            type_style = "blue" if cmd_type == "family" else "dim"
            table.add_row(f"p {cmd}", desc, f"[{type_style}]{cmd_type}[/{type_style}]")

        con.print(table)
    else:
        con.print(f"[yellow]No commands found matching '{query}'[/yellow]")

    con.print()


def run_family_commands(family_name: str):
    """Show commands for a specific family."""
    family = get_family(family_name)
    if family:
        con.print()
        con.print(format_header(f"p {family.name}", family.description))
        con.print()

        if family.commands:
            table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
            table.add_column("Command", style="cyan", ratio=1)
            table.add_column("Full Command", ratio=2)

            for cmd in family.commands:
                table.add_row(cmd, f"p {family.name} {cmd}")

            con.print(table)
        else:
            con.print("[dim]No subcommands — use 'p {family.name}' directly.[/dim]")

        con.print()
    else:
        con.print(f"[red]Unknown family: {family_name}[/red]")
        con.print(f"[dim]Available families: {', '.join(sorted(FAMILIES.keys()))}[/dim]")