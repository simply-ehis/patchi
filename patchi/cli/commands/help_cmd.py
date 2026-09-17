"""
`p help` — Show command help.

Also provides `p command` — List all commands with their tags and descriptions.
"""

from __future__ import annotations

from pathlib import Path

from patchi.cli.registry import COMMANDS


def _collect_commands(commands: list, prefix: str = "") -> list[dict]:
    """Recursively collect all commands with their metadata."""
    result = []
    for cmd in commands:
        full_name = f"{prefix}{cmd.name}" if prefix else cmd.name
        entry = {
            "name": full_name,
            "help": cmd.help,
            "handler": cmd.handler,
            "namespace_handler": cmd.namespace_handler,
            "args": [],
            "subcommands": [],
        }
        if cmd.args:
            for arg in cmd.args:
                entry["args"].append(
                    {
                        "name": arg.name,
                        "help": arg.help,
                        "type": getattr(arg, "type", "string"),
                        "required": getattr(arg, "required", False),
                        "choices": getattr(arg, "choices", None),
                        "default": getattr(arg, "default", None),
                        "action": getattr(arg, "action", None),
                        "nargs": getattr(arg, "nargs", None),
                        "dest": getattr(arg, "dest", None),
                    }
                )
        if cmd.subcommands:
            entry["subcommands"] = _collect_commands(cmd.subcommands, full_name + " ")
        result.append(entry)
    return result


def _print_commands_table(commands: list[dict], show_all: bool = False) -> None:
    """Print commands in a formatted table."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="Patchi Commands", show_header=True, header_style="bold cyan")
    table.add_column("Command", style="green", no_wrap=True)
    table.add_column("Description", style="white")
    if show_all:
        table.add_column("Args", style="yellow")
        table.add_column("Subcommands", style="blue")

    for cmd in commands:
        if show_all:
            args_str = ""
            if cmd["args"]:
                args_list = []
                for arg in cmd["args"]:
                    arg_str = arg["name"]
                    if arg.get("help"):
                        arg_str += f" - {arg['help']}"
                    if arg.get("required"):
                        arg_str += " (required)"
                    if arg.get("choices"):
                        arg_str += f" [choices: {', '.join(arg['choices'])}]"
                    if arg.get("default") is not None:
                        arg_str += f" [default: {arg['default']}]"
                    args_list.append(arg_str)
                args_str = "\n".join(args_list)

            subc_str = ""
            if cmd["subcommands"]:
                subc_list = []
                for sub in cmd["subcommands"]:
                    subc_list.append(f"{sub['name']} - {sub['help']}")
                subc_str = "\n".join(subc_list)

            table.add_row(cmd["name"], cmd["help"], args_str, subc_str)
        else:
            table.add_row(cmd["name"], cmd["help"])

    console.print(table)


def _write_command_list_md(commands: list[dict], output_path: Path) -> None:
    """Write the command list to a Markdown file."""
    lines = [
        "# Patchi Command Reference",
        "",
        "Auto-generated from the command registry. **Do not edit manually.**",
        "When adding a new command, update this file by running `p command --write-md`.",
        "",
        "## Commands",
        "",
    ]

    def write_cmds(cmds: list[dict], indent: int = 0):
        for cmd in cmds:
            prefix = "  " * indent
            lines.append(f"{prefix}- **{cmd['name']}**: {cmd['help']}")
            if cmd["args"]:
                lines.append(f"{prefix}  - Arguments:")
                for arg in cmd["args"]:
                    req = " (required)" if arg.get("required") else ""
                    choices = f" (choices: {', '.join(arg['choices'])})" if arg.get("choices") else ""
                    default = f" (default: {arg['default']})" if arg.get("default") is not None else ""
                    lines.append(f"{prefix}    - `{arg['name']}`{req}{choices}{default}: {arg.get('help', '')}")
            if cmd["subcommands"]:
                lines.append(f"{prefix}  - Subcommands:")
                write_cmds(cmd["subcommands"], indent + 2)

    write_cmds(commands)
    output_path.write_text("\n".join(lines), encoding="utf-8")


def run(args) -> None:
    """Entry point for `p help` and `p command`."""
    import sys

    # Check if called as `p command` (first arg after command)
    if len(sys.argv) > 1 and sys.argv[1] == "command":
        # `p command [--all] [--json] [--write-md]`
        import argparse

        parser = argparse.ArgumentParser(prog="p command")
        parser.add_argument("--all", action="store_true", help="Show all commands with arguments and subcommands")
        parser.add_argument("--json", action="store_true", help="Output as JSON")
        parser.add_argument("--write-md", action="store_true", help="Write command_list.md")
        sub_args = parser.parse_args(sys.argv[2:])

        all_cmds = _collect_commands(COMMANDS)

        if sub_args.write_md:
            output_path = Path("command_list.md")
            _write_command_list_md(all_cmds, output_path)
            return

        if sub_args.json:
            # Machine-readable surface: the same data the table renders.
            import json

            from patchi.cli.console import con as _con

            _con.print(json.dumps(all_cmds, indent=2))
            return

        _print_commands_table(all_cmds, show_all=sub_args.all)
        return

    # Original `p help` behavior
    group = getattr(args, "group", None)
    if group:
        # `p help all` is an advertised family entry — show everything.
        if group.lower() == "all":
            _print_commands_table(_collect_commands(COMMANDS))
            return
        filtered = [c for c in COMMANDS if c.name.startswith(group)]
        if not filtered:
            # Never silently produce nothing: name the miss and the valid
            # groups (this exact silent-return is how `p help json` and
            # friends used to vanish without a trace).
            from patchi.cli.console import con as _con

            _con.print(f"[yellow]No commands match '{group}'.[/yellow]")
            _con.print(f"[dim]Groups: {', '.join(sorted({c.name for c in COMMANDS}))}[/dim]")
            return
        _print_commands_table(_collect_commands(filtered))
    else:
        _print_commands_table(_collect_commands(COMMANDS))
