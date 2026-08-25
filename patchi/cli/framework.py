"""
Command framework — §3 Command Unification.

Replaces the three-places-to-edit pattern (lazy-import factory function +
argparse subparser block + elif dispatch chain) with one declarative
`Command` per command, registered once in `registry.py`.

Design note (refinement made during implementation, not in the original design
doc): a handful of existing commands read GLOBAL flags (--quiet, --verbose)
that are defined once on the top-level parser, not re-declared per-subcommand.
`Arg(global_flag=True)` marks these — the builder skips calling add_argument
for them (the global parser already defines it), but the dispatcher still
reads them into the handler's kwargs. Without this distinction, migrating
`scan` (which reads the global `quiet`) would either duplicate the flag
definition (argparse conflict) or silently drop the value.

Second design note: the `namespace_handler` shape (see Command). notify,
hosted, test, security and cross-repo all dispatch on parsed values in ways a
static Arg->kwarg mapping can't express (e.g. `p test generate` routes to a
different function than `p test unit`), and their legacy handlers already
received the whole Namespace. Rather than force those into per-subcommand
handlers, the framework supports passing the Namespace straight through and
letting the one handler self-route — `resolve` returns the top command
regardless of how deep the subcommand path goes.

Lazy loading is preserved exactly as the original factories did: `handler` is
a dotted string ("module:function"), not a function object — nothing is
imported until dispatch actually resolves it, so `p --help` / cold start
stays fast regardless of how many commands are registered.
"""

from __future__ import annotations

import argparse
import importlib
import logging
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger("patchi.cli.framework")


@dataclass(frozen=True)
class Arg:
    name: str  # "--area" or "area" (positional)
    help: str = ""
    default: Any = None
    action: str | None = None  # "store_true", "store_false", etc.
    choices: tuple | None = None
    nargs: str | None = None
    dest: str | None = None
    type: type | None = None
    global_flag: bool = False  # True = already defined on the top-level
    # parser; don't re-add, just read it

    def resolved_dest(self) -> str:
        is_positional = not self.name.startswith("-")
        if is_positional:
            # argparse always uses the name itself as dest for positionals --
            # any `dest` set here would be ignored by the real parser, so
            # resolving it here too keeps kwarg-building consistent with what
            # actually gets parsed.
            return self.name.replace("-", "_")
        if self.dest:
            return self.dest
        return self.name.lstrip("-").replace("-", "_")


@dataclass(frozen=True)
class Command:
    name: str
    help: str
    handler: str = ""  # dotted path: "patchi.cli.commands.scan_cmd:run"
    args: tuple[Arg, ...] = ()
    subcommands: tuple[Command, ...] = ()
    aliases: tuple[str, ...] = ()
    fixed_kwargs: dict = field(default_factory=dict)
    # ^ For cases where several subcommands share ONE handler but each needs a
    # different hardcoded value baked in -- e.g. `restrict add`/`scan-only`/
    # `sensitive` all call the same run_add(path, restriction_type, reason),
    # only restriction_type differs per subcommand. These values are merged
    # into the kwargs unconditionally, never derived from parsed args.
    namespace_handler: bool = False
    # ^ Self-routing Namespace-handler shape: the handler receives the WHOLE
    # argparse Namespace (fn(args)) and routes on the subcommand dests itself
    # (notify_cmd/hosted_cmd/token_cmd...). The subcommand tree is declared
    # purely for parsing + help — resolve() always returns the top command, so
    # one function owns the entire command tree. Used by notify, hosted, test,
    # security, and cross-repo, which all dispatch on parsed values in ways a
    # static Arg->kwarg mapping cannot express.


def _add_args(parser: argparse.ArgumentParser, cmd: Command) -> None:
    args = cmd.args
    # Normalize: accept a single Arg or None as well as a list/tuple so a
    # mis-registered command can never crash parser construction.
    if args is None:
        return
    if isinstance(args, (list, tuple)):
        arg_list = args
    else:
        arg_list = [args]
    for a in arg_list:
        if a.global_flag:
            continue  # already defined on the top-level parser
        is_positional = not a.name.startswith("-")
        kwargs: dict[str, Any] = {"help": a.help}
        if a.action:
            kwargs["action"] = a.action
        if a.default is not None:
            kwargs["default"] = a.default
        if a.choices:
            kwargs["choices"] = a.choices
        if a.nargs:
            kwargs["nargs"] = a.nargs
        if a.dest and not is_positional:
            # argparse forbids dest= on positional args (the name IS the dest) --
            # only pass it for optional flags. A positional Arg must name itself
            # exactly what the handler's kwarg expects; there's no override.
            kwargs["dest"] = a.dest
        if a.type:
            kwargs["type"] = a.type
        parser.add_argument(a.name, **kwargs)


def _add_command(sub, cmd: Command) -> None:
    parser = sub.add_parser(cmd.name, help=cmd.help, aliases=list(cmd.aliases))
    _add_args(parser, cmd)
    if cmd.subcommands:
        sub_sub = parser.add_subparsers(dest=f"{cmd.name}_cmd")
        for child in cmd.subcommands:
            _add_command(sub_sub, child)


def register_commands(sub, commands: list[Command]) -> None:
    """
    Add every registered Command as a subparser on an EXISTING subparsers
    object. Used during the incremental migration window, where most commands
    still add themselves to the same `sub` the legacy code creates — this lets
    registry-driven and legacy-declared commands coexist on one parser tree
    without either side needing to know about the other.
    """
    for cmd in commands:
        _add_command(sub, cmd)


def build_parser(commands: list[Command], base: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """
    Standalone variant: builds a brand-new subparsers object on `base` and
    registers every Command onto it. Only safe to use once nothing else adds
    subparsers to `base` — during the migration window main.py uses
    `register_commands` against its own existing `sub` instead.
    """
    sub = base.add_subparsers(dest="command")
    register_commands(sub, commands)
    return base


def _find_command(commands: list[Command], name: str) -> Command | None:
    for cmd in commands:
        if cmd.name == name or name in cmd.aliases:
            return cmd
    return None


def _lazy_import(dotted_handler: str):
    mod_path, _, func_name = dotted_handler.partition(":")
    module = importlib.import_module(mod_path)
    return getattr(module, func_name)


def _build_kwargs(cmd: Command, args: argparse.Namespace) -> dict[str, Any]:
    kwargs = dict(cmd.fixed_kwargs)
    for a in cmd.args:
        dest = a.resolved_dest()
        kwargs[dest] = getattr(args, dest, a.default)
    return kwargs


def resolve(commands: list[Command], args: argparse.Namespace) -> Command | None:
    """Find the Command (and subcommand, if any) matching parsed args.command."""
    top_name = getattr(args, "command", None)
    if top_name is None:
        return None
    cmd = _find_command(commands, top_name)
    if cmd is None:
        return None
    if cmd.namespace_handler:
        # Self-routing command: one handler owns the whole subcommand tree and
        # routes on the parsed dests itself, so the top Command is what gets
        # dispatched no matter how deep the invocation went.
        return cmd
    if cmd.subcommands:
        sub_name = getattr(args, f"{cmd.name}_cmd", None)
        if sub_name:
            child = _find_command(list(cmd.subcommands), sub_name)
            if child is not None:
                return child
    return cmd


def dispatch(commands: list[Command], args: argparse.Namespace):
    """
    Resolve the matching Command, lazily import its handler, and call it with
    kwargs derived from the SAME Arg specs used to build the parser — so
    parser and dispatch can never drift out of sync (the exact bug class this
    design exists to eliminate).

    Returns None if no registered Command matches (caller should fall through
    to the legacy dispatch ladder during the incremental migration window).
    """
    cmd = resolve(commands, args)
    if cmd is None:
        return None, False  # (result, handled) -- not handled, fall through
    fn = _lazy_import(cmd.handler)
    if cmd.namespace_handler:
        # Self-routing shape: hand the whole parsed Namespace to the handler;
        # it dispatches on the subcommand dests itself. Kwargs are deliberately
        # not built — the subcommands are parsing/help sugar only.
        return fn(args), True
    kwargs = _build_kwargs(cmd, args)
    return fn(**kwargs), True
