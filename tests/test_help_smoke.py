"""--help smoke over every registered command path via the REAL parser.

The import-existence checks (test_registry_handlers_exist, doctor's registry
check) prove handlers resolve — they cannot see argparse-level breakage:
a bad ``Arg`` spec (invalid kwarg, malformed choices, duplicate dest) only
explodes when the parser is built, i.e. the first time anyone runs
``p <cmd> --help``. This module builds the real parser once and asks for
help on every invocable path — top-level commands, aliases, and every
subcommand chain — asserting each exits 0 with a usage banner.

Slow-ish (one full parser build ~ seconds, shared session-wide) but it is
the only test that exercises the exact surface a user's shell touches.
"""

from __future__ import annotations

import sys

import pytest

from patchi.cli.registry import COMMANDS


def _all_help_paths() -> list[list[str]]:
    """Every argv that should render help: each command (plus top-level
    aliases) and each subcommand chain."""
    paths: list[list[str]] = []

    def walk(cmds, prefix):
        for cmd in cmds:
            if not prefix and cmd.aliases:
                for alias in cmd.aliases:
                    paths.append([alias])
            paths.append([*prefix, cmd.name])
            walk(list(cmd.subcommands), [*prefix, cmd.name])

    walk(COMMANDS, [])
    return paths


def _parser():
    from patchi.cli.main import _build_parser

    return _build_parser()


@pytest.fixture(scope="session")
def parser():
    # _build_parser reads no argv state, but guard anyway: argparse writes
    # help to sys.stdout of the moment parse_args runs.
    return _parser()


@pytest.mark.parametrize("argv", _all_help_paths(), ids=lambda a: " ".join(a))
def test_help_exits_clean_with_usage(parser, argv, capsys):
    """`p <path> --help` must exit 0 printing a usage banner — never a
    traceback, never a bare exit, never empty output."""
    code = 0
    try:
        with contextlib_redirect_stdout():
            parser.parse_args([*argv, "--help"])
    except SystemExit as e:
        code = e.code or 0
    # argparse prints help to stdout and exits 0 on --help
    captured = capsys.readouterr()
    assert code == 0, f"`p {' '.join(argv)} --help` exited {code}"
    out = captured.out
    assert out.startswith("usage:"), f"`p {' '.join(argv)} --help` printed no usage banner"
    assert len(out) > 40, f"`p {' '.join(argv)} --help` output suspiciously short"


def contextlib_redirect_stdout():
    import contextlib

    return contextlib.redirect_stdout(sys.stdout)


def test_help_paths_cover_the_registry():
    """Guard the guard: the smoke must cover every top-level command."""
    paths = _all_help_paths()
    tops = {c.name for c in COMMANDS}
    covered = {p[0] for p in paths}
    assert tops <= covered, f"help smoke missing top-level commands: {sorted(tops - covered)}"
    assert len(paths) >= 120, f"registry unexpectedly shrank: {len(paths)} help paths"
