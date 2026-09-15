"""
Shared Console factory — ensures consistent encoding handling across all commands.

Usage:
    from patchi.cli.console import con
    con.print("...")

    # Once, early in dispatch (main.py), after CLI flags are parsed:
    from patchi.cli.console import configure_theme
    configure_theme(explicit=getattr(args, "theme", None),
                     no_color_flag=getattr(args, "no_color", False),
                     json_mode=getattr(args, "json_output", False))
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import contextmanager

from rich.console import Console

_encoding_fixed = False


_log = logging.getLogger("patchi.cli.console")


def _ensure_utf8():
    global _encoding_fixed
    if _encoding_fixed:
        return
    _encoding_fixed = True
    try:
        if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception as e:
        _log.warning("_ensure_utf8 failed: %s", e)


_ensure_utf8()
con = Console(highlight=False)

# Active symbol set for the current palette (style.py reads this). Starts as
# the dark palette's symbols so con.print(...) with semantic tokens works
# correctly even if configure_theme() is never called (e.g. tests, scripts
# that import con directly without going through main.py's dispatch).
_active_symbols: dict[str, str] = {}


def configure_theme(
    explicit: str | None = None,
    no_color_flag: bool = False,
    json_mode: bool = False,
    root=None,
) -> str:
    """
    Resolve the effective palette (see themes.resolve_palette_name for the
    exact precedence) and apply it to the shared `con`. Returns the palette
    name actually applied, mainly so callers/tests can assert on it.

    Safe to call multiple times (e.g. once per command invocation) --
    push_theme() replaces the active theme rather than stacking indefinitely
    in practice, since this is only ever called once per process at
    dispatch time, not nested.
    """
    from patchi.cli.themes import PALETTES, resolve_palette_name

    config_theme = None
    try:
        from patchi.core import config as cfg

        config_theme = cfg.get("theme", root)
    except Exception as e:
        _log.debug("configure_theme: could not read config theme, using default: %s", e)

    no_color_env = no_color_flag or bool(os.environ.get("NO_COLOR"))
    is_tty = con.is_terminal

    name = resolve_palette_name(
        explicit=explicit,
        config_theme=config_theme,
        no_color_env=no_color_env,
        is_tty=is_tty,
        json_mode=json_mode,
    )
    palette = PALETTES[name]
    con.push_theme(palette["theme"])
    con.no_color = name == "mono"
    _active_symbols.clear()
    _active_symbols.update(palette["symbols"])
    return name


@contextmanager
def muted_console():
    """Silence the shared console for a block; restore afterwards.

    Used to make ``--json`` stdout machine-pure: everything a command (and
    the core modules it calls) prints through ``con`` during the run phase
    is captured to a discard buffer, so the JSON document emitted after the
    block — via plain ``print``, never ``con.print`` (Rich soft-wraps at 80
    columns, corrupting long string values mid-line) — is the only thing on
    stdout.

    Swaps the underlying ``_file`` attribute, NOT the ``file`` property: the
    getter resolves ``None`` to the live ``sys.stdout``, so a save/restore
    through the property can pin the console to a stream that is closed
    later (e.g. pytest capsys) — every ``con.print`` after that dies with
    "I/O operation on closed file". ``_file = None`` is the valid
    "follow sys.stdout" state and must round-trip untouched.
    """
    import io as _io

    saved = con._file
    con._file = _io.StringIO()
    try:
        yield
    finally:
        con._file = saved


def print_json(document, **dumps_kwargs) -> None:
    """Emit a JSON document to stdout, byte-pure.

    Plain ``print``, not ``con.print``: Rich soft-wraps at 80 columns when
    stdout is not a terminal, corrupting JSON string values mid-line (and
    with them every machine consumer). Call this after a ``muted_console``
    block so the document is the only thing on stdout. Extra kwargs
    (e.g. ``default=str`` for datetime/Path payloads) pass through to
    ``json.dumps``.
    """
    import json as _json

    print(_json.dumps(document, indent=2, **dumps_kwargs))  # noqa: T201 — plain print IS the machine contract (Rich soft-wraps)


def symbol(key: str) -> str:
    """Get the current palette's symbol for 'ok'/'warn'/'err', defaulting to
    the dark palette's Unicode glyphs if configure_theme() was never called."""
    if not _active_symbols:
        from patchi.cli.themes import PALETTES

        return PALETTES["dark"]["symbols"].get(key, "")
    return _active_symbols.get(key, "")
