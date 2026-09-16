"""Every registry-referenced command must resolve on disk.

Regression coverage for the dangling-command bug class: commands were
registered in ``patchi/cli/registry.py`` pointing at handler modules that
no longer existed (the old ``mode_cmd`` among them — ``ef77be5`` deleted 14
command files while the registry kept pointing at them). Every such command
crashed on dispatch with an unhelpful ModuleNotFoundError.

Two layers of defense here:

1. **File existence** — ``importlib.util.find_spec`` for each handler module.
   Pure metadata lookup: no module side effects, so a broken *import* (e.g.
   a syntax error inside the handler) still fails HERE with a message that
   names the registry entry, not deep inside dispatch.

2. **Importability + attribute** — the module actually imports and exposes
   the named function, i.e. the exact check ``framework._lazy_import``
   performs at dispatch time. This catches renamed/deleted handler functions
   and import-time crashes, which file existence alone cannot.

The walk covers top-level commands *and* every subcommand (137 Command
objects, 94 unique handlers today). Duplicate ``(name, handler)`` pairs are
legal by design — the undo family is canonical under ``p patch`` *and*
compat-registered at top level — so dedup happens before parametrizing.
Empty ``handler`` strings are skipped — that shape means "handled
elsewhere" (e.g. family routing), not dangling.
"""

from __future__ import annotations

import importlib
import importlib.util

import pytest

from patchi.cli.registry import COMMANDS


def _iter_commands():
    """Yield (name, handler) for every Command and subcommand in the registry."""

    def walk(cmds):
        for cmd in cmds:
            if cmd.handler:
                yield cmd.name, cmd.handler
            yield from walk(list(cmd.subcommands))

    yield from walk(COMMANDS)


def _all_handlers() -> list[tuple[str, str]]:
    """Unique (name, handler) pairs, deduped (the undo family is registered
    both canonically and as compat top-level aliases — same handlers)."""
    return sorted(set(_iter_commands()))


def test_registry_has_handlers_to_check():
    """Guard the guard: if the registry shape ever changes so that no
    handlers are collected, these tests must fail loudly, not pass vacuously."""
    handlers = _all_handlers()
    assert len(handlers) >= 80, f"registry unexpectedly shrank: {len(handlers)} handlers"
    assert any(name == "why" and "reason_cmd" in h for name, h in handlers)


def test_registry_parametrize_is_complete():
    """The parametrized checks must cover every *unique* handler; the raw
    registry may legitimately repeat a pair (compat aliases)."""
    raw = list(_iter_commands())
    unique = set(raw)
    assert len(unique) >= 80, f"registry unexpectedly shrank: {len(unique)} unique handlers"
    # every raw entry must be covered by the deduped list
    assert unique == set(_all_handlers())


@pytest.mark.parametrize(("name", "handler"), _all_handlers())
def test_handler_module_exists_on_disk(name, handler):
    mod_path, _, _func = handler.partition(":")
    spec = importlib.util.find_spec(mod_path)
    assert spec is not None, (
        f"`p {name}` references handler module '{mod_path}' which does not "
        f"exist on disk — dangling command (the mode_cmd bug class). "
        f"Restore the module or drop the registry entry."
    )


@pytest.mark.parametrize(("name", "handler"), _all_handlers())
def test_handler_imports_and_exposes_function(name, handler):
    """The exact resolution _lazy_import performs at dispatch time."""
    mod_path, _, func = handler.partition(":")
    assert func, f"`p {name}` handler '{handler}' has no ':function' part"
    try:
        module = importlib.import_module(mod_path)
    except Exception as exc:  # noqa: BLE001 - report the registry entry, not the traceback
        pytest.fail(f"`p {name}` handler module '{mod_path}' cannot be imported: {exc!r}")
    assert hasattr(module, func), (
        f"`p {name}` references '{handler}' but '{mod_path}' has no "
        f"attribute '{func}' — renamed or deleted without updating the registry."
    )
