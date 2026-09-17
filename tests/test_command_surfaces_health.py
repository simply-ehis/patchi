"""The two non-registry command surfaces stay wired to reality.

Doctor's "Command registry" check covers the registry walk; this suite pins
the two surfaces *outside* it, which fail differently in the field:

- command_families.py advertises `p <family> <cmd>` through `p commands` and
  the `p <family> commands` display, but `p <family>` only parses when the
  family name is itself a registered command — a stale family advertised
  `p config key` / `p agent run` that argparse rejects outright.
- watch_cmd's rescan pipeline imports its phase handlers lazily inside
  try/except blocks, so a moved/renamed module never fails at import time or
  test time — watch prints "Rescan failed" on every save and silently does
  nothing.

check_family_map() and check_watch_phase_imports() (patchi/cli/framework.py)
probe both; doctor renders them alongside the registry check.
"""

from __future__ import annotations

import ast
from pathlib import Path

from patchi.cli.command_families import FAMILIES
from patchi.cli.framework import check_family_map, check_watch_phase_imports

REPO = Path(__file__).resolve().parent.parent
FAMILIES_PY = REPO / "patchi" / "cli" / "command_families.py"


# ── healthy-repo checks ───────────────────────────────────────────────────────


def test_family_map_fully_resolves():
    """Every advertised family invocation parses against the real parser."""
    problems, checked, broken = check_family_map()
    assert problems == []
    assert broken == 0
    assert checked > 90  # 23 families × entries + defaults — pin the scale


def test_watch_phase_imports_resolve():
    """Every try-block import in watch_cmd's pipeline resolves."""
    problems, checked, broken = check_watch_phase_imports()
    assert problems == []
    assert broken == 0
    assert checked >= 10  # rescan + proactive + impact + secrets + quiet-hours


# ── resolution-rule pins (what the checker accepts and why) ──────────────────


def test_family_entries_are_parsable_or_flags():
    """Every family command is a subcommand form, a base flag, or a real command."""
    from patchi.cli.registry import COMMANDS

    top = {c.name for c in COMMANDS}
    for c in COMMANDS:
        top.update(c.aliases)
    problems, _checked, _broken = check_family_map()
    assert problems == []  # self-consistency: checker and static rule agree
    # and every family name that claims subcommands is a real command
    for fam in FAMILIES.values():
        if fam.commands:
            assert fam.name in top or any(c in top for c in fam.commands), (
                f"family '{fam.name}' advertises commands but neither the family "
                f"name nor any entry is a registered command"
            )


def test_family_defaults_are_runnable_commands():
    """A family default is always a registered top-level command."""
    from patchi.cli.registry import COMMANDS

    top = {c.name for c in COMMANDS}
    for c in COMMANDS:
        top.update(c.aliases)
    for fam in FAMILIES.values():
        if fam.default_command:
            assert fam.default_command in top, (
                f"family '{fam.name}' defaults to '{fam.default_command}', which is not a registered command"
            )


# ── failure-detection (seeded break, no subprocess per case) ─────────────────


def test_family_check_catches_unparsable_entry(monkeypatch):
    """A family entry that parses to argparse-rejected shows as a problem."""
    real = FAMILIES["test"]

    class BrokenFamily(type(real)):
        pass

    broken = BrokenFamily(
        name="test",
        description=real.description,
        default_command="test",
        commands=[*real.commands, "time-travel"],
    )
    monkeypatch.setitem(FAMILIES, "test", broken)
    problems, _checked, broken_count = check_family_map()
    assert broken_count >= 1
    assert any("p test time-travel" in p for p in problems)


def test_family_check_catches_dangling_default(monkeypatch):
    """A family defaulting to a removed command shows as a problem."""
    real = FAMILIES["verify"]
    broken = type(real)(
        name="verify",
        description=real.description,
        default_command="astral-project",
        commands=[],
    )
    monkeypatch.setitem(FAMILIES, "verify", broken)
    problems, _checked, broken_count = check_family_map()
    assert broken_count == 1
    assert any("astral-project" in p for p in problems)


def test_watch_check_catches_moved_module(monkeypatch, tmp_path):
    """A try-block import pointing at a missing module shows as a problem."""
    # Build a minimal fake watch_cmd source with a Try-wrapped bad import.
    fake = tmp_path / "watch_cmd.py"
    fake.write_text(
        "def on_change(paths):\n"
        "    try:\n"
        "        from patchi.cli.commands.gone_cmd import run as run_scan\n"
        "        run_scan()\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )

    import patchi.cli.commands.watch_cmd as wc

    real_file = wc.__file__
    monkeypatch.setattr(wc, "__file__", str(fake))
    try:
        problems, checked, broken = check_watch_phase_imports()
    finally:
        monkeypatch.setattr(wc, "__file__", real_file)
    assert broken == 1
    assert checked == 1
    assert any("gone_cmd" in p for p in problems)
    assert any("module does not exist" in p for p in problems)


def test_watch_check_catches_renamed_symbol(monkeypatch, tmp_path):
    """Module exists but the imported name doesn't — the getattr layer."""
    fake = tmp_path / "watch_cmd.py"
    fake.write_text(
        "def on_change(paths):\n"
        "    try:\n"
        "        from patchi.cli.commands.scan_cmd import run_as_gone\n"
        "        run_as_gone()\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )
    import patchi.cli.commands.watch_cmd as wc

    real_file = wc.__file__
    monkeypatch.setattr(wc, "__file__", str(fake))
    try:
        problems, _checked, broken = check_watch_phase_imports()
    finally:
        monkeypatch.setattr(wc, "__file__", real_file)
    assert broken == 1
    assert any("run_as_gone" in p and "attribute missing" in p for p in problems)


def test_watch_check_ignores_top_level_imports():
    """Module-level imports aren't phases — they fail loudly at import time."""
    src = (REPO / "patchi" / "cli" / "commands" / "watch_cmd.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    top_level = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert top_level, "watch_cmd structure changed — revisit the AST walk"
    # and the checker's count matches try-block-only phases, not all imports
    _problems, checked, _ = check_watch_phase_imports()
    all_from_imports = sum(1 for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))
    assert checked <= all_from_imports  # subset: Try-nested only
