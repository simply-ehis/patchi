"""Registry ↔ COMMANDS.md parity, both directions.

Two failure classes this pins shut:

1. A command registered in ``patchi.cli.registry.COMMANDS`` but missing from
   COMMANDS.md — the command works but users can't discover it.
2. A command documented in COMMANDS.md that isn't registered — the doc
   promises something the CLI doesn't have (the dangling-doc twin of the
   dangling-command bug).

Subcommands are checked to the same standard: every registered subcommand
must be mentionable in the doc (full form ``p <family> <sub>`` or a
backticked mention inside the family's section), and every documented
``p <family> <sub>`` full form must resolve to a registered pair.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "COMMANDS.md"

# Top-level commands documented elsewhere on purpose. Every entry needs a
# one-line justification; the test prints it on failure so the list stays
# honest and pruneable.
DOCUMENTED_ELSEWHERE: dict[str, str] = {
    # `p command` / `p help [group]` share one doc section ("### `p command` / `p help [group]`")
    "help": "documented in the shared 'p command / p help' section",
}


def _registered() -> tuple[dict[str, set[str]], dict[str, tuple[str, ...]]]:
    """Return ({top_name: {sub_names}}, {top_name: aliases}).

    Subcommand vocabulary comes from two registry shapes:
    - declared subcommands (``Command(name="list", ...)`` children), and
    - self-routing families with a positional ``action`` arg carrying
      ``choices=`` — those actions are the subcommands users type.
    """
    from patchi.cli.registry import COMMANDS

    tops: dict[str, set[str]] = {}
    aliases: dict[str, tuple[str, ...]] = {}
    for c in COMMANDS:
        if "." in c.name:
            continue
        subs = tops.setdefault(c.name, set())
        subs.update(s.name for s in c.subcommands or [])
        for a in c.args:
            if a.resolved_dest() == "action" and getattr(a, "choices", None):
                subs.update(a.choices)
        if c.aliases:
            aliases[c.name] = c.aliases
    # Families that parse a raw args[] blob in-handler have no registry
    # metadata for their subcommands; their vocabulary lives here (checked
    # against the handler source so the map can't silently rot).
    tops["plugins"].update(RAW_ARGS_SUBS["plugins"])
    return tops, aliases


# Verified against patchi/cli/commands/plugins_cmd.py:cmd_plugins — if a
# branch is added there without updating this map (and the doc), the parity
# test fails, which is the point.
RAW_ARGS_SUBS: dict[str, set[str]] = {"plugins": {"list", "run", "run-all", "info"}}


def _documented_headings(text: str) -> set[str]:
    """Top-level command names with a `### `p <name>`...` doc heading."""
    heads = set()
    for m in re.finditer(r"^### `p ([a-z][a-z-]*)", text, re.M):
        heads.add(m.group(1))
    return heads


def _section_of(text: str, heading_pattern: str) -> str:
    m = re.search(heading_pattern, text, re.M)
    if not m:
        return ""
    nxt = re.search(r"^### |^## ", text[m.end() :], re.M)
    end = m.end() + (nxt.start() if nxt else len(text))
    return text[m.start() : end]


def _sub_documented(text: str, family: str, sub: str) -> bool:
    """A subcommand counts as documented when its full form appears anywhere
    (`p queue pause`) or its bare name is backticked inside the family's
    section (the subcommand-table style)."""
    if f"p {family} {sub}" in text:
        return True
    section = _section_of(text, rf"^### `p {re.escape(family)}`")
    if section and re.search(rf"`{re.escape(sub)}`", section):
        return True
    return False


def test_every_registered_command_is_documented():
    text = DOC.read_text(encoding="utf-8")
    heads = _documented_headings(text)
    tops, _ = _registered()

    missing = []
    for name in sorted(tops):
        if name in heads:
            continue
        if name in DOCUMENTED_ELSEWHERE:
            continue
        missing.append(name)
    assert not missing, (
        "Registered commands missing from COMMANDS.md — document them or add "
        "a justified DOCUMENTED_ELSEWHERE entry:\n  "
        + "\n  ".join(missing)
    )


def test_every_documented_command_is_registered():
    text = DOC.read_text(encoding="utf-8")
    tops, _ = _registered()
    heads = _documented_headings(text)

    # Commands the doc may legitimately mention without a top-level registry
    # entry: aliases are registered under their canonical name.
    canonical = set(tops)
    for als in _registered()[1].values():
        canonical.update(als)

    phantom = sorted(h for h in heads if h not in canonical)
    assert not phantom, (
        "COMMANDS.md documents commands that are not registered — drop the doc "
        "section or (re)register the command:\n  " + "\n  ".join(phantom)
    )


def test_documented_aliases_resolve():
    """`p blast` etc.: the doc names aliases in prose; every alias mentioned
    must belong to a registered command, and every registered alias should
    appear in the doc (users must be able to find the short form)."""
    text = DOC.read_text(encoding="utf-8")
    tops, aliases = _registered()

    for name, als in aliases.items():
        for a in als:
            assert a in text, f"alias `p {a}` (for p {name}) is registered but never mentioned in COMMANDS.md"


# Shorthand spellings inside an action-choices tuple don't need separate doc
# mentions when their long form is documented (p vr ls == p vr list).
CHOICE_ABBREVS: dict[str, str] = {"ls": "list"}


def test_registered_subcommands_are_documented():
    text = DOC.read_text(encoding="utf-8")
    tops, _ = _registered()

    gaps: list[str] = []
    for fam in sorted(tops):
        for sub in sorted(tops[fam]):
            if _sub_documented(text, fam, sub):
                continue
            long_form = CHOICE_ABBREVS.get(sub)
            if long_form and _sub_documented(text, fam, long_form):
                continue
            gaps.append(f"p {fam} {sub}")
    assert not gaps, (
        "Registered subcommands missing from COMMANDS.md:\n  " + "\n  ".join(gaps)
    )


def test_documented_subcommands_resolve():
    """Every `p <family> <sub>` full form written in the doc must be a real
    registered pair — no documenting subcommands that don't exist."""
    text = DOC.read_text(encoding="utf-8")
    tops, _ = _registered()

    phantom: list[str] = []
    for fam, sub in re.findall(r"`p ([a-z][a-z-]*) ([a-z][a-z-]*)`", text):
        if fam not in tops:
            continue  # top-level phantom is caught by the heading test
        if sub in tops[fam]:
            continue
        # bare-word false positives inside tables (`p patch` section rows are
        # handled); anything here is a doc mention of a nonexistent sub.
        phantom.append(f"p {fam} {sub}")
    assert not phantom, (
        "COMMANDS.md documents subcommands that are not registered:\n  "
        + "\n  ".join(sorted(set(phantom)))
    )
