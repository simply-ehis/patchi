"""
§2 CLI Theme System — semantic helpers.

Thin wrappers so migrating a raw `print(...)` to something themed is a
one-liner: `print(f"Error: {msg}")` -> `err(msg)`. Every helper uses semantic
tokens (never raw color) and pulls its symbol from the active palette via
`console.symbol()`, so `mono` gets ASCII (`[OK]`/`[!]`/`[X]`) automatically
instead of Unicode glyphs a dumb terminal or encoding can't render.
"""

from __future__ import annotations

from patchi.cli.console import con, symbol


def ok(msg: str) -> None:
    con.print(f"[success]{symbol('ok')}[/] {msg}")


def warn(msg: str) -> None:
    con.print(f"[warn]{symbol('warn')}[/] {msg}")


def err(msg: str) -> None:
    con.print(f"[error]{symbol('err')}[/] {msg}")


def info(msg: str) -> None:
    con.print(f"[info]{msg}[/]")


def muted(msg: str) -> None:
    con.print(f"[muted]{msg}[/]")


def heading(msg: str) -> None:
    con.print(f"\n[heading]{msg}[/]")


def accent(msg: str) -> str:
    """Returns markup (not printed) for embedding in a larger f-string."""
    return f"[accent]{msg}[/]"


def path(p: str) -> str:
    """Returns markup (not printed) for embedding a file path in a larger line."""
    return f"[path]{p}[/]"


def grade(score, letter: str) -> str:
    """Returns markup for a health-grade display, e.g. grade(87, 'B') -> '87 (B)' styled."""
    key = f"grade.{letter.lower()}"
    return f"[{key}]{score} ({letter})[/]"


def severity(label: str) -> str:
    """Returns markup for a severity label: severity('critical') -> styled 'CRITICAL'."""
    key = f"sev.{label.lower()}"
    return f"[{key}]{label.upper()}[/]"


def kv(k: str, v) -> None:
    con.print(f"  [muted]{k}[/] {v}")


def count(n) -> str:
    """Returns markup for a count/number that should stand out, e.g. in a summary line."""
    return f"[count]{n}[/]"
