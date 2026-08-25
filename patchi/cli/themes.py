"""
§2 CLI Theme System — palette definitions.

Each palette maps the SAME semantic token set to different Rich styles, plus a
matching symbol set. Symbols are separate from the Rich Theme (which only maps
str -> Style, not str -> arbitrary text) so `mono` can swap Unicode glyphs for
plain ASCII on terminals/encodings that can't render them, and so status is
never conveyed by color alone (colorblind-safe: shape/symbol/label carries the
meaning, color is a bonus, not the only signal).

Token set (used identically across every palette — callers use meaning, never
raw color):
    success, warn, error, info, muted        -- status
    heading, accent, path, count             -- structure
    grade.a .. grade.f                       -- health grades
    sev.critical, sev.high, sev.medium, sev.low  -- finding severity
"""

from __future__ import annotations

from rich.theme import Theme

_TOKEN_NAMES = (
    "success",
    "warn",
    "error",
    "info",
    "muted",
    "heading",
    "accent",
    "path",
    "count",
    "grade.a",
    "grade.b",
    "grade.c",
    "grade.d",
    "grade.f",
    "sev.critical",
    "sev.high",
    "sev.medium",
    "sev.low",
)


def _make(styles: dict[str, str], symbols: dict[str, str]) -> dict:
    missing = set(_TOKEN_NAMES) - set(styles)
    assert not missing, f"palette missing tokens: {missing}"
    return {"theme": Theme(styles), "symbols": symbols}


PALETTES: dict[str, dict] = {
    # Matches config.py's existing default ("theme": "dark") -- not renamed to
    # "default" to avoid yet another naming mismatch between config values and
    # palette keys.
    "dark": _make(
        {
            "success": "bold green",
            "warn": "bold yellow",
            "error": "bold red",
            "info": "cyan",
            "muted": "dim",
            "heading": "bold white",
            "accent": "bold magenta",
            "path": "underline cyan",
            "count": "bold",
            "grade.a": "bold green",
            "grade.b": "green",
            "grade.c": "yellow",
            "grade.d": "bold yellow",
            "grade.f": "bold red",
            "sev.critical": "bold white on red",
            "sev.high": "bold red",
            "sev.medium": "yellow",
            "sev.low": "dim",
        },
        {"ok": "✓", "warn": "!", "err": "✗"},
    ),
    "light": _make(
        {
            "success": "bold green3",
            "warn": "bold dark_orange",
            "error": "bold red3",
            "info": "blue3",
            "muted": "grey50",
            "heading": "bold black",
            "accent": "bold purple3",
            "path": "underline blue3",
            "count": "bold",
            "grade.a": "bold green3",
            "grade.b": "green3",
            "grade.c": "dark_orange",
            "grade.d": "bold dark_orange",
            "grade.f": "bold red3",
            "sev.critical": "bold white on red3",
            "sev.high": "bold red3",
            "sev.medium": "dark_orange",
            "sev.low": "grey50",
        },
        {"ok": "✓", "warn": "!", "err": "✗"},
    ),
    # Accessibility / NO_COLOR / non-TTY / --json. No color at all -- status is
    # conveyed entirely by ASCII labels, since a dumb terminal or a screen
    # reader gets nothing from color and may not even render Unicode glyphs.
    "mono": _make(
        {
            "success": "none",
            "warn": "none",
            "error": "none",
            "info": "none",
            "muted": "none",
            "heading": "bold",
            "accent": "bold",
            "path": "underline",
            "count": "bold",
            "grade.a": "none",
            "grade.b": "none",
            "grade.c": "none",
            "grade.d": "none",
            "grade.f": "none",
            "sev.critical": "bold",
            "sev.high": "bold",
            "sev.medium": "none",
            "sev.low": "none",
        },
        {"ok": "[OK]", "warn": "[!]", "err": "[X]"},
    ),
    "highcontrast": _make(
        {
            "success": "bold bright_green",
            "warn": "bold bright_yellow",
            "error": "bold bright_red",
            "info": "bold bright_cyan",
            "muted": "white",
            "heading": "bold bright_white",
            "accent": "bold bright_magenta",
            "path": "underline bright_cyan",
            "count": "bold bright_white",
            "grade.a": "bold bright_green",
            "grade.b": "bright_green",
            "grade.c": "bold bright_yellow",
            "grade.d": "bold bright_yellow",
            "grade.f": "bold bright_red",
            "sev.critical": "bold bright_white on bright_red",
            "sev.high": "bold bright_red",
            "sev.medium": "bold bright_yellow",
            "sev.low": "white",
        },
        {"ok": "✓", "warn": "!", "err": "✗"},
    ),
}

DEFAULT_PALETTE = "dark"


def resolve_palette_name(
    explicit: str | None,
    config_theme: str | None,
    no_color_env: bool,
    is_tty: bool,
    json_mode: bool,
) -> str:
    """
    Selection precedence, highest first:
    1. --json -> force mono, UNCONDITIONALLY (deliberately ranked above even an
       explicit --theme flag). This deviates from this feature's original
       design doc, which put --theme above --json -- but --json's whole
       purpose is a machine-parseable contract, and ANSI codes leaking into
       JSON output from a theme flag (e.g. a shell alias someone forgot about)
       would silently break downstream parsers. That's a correctness bug, not
       a style preference, so it can't be overridden.
    2. --theme flag (explicit)
    3. NO_COLOR env var -> force mono (spec: https://no-color.org)
    4. non-TTY -> force mono (piped output, no ANSI to confuse a non-terminal reader)
    5. settings.json's theme value
    6. DEFAULT_PALETTE
    """
    if json_mode:
        return "mono"
    if explicit and explicit in PALETTES:
        return explicit
    if no_color_env:
        return "mono"
    if not is_tty:
        return "mono"
    if config_theme and config_theme in PALETTES:
        return config_theme
    return DEFAULT_PALETTE
