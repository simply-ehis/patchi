"""
Logo draw sequence for Patchi CLI.

Big, bold green ASCII art wordmark "PATCHI" with letter-by-letter animation.
"""

import sys
import time

from rich.console import Console
from rich.style import Style
from rich.text import Text

from patchi.core.constants import PATCHI_VERSION

GREEN = "#4ADE80"
GREEN_DIM = "#22C55E"
VERSION_COLOR = "#7A6A5A"

# Big block-letter Unicode box-drawing art for PATCHI (6 lines tall)
_FULL_ART = [
    "██████╗  █████╗ ████████╗ ██████╗██╗  ██╗██╗",
    "██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║  ██║██║",
    "██████╔╝███████║   ██║   ██║     ███████║██║",
    "██╔═══╝ ██╔══██║   ██║   ██║     ██╔══██║██║",
    "██║     ██║  ██║   ██║   ╚██████╗██║  ██║██║",
    "╚═╝     ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝",
]

# Each letter's column span in the art (start, end)
_LETTER_COLS = {
    "P": (0, 11),
    "A": (11, 17),
    "T": (17, 28),
    "C": (28, 39),
    "H": (39, 50),
    "I": (50, 57),
}

_ANIM_FRAMES = [
    (150, "P"),
    (300, "PA"),
    (450, "PAT"),
    (600, "PATC"),
    (750, "PATCH"),
    (900, "PATCHI"),
]


def draw(console: Console | None = None, skip: bool = False) -> None:
    """Run the logo draw sequence."""
    if skip:
        return

    con = console or Console(stderr=False, highlight=False)
    is_tty = sys.stdout.isatty() or (
        con.file is not None and hasattr(con.file, "isatty") and con.file.isatty()
    )

    if not is_tty:
        _print_final(con)
        return

    start = time.monotonic()
    current_lines = 0

    def erase_frame(n_lines: int) -> None:
        if n_lines <= 0:
            return
        for _ in range(n_lines):
            con.file.write("\033[F\033[2K")
        con.file.flush()

    def print_art(text: str) -> int:
        t = Text()
        t.append(text, style=Style(color=GREEN, bold=True))
        con.print(t, end="\n")
        return text.count("\n") + 1

    def build_partial_art(partial_word: str) -> str:
        if not partial_word:
            return ""
        max_col = max(_LETTER_COLS[ch][1] for ch in partial_word if ch in _LETTER_COLS)
        lines = []
        for art_line in _FULL_ART:
            lines.append(art_line[:max_col].rstrip())
        return "\n".join(lines)

    for target_ms, word in _ANIM_FRAMES:
        target_s = target_ms / 1000.0
        elapsed = time.monotonic() - start
        wait = target_s - elapsed
        if wait > 0:
            time.sleep(wait)

        erase_frame(current_lines)
        art_text = build_partial_art(word)
        current_lines = print_art(art_text)

    time.sleep(0.3)

    erase_frame(current_lines)
    art_text = build_partial_art("PATCHI")
    t = Text()
    t.append(art_text + "\n", style=Style(color=GREEN, bold=True))
    t.append(
        f"  v{PATCHI_VERSION}  An immune system for your apps.\n",
        style=Style(color=VERSION_COLOR),
    )
    con.print(t)


def _print_final(con: Console) -> None:
    """Non-interactive fallback - print full art in one shot."""
    art_text = build_partial_art("PATCHI")
    t = Text()
    t.append(art_text + "\n", style=Style(color=GREEN, bold=True))
    t.append(
        f"  v{PATCHI_VERSION}  An immune system for your apps.\n",
        style=Style(color=VERSION_COLOR),
    )
    con.print(t)


def build_partial_art(partial_word: str) -> str:
    """Build the ASCII art showing only the letters typed so far."""
    if not partial_word:
        return ""
    max_col = max(_LETTER_COLS[ch][1] for ch in partial_word if ch in _LETTER_COLS)
    lines = []
    for art_line in _FULL_ART:
        lines.append(art_line[:max_col].rstrip())
    return "\n".join(lines)


if __name__ == "__main__":
    draw()
