"""Shared Markdown writer — consistent file output for all CLI commands.

Standard format:
- Starts with ``# <title>``
- Sections separated by blank lines
- Heading hierarchy never jumps levels
- Single trailing newline

Usage::

    from patchi.cli.markdown_writer import write_markdown

    write_markdown(
        Path("report.md"),
        "Project Report",
        [
            (2, "Summary", ["Line 1", "Line 2"]),
            (2, "Details", ["- item one", "- item two"]),
            (3, "Sub-section", ["Sub content"]),
        ],
    )
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path


def write_markdown(
    path: Path,
    title: str,
    sections: Sequence[tuple[int, str, list[str]]],
    *,
    encoding: str = "utf-8",
) -> None:
    """Write a Markdown file with consistent formatting.

    Parameters
    ----------
    path:
        Destination file.  Parent directories are created automatically.
    title:
        Top-level heading (rendered as ``# title``).
    sections:
        Each entry is ``(heading_level, heading_text, content_lines)``.
        *heading_level* is an integer (2 = ``##``, 3 = ``###``, etc.).
        Content lines are plain strings — the caller is responsible for
        any inline Markdown.
    encoding:
        File encoding, default UTF-8.
    """
    lines: list[str] = []

    # Title — always H1.
    lines.append(f"# {title}")
    lines.append("")

    # Sections.
    for level, heading, content in sections:
        level = max(2, min(level, 6))  # Clamp 2-6; title is always H1.
        lines.append(f"{'#' * level} {heading}")
        lines.append("")
        if content:
            lines.extend(content)
            lines.append("")

    # Trailing newline.
    text = "\n".join(lines)
    if not text.endswith("\n"):
        text += "\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding=encoding)
