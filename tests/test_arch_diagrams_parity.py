"""README architecture-diagram parity: the committed section must equal a
fresh regeneration.

The ``<!-- BEGIN/END GENERATED: architecture-diagrams -->`` block in
README.md is derived from the live Brain pipeline (import graph + web
routes). If someone edits the block by hand, or a code change makes the
diagrams stale without regenerating, this test fails with the exact fix.
The CLI twin is ``tools/gates/generate_arch_diagrams.py --check``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "tools" / "gates" / "generate_arch_diagrams.py"
README = REPO_ROOT / "README.md"

BEGIN = "<!-- BEGIN GENERATED: architecture-diagrams -->"
END = "<!-- END GENERATED: architecture-diagrams -->"


def _load_gate():
    """Import the gate module without executing its __main__ block."""
    spec = importlib.util.spec_from_file_location("generate_arch_diagrams", GATE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def fresh_block():
    """One regeneration shared by all tests in this module (~seconds)."""
    mod = _load_gate()
    return f"{BEGIN}\n{mod._render_diagrams()}{END}"


def _committed_section() -> str:
    text = README.read_text(encoding="utf-8")
    i, j = text.find(BEGIN), text.find(END)
    assert i != -1 and j != -1 and j > i, "README.md is missing the generated-section markers"
    return text[i : j + len(END)]


def test_readme_has_generated_markers():
    text = README.read_text(encoding="utf-8")
    assert BEGIN in text and END in text, (
        "README.md lost its architecture-diagram markers — re-add "
        f"{BEGIN!r} ... {END!r} or run tools/gates/generate_arch_diagrams.py"
    )


def test_committed_diagrams_match_regeneration(fresh_block):
    committed = _committed_section()
    if committed != fresh_block:
        diff_lines = [
            f"  committed: {a!r}\n  fresh:     {b!r}"
            for a, b in zip(committed.splitlines(), fresh_block.splitlines(), strict=False)
            if a != b
        ]
        pytest.fail(
            "README architecture diagrams are STALE — regenerate and commit:\n"
            "  python tools/gates/generate_arch_diagrams.py\n"
            + ("\nFirst differing lines:\n" + "\n".join(diff_lines[:4]) if diff_lines else "")
        )


def test_fresh_section_contains_both_diagrams(fresh_block):
    """The regeneration itself must stay well-formed (guards the guard)."""
    assert "```mermaid" in fresh_block, "regeneration produced no mermaid block"
    assert "### Module dependency map" in fresh_block
    assert "### Web dashboard routes" in fresh_block


def test_hand_edit_is_detected(fresh_block):
    """Guard the guard: one seeded byte of drift in the committed section
    must change the verdict — otherwise a whitespace-only edit could slip
    through a broken comparison. Pure string comparison, no README writes,
    no monkeypatching (the gate's renderer reads files internally)."""
    drifted = fresh_block.replace("```mermaid", "```mermaid ", 1)
    assert drifted != fresh_block
    # The parity verdict is exactly: committed_section == fresh_block.
    assert (drifted == fresh_block) is False
