"""A real failing pytest test file used to verify the pytest-capture path.

This file imports cleanly (no module-level crash) but its test function
fails at runtime — the case that the standalone harness cannot see and the
pytest harness exists for.
"""


def test_total_is_none() -> None:
    total = None
    assert total + 5 == 10  # TypeError: NoneType + int


def test_passing() -> None:
    assert 1 + 1 == 2
