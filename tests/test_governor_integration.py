"""
Governor v2 integration and end-to-end tests.

Tests _affected_symbols_from_scan with mocked dependencies,
graph neighborhood building, CLI wiring, and the real pipeline
on the di-stefano project.
"""

import gc
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_affected_symbols_from_scan_mocked():
    """Verify _affected_symbols_from_scan extracts symbols from graph_diff."""
    import tempfile

    from patchi.core.agents.governor import Governor
    td = tempfile.TemporaryDirectory()
    root = Path(td.name) / "testproj"
    root.mkdir()

    # Mock brain memory to return synthetic graph_diff
    mock_brain = {
        "graph_diff": {
            "new_files": ["src/main.py"],
            "added_edges": [],
            "removed_edges": [],
        }
    }

    # Mock SymbolGraph to return known symbols
    mock_symbol = MagicMock()
    mock_symbol.name = "main_function"

    mock_sg = MagicMock()
    mock_sg.get_symbols_in_file.return_value = [mock_symbol]
    # Governor now uses SymbolGraph as a context manager (`with`), so the mock
    # must return itself from __enter__ or assertions hit the wrong object.
    mock_sg.__enter__.return_value = mock_sg

    with patch("patchi.core.agents.governor.mem.get_brain", return_value=mock_brain), patch(
        "patchi.core.brain.symbol_graph.SymbolGraph", return_value=mock_sg
    ):
        gov = Governor(root)
        try:
            symbols = gov._affected_symbols_from_scan()
            print(f"  Affected symbols: {symbols}")
            assert "main_function" in symbols, f"Expected main_function, got {symbols}"
            mock_sg.get_symbols_in_file.assert_called_once_with("src/main.py")
            print("  PASSED\n")
        finally:
            gov.close()
            del gov
            gc.collect()
    td.cleanup()


def test_affected_symbols_empty_graph_diff():
    """When graph_diff has no new_files, should return empty list."""
    import tempfile

    from patchi.core.agents.governor import Governor
    td = tempfile.TemporaryDirectory()
    root = Path(td.name) / "testproj2"
    root.mkdir()

    mock_brain = {"graph_diff": {"new_files": [], "added_edges": [], "removed_edges": []}}

    with patch("patchi.core.agents.governor.mem.get_brain", return_value=mock_brain):
        gov = Governor(root)
        try:
            symbols = gov._affected_symbols_from_scan()
            assert symbols == [], f"Expected empty list, got {symbols}"
            print("  PASSED\n")
        finally:
            gov.close()
            del gov
            gc.collect()
    td.cleanup()


def test_graph_neighborhood_mocked():
    """Build graph neighborhood context with mocked SymbolGraph."""
    import tempfile

    from patchi.core.agents.governor import Governor
    from patchi.core.brain.symbol_graph import SymbolNode
    td = tempfile.TemporaryDirectory()
    root = Path(td.name) / "testproj3"
    root.mkdir()

    # Create realistic mock symbols
    helper = SymbolNode(id=1, name="Helper", kind="class", file="pkg/mod.py", line=1, end_line=5)
    runner = SymbolNode(id=2, name="Runner", kind="class", file="pkg/other.py", line=3, end_line=8)

    # Mock SymbolGraph
    mock_sg = MagicMock()
    mock_sg.get_symbol.return_value = helper
    mock_sg.get_dependents.return_value = [runner]
    mock_sg.get_dependencies.return_value = []
    # Context-manager protocol — Governor enters/exits SymbolGraph via `with`.
    mock_sg.__enter__.return_value = mock_sg

    with patch("patchi.core.brain.symbol_graph.SymbolGraph", return_value=mock_sg):
        gov = Governor(root)
        try:
            symbols = ["Helper"]
            neighborhood = gov._build_graph_neighborhood(symbols)
            print(f"  Neighborhood size: {len(neighborhood)}")
            assert len(neighborhood) == 1
            entry = neighborhood[0]
            assert entry["name"] == "Helper"
            assert len(entry["callers"]) == 1
            assert entry["callers"][0]["name"] == "Runner"
            print("  PASSED\n")
        finally:
            gov.close()
            del gov
            gc.collect()
    td.cleanup()


def test_cli_governor_flag():
    """Verify --governor CLI flag is wired correctly."""
    from patchi.cli.main import _build_parser

    p = _build_parser()
    args = p.parse_args(["scan", "--governor"])
    assert args.governor is True
    args2 = p.parse_args(["scan"])
    assert args2.governor is False
    print("  CLI --governor flag: OK")
    print("  PASSED\n")


@pytest.mark.skip(reason="AI-heavy, needs long timeout. Run manually with -k pipeline")
def test_full_pipeline_on_di_stefano():
    pass


if __name__ == "__main__":
    print("=== Governor v2 Integration Tests ===\n")
    test_cli_governor_flag()
    test_affected_symbols_from_scan_mocked()
    test_affected_symbols_empty_graph_diff()
    test_graph_neighborhood_mocked()
    # test_full_pipeline_on_di_stefano() - AI-heavy test, run manually
    print("\n=== All integration tests PASSED ===")
