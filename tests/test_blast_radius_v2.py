"""Tests for patchi.core.brain.blast_radius (v2 symbol-level)"""

import unittest
from dataclasses import dataclass

from patchi.core.brain.blast_radius import (
    GraphDiffImpact,
    SymbolBlastResult,
    analyze_graph_diff,
    calculate_file_symbol_blast_radius,
    calculate_symbol_blast_radius,
)
from patchi.core.brain.symbol_graph import GraphDiff

# ── Mock SymbolNode ─────────────────────────────────────────────────────────────

@dataclass
class MockSymbolNode:
    id: int = 0
    name: str = ""
    kind: str = ""
    file: str = ""
    line: int = 0
    is_exported: bool = False


# ── Mock SymbolGraph ────────────────────────────────────────────────────────────

class MockSymbolGraph:
    """Minimal symbol graph for testing."""

    def __init__(self):
        self._symbols: dict[str, MockSymbolNode] = {}
        self._file_symbols: dict[str, list[MockSymbolNode]] = {}
        self._dependents: dict[int, list[MockSymbolNode]] = {}
        self._dependencies: dict[int, list[MockSymbolNode]] = {}
        self._next_id = 1

    def add_symbol(
        self, name: str, file: str, kind: str = "function", line: int = 1, exported: bool = False
    ) -> MockSymbolNode:
        sym = MockSymbolNode(
            id=self._next_id,
            name=name,
            kind=kind,
            file=file,
            line=line,
            is_exported=exported,
        )
        self._next_id += 1
        self._symbols[f"{name}:{file}"] = sym
        self._file_symbols.setdefault(file, []).append(sym)
        self._dependents.setdefault(sym.id, [])
        self._dependencies.setdefault(sym.id, [])
        return sym

    def add_dependent(self, from_name: str, from_file: str, to_name: str, to_file: str) -> None:
        from_sym = self._symbols.get(f"{from_name}:{from_file}")
        to_sym = self._symbols.get(f"{to_name}:{to_file}")
        if from_sym and to_sym:
            self._dependents[to_sym.id].append(from_sym)
            self._dependencies[from_sym.id].append(to_sym)

    # SymbolGraph API methods used by blast_radius
    def get_symbol(self, name, file):
        return self._symbols.get(f"{name}:{file}")

    def get_symbols_in_file(self, file):
        return self._file_symbols.get(file, [])

    def get_dependents(self, name, file=None):
        sym = self._symbols.get(f"{name}:{file}")
        if not sym:
            return []
        return self._dependents.get(sym.id, [])

    def get_dependencies(self, symbol_id):
        return self._dependencies.get(symbol_id, [])


# ── Tests ───────────────────────────────────────────────────────────────────────

class TestSymbolBlastResult(unittest.TestCase):
    def test_minimal_result(self):
        r = SymbolBlastResult(symbol_name="foo", file="src/lib.py", line=10)
        self.assertEqual(r.symbol_name, "foo")
        self.assertEqual(r.total_affected, 0)
        self.assertEqual(r.risk_level, "low")

    def test_to_dict_format(self):
        r = SymbolBlastResult(
            symbol_name="bar",
            file="src/api.py",
            line=42,
            downstream_direct=[{"name": "caller", "file": "src/caller.py", "depth": 1}],
            downstream_count=3,
            risk_level="high",
            risk_score=0.75,
        )
        d = r.to_dict()
        self.assertEqual(d["symbol"], "bar")
        self.assertEqual(d["file"], "src/api.py")
        self.assertEqual(d["downstream"]["all"], 3)
        self.assertEqual(len(d["downstream"]["samples"]), 1)


class TestCalculateSymbolBlastRadius(unittest.TestCase):
    def test_unknown_symbol_returns_empty(self):
        graph = MockSymbolGraph()
        result = calculate_symbol_blast_radius("nobody", "no/file.py", graph)
        self.assertEqual(result.risk_level, "unknown")
        self.assertEqual(result.risk_score, 0.0)

    def test_no_dependents_low_risk(self):
        graph = MockSymbolGraph()
        graph.add_symbol("isolated", "src/lib.py")
        result = calculate_symbol_blast_radius("isolated", "src/lib.py", graph)
        self.assertEqual(result.downstream_count, 0)
        self.assertLessEqual(result.risk_score, 0.5)

    def test_single_direct_dependent(self):
        graph = MockSymbolGraph()
        graph.add_symbol("helper", "src/helpers.py")
        graph.add_symbol("caller", "src/main.py")
        graph.add_dependent("caller", "src/main.py", "helper", "src/helpers.py")
        result = calculate_symbol_blast_radius("helper", "src/helpers.py", graph)
        self.assertEqual(result.downstream_count, 1)
        self.assertEqual(len(result.downstream_direct), 1)
        self.assertEqual(result.downstream_direct[0]["name"], "caller")

    def test_transitive_dependents(self):
        graph = MockSymbolGraph()
        graph.add_symbol("base", "src/base.py")
        graph.add_symbol("middle", "src/middle.py")
        graph.add_symbol("top", "src/top.py")
        graph.add_dependent("middle", "src/middle.py", "base", "src/base.py")
        graph.add_dependent("top", "src/top.py", "middle", "src/middle.py")
        result = calculate_symbol_blast_radius("base", "src/base.py", graph, max_depth=5)
        self.assertEqual(result.downstream_count, 2)

    def test_upstream_dependencies(self):
        graph = MockSymbolGraph()
        graph.add_symbol("worker", "src/worker.py")
        graph.add_symbol("lib", "src/lib.py")
        graph.add_symbol("tool", "src/tool.py")
        graph.add_dependent("worker", "src/worker.py", "lib", "src/lib.py")
        graph.add_dependent("tool", "src/tool.py", "lib", "src/lib.py")
        # worker also depends on tool
        graph.add_dependent("worker", "src/worker.py", "tool", "src/tool.py")
        result = calculate_symbol_blast_radius("lib", "src/lib.py", graph)
        self.assertEqual(result.downstream_count, 2)

    def test_route_symbol_gets_high_criticality(self):
        graph = MockSymbolGraph()
        graph.add_symbol("login_user", "src/routes.py", kind="route", line=15)
        result = calculate_symbol_blast_radius("login_user", "src/routes.py", graph)
        self.assertGreaterEqual(result.criticality_score, 0.8)

    def test_exported_symbol_gets_medium_criticality(self):
        graph = MockSymbolGraph()
        graph.add_symbol("exported_func", "src/__init__.py", kind="function", exported=True)
        result = calculate_symbol_blast_radius("exported_func", "src/__init__.py", graph)
        self.assertGreaterEqual(result.criticality_score, 0.5)

    def test_test_coverage_reduces_risk(self):
        graph = MockSymbolGraph()
        graph.add_symbol("util", "src/util.py")
        graph.add_symbol("test_util", "tests/test_util.py")
        graph.add_dependent("test_util", "tests/test_util.py", "util", "src/util.py")
        result_covered = calculate_symbol_blast_radius(
            "util", "src/util.py", graph,
            test_coverage={"src/util.py": 0.95, "tests/test_util.py": 1.0},
        )
        result_naked = calculate_symbol_blast_radius(
            "util", "src/util.py", graph,
            test_coverage={"src/util.py": 0.0, "tests/test_util.py": 0.0},
        )
        self.assertLessEqual(result_covered.risk_score, result_naked.risk_score)

    def test_criticality_tag_overrides_default(self):
        graph = MockSymbolGraph()
        graph.add_symbol("critical_fn", "src/core.py", kind="function")
        result = calculate_symbol_blast_radius(
            "critical_fn", "src/core.py", graph,
            criticality_tags={"critical_fn": 0.95},
        )
        self.assertAlmostEqual(result.criticality_score, 0.95, places=2)

    def test_risk_level_escalation(self):
        graph = MockSymbolGraph()
        graph.add_symbol("hub", "src/hub.py")
        for i in range(25):
            name = f"consumer_{i}"
            graph.add_symbol(name, f"src/consumer_{i}.py")
            graph.add_dependent(name, f"src/consumer_{i}.py", "hub", "src/hub.py")
        result = calculate_symbol_blast_radius("hub", "src/hub.py", graph)
        # 25 direct consumers + no test coverage + default criticality 0.3
        # downstream_risk = 25/50 = 0.5, coverage_risk = 0.5, criticality = 0.3
        # risk_score = 0.5*0.4 + 0.5*0.3 + 0.3*0.3 = 0.2 + 0.15 + 0.09 = 0.44
        # With no transitive dependents and no criticality tag, this is medium
        self.assertEqual(result.risk_level, "medium")
        self.assertGreater(result.risk_score, 0.3)


class TestCalculateFileSymbolBlastRadius(unittest.TestCase):
    def test_all_symbols_in_file(self):
        graph = MockSymbolGraph()
        graph.add_symbol("func_a", "src/multi.py")
        graph.add_symbol("func_b", "src/multi.py")
        graph.add_symbol("func_c", "src/multi.py")
        results = calculate_file_symbol_blast_radius("src/multi.py", graph)
        self.assertEqual(len(results), 3)

    def test_empty_file(self):
        graph = MockSymbolGraph()
        results = calculate_file_symbol_blast_radius("src/empty.py", graph)
        self.assertEqual(results, [])


class TestGraphDiffImpact(unittest.TestCase):
    def test_minimal_impact(self):
        imp = GraphDiffImpact(file="src/main.py")
        self.assertEqual(imp.total_changes, 0)
        self.assertEqual(imp.risk_level, "low")

    def test_to_dict_format(self):
        imp = GraphDiffImpact(
            file="src/main.py",
            symbols_added=2,
            symbols_removed=1,
            downstream_impact=5,
            risk_level="high",
        )
        d = imp.to_dict()
        self.assertEqual(d["file"], "src/main.py")
        self.assertEqual(d["symbols_added"], 2)
        self.assertEqual(d["symbols_removed"], 1)
        self.assertEqual(d["downstream_impact"], 5)

    def test_total_changes(self):
        imp = GraphDiffImpact(
            file="src/lib.py",
            symbols_added=3,
            symbols_removed=1,
            symbols_modified=2,
        )
        self.assertEqual(imp.total_changes, 6)


class TestAnalyzeGraphDiff(unittest.TestCase):
    def test_no_changes_returns_empty(self):
        graph = MockSymbolGraph()
        diff = GraphDiff()
        results = analyze_graph_diff(diff, graph)
        self.assertEqual(results, [])

    def test_added_symbols_appear_in_impact(self):
        graph = MockSymbolGraph()
        sym = graph.add_symbol("new_fn", "src/new.py")
        diff = GraphDiff(added=[sym])
        results = analyze_graph_diff(diff, graph)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].file, "src/new.py")
        self.assertEqual(results[0].symbols_added, 1)

    def test_removed_symbols_appear_in_impact(self):
        graph = MockSymbolGraph()
        sym = graph.add_symbol("dead_fn", "src/dead.py")
        diff = GraphDiff(removed=[sym])
        results = analyze_graph_diff(diff, graph)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].symbols_removed, 1)

    def test_modified_symbols_appear_in_impact(self):
        graph = MockSymbolGraph()
        sym = graph.add_symbol("patched", "src/patched.py")
        diff = GraphDiff(modified=[sym])
        results = analyze_graph_diff(diff, graph)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].symbols_modified, 1)

    def test_multiple_files_in_diff(self):
        graph = MockSymbolGraph()
        s1 = graph.add_symbol("fn_a", "src/a.py")
        s2 = graph.add_symbol("fn_b", "src/b.py")
        s3 = graph.add_symbol("fn_c", "src/a.py")
        diff = GraphDiff(added=[s1, s3], removed=[s2])
        results = analyze_graph_diff(diff, graph)
        self.assertEqual(len(results), 2)

    def test_risk_level_critical(self):
        graph = MockSymbolGraph()
        base = graph.add_symbol("base", "src/base.py")
        for i in range(20):
            graph.add_symbol(f"consumer_{i}", f"src/consumer_{i}.py")
            graph.add_dependent(f"consumer_{i}", f"src/consumer_{i}.py", "base", "src/base.py")
        diff = GraphDiff(modified=[base])
        results = analyze_graph_diff(diff, graph)
        self.assertIn(results[0].risk_level, ("critical", "high"))


if __name__ == "__main__":
    unittest.main()
