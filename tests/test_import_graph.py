"""Unit tests for patchi.core.brain.import_graph"""

import tempfile
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core.brain.blast_radius import (
    calculate_blast_radius,
)
from patchi.core.brain.import_graph import (
    ImportGraph,
    build_graph,
    find_circular_dependencies,
    find_dead_files,
)
from patchi.core.brain.scanner import FileInfo, FileScanner


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


def _write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _scan_files(root: Path) -> list[FileInfo]:
    scanner = FileScanner(root)
    return scanner.scan()


class TestImportGraph(unittest.TestCase):
    def test_add_edge(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "b.py")
        self.assertIn("b.py", graph.edges["a.py"])
        self.assertIn("a.py", graph.reverse["b.py"])

    def test_nodes_populated(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "b.py")
        self.assertIn("a.py", graph.nodes)
        self.assertIn("b.py", graph.nodes)

    def test_to_dict(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "b.py")
        d = graph.to_dict()
        self.assertIn("nodes", d)
        self.assertIn("edges", d)


class TestBuildGraph(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_builds_graph_from_relative_imports(self):
        _write(self.root, "src/app.py", "from .utils import helper\n")
        _write(self.root, "src/utils.py", "def helper(): pass\n")
        files = _scan_files(self.root)
        graph = build_graph(files, self.root)
        # app.py should import utils.py
        app_edges = graph.edges.get("src/app.py", set())
        self.assertIn("src/utils.py", app_edges)

    def test_external_imports_not_in_graph_edges(self):
        _write(self.root, "src/app.py", "import os\nimport sys\n")
        files = _scan_files(self.root)
        graph = build_graph(files, self.root)
        # External packages should not create edges to local files
        app_edges = graph.edges.get("src/app.py", set())
        self.assertEqual(len(app_edges), 0)

    def test_all_files_registered_as_nodes(self):
        _write(self.root, "src/app.py", "pass")
        _write(self.root, "src/utils.py", "pass")
        files = _scan_files(self.root)
        graph = build_graph(files, self.root)
        self.assertIn("src/app.py", graph.nodes)
        self.assertIn("src/utils.py", graph.nodes)


class TestCircularDependencies(unittest.TestCase):
    def test_no_cycles_in_clean_graph(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "b.py")
        graph.add_edge("b.py", "c.py")
        cycles = find_circular_dependencies(graph)
        self.assertEqual(cycles, [])

    def test_detects_simple_cycle(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "b.py")
        graph.add_edge("b.py", "a.py")
        cycles = find_circular_dependencies(graph)
        self.assertGreater(len(cycles), 0)
        cycle_files = set(cycles[0].cycle)
        self.assertIn("a.py", cycle_files)
        self.assertIn("b.py", cycle_files)

    def test_detects_three_way_cycle(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "b.py")
        graph.add_edge("b.py", "c.py")
        graph.add_edge("c.py", "a.py")
        cycles = find_circular_dependencies(graph)
        self.assertGreater(len(cycles), 0)
        all_files = set()
        for c in cycles:
            all_files.update(c.cycle)
        self.assertIn("a.py", all_files)
        self.assertIn("b.py", all_files)
        self.assertIn("c.py", all_files)

    def test_short_label(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "b.py")
        graph.add_edge("b.py", "a.py")
        cycles = find_circular_dependencies(graph)
        self.assertIn("→", cycles[0].short_label)

    def test_deduplicates_cycles(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "b.py")
        graph.add_edge("b.py", "a.py")
        cycles = find_circular_dependencies(graph)
        # Should only be one cycle, not two (a→b→a and b→a→b are the same)
        self.assertEqual(len(cycles), 1)


class TestBlastRadius(unittest.TestCase):
    def test_no_dependents(self):
        graph = ImportGraph()
        graph.nodes.add("standalone.py")
        br = calculate_blast_radius("standalone.py", graph)
        self.assertEqual(br.direct_dependents, [])
        self.assertEqual(br.all_dependents, [])
        self.assertEqual(br.risk_level, "low")

    def test_direct_dependents(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "base.py")
        graph.add_edge("b.py", "base.py")
        br = calculate_blast_radius("base.py", graph)
        self.assertEqual(sorted(br.direct_dependents), ["a.py", "b.py"])

    def test_transitive_dependents(self):
        graph = ImportGraph()
        # a → base, b → a, c → b  (changing base affects a, b, c)
        graph.add_edge("a.py", "base.py")
        graph.add_edge("b.py", "a.py")
        graph.add_edge("c.py", "b.py")
        br = calculate_blast_radius("base.py", graph)
        self.assertIn("a.py", br.all_dependents)
        self.assertIn("b.py", br.all_dependents)
        self.assertIn("c.py", br.all_dependents)

    def test_risk_level_low_zero(self):
        graph = ImportGraph()
        graph.nodes.add("isolated.py")
        br = calculate_blast_radius("isolated.py", graph)
        self.assertEqual(br.risk_level, "low")

    def test_risk_level_medium(self):
        graph = ImportGraph()
        graph.nodes.add("target.py")
        for i in range(4):
            graph.add_edge(f"dep{i}.py", "target.py")
        br = calculate_blast_radius("target.py", graph)
        self.assertEqual(br.risk_level, "medium")

    def test_risk_level_high(self):
        graph = ImportGraph()
        graph.nodes.add("target.py")
        for i in range(10):
            graph.add_edge(f"dep{i}.py", "target.py")
        br = calculate_blast_radius("target.py", graph)
        self.assertEqual(br.risk_level, "high")

    def test_total_affected(self):
        graph = ImportGraph()
        graph.add_edge("a.py", "core.py")
        graph.add_edge("b.py", "core.py")
        br = calculate_blast_radius("core.py", graph)
        self.assertEqual(br.total_affected, 2)


class TestDeadFiles(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_unused_file_is_dead(self):
        _write(self.root, "src/app.py", "pass")
        _write(self.root, "src/unused.py", "def orphan(): pass")
        files = _scan_files(self.root)
        graph = build_graph(files, self.root)
        dead = find_dead_files(files, graph)
        dead_names = [d.split("/")[-1] for d in dead]
        self.assertIn("unused.py", dead_names)

    def test_imported_file_not_dead(self):
        _write(self.root, "src/app.py", "from .utils import foo\n")
        _write(self.root, "src/utils.py", "def foo(): pass\n")
        files = _scan_files(self.root)
        graph = build_graph(files, self.root)
        dead = find_dead_files(files, graph)
        dead_names = [d.split("/")[-1] for d in dead]
        self.assertNotIn("utils.py", dead_names)

    def test_test_files_excluded_from_dead(self):
        _write(self.root, "tests/test_app.py", "def test_foo(): pass")
        files = _scan_files(self.root)
        graph = build_graph(files, self.root)
        dead = find_dead_files(files, graph)
        for d in dead:
            self.assertNotIn("test_", d.split("/")[-1])


if __name__ == "__main__":
    unittest.main()
