"""
Performance benchmarks for Patchi's scanner, agents, and pipeline.

Run standalone: python -m tests.benchmarks.test_benchmarks
Run via pytest:  pytest tests/benchmarks/ -v
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures" / "languages"


def _time_it(func, *args, runs=3, **kwargs):
    """Run func multiple times, return (min_time_ms, result)."""
    best = float("inf")
    result = None
    for _ in range(runs):
        t0 = time.perf_counter()
        result = func(*args, **kwargs)
        t1 = time.perf_counter()
        best = min(best, (t1 - t0) * 1000)
    return best, result


# ── Scanner benchmarks ────────────────────────────────────────────────────────


class TestScannerPerformance:
    """Measure scanner speed per language and overall."""

    def test_scan_all_languages(self):
        """Benchmark: scan all 37 fixture files across 12 languages."""
        from patchi.core.brain.scanner import FileScanner
        scanner = FileScanner(FIXTURES)
        ms, result = _time_it(scanner.scan)
        assert len(result) >= 30
        print(f"\n  [BENCH] Scan all 12 languages: {ms:.1f}ms ({len(result)} files)")

    def test_scan_python(self):
        from patchi.core.brain.scanner import FileScanner
        s = FileScanner(FIXTURES / "python")
        ms, result = _time_it(s.scan)
        assert len(result) >= 3
        print(f"\n  [BENCH] Scan Python: {ms:.1f}ms ({len(result)} files)")

    def test_scan_typescript(self):
        from patchi.core.brain.scanner import FileScanner
        s = FileScanner(FIXTURES / "typescript")
        ms, result = _time_it(s.scan)
        assert len(result) >= 5
        print(f"\n  [BENCH] Scan TypeScript: {ms:.1f}ms ({len(result)} files)")

    def test_scan_java(self):
        from patchi.core.brain.scanner import FileScanner
        s = FileScanner(FIXTURES / "java")
        ms, result = _time_it(s.scan)
        assert len(result) >= 4
        print(f"\n  [BENCH] Scan Java: {ms:.1f}ms ({len(result)} files)")


# ── Import graph benchmarks ───────────────────────────────────────────────────


class TestImportGraphPerformance:
    """Measure import graph build speed."""

    @pytest.fixture(scope="class")
    def files(self):
        from patchi.core.brain.scanner import FileScanner
        return FileScanner(FIXTURES).scan()

    def test_build_graph(self, files):
        from patchi.core.brain.import_graph import build_graph
        ms, result = _time_it(build_graph, files, FIXTURES)
        assert len(result.nodes) > 0
        print(f"\n  [BENCH] Build import graph: {ms:.1f}ms ({len(result.nodes)} nodes)")

    def test_find_circular(self, files):
        from patchi.core.brain.import_graph import build_graph, find_circular_dependencies
        graph = build_graph(files, FIXTURES)
        ms, result = _time_it(find_circular_dependencies, graph)
        assert isinstance(result, list)
        print(f"\n  [BENCH] Find circular deps: {ms:.1f}ms ({len(result)} found)")

    def test_find_dead(self, files):
        from patchi.core.brain.import_graph import build_graph, find_dead_files
        graph = build_graph(files, FIXTURES)
        ms, result = _time_it(find_dead_files, files, graph)
        assert isinstance(result, list)
        print(f"\n  [BENCH] Find dead files: {ms:.1f}ms ({len(result)} dead)")


# ── Type checker benchmarks ───────────────────────────────────────────────────


class TestTypeCheckerPerformance:
    """Measure type checking speed per language."""

    def test_check_python(self):
        from patchi.core.brain.languages import Lang
        from patchi.core.brain.type_checker import check_types
        source = (FIXTURES / "python" / "app.py").read_text()
        ms, result = _time_it(check_types, source, Lang.PYTHON, "app.py")
        assert isinstance(result, list)
        print(f"\n  [BENCH] Type check Python: {ms:.1f}ms ({len(result)} issues)")

    def test_check_typescript(self):
        from patchi.core.brain.languages import Lang
        from patchi.core.brain.type_checker import check_types
        source = (FIXTURES / "typescript" / "app.ts").read_text()
        ms, result = _time_it(check_types, source, Lang.TYPESCRIPT, "app.ts")
        assert isinstance(result, list)
        print(f"\n  [BENCH] Type check TypeScript: {ms:.1f}ms ({len(result)} issues)")


# ── Security agent benchmarks ─────────────────────────────────────────────────


class TestSecurityAgentPerformance:
    """Measure security agent execution time."""

    def _make_input(self):
        from patchi.core.agents.base import AgentInput
        return AgentInput(root=FIXTURES, scope=[], brain={}, config={})

    def test_injection_agent(self):
        from patchi.core.security.injection_agent import InjectionAgent
        agent = InjectionAgent()
        inp = self._make_input()
        ms, result = _time_it(agent.run, inp)
        assert result is not None
        print(f"\n  [BENCH] InjectionAgent: {ms:.1f}ms ({len(result.findings)} findings)")

    def test_ssrf_agent(self):
        from patchi.core.security.ssrf_agent import SSRFProtectionAgent
        agent = SSRFProtectionAgent()
        inp = self._make_input()
        ms, result = _time_it(agent.run, inp)
        assert result is not None
        print(f"\n  [BENCH] SSRFProtectionAgent: {ms:.1f}ms ({len(result.findings)} findings)")

    def test_catch_block_agent(self):
        from patchi.core.security.catch_block_auditor import CatchBlockAuditor
        agent = CatchBlockAuditor()
        inp = self._make_input()
        ms, result = _time_it(agent.run, inp)
        assert result is not None
        print(f"\n  [BENCH] CatchBlockAuditor: {ms:.1f}ms ({len(result.findings)} findings)")


# ── Duplicate scanner benchmarks ─────────────────────────────────────────────
# REMOVED: DuplicateScanner was deleted (function-level clone detection never
# produced signal worth its noise — 5704 raw findings for ~32 real). This
# section intentionally left blank to keep diff history greppable.


# ── Blast radius benchmarks ──────────────────────────────────────────────────


class TestBlastRadiusPerformance:
    """Measure blast radius calculation speed."""

    @pytest.fixture(scope="class")
    def graph(self):
        from patchi.core.brain.import_graph import build_graph
        from patchi.core.brain.scanner import FileScanner
        files = FileScanner(FIXTURES).scan()
        return build_graph(files, FIXTURES)

    def test_build_map(self, graph):
        from patchi.core.brain.blast_radius import build_blast_radius_map
        ms, result = _time_it(build_blast_radius_map, graph)
        assert isinstance(result, dict)
        print(f"\n  [BENCH] Blast radius map: {ms:.1f}ms ({len(result)} entries)")


# ── Standalone timing ────────────────────────────────────────────────────────


def _standalone_timing():
    """Run timing without pytest-benchmark."""
    print("\n=== Patchi Performance Benchmarks ===\n")

    from patchi.core.agents.base import AgentInput
    from patchi.core.brain.blast_radius import build_blast_radius_map
    from patchi.core.brain.import_graph import build_graph, find_dead_files
    from patchi.core.brain.languages import Lang
    from patchi.core.brain.scanner import FileScanner
    from patchi.core.brain.type_checker import check_types
    from patchi.core.security.catch_block_auditor import CatchBlockAuditor
    from patchi.core.security.injection_agent import InjectionAgent
    from patchi.core.security.ssrf_agent import SSRFProtectionAgent

    scanner = FileScanner(FIXTURES)
    ms, files = _time_it(scanner.scan, runs=5)
    print(f"Scanner:       {ms:.1f}ms  ({len(files)} files)")

    ms, graph = _time_it(build_graph, files, FIXTURES, runs=5)
    print(f"Import graph:  {ms:.1f}ms  ({len(graph.nodes)} nodes, {sum(len(v) for v in graph.edges.values())} edges)")

    ms, dead = _time_it(find_dead_files, files, graph, runs=5)
    print(f"Dead files:    {ms:.1f}ms  ({len(dead)} dead)")

    ms, br_map = _time_it(build_blast_radius_map, graph, runs=5)
    print(f"Blast radius:  {ms:.1f}ms  ({len(br_map)} entries)")

    for lang, file_name, lang_enum in [
        ("Python", "app.py", Lang.PYTHON),
        ("TypeScript", "app.ts", Lang.TYPESCRIPT),
    ]:
        source = (FIXTURES / lang_enum.value / file_name).read_text()
        ms, issues = _time_it(check_types, source, lang_enum, file_name, runs=5)
        print(f"Type check {lang:12s}: {ms:.1f}ms  ({len(issues)} issues)")

    inp = AgentInput(root=FIXTURES, scope=[], brain={}, config={})
    for name, agent_cls in [
        ("Injection", InjectionAgent),
        ("SSRF", SSRFProtectionAgent),
        ("CatchBlock", CatchBlockAuditor),
    ]:
        agent = agent_cls()
        ms, result = _time_it(agent.run, inp, runs=3)
        print(f"Agent {name:12s}: {ms:.1f}ms  ({len(result.findings)} findings)")

    print("\n=== Done ===\n")


if __name__ == "__main__":
    _standalone_timing()
