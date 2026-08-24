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
        from patchi.core.brain.type_checker import check_types
        from patchi.core.brain.languages import Lang
        source = (FIXTURES / "python" / "app.py").read_text()
        ms, result = _time_it(check_types, source, Lang.PYTHON, "app.py")
        assert isinstance(result, list)
        print(f"\n  [BENCH] Type check Python: {ms:.1f}ms ({len(result)} issues)")

    def test_check_typescript(self):
        from patchi.core.brain.type_checker import check_types
        from patchi.core.brain.languages import Lang
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


def _make_duplicate_corpus(n_functions: int, n_clusters: int) -> list[dict]:
    """Synthetic corpus: `n_clusters` groups of near-identical functions plus
    distinct filler, sized to stress duplicate detection.

    IMPORTANT: every cluster uses DISTINCT token names, so buckets stay
    per-cluster — the corpus stresses the bucket/candidate machinery, not
    the (inherently quadratic) "one giant cluster of k identical bodies"
    output case. Within a cluster each function shares a 20-token body;
    filler functions are fully unique.
    """
    functions: list[dict] = []
    per_cluster = max(1, n_functions // (n_clusters or 1))
    for c in range(n_clusters):
        cluster_body = " ".join(f"tc{c}_{i}" for i in range(20))
        for k in range(per_cluster):
            functions.append(
                {
                    "file": f"src/cluster_{c}.py",
                    "name": f"func_{c}_{k}",
                    "line": k + 1,
                    "body": cluster_body,
                    "normalized_body": cluster_body,
                }
            )
    # Distinct filler to reach n_functions
    while len(functions) < n_functions:
        idx = len(functions)
        body = " ".join(f"unique_{idx}_{i}" for i in range(12))
        functions.append(
            {
                "file": "src/filler.py",
                "name": f"filler_{idx}",
                "line": idx,
                "body": body,
                "normalized_body": body,
            }
        )
    return functions


class TestDuplicateScannerPerformance:
    """Measure duplicate detection scaling on large synthetic corpora."""

    def test_large_corpus_scales_subquadratically(self):
        """Benchmark: 2000 functions (400 clusters × 5 dupes) must complete
        quickly — the former all-pairs algorithm did ~2M comparisons here.
        """
        from patchi.core.agents.duplicate_scanner import DuplicateScanner

        functions = _make_duplicate_corpus(n_functions=2000, n_clusters=400)
        scanner = DuplicateScanner()
        ms, pairs = _time_it(scanner._find_duplicate_functions, functions, runs=2)
        # 400 clusters × C(5,2) = 4000 duplicate pairs, no filler false-positives
        assert len(pairs) == 4000, f"expected 4000 pairs, got {len(pairs)}"
        print(f"\n  [BENCH] DuplicateScanner 2000 funcs: {ms:.1f}ms ({len(pairs)} pairs)")
        # Former O(n²) on 2000 funcs ≈ 2M comparisons; budget is generous so
        # this stays stable on slow CI while still catching quadratic blowup.
        assert ms < 5000, f"duplicate detection too slow: {ms:.1f}ms"

    def test_very_large_corpus(self):
        """Benchmark: 8000 functions must stay well under the O(n²) horizon.
        The old algorithm would compare ~32M pairs here.
        """
        from patchi.core.agents.duplicate_scanner import DuplicateScanner

        functions = _make_duplicate_corpus(n_functions=8000, n_clusters=800)
        scanner = DuplicateScanner()
        ms, pairs = _time_it(scanner._find_duplicate_functions, functions, runs=1)
        # 800 clusters × C(10,2) = 36000 duplicate pairs
        assert len(pairs) == 800 * 45, f"expected {800*45} pairs, got {len(pairs)}"
        print(f"\n  [BENCH] DuplicateScanner 8000 funcs: {ms:.1f}ms ({len(pairs)} pairs)")
        assert ms < 20000, f"duplicate detection too slow: {ms:.1f}ms"

    def test_parity_with_brute_force(self):
        """Correctness guardrail: hashed candidate generation must match the
        original O(n²) algorithm pair-for-pair on a small mixed corpus.
        """
        from patchi.core.agents.duplicate_scanner import DuplicateScanner

        common = " ".join(f"t{i}" for i in range(20))
        functions = [
            {"file": "a.py", "name": "d1", "line": 1, "body": common, "normalized_body": common},
            {"file": "b.py", "name": "d2", "line": 1, "body": common, "normalized_body": common},
            {"file": "c.py", "name": "n1", "line": 1, "body": f"{common} extra", "normalized_body": f"{common} extra"},
            {"file": "d.py", "name": "u1", "line": 1, "body": "alpha beta gamma", "normalized_body": "alpha beta gamma"},
            {"file": "e.py", "name": "u2", "line": 1, "body": "delta epsilon zeta", "normalized_body": "delta epsilon zeta"},
        ]
        scanner = DuplicateScanner()
        optimized = scanner._find_duplicate_functions(functions)

        # Brute-force reference
        expected = []
        for i, f1 in enumerate(functions):
            for j, f2 in enumerate(functions[i + 1 :], i + 1):
                sim = scanner._calculate_similarity(f1["normalized_body"], f2["normalized_body"])
                if sim > 0.85:
                    expected.append((i, j, round(sim, 6)))

        opt_map = {}
        for fi, fj, sim in optimized:
            # optimized returns similarity × 100; normalize to 0–1 scale
            opt_map[(functions.index(fi), functions.index(fj))] = round(sim / 100.0, 6)
        exp_map = {(i, j): sim for i, j, sim in expected}
        assert sorted(opt_map.items()) == sorted(exp_map.items())


# ── Blast radius benchmarks ──────────────────────────────────────────────────


class TestBlastRadiusPerformance:
    """Measure blast radius calculation speed."""

    @pytest.fixture(scope="class")
    def graph(self):
        from patchi.core.brain.scanner import FileScanner
        from patchi.core.brain.import_graph import build_graph
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

    from patchi.core.brain.scanner import FileScanner
    from patchi.core.brain.import_graph import build_graph, find_dead_files
    from patchi.core.brain.blast_radius import build_blast_radius_map
    from patchi.core.brain.type_checker import check_types
    from patchi.core.brain.languages import Lang
    from patchi.core.agents.base import AgentInput
    from patchi.core.security.injection_agent import InjectionAgent
    from patchi.core.security.ssrf_agent import SSRFProtectionAgent
    from patchi.core.security.catch_block_auditor import CatchBlockAuditor

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
