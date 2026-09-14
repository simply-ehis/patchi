"""Unit tests for patchi.core.testing.coverage_prioritizer"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from patchi.core.config import init_project
from patchi.core.testing.coverage_prioritizer import (
    CoverageData,
    CoveragePrioritizer,
    FileCoverage,
    FunctionCoverage,
    PrioritizedTest,
    UncoveredPath,
    _parse_coverage_json,
)


def _setup(tmp: Path) -> Path:
    init_project(tmp)
    return tmp


def _write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


_SAMPLE_COVERAGE_JSON = {
    "totals": {
        "covered_lines": 80,
        "num_statements": 100,
        "covered_branches": 12,
        "num_branches": 20,
    },
    "files": {
        "patchi/core/foo.py": {
            "summary": {
                "covered_lines": 50,
                "num_statements": 60,
                "covered_branches": 8,
                "num_branches": 12,
            },
            "functions": [
                {"name": "handle_request", "lineno": 10, "execution_count": 5},
                {"name": "parse_body", "lineno": 25, "execution_count": 0},
            ],
        },
        "patchi/core/bar.py": {
            "summary": {
                "covered_lines": 30,
                "num_statements": 40,
                "covered_branches": 4,
                "num_branches": 8,
            },
            "functions": [
                {"name": "validate", "lineno": 5, "execution_count": 12},
                {"name": "format_output", "lineno": 20, "execution_count": 0},
            ],
        },
    },
}


class TestDataClasses(unittest.TestCase):
    def test_coverage_data_defaults(self):
        cd = CoverageData()
        self.assertEqual(cd.total_statement_coverage, 0.0)
        self.assertEqual(cd.files, {})

    def test_file_coverage(self):
        fc = FileCoverage(
            path="a.py",
            statement_coverage=0.75,
            branch_coverage=0.5,
        )
        self.assertEqual(fc.path, "a.py")
        self.assertEqual(fc.statement_coverage, 0.75)

    def test_function_coverage(self):
        fn = FunctionCoverage(name="foo", file="a.py", lineno=1, executed=True)
        self.assertTrue(fn.executed)

    def test_prioritized_test(self):
        pt = PrioritizedTest(test_file="test_a.py", priority_score=100.0)
        self.assertEqual(pt.priority_score, 100.0)
        self.assertFalse(pt.covers_changed_files)

    def test_uncovered_path(self):
        up = UncoveredPath(
            function_name="critical_fn",
            file="core.py",
            line=42,
            fan_in=5,
            in_routes=True,
        )
        self.assertEqual(up.fan_in, 5)
        self.assertTrue(up.in_routes)


class TestParseCoverageJson(unittest.TestCase):
    def test_parses_valid_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(_SAMPLE_COVERAGE_JSON, f)
            f.flush()
            result = _parse_coverage_json(Path(f.name))

        self.assertIsNotNone(result)
        self.assertAlmostEqual(result.total_statement_coverage, 0.8, places=2)
        self.assertAlmostEqual(result.total_branch_coverage, 0.6, places=2)
        self.assertEqual(len(result.files), 2)

        foo = result.files["patchi/core/foo.py"]
        self.assertEqual(foo.executed_statements, 50)
        self.assertEqual(foo.total_statements, 60)
        self.assertEqual(len(foo.functions), 2)
        self.assertTrue(foo.functions[0].executed)
        self.assertFalse(foo.functions[1].executed)

    def test_returns_none_for_invalid_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write("not json {{{")
            f.flush()
            result = _parse_coverage_json(Path(f.name))

        self.assertIsNone(result)

    def test_returns_none_for_missing_file(self):
        result = _parse_coverage_json(Path("/nonexistent/path.json"))
        self.assertIsNone(result)

    def test_handles_empty_files(self):
        data = {
            "totals": {
                "covered_lines": 0,
                "num_statements": 0,
                "covered_branches": 0,
                "num_branches": 0,
            },
            "files": {},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(data, f)
            f.flush()
            result = _parse_coverage_json(Path(f.name))

        self.assertIsNotNone(result)
        self.assertEqual(result.total_statement_coverage, 0.0)
        self.assertEqual(len(result.files), 0)

    def test_handles_missing_branch_totals(self):
        data = {
            "totals": {
                "covered_lines": 50,
                "num_statements": 100,
            },
            "files": {},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(data, f)
            f.flush()
            result = _parse_coverage_json(Path(f.name))

        self.assertIsNotNone(result)
        self.assertAlmostEqual(result.total_statement_coverage, 0.5, places=2)
        self.assertEqual(result.total_branch_coverage, 0.0)


class TestCoveragePrioritizer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_collect_coverage_returns_empty_when_no_data(self):
        p = CoveragePrioritizer(self.root)
        # Mock _run_pytest_cov to avoid actually running pytest
        with patch(
            "patchi.core.testing.coverage_prioritizer._run_pytest_cov", return_value=None
        ):
            result = p.collect_coverage()
        self.assertEqual(result.total_statement_coverage, 0.0)
        self.assertEqual(len(result.files), 0)

    def test_collect_coverage_uses_existing_json(self):
        _write(self.root, "coverage.json", json.dumps(_SAMPLE_COVERAGE_JSON))
        p = CoveragePrioritizer(self.root)
        result = p.collect_coverage()
        self.assertAlmostEqual(result.total_statement_coverage, 0.8, places=2)
        self.assertEqual(len(result.files), 2)

    def test_prioritize_tests_empty_when_no_test_files(self):
        p = CoveragePrioritizer(self.root)
        cov = CoverageData()
        result = p.prioritize_tests(cov)
        self.assertEqual(result, [])

    def test_prioritize_tests_orders_by_changed_files(self):
        _write(self.root, "src/core.py", "def process(): pass")
        _write(self.root, "tests/test_core.py", "from src.core import process\ndef test_process(): process()")

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "src/core.py": FileCoverage(
                    path="src/core.py",
                    statement_coverage=0.5,
                    branch_coverage=0.5,
                )
            }
        )
        result = p.prioritize_tests(cov, changed_files=["src/core.py"])
        self.assertGreater(len(result), 0)
        self.assertTrue(result[0].covers_changed_files)
        self.assertGreater(result[0].priority_score, 10.0)

    def test_prioritize_tests_low_coverage_bonus(self):
        _write(self.root, "src/weak.py", "def foo(): pass")
        _write(self.root, "tests/test_weak.py", "from src.weak import foo\ndef test_foo(): foo()")

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "src/weak.py": FileCoverage(
                    path="src/weak.py",
                    statement_coverage=0.3,  # below 0.5 threshold
                    branch_coverage=0.0,
                )
            }
        )
        result = p.prioritize_tests(cov)
        self.assertGreater(len(result), 0)
        # Should get low coverage bonus
        self.assertTrue(result[0].covers_low_coverage)

    def test_prioritize_tests_critical_path_bonus(self):
        _write(self.root, "src/hub.py", "def shared(): pass")
        _write(self.root, "tests/test_hub.py", "from src.hub import shared\ndef test_shared(): shared()")

        # Create fan-in by making multiple files import hub.py
        for i in range(4):
            _write(self.root, f"src/dep{i}.py", f"from src.hub import shared\ndef use{i}(): shared()")

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "src/hub.py": FileCoverage(
                    path="src/hub.py",
                    statement_coverage=0.8,
                    branch_coverage=0.8,
                )
            }
        )
        # Mock import graph to avoid needing full scanner
        with patch(
            "patchi.core.testing.coverage_prioritizer._build_fan_in_map",
            return_value={"src/hub.py": 4},
        ):
            result = p.prioritize_tests(cov)
        self.assertGreater(len(result), 0)
        self.assertTrue(result[0].covers_critical_paths)

    def test_prioritize_tests_sorts_descending(self):
        _write(self.root, "src/a.py", "def a(): pass")
        _write(self.root, "src/b.py", "def b(): pass")
        _write(self.root, "tests/test_a.py", "from src.a import a\ndef test_a(): a()")
        _write(self.root, "tests/test_b.py", "from src.b import b\ndef test_b(): b()")

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "src/a.py": FileCoverage(path="src/a.py", statement_coverage=0.2),
                "src/b.py": FileCoverage(path="src/b.py", statement_coverage=0.9),
            }
        )
        result = p.prioritize_tests(cov, changed_files=["src/a.py"])
        self.assertGreater(len(result), 0)
        # test_a should rank higher (covers changed file)
        scores = [r.priority_score for r in result]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_get_critical_uncovered_identifies_zero_coverage(self):
        _write(self.root, "routes/api.py", "def handle(): pass")

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "routes/api.py": FileCoverage(
                    path="routes/api.py",
                    statement_coverage=0.0,
                    functions=[
                        FunctionCoverage(name="handle", file="routes/api.py", lineno=1, executed=False),
                    ],
                )
            }
        )
        with patch(
            "patchi.core.testing.coverage_prioritizer._build_fan_in_map",
            return_value={},
        ):
            result = p.get_critical_uncovered(cov)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].function_name, "handle")
        self.assertTrue(result[0].in_routes)

    def test_get_critical_uncovered_skips_non_critical(self):
        _write(self.root, "src/leaf.py", "def leaf(): pass")

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "src/leaf.py": FileCoverage(
                    path="src/leaf.py",
                    statement_coverage=0.0,
                    functions=[
                        FunctionCoverage(name="leaf", file="src/leaf.py", lineno=1, executed=False),
                    ],
                )
            }
        )
        with patch(
            "patchi.core.testing.coverage_prioritizer._build_fan_in_map",
            return_value={"src/leaf.py": 1},  # low fan-in, not in routes
        ):
            result = p.get_critical_uncovered(cov)
        self.assertEqual(len(result), 0)

    def test_get_critical_uncovered_fan_in_threshold(self):
        _write(self.root, "src/core.py", "def fn(): pass")

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "src/core.py": FileCoverage(
                    path="src/core.py",
                    statement_coverage=0.0,
                    functions=[
                        FunctionCoverage(name="fn", file="src/core.py", lineno=1, executed=False),
                    ],
                )
            }
        )
        with patch(
            "patchi.core.testing.coverage_prioritizer._build_fan_in_map",
            return_value={"src/core.py": 5},  # above threshold
        ):
            result = p.get_critical_uncovered(cov)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].fan_in, 5)

    def test_collect_coverage_uses_cache(self):
        """If cache exists and source files haven't changed, use cache."""
        _write(self.root, "coverage.json", json.dumps(_SAMPLE_COVERAGE_JSON))

        p = CoveragePrioritizer(self.root)
        # First call: loads from coverage.json and caches
        result1 = p.collect_coverage()
        self.assertAlmostEqual(result1.total_statement_coverage, 0.8, places=2)

        # Verify cache was written
        cache = self.root / ".patchi" / "coverage_cache.json"
        self.assertTrue(cache.exists())

        # Second call: should use cache (not re-parse coverage.json)
        result2 = p.collect_coverage()
        self.assertAlmostEqual(result2.total_statement_coverage, 0.8, places=2)

    def test_cache_invalidation_on_source_change(self):
        """Cache should be invalidated when coverage.json is updated."""
        data1 = {
            "totals": {"covered_lines": 50, "num_statements": 100, "covered_branches": 0, "num_branches": 0},
            "files": {},
        }
        _write(self.root, "coverage.json", json.dumps(data1))

        p = CoveragePrioritizer(self.root)
        result1 = p.collect_coverage()
        self.assertAlmostEqual(result1.total_statement_coverage, 0.5, places=2)

        # Update coverage.json (simulating a new run)
        import time

        time.sleep(0.05)
        data2 = {
            "totals": {"covered_lines": 80, "num_statements": 100, "covered_branches": 0, "num_branches": 0},
            "files": {},
        }
        _write(self.root, "coverage.json", json.dumps(data2))

        # Cache should be stale now
        result2 = p.collect_coverage()
        self.assertAlmostEqual(result2.total_statement_coverage, 0.8, places=2)


class TestDiscoverTestFiles(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_finds_test_files(self):
        _write(self.root, "tests/test_alpha.py", "")
        _write(self.root, "tests/test_beta.py", "")
        _write(self.root, "tests/not_a_test.py", "")
        _write(self.root, "src/module.py", "")

        p = CoveragePrioritizer(self.root)
        result = p._discover_test_files()
        self.assertIn("tests/test_alpha.py", result)
        self.assertIn("tests/test_beta.py", result)
        self.assertNotIn("tests/not_a_test.py", result)
        self.assertNotIn("src/module.py", result)

    def test_excludes_pycache(self):
        _write(self.root, "tests/__pycache__/test_cached.py", "")

        p = CoveragePrioritizer(self.root)
        result = p._discover_test_files()
        self.assertEqual(len(result), 0)

    def test_excludes_patchi_dir(self):
        _write(self.root, ".patchi/test_internal.py", "")

        p = CoveragePrioritizer(self.root)
        result = p._discover_test_files()
        self.assertEqual(len(result), 0)


class TestInferCoveredSources(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_name_based_matching(self):
        _write(self.root, "src/foo.py", "def bar(): pass")
        _write(self.root, "tests/test_foo.py", "def test_bar(): pass")

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "src/foo.py": FileCoverage(path="src/foo.py", statement_coverage=0.5),
            }
        )
        result = p._infer_covered_sources("tests/test_foo.py", cov)
        self.assertIn("src/foo.py", result)

    def test_import_based_matching(self):
        _write(self.root, "src/auth.py", "def login(): pass")
        _write(
            self.root,
            "tests/test_auth.py",
            "from src.auth import login\ndef test_login(): login()",
        )

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "src/auth.py": FileCoverage(path="src/auth.py", statement_coverage=0.5),
            }
        )
        result = p._infer_covered_sources("tests/test_auth.py", cov)
        self.assertIn("src/auth.py", result)

    def test_no_match_returns_empty(self):
        _write(self.root, "src/unrelated.py", "pass")
        _write(self.root, "tests/test_other.py", "pass")

        p = CoveragePrioritizer(self.root)
        cov = CoverageData(
            files={
                "src/unrelated.py": FileCoverage(path="src/unrelated.py", statement_coverage=0.5),
            }
        )
        result = p._infer_covered_sources("tests/test_other.py", cov)
        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    unittest.main()
