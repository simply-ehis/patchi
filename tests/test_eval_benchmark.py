"""Unit tests for the detection benchmark harness."""

from __future__ import annotations

import unittest
from pathlib import Path

from patchi.core.evals import benchmark as bench


class TestMatcher(unittest.TestCase):
    def test_type_substring_and_cwe(self):
        case = {"file": "a.py", "expect": {"type": ["sql_injection"], "cwe": ["CWE-89"]}}
        self.assertTrue(bench._matches(case, {"file": "a.py", "type": "sql_injection", "cwe": ""}))
        self.assertTrue(bench._matches(case, {"file": "a.py", "type": "something-else", "cwe": "CWE-89"}))
        self.assertFalse(bench._matches(case, {"file": "a.py", "type": "xss", "cwe": ""}))
        self.assertFalse(bench._matches(case, {"file": "b.py", "type": "sql_injection", "cwe": ""}))

    def test_empty_expect_matches_any_finding_on_file(self):
        case = {"file": "a.py", "expect": {}}
        self.assertTrue(bench._matches(case, {"file": "a.py", "type": "whatever", "cwe": ""}))


class TestManifest(unittest.TestCase):
    def test_injection_lists(self):
        self.assertIn("injection", bench.list_benchmarks())
        manifest = bench.load_manifest("injection")
        self.assertEqual(manifest["owasp"], "A03:2021 – Injection")
        self.assertIn("InjectionAgent", manifest["agents"])

    def test_missing_benchmark_errors(self):
        result = bench.eval_benchmark("no-such-benchmark-xyz")
        self.assertFalse(result["ok"])
        self.assertIn("error", result)


class TestInjectionBenchmark(unittest.TestCase):
    def test_scorecard(self):
        result = bench.eval_benchmark("injection")
        self.assertTrue(result["ok"], result.get("failures"))
        self.assertEqual(result["detection_rate"], 1.0)
        self.assertEqual(result["clean_fp"], 0)
        self.assertEqual(result["clean_total"], 2)
        # Known gap partitioned out of the verdict, still reported.
        self.assertEqual([g["id"] for g in result["known_gaps"]], ["sqli-variable-mediated"])
        self.assertFalse(result["known_gaps"][0]["pass"])
        self.assertEqual(result["failures"], [])


class TestNewBenchmarks(unittest.TestCase):
    def test_all_green(self):
        for name in ("xss", "secrets", "traversal", "jwt", "crypto", "ssrf"):
            with self.subTest(benchmark=name):
                result = bench.eval_benchmark(name)
                self.assertTrue(result["ok"], result.get("failures"))
                self.assertEqual(result["detection_rate"], 1.0)
                self.assertEqual(result["clean_fp"], 0)

    def test_jwt_fixes_hold(self):
        # Bare-name disease: bcrypt files must not read as JWT usage.
        result = bench.eval_benchmark("jwt")
        flagged = [d["id"] for d in result["details"]]
        self.assertIn("jwt-no-expiry", flagged)
        # Env-secret clean file stays silent (literal-only secret check).
        clean = next(d for d in result["details"] if d["id"] == "clean-rs256-env-expiry")
        self.assertTrue(clean["pass"])

    def test_ssrf_noise_listed_not_failing(self):
        result = bench.eval_benchmark("ssrf")
        clean = next(d for d in result["details"] if d["id"] == "clean-allowlisted")
        self.assertTrue(clean["pass"])
        self.assertTrue(any(n["type"] == "ssrf_http_client" for n in clean.get("noise", [])))

    def test_xss_gap_partitioned(self):
        result = bench.eval_benchmark("xss")
        self.assertEqual([g["id"] for g in result["known_gaps"]], ["xss-flask-return"])

    def test_path_normalization(self):
        # SecretScanner reports absolute paths; matcher sees relative.
        result = bench.eval_benchmark("secrets")
        hit_files = [h["file"] for d in result["details"] for h in d["hits"]]
        self.assertTrue(hit_files)
        for f in hit_files:
            self.assertFalse(Path(f).is_absolute(), f)
            self.assertNotIn("\\", f)


if __name__ == "__main__":
    unittest.main()
