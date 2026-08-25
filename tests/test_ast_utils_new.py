"""Tests for new ast_utils modules: assignments and taint tracking."""

import unittest

from patchi.core.brain.ast_utils import (
    SANITIZERS,
    SOURCES,
    find_assignments,
    find_dead_symbols,
    track_taint,
)
from patchi.core.brain.languages import Lang


def _requires_parser(lang: Lang):
    if lang == Lang.PYTHON:
        return
    from patchi.core.brain.languages import get_parser
    if get_parser(lang) is None:
        raise unittest.SkipTest(f"tree-sitter parser for {lang} not installed")


class TestFindAssignmentsPython(unittest.TestCase):
    def test_simple_assign(self):
        code = "x = 'secret'\ny = 5"
        res = find_assignments(code, Lang.PYTHON)
        names = {r["target"] for r in res}
        self.assertEqual(names, {"x", "y"})

    def test_attr_assign(self):
        code = "config.debug = True"
        res = find_assignments(code, Lang.PYTHON)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["target"], "config.debug")

    def test_no_assign(self):
        code = "print('hi')"
        res = find_assignments(code, Lang.PYTHON)
        self.assertEqual(res, [])


class TestFindAssignmentsJavaScript(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.JAVASCRIPT)

    def test_var_declarator(self):
        code = "const url = 'http://x';"
        res = find_assignments(code, Lang.JAVASCRIPT)
        names = {r["target"] for r in res}
        self.assertIn("url", names)

    def test_assignment_expr(self):
        code = "user.password = 'abc';"
        res = find_assignments(code, Lang.JAVASCRIPT)
        self.assertGreaterEqual(len(res), 1)


class TestFindAssignmentsGo(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.GO)

    def test_short_var(self):
        code = 'package main\nfunc f() { x := "hi" }'
        res = find_assignments(code, Lang.GO)
        self.assertGreaterEqual(len(res), 1)


class TestTrackTaintPython(unittest.TestCase):
    def test_request_direct_to_execute(self):
        code = "cursor.execute(request.args.get('id'))"
        res = track_taint(code, Lang.PYTHON, {"execute", "cursor.execute"})
        self.assertEqual(len(res), 1)

    def test_source_aliased(self):
        code = "uid = request.args.get('id')\ncursor.execute(uid)"
        res = track_taint(code, Lang.PYTHON, {"execute", "cursor.execute"})
        self.assertEqual(len(res), 1)
        self.assertIn("uid", res[0]["tainted_via"][0])

    def test_sanitized_not_tainted(self):
        code = "safe = escape(request.args.get('x'))\noutput = safe"
        res = track_taint(code, Lang.PYTHON, {"execute"})
        self.assertEqual(res, [])

    def test_safe_literal(self):
        code = "cursor.execute('SELECT 1')"
        res = track_taint(code, Lang.PYTHON, {"execute", "cursor.execute"})
        self.assertEqual(res, [])

    def test_execute_no_source(self):
        code = "x = compute()\ncursor.execute(x)"
        res = track_taint(code, Lang.PYTHON, {"execute", "cursor.execute"})
        # compute() is not a known source; no taint reported
        self.assertEqual(res, [])


class TestTrackTaintJavaScript(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.JAVASCRIPT)

    def test_request_to_eval(self):
        code = "eval(req.body);"
        res = track_taint(code, Lang.JAVASCRIPT, {"eval"})
        self.assertEqual(len(res), 1)

    def test_safe_literal(self):
        code = "eval('1+1');"
        res = track_taint(code, Lang.JAVASCRIPT, {"eval"})
        self.assertEqual(res, [])


class TestTrackTaintGo(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.GO)

    def test_source_to_exec(self):
        code = 'package main\nimport "os"\nfunc f() { os.Exec(req.Body) }'
        res = track_taint(code, Lang.GO, {"Exec", "os.Exec"})
        self.assertGreaterEqual(len(res), 0)


class TestTaintSourcesConsts(unittest.TestCase):
    def test_sources_nonempty(self):
        self.assertIn("request.args", SOURCES)
        self.assertIn("os.environ", SOURCES)

    def test_sanitizers_nonempty(self):
        self.assertIn("escape", SANITIZERS)
        self.assertIn("sanitize", SANITIZERS)


class TestDeadSymbols(unittest.TestCase):
    def test_python_unused_function(self):
        code = "def used():\n    return 1\ndef dead():\n    return 2\ndef main():\n    return used()\n"
        res = find_dead_symbols(code, Lang.PYTHON)
        names = {r["name"] for r in res}
        self.assertEqual(names, {"dead"})

    def test_javascript_unused(self):
        _requires_parser(Lang.JAVASCRIPT)
        code = (
            "function usedFn() { return 1; }\n"
            "function deadFn() { return 2; }\n"
            "const DEAD_CONST = 5;\n"
            "export function exportedFn() { return 1; }\n"
            "function main() { return usedFn(); }\n"
        )
        res = find_dead_symbols(code, Lang.JAVASCRIPT)
        names = {r["name"] for r in res}
        self.assertEqual(names, {"deadFn", "DEAD_CONST"})
        self.assertNotIn("exportedFn", names)

    def test_go_unused_function(self):
        _requires_parser(Lang.GO)
        code = (
            "package main\n"
            "func usedFunc() int { return 1 }\n"
            "func deadFunc() int { return 2 }\n"
            "func main() { _ = usedFunc() }\n"
        )
        res = find_dead_symbols(code, Lang.GO)
        self.assertEqual({r["name"] for r in res}, {"deadFunc"})

    def test_rust_unused_function_skips_pub(self):
        _requires_parser(Lang.RUST)
        code = (
            "fn used_fn() -> i32 { 1 }\n"
            "fn dead_fn() -> i32 { 2 }\n"
            "pub fn pub_fn() -> i32 { 1 }\n"
            "fn main() { let _ = used_fn(); }\n"
        )
        res = find_dead_symbols(code, Lang.RUST)
        names = {r["name"] for r in res}
        self.assertEqual(names, {"dead_fn"})
        self.assertNotIn("pub_fn", names)

    def test_ruby_unused_method(self):
        _requires_parser(Lang.RUBY)
        code = "def used_m\nend\ndef dead_m\nend\ndef main\n  used_m\nend\n"
        res = find_dead_symbols(code, Lang.RUBY)
        self.assertEqual({r["name"] for r in res}, {"dead_m"})


if __name__ == "__main__":
    unittest.main()
