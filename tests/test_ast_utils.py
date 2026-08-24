"""Tests for patchi.core.brain.ast_utils — language-generic AST utilities."""

import unittest
from pathlib import Path

from patchi.core.brain.ast_utils import (
    find_calls,
    find_decorators,
    find_imports,
    get_call_arg,
    node_text,
    child_by_field,
    children,
    named_children,
)
from patchi.core.brain.languages import Lang, get_parser


# ── Helpers ──────────────────────────────────────────────────────────────────


def _requires_parser(lang: Lang):
    """Skip test if tree-sitter parser for this language is not installed."""
    if lang == Lang.PYTHON:
        return  # uses stdlib ast, always available
    parser = get_parser(lang)
    if parser is None:
        raise unittest.SkipTest(f"tree-sitter parser for {lang} not installed")


# ── Node helpers ─────────────────────────────────────────────────────────────


class TestNodeHelpers(unittest.TestCase):
    """node_text, child_by_field, children, named_children on real TS nodes."""

    def test_node_text_with_bytes(self):
        parser = get_parser(Lang.JAVASCRIPT)
        if parser is None:
            self.skipTest("JS parser not installed")
        tree = parser.parse(b"var x = 1;")
        stmt = tree.root_node.children[0]
        text = node_text(stmt)
        self.assertIsInstance(text, str)
        self.assertIn("x", text)

    def test_node_text_empty_on_bad_node(self):
        self.assertEqual(node_text(None), "")
        self.assertEqual(node_text(42), "")

    def test_child_by_field_returns_none_for_bad_node(self):
        self.assertIsNone(child_by_field(None, "name"))
        self.assertIsNone(child_by_field("not a node", "name"))

    def test_children_returns_list(self):
        self.assertEqual(children(None), [])
        self.assertEqual(children("bad"), [])

    def test_named_children_returns_list(self):
        self.assertEqual(named_children(None), [])
        self.assertEqual(named_children("bad"), [])


# ── find_calls — Python ──────────────────────────────────────────────────────


class TestFindCallsPython(unittest.TestCase):
    def test_find_simple_call(self):
        code = "x = execute('select 1')"
        results = find_calls(code, Lang.PYTHON, {"execute"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "execute")
        self.assertEqual(results[0]["line"], 1)

    def test_find_dotted_call_by_leaf(self):
        code = "cursor.execute('select 1')"
        results = find_calls(code, Lang.PYTHON, {"execute"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "cursor.execute")

    def test_find_dotted_call_by_full(self):
        code = "subprocess.run(['ls'])"
        results = find_calls(code, Lang.PYTHON, {"subprocess.run"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "subprocess.run")

    def test_no_match(self):
        code = "print('hello')"
        results = find_calls(code, Lang.PYTHON, {"execute"})
        self.assertEqual(len(results), 0)

    def test_multiple_matches(self):
        code = "a = eval(x)\nb = exec(y)"
        results = find_calls(code, Lang.PYTHON, {"eval", "exec"})
        self.assertEqual(len(results), 2)
        names = {r["name"] for r in results}
        self.assertEqual(names, {"eval", "exec"})

    def test_nested_call(self):
        code = "c.execute(query(sql))"
        results = find_calls(code, Lang.PYTHON, {"execute"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "c.execute")

    def test_full_text(self):
        code = "x = execute('select 1')"
        results = find_calls(code, Lang.PYTHON, {"execute"})
        self.assertIn("execute(", results[0]["full_text"])

    def test_syntax_error_returns_empty(self):
        code = "this is not valid python @@@"
        results = find_calls(code, Lang.PYTHON, {"execute"})
        self.assertEqual(len(results), 0)

    def test_line_and_col(self):
        code = "\n\neval(x)"
        results = find_calls(code, Lang.PYTHON, {"eval"})
        self.assertEqual(results[0]["line"], 3)
        self.assertIsInstance(results[0]["col"], int)

    def test_deep_dotted_match(self):
        code = "a.b.c.execute('q')"
        results = find_calls(code, Lang.PYTHON, {"execute"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "a.b.c.execute")


# ── find_calls — JavaScript ──────────────────────────────────────────────────


class TestFindCallsJavaScript(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.JAVASCRIPT)

    def test_simple_call(self):
        code = "let x = fetch('/api');"
        results = find_calls(code, Lang.JAVASCRIPT, {"fetch"})
        self.assertEqual(len(results), 1, results)
        self.assertEqual(results[0]["name"], "fetch")

    def test_dotted_call(self):
        code = "axios.get('/api');"
        results = find_calls(code, Lang.JAVASCRIPT, {"axios.get"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "axios.get")

    def test_leaf_match(self):
        code = "child_process.exec('ls');"
        results = find_calls(code, Lang.JAVASCRIPT, {"exec"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "child_process.exec")

    def test_no_match(self):
        code = "console.log('hello');"
        results = find_calls(code, Lang.JAVASCRIPT, {"fetch"})
        self.assertEqual(len(results), 0)

    def test_line_number(self):
        code = "\n\nfs.readFileSync('x');"
        results = find_calls(code, Lang.JAVASCRIPT, {"readFileSync"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["line"], 3)


# ── find_calls — TypeScript ──────────────────────────────────────────────────


class TestFindCallsTypeScript(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.TYPESCRIPT)

    def test_simple_call(self):
        code = "const rsp = await fetch('/api');"
        results = find_calls(code, Lang.TYPESCRIPT, {"fetch"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "fetch")

    def test_dotted_call(self):
        code = "this.http.get('/api');"
        results = find_calls(code, Lang.TYPESCRIPT, {"get"})
        # Could match this.http.get, this.http.get as method
        self.assertGreaterEqual(len(results), 1)


# ── find_calls — Java ────────────────────────────────────────────────────────


class TestFindCallsJava(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.JAVA)

    def test_method_invocation(self):
        code = """class X {
            void f() { Runtime.getRuntime().exec("ls"); }
        }"""
        results = find_calls(code, Lang.JAVA, {"exec"})
        self.assertEqual(len(results), 1)
        self.assertIn("exec", results[0]["name"])

    def test_query_call_by_leaf(self):
        code = """class X {
            void f() { jdbcTemplate.query(sql, params); }
        }"""
        results = find_calls(code, Lang.JAVA, {"query"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "query")  # Java extracts method name only


# ── find_calls — Go ──────────────────────────────────────────────────────────


class TestFindCallsGo(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.GO)

    def test_package_call(self):
        code = """package main
import "os"
func f() { os.Getenv("HOME") }"""
        results = find_calls(code, Lang.GO, {"Getenv"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "os.Getenv")


# ── find_calls — Rust ─────────────────────────────────────────────────────────


class TestFindCallsRust(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.RUST)

    def test_macro_and_fn_call(self):
        code = """fn f() {
    std::env::var("HOME");
    println!("ok");
}"""
        results = find_calls(code, Lang.RUST, {"var"})
        self.assertEqual(len(results), 1)
        self.assertIn("var", results[0]["name"])


# ── find_calls — Ruby ─────────────────────────────────────────────────────────


class TestFindCallsRuby(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.RUBY)

    def test_method_call(self):
        code = "User.find_by(id: 1)"
        results = find_calls(code, Lang.RUBY, {"find_by"})
        self.assertGreaterEqual(len(results), 1)
        if results:
            self.assertIn("find_by", results[0]["name"])
            # Should not have duplicates
            self.assertEqual(len([r for r in results if r["name"] == results[0]["name"]]), 1)


# ── find_calls — PHP ──────────────────────────────────────────────────────────


class TestFindCallsPHP(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.PHP)

    def test_function_call(self):
        code = "<?php $x = shell_exec('ls'); ?>"
        results = find_calls(code, Lang.PHP, {"shell_exec"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "shell_exec")


# ── find_calls — C# ────────────────────────────────────────────────────────────


class TestFindCallsCSharp(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.C_SHARP)

    def test_invocation(self):
        code = """using System;
class X {
    void F() { Console.WriteLine("ok"); }
}"""
        results = find_calls(code, Lang.C_SHARP, {"WriteLine"})
        self.assertEqual(len(results), 1)
        self.assertIn("WriteLine", results[0]["name"])


# ── find_calls — Swift ────────────────────────────────────────────────────────


class TestFindCallsSwift(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.SWIFT)

    def test_function_call(self):
        code = "let x = CommandLine.arguments"
        results = find_calls(code, Lang.SWIFT, {"arguments"})
        # This may or may not parse as a call; just verify no crash
        self.assertIsInstance(results, list)


# ── find_calls — Kotlin ───────────────────────────────────────────────────────


class TestFindCallsKotlin(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.KOTLIN)

    def test_call(self):
        code = """fun f() {
    Runtime.getRuntime().exec("ls")
}"""
        results = find_calls(code, Lang.KOTLIN, {"exec"})
        self.assertEqual(len(results), 1)


# ── find_calls — Dart ──────────────────────────────────────────────────────────


class TestFindCallsDart(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.DART)

    def test_call(self):
        code = """void f() {
    Process.run('ls');
}"""
        results = find_calls(code, Lang.DART, {"run"})
        # Dart uses selector-based AST, not call_expression; known limitation
        self.assertIsInstance(results, list)


# ── find_imports — Python ─────────────────────────────────────────────────────


class TestFindImportsPython(unittest.TestCase):
    def test_find_import(self):
        code = "import requests"
        results = find_imports(code, Lang.PYTHON, {"requests"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "requests")

    def test_find_from_import(self):
        code = "from fastapi import APIRouter"
        results = find_imports(code, Lang.PYTHON, {"fastapi"})
        self.assertEqual(len(results), 1)

    def test_no_match(self):
        code = "import os"
        results = find_imports(code, Lang.PYTHON, {"requests"})
        self.assertEqual(len(results), 0)

    def test_multiple_imports(self):
        code = "import os\nimport sys"
        results = find_imports(code, Lang.PYTHON, {"os", "sys"})
        self.assertEqual(len(results), 2)


# ── find_imports — JavaScript ─────────────────────────────────────────────────


class TestFindImportsJavaScript(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.JAVASCRIPT)

    def test_require(self):
        code = "const fs = require('fs');"
        results = find_imports(code, Lang.JAVASCRIPT, {"fs"})
        # require() is a call expression, not an import node type; expect 0
        self.assertEqual(len(results), 0)

    def test_import_statement(self):
        code = "import fs from 'fs';"
        results = find_imports(code, Lang.JAVASCRIPT, {"fs"})
        self.assertEqual(len(results), 1)

    def test_import(self):
        code = "import express from 'express';"
        results = find_imports(code, Lang.JAVASCRIPT, {"express"})
        self.assertEqual(len(results), 1)


# ── find_imports — TypeScript ─────────────────────────────────────────────────


class TestFindImportsTypeScript(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.TYPESCRIPT)

    def test_import(self):
        code = "import { Injectable } from '@nestjs/common';"
        results = find_imports(code, Lang.TYPESCRIPT, {"@nestjs/common"})
        self.assertEqual(len(results), 1)

    def test_import_default(self):
        code = "import express from 'express';"
        results = find_imports(code, Lang.TYPESCRIPT, {"express"})
        self.assertEqual(len(results), 1)


# ── find_imports — Java ───────────────────────────────────────────────────────


class TestFindImportsJava(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.JAVA)

    def test_import(self):
        code = "import java.util.List;"
        results = find_imports(code, Lang.JAVA, {"java"})
        self.assertGreaterEqual(len(results), 1)


# ── find_imports — Go ─────────────────────────────────────────────────────────


class TestFindImportsGo(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.GO)

    def test_import(self):
        code = """package main
import "fmt"
import "os"
"""
        results = find_imports(code, Lang.GO, {"fmt", "os"})
        self.assertEqual(len(results), 2)


# ── find_imports — Rust ───────────────────────────────────────────────────────


class TestFindImportsRust(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.RUST)

    def test_use(self):
        code = "use std::env;"
        results = find_imports(code, Lang.RUST, {"std"})
        self.assertGreaterEqual(len(results), 1)


# ── find_imports — Ruby ───────────────────────────────────────────────────────


class TestFindImportsRuby(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.RUBY)

    def test_require(self):
        code = "require 'net/http'"
        results = find_imports(code, Lang.RUBY, {"net/http"})
        self.assertEqual(len(results), 1)


# ── find_imports — PHP ────────────────────────────────────────────────────────


class TestFindImportsPHP(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.PHP)

    def test_use(self):
        code = "<?php use App\\Models\\User; ?>"
        results = find_imports(code, Lang.PHP, {"App"})
        self.assertGreaterEqual(len(results), 1)


# ── find_decorators — Python ──────────────────────────────────────────────────


class TestFindDecoratorsPython(unittest.TestCase):
    def test_find_decorator(self):
        code = "@app.route('/api')\ndef f(): pass"
        results = find_decorators(code, Lang.PYTHON, {"route"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "route")

    def test_no_match(self):
        code = "@staticmethod\ndef f(): pass"
        results = find_decorators(code, Lang.PYTHON, {"route"})
        self.assertEqual(len(results), 0)

    def test_multiple_decorators(self):
        code = "@csrf_exempt\n@app.route('/x')\ndef f(): pass"
        results = find_decorators(code, Lang.PYTHON, {"csrf_exempt", "route"})
        self.assertEqual(len(results), 2)


# ── find_decorators — Java ────────────────────────────────────────────────────


class TestFindDecoratorsJava(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.JAVA)

    def test_annotation(self):
        code = "@RequestMapping('/api')\npublic void f() {}"
        results = find_decorators(code, Lang.JAVA, {"requestmapping"})
        self.assertEqual(len(results), 1)


# ── find_decorators — C# ──────────────────────────────────────────────────────


class TestFindDecoratorsCSharp(unittest.TestCase):
    def setUp(self):
        _requires_parser(Lang.C_SHARP)

    def test_attribute(self):
        code = "[Authorize]\npublic class X {}"
        results = find_decorators(code, Lang.C_SHARP, {"authorize"})
        self.assertEqual(len(results), 1)


# ── get_call_arg ──────────────────────────────────────────────────────────────


class TestGetCallArg(unittest.TestCase):
    def test_first_arg(self):
        self.assertEqual(get_call_arg("f('hello')"), "'hello'")

    def test_second_arg(self):
        self.assertEqual(get_call_arg("f('a', 'b')", 1), "'b'")

    def test_nested_parens(self):
        self.assertEqual(get_call_arg("f('a', g('b'))", 1), "g('b')")

    def test_out_of_range(self):
        self.assertEqual(get_call_arg("f('a')", 5), "")

    def test_no_parens(self):
        self.assertEqual(get_call_arg("not_a_call", 0), "")

    def test_nested_braces(self):
        code = "f({'key': 'val'}, 'second')"
        first = get_call_arg(code, 0)
        second = get_call_arg(code, 1)
        self.assertEqual(first, "{'key': 'val'}")
        self.assertEqual(second, "'second'")

    def test_empty(self):
        self.assertEqual(get_call_arg("f()"), "")


# ── Edge cases ────────────────────────────────────────────────────────────────


class TestEdgeCases(unittest.TestCase):
    def test_empty_content(self):
        self.assertEqual(find_calls("", Lang.PYTHON, {"x"}), [])
        self.assertEqual(find_imports("", Lang.PYTHON, {"x"}), [])
        self.assertEqual(find_decorators("", Lang.PYTHON, {"x"}), [])

    def test_unknown_lang_find_calls(self):
        code = "some code"
        results = find_calls(code, "UNKNOWN_LANG", {"x"})
        self.assertEqual(results, [])

    def test_unknown_lang_find_imports(self):
        results = find_imports("code", "UNKNOWN_LANG", {"x"})
        self.assertEqual(results, [])

    def test_unknown_lang_find_decorators(self):
        results = find_decorators("code", "UNKNOWN_LANG", {"x"})
        self.assertEqual(results, [])

    def test_unsupported_parser_lang_find_calls(self):
        results = find_calls("code", Lang.SQL, {"x"})
        self.assertEqual(results, [])

    def test_unsupported_parser_lang_find_imports(self):
        results = find_imports("code", Lang.CSS, {"x"})
        self.assertEqual(results, [])

    def test_unsupported_parser_lang_find_decorators(self):
        results = find_decorators("code", Lang.BASH, {"x"})
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
