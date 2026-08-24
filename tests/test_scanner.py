"""Unit tests for patchi.core.brain.scanner"""

import tempfile
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core.brain.languages import Lang
from patchi.core.brain.scanner import (
    FileInfo,
    FileScanner,
)


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


def _write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


class TestFileDiscovery(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_discovers_python_files(self):
        _write(self.root, "src/app.py", "print('hello')")
        _write(self.root, "src/utils.py", "def foo(): pass")
        scanner = FileScanner(self.root)
        paths = scanner.discover()
        names = {p.name for p in paths}
        self.assertIn("app.py", names)
        self.assertIn("utils.py", names)

    def test_ignores_node_modules(self):
        _write(self.root, "node_modules/react/index.js", "module.exports = {}")
        _write(self.root, "src/app.js", "console.log('hi')")
        scanner = FileScanner(self.root)
        paths = scanner.discover()
        for p in paths:
            self.assertNotIn("node_modules", p.parts)

    def test_ignores_pycache(self):
        _write(self.root, "__pycache__/app.cpython-312.pyc", "")
        _write(self.root, "src/app.py", "pass")
        scanner = FileScanner(self.root)
        paths = scanner.discover()
        for p in paths:
            self.assertNotIn("__pycache__", p.parts)

    def test_ignores_patchi_dir(self):
        scanner = FileScanner(self.root)
        paths = scanner.discover()
        for p in paths:
            self.assertNotIn(".patchi", p.parts)

    def test_targeted_scan(self):
        _write(self.root, "src/auth/login.py", "def login(): pass")
        _write(self.root, "src/billing/pay.py", "def pay(): pass")
        scanner = FileScanner(self.root)
        paths = scanner.discover(area="src/auth")
        names = [p.name for p in paths]
        self.assertIn("login.py", names)
        self.assertNotIn("pay.py", names)

    def test_ignores_unknown_extensions(self):
        _write(self.root, "src/app.py", "pass")
        _write(self.root, "assets/logo.png", b"\x89PNG\r\n".decode(errors="replace"))
        scanner = FileScanner(self.root)
        paths = scanner.discover()
        for p in paths:
            self.assertNotEqual(p.suffix, ".png")

    def test_respects_custom_ignore_paths(self):
        _write(self.root, "payments/stripe.py", "pass")
        _write(self.root, "src/app.py", "pass")
        scanner = FileScanner(self.root, ignore_paths=["payments"])
        paths = scanner.discover()
        for p in paths:
            self.assertNotIn("payments", p.parts)


class TestPythonParser(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def _scan(self, content: str, filename: str = "app.py") -> FileInfo:
        path = _write(self.root, f"src/{filename}", content)
        scanner = FileScanner(self.root)
        return scanner.scan_file(path)

    def test_detects_imports(self):
        fi = self._scan("import os\nimport sys\n")
        sources = [i.source for i in fi.imports]
        self.assertIn("os", sources)
        self.assertIn("sys", sources)

    def test_detects_from_imports(self):
        fi = self._scan("from pathlib import Path\n")
        self.assertEqual(len(fi.imports), 1)
        self.assertEqual(fi.imports[0].source, "pathlib")
        self.assertIn("Path", fi.imports[0].names)

    def test_detects_relative_imports(self):
        fi = self._scan("from .utils import helper\n")
        self.assertTrue(fi.imports[0].is_relative)
        self.assertIn("helper", fi.imports[0].names)

    def test_detects_functions(self):
        src = "def foo():\n    pass\ndef bar(x, y):\n    return x + y\n"
        fi = self._scan(src)
        names = [f.name for f in fi.functions]
        self.assertIn("foo", names)
        self.assertIn("bar", names)

    def test_detects_async_functions(self):
        src = "async def handler(request):\n    return {}\n"
        fi = self._scan(src)
        self.assertEqual(len(fi.functions), 1)
        self.assertTrue(fi.functions[0].is_async)

    def test_detects_classes(self):
        src = "class User(BaseModel):\n    pass\n"
        fi = self._scan(src)
        self.assertEqual(len(fi.classes), 1)
        self.assertEqual(fi.classes[0].name, "User")
        self.assertIn("BaseModel", fi.classes[0].bases)

    def test_detects_decorators(self):
        src = "@app.get('/users')\ndef list_users():\n    pass\n"
        fi = self._scan(src)
        self.assertEqual(len(fi.functions), 1)
        self.assertIn("app.get", fi.functions[0].decorators)

    def test_detects_dunder_all_exports(self):
        src = "__all__ = ['foo', 'bar']\ndef foo(): pass\ndef bar(): pass\n"
        fi = self._scan(src)
        self.assertIn("foo", fi.exports)
        self.assertIn("bar", fi.exports)

    def test_syntax_error_recorded(self):
        fi = self._scan("def broken(\n    missing_close\n")
        self.assertIsNotNone(fi.error)

    def test_records_line_count(self):
        # 3 lines of content — scanner counts newlines so trailing newline = 3
        src = "a = 1\nb = 2\nc = 3\n"
        fi = self._scan(src)
        # write_text adds the content as-is; source.count('\n') = 3
        self.assertEqual(fi.lines, 3)

    def test_language_is_python(self):
        fi = self._scan("pass")
        self.assertEqual(fi.language, Lang.PYTHON)


class TestJavaScriptParser(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def _scan(self, content: str, filename: str = "app.js") -> FileInfo:
        path = _write(self.root, f"src/{filename}", content)
        scanner = FileScanner(self.root)
        return scanner.scan_file(path)

    def test_detects_es_import(self):
        fi = self._scan("import express from 'express';\n")
        self.assertEqual(len(fi.imports), 1)
        self.assertEqual(fi.imports[0].source, "express")

    def test_detects_named_imports(self):
        fi = self._scan("import { useState, useEffect } from 'react';\n")
        self.assertEqual(fi.imports[0].source, "react")

    def test_detects_relative_import(self):
        fi = self._scan("import auth from './auth';\n")
        self.assertTrue(fi.imports[0].is_relative)

    def test_detects_require(self):
        fi = self._scan("const express = require('express');\n")
        sources = [i.source for i in fi.imports]
        self.assertIn("express", sources)

    def test_detects_function_declaration(self):
        fi = self._scan("function getUser(id) { return id; }\n")
        names = [f.name for f in fi.functions]
        self.assertIn("getUser", names)

    def test_detects_class(self):
        fi = self._scan("class UserService {}\n")
        self.assertEqual(len(fi.classes), 1)
        self.assertEqual(fi.classes[0].name, "UserService")

    def test_typescript_file_detected(self):
        fi = self._scan("const x: number = 1;\n", filename="server.ts")
        self.assertEqual(fi.language, Lang.TYPESCRIPT)


class TestJSONParser(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_package_json_deps_as_imports(self):
        content = '{"dependencies":{"react":"^18.0.0","express":"^4.18.0"}}'
        path = _write(self.root, "package.json", content)
        scanner = FileScanner(self.root)
        fi = scanner.scan_file(path)
        sources = [i.source for i in fi.imports]
        self.assertIn("react", sources)
        self.assertIn("express", sources)

    def test_invalid_json_records_error(self):
        path = _write(self.root, "bad.json", "{not: valid json}")
        scanner = FileScanner(self.root)
        fi = scanner.scan_file(path)
        self.assertIsNotNone(fi.error)


class TestScannerFull(unittest.TestCase):
    """Integration: scan() returns FileInfo list for all discovered files."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_scan_returns_list_of_fileinfo(self):
        _write(self.root, "src/app.py", "import os\ndef main(): pass\n")
        _write(self.root, "src/utils.py", "def helper(): pass\n")
        scanner = FileScanner(self.root)
        results = scanner.scan()
        self.assertGreater(len(results), 0)
        self.assertIsInstance(results[0], FileInfo)

    def test_progress_callback_called(self):
        _write(self.root, "src/app.py", "pass")
        calls = []

        def on_progress(current, total, path):
            calls.append((current, total))

        scanner = FileScanner(self.root)
        scanner.scan(on_progress=on_progress)
        self.assertGreater(len(calls), 0)

    def test_purpose_inferred(self):
        _write(
            self.root,
            "src/auth/middleware.py",
            "from functools import wraps\ndef auth_required(f): pass\n",
        )
        scanner = FileScanner(self.root)
        results = scanner.scan()
        auth_file = next((r for r in results if "middleware" in r.path), None)
        self.assertIsNotNone(auth_file)
        self.assertNotEqual(auth_file.purpose, "")


if __name__ == "__main__":
    unittest.main()
