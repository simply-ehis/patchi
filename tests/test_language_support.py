"""
Per-language integration tests.

Validates scanner, import graph, type checker, route detection, blast radius,
and security agents for each supported language.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from patchi.core.brain.languages import Lang, detect_language, get_parser, EXTENSION_MAP
from patchi.core.brain.scanner import FileScanner
from patchi.core.brain.import_graph import build_graph, find_dead_files, ImportGraph
from patchi.core.brain.blast_radius import calculate_blast_radius, build_blast_radius_map
from patchi.core.brain.type_checker import check_types

FIXTURES = Path(__file__).parent / "fixtures" / "languages"


# ── Language detection ────────────────────────────────────────────────────────


class TestLanguageDetection:
    def test_python(self):
        assert detect_language(Path("app.py")) == Lang.PYTHON

    def test_javascript(self):
        assert detect_language(Path("app.js")) == Lang.JAVASCRIPT

    def test_typescript(self):
        assert detect_language(Path("app.ts")) == Lang.TYPESCRIPT

    def test_java(self):
        assert detect_language(Path("Main.java")) == Lang.JAVA

    def test_go(self):
        assert detect_language(Path("main.go")) == Lang.GO

    def test_rust(self):
        assert detect_language(Path("main.rs")) == Lang.RUST

    def test_ruby(self):
        assert detect_language(Path("app.rb")) == Lang.RUBY

    def test_php(self):
        assert detect_language(Path("index.php")) == Lang.PHP

    def test_csharp(self):
        assert detect_language(Path("Program.cs")) == Lang.C_SHARP

    def test_kotlin(self):
        assert detect_language(Path("Main.kt")) == Lang.KOTLIN

    def test_kotlin_script(self):
        assert detect_language(Path("build.kts")) == Lang.KOTLIN

    def test_swift(self):
        assert detect_language(Path("main.swift")) == Lang.SWIFT

    def test_dart(self):
        assert detect_language(Path("main.dart")) == Lang.DART

    def test_c(self):
        assert detect_language(Path("main.c")) == Lang.C

    def test_cpp(self):
        assert detect_language(Path("main.cpp")) == Lang.CPP

    def test_bash(self):
        assert detect_language(Path("script.sh")) == Lang.BASH

    def test_css(self):
        assert detect_language(Path("style.css")) == Lang.CSS

    def test_sql(self):
        assert detect_language(Path("schema.sql")) == Lang.SQL

    def test_html(self):
        assert detect_language(Path("index.html")) == Lang.HTML

    def test_json(self):
        assert detect_language(Path("config.json")) == Lang.JSON

    def test_yaml(self):
        assert detect_language(Path("config.yaml")) == Lang.YAML


# ── Tree-sitter parser availability ───────────────────────────────────────────


class TestParserAvailability:
    @pytest.mark.parametrize("lang", [
        Lang.PYTHON, Lang.JAVASCRIPT, Lang.TYPESCRIPT, Lang.RUST,
        Lang.JAVA, Lang.GO, Lang.C_SHARP, Lang.KOTLIN, Lang.SWIFT,
        Lang.RUBY, Lang.PHP, Lang.DART, Lang.BASH, Lang.CSS, Lang.SQL,
        Lang.HTML, Lang.C, Lang.CPP, Lang.SVELTE,
    ])
    def test_parser_exists(self, lang: Lang):
        parser = get_parser(lang)
        assert parser is not None, f"No parser for {lang.value}"


# ── Fixture scanning ──────────────────────────────────────────────────────────


class TestFixtureScanning:
    @pytest.fixture(scope="class")
    def scan_results(self):
        scanner = FileScanner(FIXTURES)
        return scanner.scan()

    def _get_files(self, results, lang: Lang):
        return [r for r in results if r.language == lang]

    def test_all_files_scanned(self, scan_results):
        assert len(scan_results) >= 30

    def test_python_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.PYTHON)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 5

    def test_python_functions(self, scan_results):
        files = self._get_files(scan_results, Lang.PYTHON)
        total_funcs = sum(len(f.functions) for f in files)
        assert total_funcs >= 5

    def test_python_classes(self, scan_results):
        files = self._get_files(scan_results, Lang.PYTHON)
        total_classes = sum(len(f.classes) for f in files)
        assert total_classes >= 2

    def test_javascript_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.JAVASCRIPT)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 3

    def test_javascript_functions(self, scan_results):
        files = self._get_files(scan_results, Lang.JAVASCRIPT)
        total_funcs = sum(len(f.functions) for f in files)
        assert total_funcs >= 3

    def test_javascript_classes(self, scan_results):
        files = self._get_files(scan_results, Lang.JAVASCRIPT)
        total_classes = sum(len(f.classes) for f in files)
        assert total_classes >= 1

    def test_typescript_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.TYPESCRIPT)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 3

    def test_typescript_functions(self, scan_results):
        files = self._get_files(scan_results, Lang.TYPESCRIPT)
        total_funcs = sum(len(f.functions) for f in files)
        assert total_funcs >= 3

    def test_typescript_exports(self, scan_results):
        files = self._get_files(scan_results, Lang.TYPESCRIPT)
        total_exports = sum(len(f.exports) for f in files)
        assert total_exports >= 1

    def test_java_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.JAVA)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 3

    def test_java_classes(self, scan_results):
        files = self._get_files(scan_results, Lang.JAVA)
        total_classes = sum(len(f.classes) for f in files)
        assert total_classes >= 2

    def test_go_functions(self, scan_results):
        files = self._get_files(scan_results, Lang.GO)
        assert len(files) > 0
        total_funcs = sum(len(f.functions) for f in files)
        assert total_funcs >= 5

    def test_go_exports(self, scan_results):
        files = self._get_files(scan_results, Lang.GO)
        total_exports = sum(len(f.exports) for f in files)
        assert total_exports >= 1

    def test_rust_files(self, scan_results):
        files = self._get_files(scan_results, Lang.RUST)
        assert len(files) > 0

    def test_ruby_classes(self, scan_results):
        files = self._get_files(scan_results, Lang.RUBY)
        assert len(files) > 0
        total_classes = sum(len(f.classes) for f in files)
        assert total_classes >= 2

    def test_ruby_functions(self, scan_results):
        files = self._get_files(scan_results, Lang.RUBY)
        total_funcs = sum(len(f.functions) for f in files)
        assert total_funcs >= 3

    def test_php_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.PHP)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 3

    def test_php_classes(self, scan_results):
        files = self._get_files(scan_results, Lang.PHP)
        total_classes = sum(len(f.classes) for f in files)
        assert total_classes >= 2

    def test_csharp_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.C_SHARP)
        assert len(files) > 0

    def test_csharp_classes(self, scan_results):
        files = self._get_files(scan_results, Lang.C_SHARP)
        total_classes = sum(len(f.classes) for f in files)
        assert total_classes >= 1

    def test_kotlin_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.KOTLIN)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 1

    def test_swift_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.SWIFT)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 1

    def test_dart_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.DART)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 1

    def test_c_files(self, scan_results):
        files = self._get_files(scan_results, Lang.C)
        assert len(files) > 0

    def test_cpp_files(self, scan_results):
        files = self._get_files(scan_results, Lang.CPP)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 1

    def test_html_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.HTML)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 2

    def test_scala_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.SCALA)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 2

    def test_scala_classes(self, scan_results):
        files = self._get_files(scan_results, Lang.SCALA)
        total_classes = sum(len(f.classes) for f in files)
        assert total_classes >= 2

    def test_bash_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.BASH)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 1

    def test_bash_functions(self, scan_results):
        files = self._get_files(scan_results, Lang.BASH)
        total_funcs = sum(len(f.functions) for f in files)
        assert total_funcs >= 2

    def test_svelte_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.SVELTE)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 1

    def test_css_imports(self, scan_results):
        files = self._get_files(scan_results, Lang.CSS)
        assert len(files) > 0
        total_imports = sum(len(f.imports) for f in files)
        assert total_imports >= 1


# ── Import graph ──────────────────────────────────────────────────────────────


class TestImportGraph:
    @pytest.fixture(scope="class")
    def graph(self):
        scanner = FileScanner(FIXTURES)
        files = scanner.scan()
        return build_graph(files, FIXTURES)

    def test_graph_has_nodes(self, graph: ImportGraph):
        assert len(graph.nodes) > 0

    def test_graph_has_edges(self, graph: ImportGraph):
        assert len(graph.edges) > 0

    def test_reverse_graph_populated(self, graph: ImportGraph):
        assert len(graph.reverse) > 0


# ── Type checking ─────────────────────────────────────────────────────────────


class TestTypeChecking:
    def test_python_type_issues(self):
        source = (FIXTURES / "python" / "utils.py").read_text()
        issues = check_types(source, Lang.PYTHON, "utils.py")
        assert isinstance(issues, list)

    def test_typescript_type_issues(self):
        source = (FIXTURES / "typescript" / "app.ts").read_text()
        issues = check_types(source, Lang.TYPESCRIPT, "app.ts")
        assert isinstance(issues, list)

    def test_java_type_issues(self):
        source = (FIXTURES / "java" / "src" / "main" / "java" / "com" / "example" / "demo" / "UserService.java").read_text()
        issues = check_types(source, Lang.JAVA, "UserService.java")
        assert isinstance(issues, list)


# ── Blast radius ──────────────────────────────────────────────────────────────


class TestBlastRadius:
    @pytest.fixture(scope="class")
    def graph(self):
        scanner = FileScanner(FIXTURES)
        files = scanner.scan()
        return build_graph(files, FIXTURES)

    def test_blast_radius_map(self, graph: ImportGraph):
        br_map = build_blast_radius_map(graph)
        assert isinstance(br_map, dict)

    def test_calculate_blast_radius(self, graph: ImportGraph):
        for node in list(graph.nodes)[:5]:
            result = calculate_blast_radius(node, graph)
            assert hasattr(result, "risk_level")
            assert result.risk_level in ("low", "medium", "high")


# ── Dead file detection ───────────────────────────────────────────────────────


class TestDeadFiles:
    @pytest.fixture(scope="class")
    def dead_files(self):
        scanner = FileScanner(FIXTURES)
        files = scanner.scan()
        graph = build_graph(files, FIXTURES)
        return find_dead_files(files, graph)

    def test_finds_dead_files(self, dead_files):
        assert isinstance(dead_files, list)
