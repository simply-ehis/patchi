"""Phase 5.1 — Integration test: end-to-end scan on a temp project."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

import patchi.core.config as config_mod
from patchi.core.brain.brain import Brain
from patchi.web.app import create_app


class TestIntegrationScan(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self._root = Path(self._tmp.name)
        config_mod.init_project(self._root)
        (self._root / "src").mkdir(parents=True, exist_ok=True)
        (self._root / "src" / "hello.py").write_text(
            "def greet(name: str) -> str:\n    return f'Hello, {name}!'\n"
        )
        (self._root / "src" / "app.py").write_text(
            "from src.hello import greet\n\nprint(greet('world'))\n"
        )
        self._app = create_app(self._root)
        self._client = TestClient(self._app)

    def tearDown(self):
        self._tmp.cleanup()

    def test_brain_scan_discovers_files(self):
        brain = Brain(self._root)
        report = brain.scan()
        self.assertGreaterEqual(report.file_count, 2)
        self.assertIn("src/hello.py", report.import_graph.nodes)
        self.assertIn("src/app.py", report.import_graph.nodes)

    def test_import_graph_has_edge(self):
        brain = Brain(self._root)
        report = brain.scan()
        edges = report.import_graph.edges
        self.assertIn("src/app.py", edges)
        self.assertIn("src/hello.py", edges["src/app.py"])

    def test_status_endpoint_returns_expected_fields(self):
        resp = self._client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for key in ("mode", "queue_depth", "brain_fresh", "health_score"):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_brain_nodes_endpoint(self):
        resp = self._client.get("/api/brain/nodes")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data.get("nodes"), list)
        if data["nodes"]:
            n = data["nodes"][0]
            for key in ("id", "label", "type", "finding_count", "severity"):
                self.assertIn(key, n, f"Missing key: {key}")

    def test_scan_via_api(self):
        resp = self._client.post("/api/action/scan")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("ok", data)

    def test_config_endpoint(self):
        resp = self._client.get("/api/config")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, dict)

    def test_findings_endpoint(self):
        resp = self._client.get("/api/findings")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, dict)
        self.assertIn("findings", data)

    def test_health_breakdown_endpoint(self):
        resp = self._client.get("/api/health-breakdown")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total", data)


# ── Go integration test ────────────────────────────────────────────────────


class TestGoIntegrationScan(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self._root = Path(self._tmp.name)
        config_mod.init_project(self._root)
        (self._root / "src").mkdir(parents=True, exist_ok=True)
        (self._root / "src" / "greeter").mkdir(parents=True, exist_ok=True)
        (self._root / "go.mod").write_text("module example.com/app\ngo 1.21\n")
        (self._root / "src" / "greeter" / "greeter.go").write_text(
            "package greeter\n\nfunc Greet(name string) string {\n\treturn \"Hello, \" + name\n}\n"
        )
        (self._root / "src" / "main.go").write_text(
            "package main\n\nimport \"example.com/app/src/greeter\"\n\nfunc main() {\n\tgreeter.Greet(\"world\")\n}\n"
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_discovers_go_files(self):
        brain = Brain(self._root)
        report = brain.scan()
        self.assertGreaterEqual(report.file_count, 2)
        for p in ("src/main.go", "src/greeter/greeter.go"):
            self.assertIn(p, report.import_graph.nodes)

    def test_go_import_graph_has_edge(self):
        brain = Brain(self._root)
        report = brain.scan()
        edges = report.import_graph.edges
        self.assertIn("src/main.go", edges)
        self.assertIn("src/greeter/greeter.go", edges["src/main.go"])

    def test_go_detects_functions(self):
        brain = Brain(self._root)
        report = brain.scan()
        main_info = next(
            (fi for fi in report.file_infos if fi.path == "src/main.go"), None
        )
        greeter_info = next(
            (fi for fi in report.file_infos if fi.path == "src/greeter/greeter.go"), None
        )
        self.assertIsNotNone(main_info)
        self.assertIsNotNone(greeter_info)
        func_names = {f.name for f in greeter_info.functions}
        self.assertIn("Greet", func_names)


# ── Rust integration test ──────────────────────────────────────────────────


class TestRustIntegrationScan(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self._root = Path(self._tmp.name)
        config_mod.init_project(self._root)
        (self._root / "src").mkdir(parents=True, exist_ok=True)
        (self._root / "Cargo.toml").write_text(
            '[package]\nname = "testapp"\nversion = "0.1.0"\nedition = "2021"\n'
        )
        (self._root / "src" / "greeter.rs").write_text(
            "pub fn greet(name: &str) -> String {\n\tformat!(\"Hello, {}\", name)\n}\n"
        )
        (self._root / "src" / "main.rs").write_text(
            "mod greeter;\n\nfn main() {\n\tprintln!(\"{}\", greeter::greet(\"world\"));\n}\n"
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_discovers_rust_files(self):
        brain = Brain(self._root)
        report = brain.scan()
        self.assertGreaterEqual(report.file_count, 2)  # main.rs + greeter.rs
        for p in ("src/main.rs", "src/greeter.rs"):
            self.assertIn(p, report.import_graph.nodes)

    def test_rust_import_graph_has_edge(self):
        brain = Brain(self._root)
        report = brain.scan()
        edges = report.import_graph.edges
        self.assertIn("src/main.rs", edges)
        self.assertIn("src/greeter.rs", edges["src/main.rs"])

    def test_rust_detects_functions(self):
        brain = Brain(self._root)
        report = brain.scan()
        greeter_info = next(
            (fi for fi in report.file_infos if fi.path == "src/greeter.rs"), None
        )
        self.assertIsNotNone(greeter_info)
        func_names = {f.name for f in greeter_info.functions}
        self.assertIn("greet", func_names)


# ── Java integration test ──────────────────────────────────────────────────


class TestJavaIntegrationScan(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self._root = Path(self._tmp.name)
        config_mod.init_project(self._root)
        pkg_dir = self._root / "src" / "main" / "java" / "com" / "example"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        (pkg_dir / "Greeter.java").write_text(
            "package com.example;\n\npublic class Greeter {\n"
            "\tpublic String greet(String name) {\n\t\treturn \"Hello, \" + name;\n\t}\n"
            "}\n"
        )
        (pkg_dir / "App.java").write_text(
            "package com.example;\n\npublic class App {\n"
            "\tpublic static void main(String[] args) {\n\t\tGreeter g = new Greeter();\n"
            "\t\tSystem.out.println(g.greet(\"world\"));\n\t}\n}\n"
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_discovers_java_files(self):
        brain = Brain(self._root)
        report = brain.scan()
        self.assertGreaterEqual(report.file_count, 2)
        for p in ("src/main/java/com/example/App.java", "src/main/java/com/example/Greeter.java"):
            self.assertIn(p, report.import_graph.nodes)

    def test_java_detects_classes(self):
        brain = Brain(self._root)
        report = brain.scan()
        greeter_info = next(
            (fi for fi in report.file_infos if "Greeter.java" in fi.path), None
        )
        self.assertIsNotNone(greeter_info)
        class_names = {c.name for c in greeter_info.classes}
        self.assertIn("Greeter", class_names)

    def test_java_detects_methods(self):
        brain = Brain(self._root)
        report = brain.scan()
        greeter_info = next(
            (fi for fi in report.file_infos if "Greeter.java" in fi.path), None
        )
        self.assertIsNotNone(greeter_info)
        method_names = {f.name for f in greeter_info.functions}
        self.assertIn("greet", method_names)
