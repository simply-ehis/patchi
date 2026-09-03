"""Tests for patchi.core.brain.layered_brain (Layered Brain — Pillar 1)."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from patchi.core.brain.languages import Lang
from patchi.core.brain.scanner import ClassInfo, FileInfo, FunctionInfo


def _fi(path, funcs=(), classes=(), imports=()):
    return FileInfo(
        path=path,
        language=Lang.PYTHON,
        size_bytes=100,
        lines=10,
        functions=[FunctionInfo(name=n, line=1) for n in funcs],
        classes=[ClassInfo(name=n, line=1) for n in classes],
        imports=list(imports),
        exports=[],
        is_entry_point=False,
        purpose="",
    )


def _route(method, path, file, framework=""):
    class R:
        pass

    R.method = method
    R.path = path
    R.file = file
    R.framework = framework
    return R()


class FakeGraph:
    """Minimal import graph stand-in with an edges dict."""

    def __init__(self, edges):
        self.edges = edges
        self.nodes = set()
        for s, ts in edges.items():
            self.nodes.add(s)
            self.nodes.update(ts)

    def to_dict(self):
        return {"nodes": list(self.nodes), "edges": {k: list(v) for k, v in self.edges.items()}}


class TestLayerDataclass(unittest.TestCase):
    def test_compute_hash_changes_with_api(self):
        from patchi.core.brain.layered_brain import Layer

        lay = Layer(name="m", level=1, files=["a.py"], public_api=["foo"])
        h1 = lay.compute_hash()
        lay.public_api = ["foo", "bar"]
        h2 = lay.compute_hash()
        self.assertNotEqual(h1, h2)

    def test_to_from_dict_roundtrip(self):
        from patchi.core.brain.layered_brain import Layer

        lay = Layer(
            name="auth",
            level=2,
            path="auth",
            summary="subsystem",
            files=["a.py", "b.py"],
            depends_on=["data"],
            public_api=["login"],
        )
        lay.validity_hash = lay.compute_hash()
        d = lay.to_dict()
        l2 = Layer.from_dict(d)
        self.assertEqual(l2.name, "auth")
        self.assertEqual(l2.level, 2)
        self.assertEqual(l2.depends_on, ["data"])
        self.assertEqual(l2.validity_hash, lay.validity_hash)


class TestBuildLayers(unittest.TestCase):
    def setUp(self):
        self.fi_auth = _fi("src/auth/login.py", funcs=["verify_jwt", "login"], classes=["AuthMiddleware"])
        self.fi_api = _fi("src/api/users.py", funcs=["get_user"])
        self.fi_data = _fi("src/data/db.py", funcs=["connect"])
        self.all_fi = [self.fi_auth, self.fi_api, self.fi_data]
        self.routes = [_route("GET", "/api/users", "src/api/users.py", "Flask")]
        self.graph = FakeGraph(
            {
                "src/api/users.py": {"src/auth/login.py"},
                "src/auth/login.py": {"src/data/db.py"},
            }
        )

    def test_module_layers_created(self):
        from patchi.core.brain.layered_brain import build_layers

        layers = build_layers(self.all_fi, self.graph, self.routes)
        self.assertIn("src/auth", layers)
        self.assertIn("src/api", layers)
        self.assertIn("src/data", layers)
        self.assertEqual(layers["src/auth"].level, 1)

    def test_subsystem_classification(self):
        from patchi.core.brain.layered_brain import build_layers

        layers = build_layers(self.all_fi, self.graph, self.routes)
        self.assertIn("auth", layers)
        self.assertIn("api", layers)
        self.assertIn("data", layers)
        self.assertEqual(layers["auth"].level, 2)
        self.assertIn("src/auth", layers["auth"].child_layers)

    def test_project_layer_present(self):
        from patchi.core.brain.layered_brain import build_layers

        layers = build_layers(self.all_fi, self.graph, self.routes)
        self.assertIn("__project__", layers)
        self.assertEqual(layers["__project__"].level, 4)
        self.assertIn("auth", layers["__project__"].child_layers)

    def test_dependencies_propagate_to_subsystem(self):
        from patchi.core.brain.layered_brain import build_layers

        layers = build_layers(self.all_fi, self.graph, self.routes)
        # api/users.py imports auth/login.py → api subsystem depends on auth
        self.assertIn("auth", layers["api"].depends_on)
        # auth/login.py imports data/db.py → auth depends on data
        self.assertIn("data", layers["auth"].depends_on)
        # dependents are symmetric
        self.assertIn("api", layers["auth"].dependents)

    def test_summary_includes_routes(self):
        from patchi.core.brain.layered_brain import build_layers

        layers = build_layers(self.all_fi, self.graph, self.routes)
        self.assertIn("GET /api/users", layers["src/api"].summary)

    def test_handles_none_graph(self):
        from patchi.core.brain.layered_brain import build_layers

        layers = build_layers(self.all_fi, None, self.routes)
        self.assertIn("__project__", layers)
        # No graph → no dependencies populated
        self.assertEqual(layers["api"].depends_on, [])


class TestLayerQueries(unittest.TestCase):
    def setUp(self):
        from patchi.core.brain.layered_brain import build_layers

        fi_auth = _fi("src/auth/login.py", funcs=["verify_jwt"])
        fi_api = _fi("src/api/users.py", funcs=["get_user"])
        fi_data = _fi("src/data/db.py", funcs=["connect"])
        graph = FakeGraph(
            {
                "src/api/users.py": {"src/auth/login.py"},
                "src/auth/login.py": {"src/data/db.py"},
            }
        )
        self.layers = build_layers([fi_auth, fi_api, fi_data], graph, [])

    def test_get_layer_context_includes_dependencies(self):
        from patchi.core.brain.layered_brain import get_layer_context

        ctx = get_layer_context(self.layers, "api", max_depth=1)
        self.assertIn("api", ctx)
        self.assertIn("auth", ctx)  # direct dependency

    def test_find_layers_for_file(self):
        from patchi.core.brain.layered_brain import find_layers_for_file

        result = find_layers_for_file(self.layers, "src/api/users.py")
        self.assertIn("src/api", result)
        self.assertIn("api", result)
        self.assertIn("__project__", result)

    def test_detect_stale_layers(self):
        from patchi.core.brain.layered_brain import detect_stale_layers

        # Copy layers and mutate one public API
        old = {n: type(v).from_dict(v.to_dict()) for n, v in self.layers.items()}
        stale = detect_stale_layers(old, self.layers)
        self.assertEqual(stale, [])  # unchanged → no stale

        # Mutate api's public api and re-hash
        self.layers["src/api"].public_api.append("new_func")
        self.layers["src/api"].validity_hash = self.layers["src/api"].compute_hash()
        stale = detect_stale_layers(old, self.layers)
        self.assertIn("src/api", stale)


class TestBrainScanIntegration(unittest.TestCase):
    """End-to-end: Brain.scan() should produce and persist layers.json."""

    def test_scan_persists_layers(self):
        from patchi.core import memory as mem
        from patchi.core.brain.brain import Brain

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "auth").mkdir(parents=True)
            (root / "src" / "api").mkdir(parents=True)
            (root / "src" / "auth" / "login.py").write_text(
                "def verify_jwt():\n    return True\n"
            )
            (root / "src" / "api" / "users.py").write_text(
                "import sys\n\ndef get_user():\n    return {}\n"
            )
            (root / "pyproject.toml").write_text("[tool.poetry]\nname = 'demo'\n")

            brain = Brain(root)
            report = brain.scan()

            # Layers present on the report
            self.assertTrue(report.layers)
            self.assertIn("__project__", report.layers)

            # layers.json persisted
            saved = mem.get_layers(root)
            self.assertIn("layers", saved)
            self.assertIn("__project__", saved["layers"])


if __name__ == "__main__":
    unittest.main()
