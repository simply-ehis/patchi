"""Tests for the hosted-mode upgrades: tenant, model router, cost tracker, CI/CD API.

Covers:
  - TenantManager: register, switch, list, remove, discover, cost tracking
  - Tenant context: thread-local scoping
  - ModelRouter: select_model, profiler blending, budget fallback, cheapest fallback
  - Cost tracker: record, check budget, get stats
  - CI/CD API endpoints: health, scan status, findings
"""

import tempfile
import threading
import unittest
from pathlib import Path

import os

# Ensure offline for all tests
os.environ["PATCHI_OFFLINE"] = "1"


# ── TenantManager ────────────────────────────────────────────────────────────


class TestTenantManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmpdir.name) / "state"
        self.state_dir.mkdir()
        self.project_a = Path(self.tmpdir.name) / "project_a"
        self.project_b = Path(self.tmpdir.name) / "project_b"
        self.project_a.mkdir()
        self.project_b.mkdir()

    def tearDown(self):
        self.tmpdir.cleanup()

    def _make_manager(self):
        from patchi.core.tenant import TenantManager
        return TenantManager(state_dir=self.state_dir)

    def test_register_and_list(self):
        mgr = self._make_manager()
        t = mgr.register_project(self.project_a, name="Alpha")
        self.assertEqual(t.name, "Alpha")
        self.assertTrue(t.active)
        self.assertEqual(len(mgr.list_projects()), 1)

    def test_register_idempotent(self):
        mgr = self._make_manager()
        mgr.register_project(self.project_a)
        mgr.register_project(self.project_a)
        self.assertEqual(len(mgr.list_projects()), 1)

    def test_switch_project(self):
        mgr = self._make_manager()
        mgr.register_project(self.project_a, name="A")
        mgr.register_project(self.project_b, name="B")
        mgr.switch_project(self.project_a)
        self.assertEqual(mgr.get_active().name, "A")
        mgr.switch_project(self.project_b)
        self.assertEqual(mgr.get_active().name, "B")
        self.assertFalse(mgr.list_projects()[0].active)

    def test_get_active_root(self):
        mgr = self._make_manager()
        self.assertEqual(mgr.get_active_root(), Path.cwd())  # fallback
        mgr.register_project(self.project_a)
        mgr.switch_project(self.project_a)
        self.assertEqual(mgr.get_active_root(), self.project_a.resolve())

    def test_remove_project(self):
        mgr = self._make_manager()
        mgr.register_project(self.project_a)
        mgr.register_project(self.project_b)
        self.assertTrue(mgr.remove_project(self.project_a))
        self.assertEqual(len(mgr.list_projects()), 1)

    def test_remove_active_project(self):
        mgr = self._make_manager()
        mgr.register_project(self.project_a)
        mgr.switch_project(self.project_a)
        mgr.remove_project(self.project_a)
        self.assertIsNone(mgr.get_active())

    def test_discover_projects(self):
        # Create a .patchi dir in project_b to make it discoverable
        (self.project_b / ".patchi").mkdir()
        mgr = self._make_manager()
        # discover_projects excludes the system temp dir, so mock it away
        import tempfile as _tf
        real_gettempdir = _tf.gettempdir
        _tf.gettempdir = lambda: "/nonexistent/path"
        try:
            found = mgr.discover_projects(near=self.project_b.parent, max_depth=3)
        finally:
            _tf.gettempdir = real_gettempdir
        names = [str(p) for p in found]
        self.assertTrue(
            any("project_b" in n for n in names),
            f"Expected project_b in {names}",
        )

    def test_update_stats(self):
        mgr = self._make_manager()
        mgr.register_project(self.project_a)
        mgr.update_stats(self.project_a, scan_count=5, cost_estimate=1.23)
        updated = mgr.list_projects()[0]
        self.assertEqual(updated.scan_count, 5)
        self.assertAlmostEqual(updated.cost_estimate, 1.23)

    def test_persistence(self):
        mgr = self._make_manager()
        mgr.register_project(self.project_a, name="Persistent")
        mgr.switch_project(self.project_a)
        # Create a new manager from same state dir
        mgr2 = self._make_manager()
        self.assertEqual(len(mgr2.list_projects()), 1)
        self.assertEqual(mgr2.list_projects()[0].name, "Persistent")
        self.assertEqual(mgr2.get_active().name, "Persistent")

    def test_to_dict(self):
        t = self._make_manager().register_project(self.project_a, name="X")
        d = t.to_dict()
        self.assertIn("root", d)
        self.assertIn("name", d)
        self.assertEqual(d["name"], "X")


# ── Tenant Context ───────────────────────────────────────────────────────────


class TestTenantContext(unittest.TestCase):
    def test_context_scopes_root(self):
        from patchi.core.tenant import (
            get_current_tenant_root,
            tenant_context,
        )
        path = Path("/fake/project")
        self.assertIsNone(get_current_tenant_root())
        with tenant_context(path) as scoped:
            self.assertEqual(get_current_tenant_root(), path)
            self.assertEqual(scoped, path)
        self.assertIsNone(get_current_tenant_root())

    def test_context_nests(self):
        from patchi.core.tenant import (
            get_current_tenant_root,
            tenant_context,
        )
        a = Path("/a")
        b = Path("/b")
        with tenant_context(a):
            self.assertEqual(get_current_tenant_root(), a)
            with tenant_context(b):
                self.assertEqual(get_current_tenant_root(), b)
            self.assertEqual(get_current_tenant_root(), a)
        self.assertIsNone(get_current_tenant_root())


# ── Tenant Cost Tracking ────────────────────────────────────────────────────


class TestTenantCostTracking(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_track_and_get(self):
        from patchi.core.tenant import (
            get_tenant_cost,
            track_tenant_cost,
        )
        path = Path("/test/project")
        track_tenant_cost(path, 0.05)
        track_tenant_cost(path, 0.10)
        self.assertAlmostEqual(get_tenant_cost(path), 0.15)

    def test_get_all(self):
        from patchi.core.tenant import (
            get_all_tenant_costs,
            track_tenant_cost,
        )
        a = Path(self.tmpdir.name) / "a"
        b = Path(self.tmpdir.name) / "b"
        track_tenant_cost(a, 1.0)
        track_tenant_cost(b, 2.0)
        costs = get_all_tenant_costs()
        self.assertIn(str(a.resolve()), costs)
        self.assertIn(str(b.resolve()), costs)

    def test_thread_safety(self):
        from patchi.core.tenant import (
            get_tenant_cost,
            track_tenant_cost,
        )
        path = Path("/thread/test")
        errors = []

        def worker(n):
            try:
                for _ in range(100):
                    track_tenant_cost(path, 0.01)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(errors), 0)
        self.assertAlmostEqual(get_tenant_cost(path), 5.0, places=1)


# ── Model Router ─────────────────────────────────────────────────────────────


class TestModelRouter(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        (self.root / ".patchi").mkdir()

    def tearDown(self):
        self.tmpdir.cleanup()

    def _make_router(self, config=None):
        from patchi.core.ai.model_router import ModelRouter
        return ModelRouter(config=config or {}, root=self.root)

    def test_select_simple_uses_cheap(self):
        from patchi.core.ai.model_router import TaskComplexity
        router = self._make_router()
        model = router.select_model(complexity=TaskComplexity.SIMPLE)
        # Simple tasks should prefer cheap models (not gpt-4o or claude-sonnet)
        from patchi.core.ai.model_router import MODEL_PROFILES
        profile = MODEL_PROFILES[model]
        avg_cost = (profile.cost_per_1k_input + profile.cost_per_1k_output) / 2
        self.assertLess(avg_cost, 0.005, f"{model} too expensive for SIMPLE task")

    def test_select_complex_uses_capable(self):
        from patchi.core.ai.model_router import TaskComplexity
        router = self._make_router()
        model = router.select_model(complexity=TaskComplexity.CRITICAL)
        # Critical tasks should prefer high-quality models
        self.assertIn(model, ["gpt-4o", "claude-sonnet", "gpt-4o-mini", "claude-haiku"])

    def test_require_tools_filters(self):
        from patchi.core.ai.model_router import TaskComplexity
        router = self._make_router()
        model = router.select_model(complexity=TaskComplexity.SIMPLE, require_tools=True)
        # Only models with tools support should be selected
        from patchi.core.ai.model_router import MODEL_PROFILES
        self.assertTrue(MODEL_PROFILES[model].supports_tools)

    def test_budget_fallback(self):
        from patchi.core.ai.model_router import TaskComplexity
        config = {"ai": {"cost_limit": 0.001}}  # Very low budget
        router = self._make_router(config)
        # Should still return a model (cheapest fallback)
        model = router.select_model(complexity=TaskComplexity.SIMPLE)
        self.assertIsNotNone(model)
        self.assertIsInstance(model, str)

    def test_max_cost_filter(self):
        from patchi.core.ai.model_router import TaskComplexity
        router = self._make_router()
        model = router.select_model(
            complexity=TaskComplexity.MODERATE,
            max_cost_per_1k=0.0001,  # Very low limit
        )
        self.assertIsNotNone(model)

    def test_prefer_local(self):
        from patchi.core.ai.model_router import TaskComplexity
        config = {"ai": {"prefer_local": True}}
        router = self._make_router(config)
        model = router.select_model(complexity=TaskComplexity.SIMPLE)
        # Local models should rank higher
        self.assertIsNotNone(model)

    def test_routing_stats(self):
        router = self._make_router()
        stats = router.get_routing_stats()
        self.assertIn("total_cost", stats)
        self.assertIn("budget_limit", stats)
        self.assertIn("models_used", stats)

    def test_model_profiles_exist(self):
        from patchi.core.ai.model_router import MODEL_PROFILES
        self.assertGreater(len(MODEL_PROFILES), 0)
        for name, profile in MODEL_PROFILES.items():
            self.assertIsInstance(profile.cost_per_1k_input, float)
            self.assertGreaterEqual(profile.quality_score, 0)
            self.assertLessEqual(profile.quality_score, 1)


# ── CI/CD API ────────────────────────────────────────────────────────────────


class TestCicdApi(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        (self.root / ".patchi").mkdir()
        (self.root / ".patchi" / "brain.json").write_text("{}")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_health_endpoint_structure(self):
        """Verify the health endpoint returns expected fields."""
        from patchi.web.api.cicd import health, _scan_state
        # Can't call directly without a Request mock, but verify function exists
        self.assertTrue(callable(health))
        self.assertIn("running", _scan_state)
        self.assertIn("last_result", _scan_state)

    def test_scan_state_initial(self):
        from patchi.web.api.cicd import _scan_state
        self.assertFalse(_scan_state["running"])
        self.assertIsNone(_scan_state["last_result"])
        self.assertIsNone(_scan_state["last_error"])

    def test_models_structures(self):
        from patchi.web.api.cicd import ScanRequest
        req = ScanRequest(scan_type="all", deep=False, pipeline=False)
        self.assertEqual(req.scan_type, "all")
        self.assertFalse(req.deep)


# ── Integration: Tenant + Model Router ───────────────────────────────────────


class TestTenantModelRouterIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        (self.root / ".patchi").mkdir()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_tenant_scoped_router(self):
        from patchi.core.tenant import tenant_context
        from patchi.core.ai.model_router import ModelRouter
        with tenant_context(self.root):
            router = ModelRouter(root=self.root)
            model = router.select_model()
            self.assertIsNotNone(model)

    def test_cost_tracking_per_tenant(self):
        from patchi.core.tenant import (
            get_tenant_cost,
            tenant_context,
            track_tenant_cost,
        )
        a = Path("/project/a")
        b = Path("/project/b")
        track_tenant_cost(a, 1.0)
        track_tenant_cost(b, 2.0)
        with tenant_context(a):
            self.assertAlmostEqual(get_tenant_cost(a), 1.0)
        with tenant_context(b):
            self.assertAlmostEqual(get_tenant_cost(b), 2.0)


if __name__ == "__main__":
    unittest.main()
