"""Tests for patchi.core.security.app_profile"""

import tempfile
import unittest
from pathlib import Path

from patchi.core.security.app_profile import (
    ActivationState,
    AppProfileBuilder,
    AppProfileScorer,
    ComponentProfile,
    DomainActivation,
)


def _make_project(root: Path, dirs: list[str] | None = None, files: dict[str, str] | None = None) -> Path:
    root = root / "testproj"
    root.mkdir(exist_ok=True)
    for d in (dirs or []):
        (root / d).mkdir(parents=True, exist_ok=True)
    for fpath, content in (files or {}).items():
        p = root / fpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return root


class TestComponentProfile(unittest.TestCase):
    def test_minimal_profile_defaults(self):
        p = ComponentProfile(component_type="unknown")
        self.assertEqual(p.component_type, "unknown")
        self.assertEqual(p.frameworks, [])
        self.assertEqual(p.languages, [])
        self.assertFalse(p.has_database)

    def test_to_dict_excludes_internal_fields(self):
        p = ComponentProfile(
            component_type="backend-api",
            display_name="My API",
            frameworks=["fastapi"],
            has_database=True,
        )
        d = p.to_dict()
        self.assertEqual(d["component_type"], "backend-api")
        self.assertEqual(d["display_name"], "My API")
        self.assertNotIn("detection_signals", d)


class TestAppProfileBuilder(unittest.TestCase):
    def test_detect_cli_binary_from_deps(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_project(
                Path(td),
                dirs=["cli"],
                files={
                    "pyproject.toml": '[project]\ndependencies = ["click>=8.0"]\n',
                },
            )
            builder = AppProfileBuilder(root)
            profile = builder.build(brain={})
            self.assertEqual(profile.component_type, "cli-binary")
            self.assertTrue(profile.is_packaged)

    def test_detect_backend_api_from_framework_and_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_project(
                Path(td),
                dirs=["routes", "models", "api"],
                files={
                    "pyproject.toml": '[project]\ndependencies = ["fastapi>=0.100.0"]\n',
                },
            )
            builder = AppProfileBuilder(root)
            profile = builder.build(brain={
                "frameworks": ["FastAPI"],
                "languages": {"python": 10},
            })
            self.assertEqual(profile.component_type, "backend-api")
            self.assertTrue(profile.has_database)
            self.assertTrue(profile.has_network)
            self.assertIn("python", profile.languages)

    def test_detect_frontend_web_from_framework(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_project(
                Path(td),
                dirs=["components", "pages"],
            )
            builder = AppProfileBuilder(root)
            profile = builder.build(brain={
                "frameworks": ["React", "Next.js"],
            })
            self.assertEqual(profile.component_type, "frontend-web")
            self.assertTrue(profile.has_user_input)

    def test_detect_frontend_web_from_package_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_project(
                Path(td),
                files={
                    "package.json": '{"dependencies": {"react": "^18.0.0", "next": "^14.0.0"}}',
                },
            )
            builder = AppProfileBuilder(root)
            profile = builder.build(brain={})
            self.assertEqual(profile.component_type, "frontend-web")

    def test_unknown_project_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_project(Path(td))
            builder = AppProfileBuilder(root)
            profile = builder.build(brain={})
            self.assertEqual(profile.component_type, "unknown")

    def test_brain_data_merges_with_file_signals(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_project(Path(td), dirs=["auth", "cli"])
            builder = AppProfileBuilder(root)
            profile = builder.build(brain={
                "frameworks": ["Click"],
                "languages": {"python": 5, "javascript": 2},
                "project_purpose": "CLI admin tool",
            })
            self.assertEqual(profile.display_name, "CLI admin tool")
            self.assertTrue(profile.has_authentication)


class TestAppProfileScorer(unittest.TestCase):
    def test_domain_activation_active_state(self):
        activation = DomainActivation(
            domain_id="backend-api",
            display_name="Backend API",
            state=ActivationState.ACTIVE,
            weight=1.0,
            score=85.0,
            reason="Framework matched: FastAPI",
        )
        d = activation.to_dict()
        self.assertEqual(d["state"], "active")
        self.assertEqual(d["score"], 85.0)

    def test_domain_activation_na_state(self):
        activation = DomainActivation(
            domain_id="web-frontend",
            display_name="Web Frontend",
            state=ActivationState.NA,
            weight=0.8,
            reason="No web framework detected",
        )
        d = activation.to_dict()
        self.assertEqual(d["state"], "n/a")
        self.assertEqual(d["score"], 0.0)

    def test_domain_activation_unclear_state(self):
        activation = DomainActivation(
            domain_id="mobile",
            display_name="Mobile",
            state=ActivationState.UNCLEAR,
            weight=0.5,
            reason="Cannot determine platform",
        )
        d = activation.to_dict()
        self.assertEqual(d["state"], "unclear")

    def test_context_score_weights_only_active(self):
        activations = [
            DomainActivation("d1", "Domain 1", ActivationState.ACTIVE, 1.0, 80.0),
            DomainActivation("d2", "Domain 2", ActivationState.ACTIVE, 2.0, 60.0),
            DomainActivation("d3", "Domain 3", ActivationState.NA, 0.5, 0.0),
        ]
        scorer = AppProfileScorer(Path("/tmp"))
        score = scorer.compute_context_score(activations)
        # (1.0*80 + 2.0*60) / (1.0 + 2.0) = 200/3 = 66.67
        self.assertAlmostEqual(score, 66.67, places=1)

    def test_context_score_all_active(self):
        activations = [
            DomainActivation("d1", "D1", ActivationState.ACTIVE, 1.0, 100.0),
            DomainActivation("d2", "D2", ActivationState.ACTIVE, 1.0, 50.0),
        ]
        scorer = AppProfileScorer(Path("/tmp"))
        score = scorer.compute_context_score(activations)
        self.assertAlmostEqual(score, 75.0, places=1)

    def test_context_score_all_na(self):
        activations = [
            DomainActivation("d1", "D1", ActivationState.NA, 1.0),
        ]
        scorer = AppProfileScorer(Path("/tmp"))
        score = scorer.compute_context_score(activations)
        self.assertEqual(score, 50.0)

    def test_signal_check_framework(self):
        with tempfile.TemporaryDirectory() as td:
            root = _make_project(Path(td), dirs=["api"])
            from patchi.core.security.app_profile import AppProfileScorer
            scorer = AppProfileScorer(root)
            profile = ComponentProfile(
                component_type="backend-api",
                frameworks=["fastapi", "pydantic"],
            )
            self.assertTrue(scorer._check_signal("fastapi", profile))
            self.assertTrue(scorer._check_signal("FastAPI", profile))
            self.assertFalse(scorer._check_signal("react", profile))

    def test_signal_check_feature(self):
        root = Path("/tmp")
        scorer = AppProfileScorer(root)
        profile = ComponentProfile(
            component_type="unknown",
            has_database=True,
            has_authentication=True,
        )
        self.assertTrue(scorer._check_signal("database", profile))
        self.assertTrue(scorer._check_signal("auth", profile))
        self.assertFalse(scorer._check_signal("network", profile))

    def test_get_applicable_domains_scopes_loader(self):
        """The scorer must scope its loader to the profile's component type so
        narrow scans never parse the full taxonomy — while still honoring the
        explicit component->domain map (web-frontend for backend-api)."""
        with tempfile.TemporaryDirectory() as td:
            import yaml

            root = _make_project(Path(td), dirs=["api"])
            dom = root / "patchi" / "core" / "security" / "domains"
            pb = root / "patchi" / "core" / "security" / "fix-playbooks"
            dom.mkdir(parents=True)
            pb.mkdir(parents=True)
            for did, ct in [("web-frontend", "frontend-web"), ("api-gateway", "backend-api")]:
                (dom / f"{did}.yaml").write_text(
                    yaml.dump({
                        "domain_id": did,
                        "component_type": ct,
                        "controls": [],
                    }),
                    encoding="utf-8",
                )
                (pb / f"{did}.playbook.yaml").write_text(
                    yaml.dump({"playbooks": []}), encoding="utf-8"
                )

            scorer = AppProfileScorer(root)
            profile = ComponentProfile(component_type="backend-api")
            applicable = scorer._get_applicable_domains(profile)

            self.assertIn("api-gateway", applicable)   # matches backend-api
            self.assertIn("web-frontend", applicable)  # explicit map entry
            # Only backend-api (+ explicit) domains parsed — web-frontend's
            # own type (frontend-web) must not pull in a second frontend file.
            self.assertLessEqual(len(scorer._loader._domains), len(applicable))

    def test_score_with_narrow_scope(self):
        """score() drives the same scoped loader and produces activations."""
        with tempfile.TemporaryDirectory() as td:
            import yaml

            root = _make_project(Path(td), dirs=["api"])
            dom = root / "patchi" / "core" / "security" / "domains"
            pb = root / "patchi" / "core" / "security" / "fix-playbooks"
            dom.mkdir(parents=True)
            pb.mkdir(parents=True)
            (dom / "api-gateway.yaml").write_text(
                yaml.dump({
                    "domain_id": "api-gateway",
                    "component_type": "backend-api",
                    "activation_signals": {"component_type": "backend-api"},
                    "controls": [],
                }),
                encoding="utf-8",
            )
            (pb / "api-gateway.playbook.yaml").write_text(
                yaml.dump({"playbooks": []}), encoding="utf-8"
            )

            scorer = AppProfileScorer(root)
            profile = ComponentProfile(component_type="backend-api", frameworks=["fastapi"])
            activations = scorer.score(profile)
            ids = {a.domain_id for a in activations}
            self.assertIn("api-gateway", ids)


if __name__ == "__main__":
    unittest.main()
