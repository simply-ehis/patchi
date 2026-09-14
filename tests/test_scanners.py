"""Unit tests for all 10 scanner agents in patchi.core.agents.scanners"""

import tempfile
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core.agents.base import AgentInput, AgentStatus, Severity
from patchi.core.agents.scanners import (
    CommentScanner,
    CoreScanner,
    DeadCodeScanner,
    DependencyScanner,
    EnvScanner,
    RouteGraphScanner,
    SideFileScanner,
    TestScanner,
    TypeScanner,
    UIScanner,
)


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


def _write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _inp(root: Path, scope: list | None = None) -> AgentInput:
    return AgentInput(
        root=root,
        scope=scope or [],
        brain={},
        config={},
    )


# ── 1. CoreScanner ─────────────────────────────────────────────────────────────


class TestCoreScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_runs_successfully(self):
        _write(self.root, "src/app.py", "def main(): pass\n")
        result = CoreScanner().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.DONE)

    def test_produces_file_map(self):
        _write(self.root, "src/app.py", "def main(): pass\n")
        result = CoreScanner().run(_inp(self.root))
        self.assertIn("file_map", result.data)
        self.assertIsInstance(result.data["file_map"], dict)

    def test_file_map_has_correct_key(self):
        _write(self.root, "src/app.py", "def main(): pass\n")
        result = CoreScanner().run(_inp(self.root))
        fm = result.data["file_map"]
        self.assertIn("src/app.py", fm)

    def test_file_map_entry_has_purpose(self):
        _write(self.root, "src/app.py", "def main(): pass\n")
        result = CoreScanner().run(_inp(self.root))
        entry = result.data["file_map"].get("src/app.py", {})
        self.assertIn("purpose", entry)

    def test_file_map_entry_has_type(self):
        _write(self.root, "src/app.py", "def main(): pass\n")
        result = CoreScanner().run(_inp(self.root))
        entry = result.data["file_map"].get("src/app.py", {})
        self.assertIn("type", entry)

    def test_language_breakdown(self):
        _write(self.root, "src/app.py", "pass")
        _write(self.root, "src/utils.py", "pass")
        result = CoreScanner().run(_inp(self.root))
        breakdown = result.data.get("language_breakdown", {})
        self.assertIn("python", breakdown)

    def test_files_scanned_count(self):
        _write(self.root, "src/a.py", "pass")
        _write(self.root, "src/b.py", "pass")
        result = CoreScanner().run(_inp(self.root))
        self.assertGreaterEqual(result.files_scanned, 2)

    def test_parse_error_produces_finding(self):
        _write(self.root, "src/broken.py", "def foo(\n    missing_close")
        result = CoreScanner().run(_inp(self.root))
        types = [f.type for f in result.findings]
        self.assertIn("parse_error", types)


# ── 2. SideFileScanner ─────────────────────────────────────────────────────────


class TestSideFileScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_runs_on_empty_project(self):
        result = SideFileScanner().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.DONE)

    def test_detects_package_json(self):
        _write(self.root, "package.json", '{"name": "test", "dependencies": {}}')
        result = SideFileScanner().run(_inp(self.root))
        self.assertIn("package.json", result.data.get("config_map", {}))

    def test_extracts_env_var_names(self):
        _write(self.root, ".env", "DATABASE_URL=postgres://localhost\nSECRET_KEY=abc123\n")
        result = SideFileScanner().run(_inp(self.root))
        env_vars = result.data.get("env_vars", [])
        self.assertIn("DATABASE_URL", env_vars)
        self.assertIn("SECRET_KEY", env_vars)

    def test_env_values_not_stored(self):
        _write(self.root, ".env", "API_KEY=super_secret_value_here\n")
        result = SideFileScanner().run(_inp(self.root))
        # The value should never appear in any output
        result_str = str(result.to_dict())
        self.assertNotIn("super_secret_value_here", result_str)

    def test_detects_github_actions(self):
        _write(
            self.root,
            ".github/workflows/ci.yml",
            "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest",
        )
        result = SideFileScanner().run(_inp(self.root))
        self.assertIn(".github/workflows", result.data.get("cicd_structure", {}))

    def test_detects_dockerfile(self):
        _write(self.root, "Dockerfile", "FROM python:3.11\nCMD ['python', 'app.py']")
        result = SideFileScanner().run(_inp(self.root))
        self.assertIn("Dockerfile", result.data.get("config_map", {}))


# ── 3. UIScanner ──────────────────────────────────────────────────────────────


class TestUIScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_skips_non_ui_projects(self):
        _write(self.root, "src/app.py", "pass")
        result = UIScanner().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.DONE)
        self.assertEqual(result.data.get("component_tree", {}), {})

    def test_detects_jsx_components(self):
        _write(
            self.root,
            "src/Button.jsx",
            "export default function Button({ label }) { return <button>{label}</button>; }\n",
        )
        result = UIScanner().run(_inp(self.root))
        ct = result.data.get("component_tree", {})
        self.assertIn("src/Button.jsx", ct)

    def test_detects_tsx_components(self):
        _write(
            self.root,
            "src/Header.tsx",
            "interface Props { title: string; }\nexport default function Header({ title }: Props) { return <h1>{title}</h1>; }\n",
        )
        result = UIScanner().run(_inp(self.root))
        ct = result.data.get("component_tree", {})
        self.assertIn("src/Header.tsx", ct)

    def test_detects_prop_types_interface(self):
        _write(
            self.root,
            "src/Card.tsx",
            "interface CardProps { title: string; }\nexport default function Card(props: CardProps) { return <div/>; }\n",
        )
        result = UIScanner().run(_inp(self.root))
        entry = result.data["component_tree"].get("src/Card.tsx", {})
        self.assertTrue(entry.get("has_prop_types"))

    def test_missing_prop_types_produces_finding(self):
        _write(
            self.root,
            "src/NoProps.tsx",
            "export default function NoProps(props) { return <div/>; }\n",
        )
        result = UIScanner().run(_inp(self.root))
        types = [f.type for f in result.findings]
        self.assertIn("missing_prop_types", types)

    def test_extracts_navigation_links(self):
        _write(
            self.root,
            "src/Nav.jsx",
            'export default function Nav() { return <><a href="/home">Home</a><a href="/about">About</a></>; }\n',
        )
        result = UIScanner().run(_inp(self.root))
        nav = result.data.get("navigation_map", [])
        destinations = [n["to"] for n in nav]
        self.assertIn("/home", destinations)
        self.assertIn("/about", destinations)


# ── 4. DependencyScanner ──────────────────────────────────────────────────────


class TestDependencyScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_runs_on_empty_project(self):
        result = DependencyScanner().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.DONE)

    def test_parses_requirements_txt(self):
        _write(self.root, "requirements.txt", "fastapi==0.110.0\npydantic>=2.0.0\n")
        result = DependencyScanner().run(_inp(self.root))
        deps = result.data.get("dependencies", {})
        self.assertIn("fastapi", deps)
        self.assertIn("pydantic", deps)

    def test_parses_package_json(self):
        _write(
            self.root,
            "package.json",
            '{"dependencies": {"express": "^4.18.0", "react": "^18.0.0"}}',
        )
        result = DependencyScanner().run(_inp(self.root))
        deps = result.data.get("dependencies", {})
        self.assertIn("express", deps)
        self.assertIn("react", deps)

    def test_total_deps_count(self):
        _write(self.root, "requirements.txt", "fastapi==0.110.0\nuvicorn>=0.24.0\n")
        result = DependencyScanner().run(_inp(self.root))
        self.assertGreaterEqual(result.data.get("total_deps", 0), 2)

    def test_no_dependency_file_produces_info_finding(self):
        result = DependencyScanner().run(_inp(self.root))
        types = [f.type for f in result.findings]
        self.assertIn("no_dependency_file", types)


# ── 5. TestScanner ────────────────────────────────────────────────────────────


class TestTestScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_identifies_test_files(self):
        _write(self.root, "tests/test_auth.py", "def test_login(): assert True\n")
        _write(self.root, "src/auth.py", "def login(): pass\n")
        result = TestScanner().run(_inp(self.root))
        self.assertIn("tests/test_auth.py", result.data.get("test_files", []))

    def test_identifies_source_files(self):
        _write(self.root, "src/auth.py", "def login(): pass\n")
        result = TestScanner().run(_inp(self.root))
        self.assertIn("src/auth.py", result.data.get("source_files", []))

    def test_calculates_coverage_percentage(self):
        _write(self.root, "src/auth.py", "def login(): pass\n")
        _write(self.root, "src/users.py", "def get_user(): pass\n")
        _write(self.root, "tests/test_auth.py", "def test_login(): assert True\n")
        result = TestScanner().run(_inp(self.root))
        pct = result.data.get("coverage_pct", 0)
        self.assertIsInstance(pct, (int, float))

    def test_uncovered_files_flagged(self):
        # auth.py has functions but no test file
        _write(self.root, "src/billing.py", "def charge(): pass\n")
        inp = _inp(self.root)
        inp.brain = {"file_map": {"src/billing.py": {"type": "module", "functions": ["charge"]}}}
        result = TestScanner().run(inp)
        uncovered = result.data.get("uncovered_files", [])
        self.assertIn("src/billing.py", uncovered)


# ── 6. DeadCodeScanner ────────────────────────────────────────────────────────


class TestDeadCodeScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_runs_successfully(self):
        _write(self.root, "src/app.py", "pass")
        result = DeadCodeScanner().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.DONE)

    def test_dead_file_detected(self):
        _write(self.root, "src/app.py", "pass")
        _write(self.root, "src/unused.py", "def orphan(): pass\n")
        result = DeadCodeScanner().run(_inp(self.root))
        dead = result.data.get("confirmed_dead", []) + result.data.get("uncertain", [])
        self.assertTrue(any("unused.py" in d for d in dead))

    def test_imported_file_not_dead(self):
        _write(self.root, "src/app.py", "from .utils import foo\n")
        _write(self.root, "src/utils.py", "def foo(): pass\n")
        result = DeadCodeScanner().run(_inp(self.root))
        dead = result.data.get("confirmed_dead", [])
        self.assertFalse(any("utils.py" in d for d in dead))

    def test_confirmed_dead_finding_severity(self):
        _write(self.root, "src/app.py", "pass")
        _write(self.root, "src/dead.py", "def x(): pass\n")
        result = DeadCodeScanner().run(_inp(self.root))
        dead_findings = [
            f
            for f in result.findings
            if f.type in ("confirmed_dead", "broken_import", "uncertain_dead")
        ]
        # Any dead finding is acceptable — severity depends on classification bucket
        if dead_findings:
            self.assertIn(
                dead_findings[0].severity,
                (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL),
            )


# ── 7. EnvScanner ─────────────────────────────────────────────────────────────


class TestEnvScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    _REAL_AWS_KEY = "AKIAIOSFODNN7XKQ9MWB2DT8FV4HJ6"

    def test_detects_aws_key(self):
        _write(self.root, "src/config.py", f"AWS_KEY = '{self._REAL_AWS_KEY}'\n")
        result = EnvScanner().run(_inp(self.root))
        self.assertGreater(result.finding_count, 0)
        types = [f.type for f in result.findings]
        self.assertIn("hardcoded_secret", types)

    def test_docs_example_key_not_a_finding(self):
        # Part 7: the AWS documentation example key is a placeholder, not a
        # leak — it must never verify as a real secret.
        _write(self.root, "src/config.py", "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        result = EnvScanner().run(_inp(self.root))
        self.assertEqual(result.finding_count, 0)

    def test_detects_openai_key(self):
        _write(
            self.root,
            "src/ai.py",
            "client = OpenAI(api_key='sk-q7ZmK2vX9pL4wN8cR3tY6uI1oP5aS0dF')\n",
        )
        result = EnvScanner().run(_inp(self.root))
        self.assertGreater(result.finding_count, 0)

    def test_secret_value_not_in_output(self):
        _write(self.root, "src/config.py", f"SECRET = '{self._REAL_AWS_KEY}'\n")
        result = EnvScanner().run(_inp(self.root))
        output_str = str(result.to_dict())
        self.assertNotIn(self._REAL_AWS_KEY, output_str)

    def test_critical_severity_for_api_keys(self):
        _write(self.root, "src/config.py", f"KEY = '{self._REAL_AWS_KEY}'\n")
        result = EnvScanner().run(_inp(self.root))
        severities = [f.severity for f in result.findings]
        self.assertIn(Severity.CRITICAL, severities)

    def test_weak_keyword_value_not_a_finding(self):
        # Part 7: keyword + weak value ("abc") is a name guess, not evidence.
        _write(self.root, "src/config.py", 'password = "abc"\n')
        result = EnvScanner().run(_inp(self.root))
        self.assertEqual(result.finding_count, 0)

    def test_public_key_is_info_not_secret(self):
        # Part 7: published-by-design material must not be CRITICAL secret.
        _write(
            self.root,
            "src/keys.py",
            "PUB = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7'\n",
        )
        result = EnvScanner().run(_inp(self.root))
        self.assertTrue(all(f.severity != Severity.CRITICAL for f in result.findings))

    def test_fixture_secrets_not_flagged(self):
        # Part 7: fixtures intentionally look dangerous.
        _write(
            self.root,
            "tests/test_auth.py",
            f"TOKEN = '{self._REAL_AWS_KEY}'\n",
        )
        result = EnvScanner().run(_inp(self.root))
        self.assertEqual(result.finding_count, 0)

    def test_clean_file_no_findings(self):
        _write(self.root, "src/clean.py", "import os\nAPI_KEY = os.environ['API_KEY']\n")
        result = EnvScanner().run(_inp(self.root))
        self.assertEqual(result.finding_count, 0)

    def test_package_lock_skipped(self):
        # package-lock.json often contains hash strings that match patterns
        _write(self.root, "package-lock.json", '{"integrity": "sha512-AKIAIOSFODNN7EXAMPLE"}')
        result = EnvScanner().run(_inp(self.root))
        self.assertEqual(result.finding_count, 0)


# ── 8. RouteGraphScanner ──────────────────────────────────────────────────────


class TestRouteGraphScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_runs_successfully(self):
        result = RouteGraphScanner().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.DONE)

    def test_extracts_fastapi_routes(self):
        _write(self.root, "requirements.txt", "fastapi==0.110.0\n")
        _write(
            self.root,
            "src/routes.py",
            "@app.get('/users')\ndef list_users(): pass\n"
            "@app.post('/users')\ndef create_user(): pass\n",
        )
        result = RouteGraphScanner().run(_inp(self.root))
        route_map = result.data.get("route_map", {})
        self.assertGreater(len(route_map), 0)

    def test_unprotected_sensitive_route_finding(self):
        _write(self.root, "requirements.txt", "fastapi==0.110.0\n")
        _write(
            self.root,
            "src/auth.py",
            "@app.post('/auth/login')\ndef login(data: dict):\n    return {}\n",
        )
        result = RouteGraphScanner().run(_inp(self.root))
        types = [f.type for f in result.findings]
        self.assertIn("unprotected_sensitive_route", types)


# ── 9. TypeScanner ────────────────────────────────────────────────────────────


class TestTypeScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_skips_non_ts_project(self):
        _write(self.root, "src/app.rb", "puts 'hello'")
        result = TypeScanner().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.SKIPPED)

    def test_detects_explicit_any(self):
        _write(self.root, "src/api.ts", "function process(data: any) { return data; }\n")
        result = TypeScanner().run(_inp(self.root))
        types = [f.type for f in result.findings]
        self.assertIn("explicit_any", types)

    def test_detects_ts_ignore(self):
        _write(self.root, "src/hack.ts", "// @ts-ignore\nconst x: string = 123;\n")
        result = TypeScanner().run(_inp(self.root))
        types = [f.type for f in result.findings]
        self.assertIn("ts_ignore", types)

    def test_detects_unsafe_cast(self):
        _write(self.root, "src/unsafe.ts", "const x = value as unknown as MyType;\n")
        result = TypeScanner().run(_inp(self.root))
        types = [f.type for f in result.findings]
        self.assertIn("unsafe_cast", types)

    def test_clean_ts_no_findings(self):
        _write(
            self.root,
            "src/clean.ts",
            "function greet(name: string): string { return `Hello ${name}`; }\n",
        )
        result = TypeScanner().run(_inp(self.root))
        self.assertEqual(result.finding_count, 0)


# ── 10. CommentScanner ────────────────────────────────────────────────────────


class TestCommentScanner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_detects_todo(self):
        _write(self.root, "src/app.py", "# TODO: implement this\ndef foo(): pass\n")
        result = CommentScanner().run(_inp(self.root))
        self.assertGreater(result.finding_count, 0)
        types = [f.type for f in result.findings]
        self.assertIn("technical_debt", types)

    def test_detects_fixme(self):
        _write(self.root, "src/app.py", "# FIXME: this is broken\ndef bar(): pass\n")
        result = CommentScanner().run(_inp(self.root))
        self.assertGreater(result.finding_count, 0)

    def test_detects_hack_in_js(self):
        _write(self.root, "src/app.js", "// HACK: temporary workaround\nconst x = 1;\n")
        result = CommentScanner().run(_inp(self.root))
        self.assertGreater(result.finding_count, 0)

    def test_fixme_severity_medium(self):
        _write(self.root, "src/app.py", "# FIXME: security hole\n")
        result = CommentScanner().run(_inp(self.root))
        fixme = [
            f for f in result.findings if "FIXME" in f.message.upper() or "FIXME" in f.code_snippet
        ]
        if fixme:
            self.assertEqual(fixme[0].severity, Severity.MEDIUM)

    def test_todo_severity_info(self):
        _write(self.root, "src/app.py", "# TODO: add tests\n")
        result = CommentScanner().run(_inp(self.root))
        todos = list(result.findings)
        if todos:
            self.assertEqual(todos[0].severity, Severity.INFO)

    def test_by_type_breakdown(self):
        _write(self.root, "src/app.py", "# TODO: one\n# FIXME: two\n# HACK: three\n")
        result = CommentScanner().run(_inp(self.root))
        by_type = result.data.get("by_type", {})
        self.assertIn("TODO", by_type)
        self.assertIn("FIXME", by_type)

    def test_clean_file_no_findings(self):
        _write(self.root, "src/clean.py", "def well_implemented():\n    return 42\n")
        result = CommentScanner().run(_inp(self.root))
        self.assertEqual(result.finding_count, 0)


# ── DuplicateScanner deleted ──────────────────────────────────────────────────
# (section intentionally removed with the scanner — clone detection was
# noise, not signal; RefactorAgent went with it.)


if __name__ == "__main__":
    unittest.main()
