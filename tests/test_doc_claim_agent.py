"""Tests for patchi.core.agents.doc_claim_agent (DocClaimAgent / LLM doc miner)."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _clear_offline_flag():
    """DocClaimAgent._run short-circuits in offline mode.

    ci-audit.sh exports PATCHI_OFFLINE=1 for the whole suite, but these tests
    exercise the LLM mining path with call_ai mocked — the agent's offline
    early-return would skip the code under test. Tests are hermetic via mocking.
    """
    old = os.environ.pop("PATCHI_OFFLINE", None)
    yield
    if old is not None:
        os.environ["PATCHI_OFFLINE"] = old


class TestClaimDataclass(unittest.TestCase):
    """Test the Claim dataclass."""

    def test_minimal_claim_defaults(self):
        from patchi.core.agents.doc_claim_agent import Claim
        c = Claim(text="supports JWT", source_file="README.md", category="feature",
                  evidence_hints=["function: verify_jwt"])
        self.assertEqual(c.text, "supports JWT")
        self.assertEqual(c.source_file, "README.md")
        self.assertEqual(c.category, "feature")
        self.assertEqual(c.evidence_hints, ["function: verify_jwt"])
        self.assertFalse(c.verified)
        self.assertEqual(c.evidence, [])

    def test_claim_with_all_fields(self):
        from patchi.core.agents.doc_claim_agent import Claim
        c = Claim(
            text="POST /api/v1/users",
            source_file="api.md",
            category="api_endpoint",
            evidence_hints=["route: POST /api/v1/users"],
            verified=True,
            evidence=["matched_route: POST /api/v1/users"],
        )
        self.assertTrue(c.verified)
        self.assertEqual(c.evidence, ["matched_route: POST /api/v1/users"])


class TestDiscoverDocs(unittest.TestCase):
    """Test DocClaimAgent._discover_docs."""

    def setUp(self):
        from patchi.core.agents.doc_claim_agent import DocClaimAgent
        self.agent = DocClaimAgent()

    def test_discover_readme(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Hello")
            files = self.agent._discover_docs(root)
            self.assertEqual(len(files), 1)
            self.assertIn("README.md", files[0].name)

    def test_discover_multiple_doc_files(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Hello")
            (root / "CHANGELOG.md").write_text("# v1.0")
            docs_dir = root / "docs"
            docs_dir.mkdir()
            (docs_dir / "guide.rst").write_text("Guide")
            files = self.agent._discover_docs(root)
            self.assertEqual(len(files), 3)

    def test_skip_excluded_dirs(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_modules = root / "node_modules" / "pkg" / "README.md"
            node_modules.parent.mkdir(parents=True)
            node_modules.write_text("dummy")
            files = self.agent._discover_docs(root)
            self.assertEqual(len(files), 0)

    def test_skip_binary_files(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "image.png").write_text("PNG")
            docs_dir = root / "docs"
            docs_dir.mkdir()
            (docs_dir / "README.md").write_text("# Docs")
            files = self.agent._discover_docs(root)
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].name, "README.md")

    def test_discover_no_duplicates(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# A")
            (root / "README.md").write_text("# B")  # same file
            files = self.agent._discover_docs(root)
            self.assertEqual(len(files), 1)

    def test_discover_empty_project(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = self.agent._discover_docs(root)
            self.assertEqual(files, [])

    def test_discover_docs_in_subdir(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "documentation" / "api.md").parent.mkdir(parents=True)
            (root / "documentation" / "api.md").write_text("# API")
            files = self.agent._discover_docs(root)
            self.assertEqual(len(files), 1)

    def test_excluded_dirs_includes_dot_idea(self):
        from patchi.core.agents.doc_claim_agent import _EXCLUDED_DIRS
        self.assertIn(".idea", _EXCLUDED_DIRS)
        self.assertIn("node_modules", _EXCLUDED_DIRS)


class TestParseClaims(unittest.TestCase):
    """Test DocClaimAgent._parse_claims."""

    def setUp(self):
        from patchi.core.agents.doc_claim_agent import DocClaimAgent
        self.agent = DocClaimAgent()

    def _parse(self, response: str):
        return self.agent._parse_claims(response, Path("test.md"))

    def test_parse_valid_json(self):
        claims = self._parse('[{"claim": "supports JWT", "category": "feature", "evidence_hints": []}]')
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["claim"], "supports JWT")

    def test_parse_strips_code_fence(self):
        claims = self._parse('```\n[{"claim": "uses Redis", "category": "dependency", "evidence_hints": []}]\n```')
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["claim"], "uses Redis")

    def test_parse_json_embedded_in_text(self):
        claims = self._parse(
            'Some text before\n[{"claim": "CLI tool", "category": "feature", "evidence_hints": []}]'
            "\ntext after"
        )
        self.assertEqual(len(claims), 1)

    def test_parse_empty_array(self):
        claims = self._parse("[]")
        self.assertEqual(claims, [])

    def test_parse_invalid_json(self):
        claims = self._parse("not json at all")
        self.assertEqual(claims, [])

    def test_parse_missing_keys_skipped(self):
        claims = self._parse('[{"claim": "only claim", "category": "feature", "evidence_hints": []}, {"foo": "bar"}]')
        self.assertEqual(len(claims), 1)

    def test_parse_non_array_response(self):
        claims = self._parse('{"claim": "not an array"}')
        self.assertEqual(claims, [])

    def test_parse_hints_defaults_to_empty_list(self):
        claims = self._parse('[{"claim": "no hints", "category": "feature"}]')
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["evidence_hints"], [])

    def test_parse_code_fence_with_lang(self):
        claims = self._parse('```json\n[{"claim": "uses JWT", "category": "security", "evidence_hints": []}]\n```')
        self.assertEqual(len(claims), 1)

    def test_parse_multiple_claims(self):
        claims = self._parse("""[
            {"claim": "first", "category": "feature", "evidence_hints": []},
            {"claim": "second", "category": "cli_command", "evidence_hints": []}
        ]""")
        self.assertEqual(len(claims), 2)


class TestExtractClaims(unittest.TestCase):
    """Test DocClaimAgent._extract_claims with mocked call_ai."""

    def setUp(self):
        from patchi.core.agents.base import AgentResult
        from patchi.core.agents.doc_claim_agent import DocClaimAgent
        self.agent = DocClaimAgent()
        self.result = AgentResult(agent_name="DocClaimAgent", agent_group="SCANNER")
        self.config = {"ai": {"keys": {"openai": "sk-test"}}}
        self.doc = Path("README.md")

    @patch("patchi.core.ai.client.call_ai")
    def test_extract_success(self, mock_call_ai):
        mock_call_ai.return_value = '[{"claim": "test", "category": "feature", "evidence_hints": []}]'
        claims = self.agent._extract_claims("Some doc text", self.doc, self.result, self.config, self.config["ai"])
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["claim"], "test")

    @patch("patchi.core.ai.client.call_ai")
    def test_extract_empty_response(self, mock_call_ai):
        mock_call_ai.return_value = None
        claims = self.agent._extract_claims("text", self.doc, self.result, self.config, self.config["ai"])
        self.assertEqual(claims, [])

    @patch("patchi.core.ai.client.call_ai")
    def test_extract_llm_error(self, mock_call_ai):
        mock_call_ai.side_effect = RuntimeError("API down")
        claims = self.agent._extract_claims("text", self.doc, self.result, self.config, self.config["ai"])
        self.assertEqual(claims, [])
        self.assertTrue(any("LLM error" in e for e in self.result.errors))

    @patch("patchi.core.ai.client.call_ai")
    def test_extract_truncates_large_doc(self, mock_call_ai):
        mock_call_ai.return_value = "[]"
        large_text = "x" * 20000
        self.agent._extract_claims(large_text, self.doc, self.result, self.config, self.config["ai"])
        passed_text = mock_call_ai.call_args[1]["user_prompt"]
        self.assertLess(len(passed_text), 17000)


class TestAgentRun(unittest.TestCase):
    """Test DocClaimAgent._run with mocked AI layer."""

    def setUp(self):
        from patchi.core.agents.doc_claim_agent import DocClaimAgent
        self.agent = DocClaimAgent()

    def test_no_ai_config_returns_no_claims(self):
        from patchi.core.agents.base import AgentInput, AgentResult
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Hello")
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = AgentResult(agent_name="DocClaimAgent", agent_group="SCANNER")
            self.agent._run(inp, result)
            self.assertEqual(result.data["claims"], [])
            self.assertTrue(result.data.get("ai_unavailable"))

    def test_no_doc_files(self):
        from patchi.core.agents.base import AgentInput, AgentResult
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = AgentResult(agent_name="DocClaimAgent", agent_group="SCANNER")
            self.agent._run(inp, result)
            self.assertEqual(result.data["claims"], [])
            self.assertEqual(result.data["doc_files_found"], [])

    @patch("patchi.core.ai.client.call_ai")
    def test_run_with_ai_and_docs(self, mock_call_ai):
        from patchi.core.agents.base import AgentInput, AgentResult
        mock_call_ai.return_value = '[{"claim": "test", "category": "feature", "evidence_hints": []}]'
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Hello\n\nThis is a test README with enough content.")
            inp = AgentInput(root=root, scope=[], brain={},
                             config={"ai": {"keys": {"openai": "sk-test"}}})
            result = AgentResult(agent_name="DocClaimAgent", agent_group="SCANNER")
            self.agent._run(inp, result)
            self.assertEqual(len(result.data["claims"]), 1)
            self.assertEqual(result.data["total_claims"], 1)

    @patch("patchi.core.ai.client.call_ai")
    def test_run_source_file_relative_path(self, mock_call_ai):
        from patchi.core.agents.base import AgentInput, AgentResult
        mock_call_ai.return_value = '[{"claim": "test", "category": "feature", "evidence_hints": []}]'
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sub = root / "docs" / "guide.md"
            sub.parent.mkdir()
            sub.write_text("# Guide\n\nThis guide has enough text to pass the length check.")
            inp = AgentInput(root=root, scope=[], brain={},
                             config={"ai": {"keys": {"openai": "sk-test"}}})
            result = AgentResult(agent_name="DocClaimAgent", agent_group="SCANNER")
            self.agent._run(inp, result)
            self.assertEqual(result.data["claims"][0]["source_file"].replace("\\", "/"), "docs/guide.md")

    @patch("patchi.core.ai.client.call_ai")
    def test_run_parallel_multiple_docs(self, mock_call_ai):
        from patchi.core.agents.base import AgentInput, AgentResult
        mock_call_ai.return_value = '[{"claim": "parallel test", "category": "feature", "evidence_hints": []}]'
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Readme\n\nSome content here.")
            (root / "CHANGELOG.md").write_text("# v1.0\n\nChanges here.")
            docs_dir = root / "docs"
            docs_dir.mkdir()
            (docs_dir / "api.md").write_text("# API\n\nEndpoint docs.")
            inp = AgentInput(root=root, scope=[], brain={},
                             config={"ai": {"keys": {"openai": "sk-test"}}})
            result = AgentResult(agent_name="DocClaimAgent", agent_group="SCANNER")
            self.agent._run(inp, result)
            self.assertEqual(result.data["total_claims"], 3)
            self.assertEqual(len(result.data["doc_files_found"]), 3)


class TestVerifyClaimsAgainstCode(unittest.TestCase):
    """Test verify_claims_against_code helper."""

    def setUp(self):
        from patchi.core.brain.languages import Lang
        from patchi.core.brain.scanner import ClassInfo, FileInfo, FunctionInfo, ImportInfo
        self.file_info = FileInfo(
            path="src/app.py",
            language=Lang.PYTHON,
            size_bytes=100,
            lines=10,
            functions=[FunctionInfo(name="verify_jwt", line=5), FunctionInfo(name="login", line=20)],
            classes=[ClassInfo(name="JwtMiddleware", line=1)],
            imports=[ImportInfo(source="redis", names=["RedisClient"], is_relative=False, line=1),
                     ImportInfo(source="flask", names=["Flask"], is_relative=False, line=2)],
        )

    def _make_route(self, method="GET", path="/api/users"):
        from patchi.core.brain.route_mapper import RouteInfo
        return RouteInfo(method=method, path=path, handler="test", file="routes.py", line=1)

    def test_route_matching(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        claims = [
            {"claim": "API endpoint", "category": "api_endpoint", "evidence_hints": ["route: GET /api/users"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [self._make_route()])
        self.assertTrue(result[0]["verified"])
        self.assertIn("matched_route:route: GET /api/users", result[0]["evidence"])

    def test_function_matching(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        claims = [
            {"claim": "JWT support", "category": "feature", "evidence_hints": ["function: verify_jwt"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [])
        self.assertTrue(result[0]["verified"])

    def test_class_matching(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        claims = [
            {"claim": "JWT middleware", "category": "architecture", "evidence_hints": ["class: JwtMiddleware"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [])
        self.assertTrue(result[0]["verified"])

    def test_import_matching(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        claims = [
            {"claim": "uses Redis", "category": "dependency", "evidence_hints": ["import: redis"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [])
        self.assertTrue(result[0]["verified"])

    def test_no_match_returns_not_verified(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        claims = [
            {"claim": "uses MongoDB", "category": "dependency", "evidence_hints": ["import: mongodb"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [])
        self.assertFalse(result[0]["verified"])

    def test_empty_claims_returns_empty(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        result = verify_claims_against_code([], [self.file_info], [])
        self.assertEqual(result, [])

    def test_cli_flag_matching(self):
        from argparse import ArgumentParser

        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        parser = ArgumentParser()
        parser.add_argument("--deep")
        config = {"_cli_parser": parser}
        claims = [
            {"claim": "deep scan", "category": "cli_command", "evidence_hints": ["cli: --deep"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [], config=config)
        self.assertTrue(result[0]["verified"])

    def test_case_insensitive_matching(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        claims = [
            {"claim": "JWT support", "category": "feature", "evidence_hints": ["function: VERIFY_JWT"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [])
        self.assertTrue(result[0]["verified"])

    def test_file_match_hint(self):
        # Part 7: a single filename-substring hit is weak — not proof alone.
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        claims = [
            {"claim": "app code", "category": "feature", "evidence_hints": ["file_match: src/app"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [])
        self.assertFalse(result[0]["verified"])
        self.assertEqual(result[0]["verify_strength"], "weak")

    def test_two_weak_hits_corroborate(self):
        # Two independent weak hits verify; one does not.
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        claims = [
            {
                "claim": "app code",
                "category": "feature",
                "evidence_hints": ["file_match: src/app", "package: app"],
            },
        ]
        result = verify_claims_against_code(claims, [self.file_info], [])
        self.assertTrue(result[0]["verified"])
        self.assertEqual(result[0]["verify_strength"], "weak")

    def test_fallback_general_keyword(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        claims = [
            {"claim": "uses verify_jwt", "category": "feature", "evidence_hints": ["verify_jwt"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [])
        self.assertTrue(result[0]["verified"])

    def test_symbol_graph_matching(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        class FakeSymbol:
            name = "JWT_SECRET"
            qualified_name = "app.JWT_SECRET"
        class FakeGraph:
            def get_all_symbols(self):
                return [FakeSymbol()]
        claims = [
            {"claim": "secret key", "category": "security", "evidence_hints": ["symbol: JWT_SECRET"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [], symbol_graph=FakeGraph())
        self.assertTrue(result[0]["verified"])

    def test_import_graph_matching(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        class FakeNode:
            def lower(self):
                return "redis"
        class FakeImportGraph:
            graph = type("obj", (object,), {"nodes": {"src/cache.py": FakeNode()}})()
        claims = [
            {"claim": "uses Redis", "category": "dependency", "evidence_hints": ["import: redis"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [], import_graph=FakeImportGraph())
        self.assertTrue(result[0]["verified"])

    def test_dependency_hint_with_import_graph(self):
        from patchi.core.agents.doc_claim_agent import verify_claims_against_code
        class FakeNode:
            def lower(self):
                return "redis"
        class FakeImportGraph:
            graph = type("obj", (object,), {"nodes": {"src/cache.py": FakeNode()}})()
        claims = [
            {"claim": "caches with Redis", "category": "dependency", "evidence_hints": ["dependency: redis"]},
        ]
        result = verify_claims_against_code(claims, [self.file_info], [], import_graph=FakeImportGraph())
        self.assertTrue(result[0]["verified"])


if __name__ == "__main__":
    unittest.main()
