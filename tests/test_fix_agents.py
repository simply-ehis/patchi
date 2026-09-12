"""
Unit tests for patchi.core.fix.fix_agents

We test agent registration, structure, and behavior without AI calls.
AI calls are mocked or bypassed since no key is available in CI.
"""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch as mock_patch

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.agents.base import AgentGroup, AgentInput, AgentStatus, list_agents
from patchi.core.fix import CodeFixer, DeadCodeRemover
from patchi.core.fix.fix_agents import (
    EnvFixer,
    UnitTestRunner,
    _extract_code_block,
)
from patchi.core.fix.patch import PatchType


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    brain = mem.get_brain(tmp)
    brain["contract_locked"] = True
    mem.save_brain(brain, tmp)
    return tmp


def _write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _inp(root: Path, findings: list | None = None, extra: dict | None = None) -> AgentInput:
    return AgentInput(
        root=root,
        scope=[],
        brain=mem.get_brain(root),
        config=cfg.load(root),
        extra={**(extra or {}), "findings": findings or []},
    )


class TestFixAgentRegistration(unittest.TestCase):
    def test_all_7_fix_agents_registered(self):
        fix_agents = list_agents(AgentGroup.FIX)
        names = {a.name for a in fix_agents}
        expected = {
            "CodeFixer",
            "SecurityFixer",
            "DeadCodeRemover",
            "DependencyFixer",
            "EnvFixer",
            "TypeFixer",
            "UnitTestRunner",
        }
        self.assertEqual(names, expected)

    def test_all_fix_agents_in_fix_group(self):
        import patchi.core.fix.fix_agents  # noqa

        for cls in list_agents(AgentGroup.FIX):
            self.assertEqual(cls.group, AgentGroup.FIX)

    def test_all_fix_agents_have_timeout(self):
        import patchi.core.fix.fix_agents  # noqa

        for cls in list_agents(AgentGroup.FIX):
            self.assertGreater(cls.timeout, 0)


class TestExtractCodeBlock(unittest.TestCase):
    def test_extracts_fenced_block(self):
        text = "Here is the fix:\n```python\ndef foo():\n    return 1\n```"
        result = _extract_code_block(text)
        self.assertIn("def foo", result)

    def test_returns_full_text_if_no_fence(self):
        text = "def foo():\n    return 1"
        result = _extract_code_block(text)
        self.assertIn("def foo", result)

    def test_first_block_only(self):
        text = "```\nblock1\n```\n```\nblock2\n```"
        result = _extract_code_block(text)
        self.assertIn("block1", result)
        self.assertNotIn("block2", result)


class TestCodeFixer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_runs_without_ai_when_no_findings(self):
        result = CodeFixer().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.DONE)
        self.assertEqual(result.data.get("patch_count", 0), 0)

    def test_produces_patch_when_ai_returns_fix(self):
        _write(self.root, "src/app.py", "def foo():\n    pass\n")
        findings = [
            {
                "type": "parse_error",
                "fix_agent": "CodeFixer",
                "file": "src/app.py",
                "line": 1,
                "message": "Missing return statement",
                "suggestion": "Add return 1",
            }
        ]
        # Mock AI to return a valid fix
        with mock_patch(
            "patchi.core.fix.code_fixer._call_ai",
            return_value="```python\ndef foo():\n    return 1\n```",
        ):
            result = CodeFixer().run(_inp(self.root, findings))

        patches = result.data.get("patches", [])
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]["agent"], "CodeFixer")

    def test_skips_when_ai_returns_identical_content(self):
        _write(self.root, "src/app.py", "def foo():\n    pass\n")
        findings = [
            {
                "type": "parse_error",
                "fix_agent": "CodeFixer",
                "file": "src/app.py",
                "line": 1,
                "message": "Issue",
                "suggestion": "Fix it",
            }
        ]
        # AI returns same content — no patch produced
        with mock_patch(
            "patchi.core.fix.code_fixer._call_ai", return_value="```\ndef foo():\n    pass\n```"
        ):
            result = CodeFixer().run(_inp(self.root, findings))

        self.assertEqual(result.data.get("patch_count", 0), 0)

    def test_test_failure_targets_crash_site_not_test_file(self):
        _write(self.root, "src/math.py", "def add(a, b):\n    return a - b\n")
        _write(self.root, "tests/test_math.py", "def test_add():\n    assert add(1, 2) == 3\n")
        findings = [
            {
                "type": "test_failure",
                "fix_agent": "CodeFixer",
                "file": "tests/test_math.py",
                "line": 2,
                "message": "Test failed: test_add",
                "detail": "AssertionError: assert 1 == 3",
            }
        ]
        dbg = {
            "exception": {"type": "AssertionError", "message": "assert 1 == 3"},
            "trigger_frame": 1,
            "frames": [
                {"name": "test_add", "path": "tests/test_math.py", "line": 2},
                {"name": "add", "path": "src/math.py", "line": 2},
            ],
        }
        with mock_patch(
            "patchi.core.fix.code_fixer._call_ai",
            return_value="```python\ndef add(a, b):\n    return a + b\n```",
        ), mock_patch(
            "patchi.core.fix.code_fixer._read_file",
            return_value="def add(a, b):\n    return a - b\n",
        ), mock_patch(
            "patchi.core.fix.code_fixer._detect_language",
            return_value="python",
        ), mock_patch(
            "patchi.core.fix.code_fixer.compute_blast_radius",
            return_value=0,
        ), mock_patch(
            "patchi.core.fix.code_fixer.debug_context_from_finding",
            return_value=dbg,
        ):
            result = CodeFixer().run(_inp(self.root, findings))

        patches = result.data.get("patches", [])
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]["changes"][0]["path"], "src/math.py")

    def test_test_failure_falls_back_to_test_file_when_no_debug(self):
        _write(self.root, "tests/test_math.py", "def test_add():\n    assert False\n")
        findings = [
            {
                "type": "test_failure",
                "fix_agent": "CodeFixer",
                "file": "tests/test_math.py",
                "line": 2,
                "message": "Test failed: test_add",
                "detail": "AssertionError",
            }
        ]
        with mock_patch(
            "patchi.core.fix.code_fixer._call_ai",
            return_value="```python\ndef test_add():\n    assert True\n```",
        ), mock_patch(
            "patchi.core.fix.code_fixer._read_file",
            return_value="def test_add():\n    assert False\n",
        ), mock_patch(
            "patchi.core.fix.code_fixer._detect_language",
            return_value="python",
        ), mock_patch(
            "patchi.core.fix.code_fixer.compute_blast_radius",
            return_value=0,
        ), mock_patch(
            "patchi.core.fix.code_fixer.debug_context_from_finding",
            return_value=None,
        ):
            result = CodeFixer().run(_inp(self.root, findings))

        patches = result.data.get("patches", [])
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]["changes"][0]["path"], "tests/test_math.py")


class TestDeadCodeRemover(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_old(self, root: Path, rel: str, content: str) -> Path:
        """Write a file that looks older than the 7-day age safety check."""
        p = _write(root, rel, content)
        old = time.time() - 40 * 86400
        os.utime(p, (old, old))
        return p

    def test_proposes_deletion_for_confirmed_dead(self):
        self._write_old(self.root, "src/unused.py", "def orphan(): pass\n")
        findings = [
            {
                "type": "confirmed_dead",
                "fix_agent": "DeadCodeRemover",
                "file": "src/unused.py",
                "message": "Nothing imports this file.",
            }
        ]
        result = DeadCodeRemover().run(_inp(self.root, findings))
        patches = result.data.get("patches", [])
        self.assertEqual(len(patches), 1)
        # Proposed is empty (deletion)
        self.assertEqual(patches[0]["changes"][0].get("lines_added", 0), 0)

    def test_patch_type_is_dead_code(self):
        self._write_old(self.root, "src/unused.py", "def orphan(): pass\n")
        findings = [
            {
                "type": "confirmed_dead",
                "fix_agent": "DeadCodeRemover",
                "file": "src/unused.py",
                "message": "Nothing imports this file.",
            }
        ]
        result = DeadCodeRemover().run(_inp(self.root, findings))
        patches = result.data.get("patches", [])
        if patches:
            self.assertEqual(patches[0]["patch_type"], PatchType.DEAD_CODE.value)


class TestEnvFixer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_generates_env_example_when_missing(self):
        findings: list = []
        extra = {"env_vars": ["DATABASE_URL", "SECRET_KEY", "API_KEY"]}
        result = EnvFixer().run(_inp(self.root, findings, extra))
        patches = result.data.get("patches", [])
        [p for p in patches if ".env.example" in str(p.get("changes", []))]
        self.assertGreater(len(patches), 0)

    def test_env_example_not_generated_if_exists(self):
        _write(self.root, ".env.example", "DATABASE_URL=\n")
        extra = {"env_vars": ["DATABASE_URL"]}
        result = EnvFixer().run(_inp(self.root, [], extra))
        env_patches = [p for p in result.data.get("patches", []) if ".env.example" in str(p)]
        self.assertEqual(len(env_patches), 0)

    def test_patches_hardcoded_secrets(self):
        _write(self.root, "src/config.py", "import os\nAPI_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        findings = [
            {
                "type": "hardcoded_secret",
                "fix_agent": "EnvFixer",
                "file": "src/config.py",
                "line": 2,
                "pattern_type": "aws_access_key",
                "code_snippet": "API_KEY = '[REDACTED]'",
            }
        ]
        with mock_patch(
            "patchi.core.fix.fix_agents.call_ai",
            return_value="```python\nimport os\nAPI_KEY = os.environ.get('API_KEY')\n```",
        ):
            result = EnvFixer().run(_inp(self.root, findings))
        secret_patches = [
            p for p in result.data.get("patches", []) if p.get("patch_type") == "env_fix"
        ]
        self.assertGreater(len(secret_patches), 0)


class TestUnitTestRunner(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_generates_test_file(self):
        _write(
            self.root,
            "src/utils.py",
            "def add(a, b):\n    return a + b\n\ndef subtract(a, b):\n    return a - b\n",
        )
        findings = [
            {
                "type": "uncovered_file",
                "fix_agent": "UnitTestRunner",
                "file": "src/utils.py",
                "message": "No test file covers utils.py",
            }
        ]
        with mock_patch(
            "patchi.core.fix.fix_agents.call_ai",
            return_value="```python\ndef test_add():\n    assert add(1,2) == 3\n```",
        ):
            result = UnitTestRunner().run(_inp(self.root, findings))

        patches = result.data.get("patches", [])
        self.assertEqual(len(patches), 1)
        test_path = patches[0]["changes"][0]["path"]
        self.assertIn("test_", test_path)

    def test_skips_when_test_already_exists(self):
        _write(self.root, "src/utils.py", "def foo(): pass\n")
        # _test_path mirrors the source dir structure: src/utils.py -> tests/src/test_utils.py
        _write(self.root, "tests/src/test_utils.py", "def test_foo(): pass\n")
        findings = [
            {
                "type": "uncovered_file",
                "fix_agent": "UnitTestRunner",
                "file": "src/utils.py",
                "message": "No test file covers utils.py",
            }
        ]
        result = UnitTestRunner().run(_inp(self.root, findings))
        # Should not produce a patch since test already exists
        patches = result.data.get("patches", [])
        self.assertEqual(len(patches), 0)

    def test_test_path_python(self):
        agent = UnitTestRunner()
        path = agent._test_path("src/utils.py", "python")
        self.assertIn("test_utils", path)
        self.assertTrue(path.endswith(".py"))

    def test_test_path_js(self):
        agent = UnitTestRunner()
        path = agent._test_path("src/utils.js", "javascript")
        self.assertIn("utils", path)
        self.assertIn(".test.", path)


if __name__ == "__main__":
    unittest.main()
