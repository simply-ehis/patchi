"""Tests for patchi.core.agents.attack_agent (AttackAgent / Metasploit bridge)."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestAttackAgentHelpers(unittest.TestCase):
    """Test helper functions in attack_agent.py without pymetasploit3."""

    def test_get_frameworks_from_string(self):
        from patchi.core.agents.attack_agent import _get_frameworks
        brain = {"framework": "Flask"}
        result = _get_frameworks(brain)
        self.assertIn("flask", result)

    def test_get_frameworks_from_list(self):
        from patchi.core.agents.attack_agent import _get_frameworks
        brain = {"frameworks": [{"name": "Django"}, {"name": "React"}]}
        result = _get_frameworks(brain)
        self.assertIn("django", result)
        self.assertIn("react", result)

    def test_get_frameworks_unknown(self):
        from patchi.core.agents.attack_agent import _get_frameworks
        brain = {"framework": "Unknown"}
        result = _get_frameworks(brain)
        self.assertEqual(result, [])

    def test_get_frameworks_empty(self):
        from patchi.core.agents.attack_agent import _get_frameworks
        result = _get_frameworks({})
        self.assertEqual(result, [])

    def test_pick_port_from_config(self):
        from patchi.core.agents.attack_agent import _pick_port
        brain = {"config": {"port": 3000}}
        result = _pick_port(brain, [])
        self.assertEqual(result, 3000)

    def test_pick_port_default(self):
        from patchi.core.agents.attack_agent import _pick_port
        result = _pick_port({}, [])
        self.assertEqual(result, 8000)

    def test_pick_modules_by_framework(self):
        from patchi.core.agents.attack_agent import _pick_modules
        result = _pick_modules(["flask"])
        self.assertIn("scanner/http/http_header_xss", result)
        self.assertNotIn("scanner/http/http_methods", [])

    def test_pick_modules_multiple_frameworks(self):
        from patchi.core.agents.attack_agent import _pick_modules
        result = _pick_modules(["flask", "django"])
        self.assertGreater(len(result), 0)

    def test_pick_modules_fallback(self):
        from patchi.core.agents.attack_agent import _pick_modules
        result = _pick_modules(["unknown_framework"])
        self.assertEqual(result, [
            "scanner/http/http_header_xss",
            "scanner/http/http_version",
            "scanner/http/options",
        ])

    def test_pick_modules_no_duplicates(self):
        from patchi.core.agents.attack_agent import _pick_modules
        result = _pick_modules(["flask", "django"])
        self.assertEqual(len(result), len(set(result)))

    def test_classify_severity_job_id_is_info(self):
        from patchi.core.agents.attack_agent import _classify_severity
        from patchi.core.agents.base import Severity
        self.assertEqual(_classify_severity("x", {"job_id": 123}), Severity.INFO)

    def test_classify_severity_vuln_keywords_medium(self):
        from patchi.core.agents.attack_agent import _classify_severity
        from patchi.core.agents.base import Severity
        self.assertEqual(_classify_severity("x", {"data": "vulnerable found"}), Severity.MEDIUM)

    def test_classify_severity_error_low(self):
        from patchi.core.agents.attack_agent import _classify_severity
        from patchi.core.agents.base import Severity
        self.assertEqual(_classify_severity("x", {"error": "timeout"}), Severity.LOW)

    def test_classify_severity_default_info(self):
        from patchi.core.agents.attack_agent import _classify_severity
        from patchi.core.agents.base import Severity
        self.assertEqual(_classify_severity("x", {"ok": True}), Severity.INFO)


class TestAttackAgentRun(unittest.TestCase):
    """Test AttackAgent._run method with mocked dependencies."""

    def setUp(self):
        self.tmpdir = Path(__file__).parent
        self.root = self.tmpdir

    @patch("patchi.core.agents.attack_agent.AttackAgent._run_module")
    def test_pymetasploit3_not_installed(self, mock_run_module):
        import sys

        from patchi.core.agents.attack_agent import AttackAgent
        from patchi.core.agents.base import AgentInput, AgentResult, AgentStatus
        agent = AttackAgent()
        inp = AgentInput(root=self.root, scope=[], brain={}, config={}, extra={})
        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")
        # Removing pymetasploit3 from modules to simulate ImportError
        saved = sys.modules.pop("pymetasploit3", None)
        try:
            agent._run(inp, result)
        finally:
            if saved:
                sys.modules["pymetasploit3"] = saved
        # Optional dependency missing → graceful SKIP, never a FAILED agent run.
        self.assertEqual(result.status, AgentStatus.SKIPPED)
        self.assertIn("pymetasploit3 not installed", result.data.get("skip_reason", ""))

    @patch("patchi.core.agents.attack_agent.AttackAgent._run_module")
    def test_run_with_frameworks(self, mock_run_module):
        import sys

        from patchi.core.agents.attack_agent import AttackAgent
        from patchi.core.agents.base import AgentInput, AgentResult
        agent = AttackAgent()
        inp = AgentInput(
            root=self.root, scope=[],
            brain={"framework": "Flask", "routes": ["/login"]},
            config={},
            extra={"msf_password": "test"},
        )
        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")

        fake_msfrpc = MagicMock()
        fake_msfrpc.MsfRpcClient = MagicMock(return_value=MagicMock())
        fake_pymetasploit3 = MagicMock()
        fake_pymetasploit3.msfrpc = fake_msfrpc
        with patch.dict(sys.modules, {"pymetasploit3": fake_pymetasploit3, "pymetasploit3.msfrpc": fake_msfrpc}):
            mock_run_module.return_value = None
            agent._run(inp, result)

        self.assertEqual(result.data["target"], "127.0.0.1:8000")
        self.assertIn("flask", result.data["frameworks"])

    @patch("patchi.core.agents.attack_agent.AttackAgent._run_module")
    def test_run_with_no_frameworks_uses_fallback(self, mock_run_module):
        import sys

        from patchi.core.agents.attack_agent import AttackAgent
        from patchi.core.agents.base import AgentInput, AgentResult
        agent = AttackAgent()
        inp = AgentInput(
            root=self.root, scope=[],
            brain={}, config={},
            extra={"msf_password": "test"},
        )
        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")

        fake_msfrpc = MagicMock()
        fake_msfrpc.MsfRpcClient = MagicMock(return_value=MagicMock())
        fake_pymetasploit3 = MagicMock()
        fake_pymetasploit3.msfrpc = fake_msfrpc
        with patch.dict(sys.modules, {"pymetasploit3": fake_pymetasploit3, "pymetasploit3.msfrpc": fake_msfrpc}):
            mock_run_module.return_value = None
            agent._run(inp, result)

        self.assertGreater(len(result.data.get("modules_selected", [])), 0)

    def test_msfrpc_connection_failure(self):
        import sys

        from patchi.core.agents.attack_agent import AttackAgent
        from patchi.core.agents.base import AgentInput, AgentResult
        agent = AttackAgent()
        inp = AgentInput(
            root=self.root, scope=[],
            brain={"framework": "Flask"}, config={},
            extra={"msf_password": "wrong"},
        )
        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")

        fake_msfrpc = MagicMock()
        fake_msfrpc.MsfRpcClient = MagicMock(side_effect=ConnectionError("refused"))
        fake_pymetasploit3 = MagicMock()
        fake_pymetasploit3.msfrpc = fake_msfrpc
        with patch.dict(sys.modules, {"pymetasploit3": fake_pymetasploit3, "pymetasploit3.msfrpc": fake_msfrpc}):
            agent._run(inp, result)

        self.assertTrue(any("Cannot connect to msfrpcd" in e for e in result.errors))

    def test_configurable_msf_port(self):
        import sys

        from patchi.core.agents.attack_agent import AttackAgent
        from patchi.core.agents.base import AgentInput, AgentResult
        agent = AttackAgent()
        inp = AgentInput(
            root=self.root, scope=[],
            brain={"framework": "Flask"}, config={},
            extra={"msf_password": "test", "msf_port": 55555},
        )
        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")

        fake_msfrpc = MagicMock()
        fake_msfrpc.MsfRpcClient = MagicMock(return_value=MagicMock())
        fake_pymetasploit3 = MagicMock()
        fake_pymetasploit3.msfrpc = fake_msfrpc
        with patch.dict(sys.modules, {"pymetasploit3": fake_pymetasploit3, "pymetasploit3.msfrpc": fake_msfrpc}):
            agent._run(inp, result)

        fake_msfrpc.MsfRpcClient.assert_called_once()
        args, kwargs = fake_msfrpc.MsfRpcClient.call_args
        self.assertEqual(kwargs.get("port"), 55555)

    def test_configurable_msf_ssl_default_true(self):
        import sys

        from patchi.core.agents.attack_agent import AttackAgent
        from patchi.core.agents.base import AgentInput, AgentResult
        agent = AttackAgent()
        inp = AgentInput(
            root=self.root, scope=[],
            brain={"framework": "Flask"}, config={},
            extra={"msf_password": "test"},
        )
        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")

        fake_msfrpc = MagicMock()
        fake_msfrpc.MsfRpcClient = MagicMock(return_value=MagicMock())
        fake_pymetasploit3 = MagicMock()
        fake_pymetasploit3.msfrpc = fake_msfrpc
        with patch.dict(sys.modules, {"pymetasploit3": fake_pymetasploit3, "pymetasploit3.msfrpc": fake_msfrpc}):
            agent._run(inp, result)

        args, kwargs = fake_msfrpc.MsfRpcClient.call_args
        self.assertEqual(kwargs.get("ssl"), True)

    def test_configurable_msf_ssl_false(self):
        import sys

        from patchi.core.agents.attack_agent import AttackAgent
        from patchi.core.agents.base import AgentInput, AgentResult
        agent = AttackAgent()
        inp = AgentInput(
            root=self.root, scope=[],
            brain={"framework": "Flask"}, config={},
            extra={"msf_password": "test", "msf_ssl": False},
        )
        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")

        fake_msfrpc = MagicMock()
        fake_msfrpc.MsfRpcClient = MagicMock(return_value=MagicMock())
        fake_pymetasploit3 = MagicMock()
        fake_pymetasploit3.msfrpc = fake_msfrpc
        with patch.dict(sys.modules, {"pymetasploit3": fake_pymetasploit3, "pymetasploit3.msfrpc": fake_msfrpc}):
            agent._run(inp, result)

        args, kwargs = fake_msfrpc.MsfRpcClient.call_args
        self.assertEqual(kwargs.get("ssl"), False)


class TestAttackAgentRunModule(unittest.TestCase):
    """Test AttackAgent._run_module."""

    def setUp(self):
        self.agent = None

    def _make_agent(self):
        from patchi.core.agents.attack_agent import AttackAgent
        return AttackAgent()

    def test_run_module_success_returns_finding(self):
        from patchi.core.agents.base import AgentResult
        agent = self._make_agent()
        client = MagicMock()
        aux_mock = MagicMock()
        client.modules.use.return_value = aux_mock
        aux_mock.execute.return_value = {"job_id": 123, "data": "ok"}

        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")
        finding = agent._run_module(client, "scanner/http/options", "127.0.0.1", 8000, [], result)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.type, "metasploit_aux")

    def test_run_module_exception_returns_none(self):
        from patchi.core.agents.base import AgentResult
        agent = self._make_agent()
        client = MagicMock()
        client.modules.use.side_effect = RuntimeError("module failed")

        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")
        finding = agent._run_module(client, "scanner/http/options", "127.0.0.1", 8000, [], result)
        self.assertIsNone(finding)
        self.assertTrue(any("module failed" in e for e in result.errors))

    def test_run_module_no_output_returns_none(self):
        from patchi.core.agents.base import AgentResult
        agent = self._make_agent()
        client = MagicMock()
        aux_mock = MagicMock()
        client.modules.use.return_value = aux_mock
        aux_mock.execute.return_value = None

        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")
        finding = agent._run_module(client, "scanner/http/options", "127.0.0.1", 8000, [], result)
        self.assertIsNone(finding)

    def test_run_module_module_result_stored(self):
        from patchi.core.agents.base import AgentResult
        agent = self._make_agent()
        client = MagicMock()
        aux_mock = MagicMock()
        client.modules.use.return_value = aux_mock
        aux_mock.execute.return_value = {"job_id": 456}

        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")
        agent._run_module(client, "scanner/test", "127.0.0.1", 8000, [], result)
        self.assertIn("scanner/test", result.data.get("module_results", {}))

    def test_run_module_sets_rhosts_and_rport(self):
        from patchi.core.agents.base import AgentResult
        agent = self._make_agent()
        client = MagicMock()
        aux_mock = {}
        client.modules.use.return_value = aux_mock
        aux_mock["RHOSTS"] = None
        aux_mock["RPORT"] = None

        def fake_execute():
            return {"job_id": 789}
        aux_mock["execute"] = fake_execute

        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")
        agent._run_module(client, "scanner/test", "10.0.0.1", 9090, [], result)
        self.assertEqual(aux_mock["RHOSTS"], "10.0.0.1")
        self.assertEqual(aux_mock["RPORT"], 9090)


class TestAttackAgentRunWithTimeout(unittest.TestCase):
    """Test _run with per-module timeout."""

    def setUp(self):
        self.tmpdir = Path(__file__).parent

    @patch("patchi.core.agents.attack_agent.AttackAgent._run_module")
    def test_module_timeout_configurable(self, mock_run_module):
        import sys

        from patchi.core.agents.attack_agent import AttackAgent
        from patchi.core.agents.base import AgentInput, AgentResult
        agent = AttackAgent()
        inp = AgentInput(
            root=self.tmpdir, scope=[],
            brain={"framework": "Flask"}, config={},
            extra={"msf_password": "test", "msf_module_timeout": 60},
        )
        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")

        fake_msfrpc = MagicMock()
        fake_msfrpc.MsfRpcClient = MagicMock(return_value=MagicMock())
        fake_pymetasploit3 = MagicMock()
        fake_pymetasploit3.msfrpc = fake_msfrpc
        mock_run_module.return_value = None
        with patch.dict(sys.modules, {"pymetasploit3": fake_pymetasploit3, "pymetasploit3.msfrpc": fake_msfrpc}):
            agent._run(inp, result)

        self.assertEqual(result.data["target"], "127.0.0.1:8000")

    @patch("patchi.core.agents.attack_agent.AttackAgent._run_module")
    def test_module_timeout_default(self, mock_run_module):
        import sys

        from patchi.core.agents.attack_agent import AttackAgent
        from patchi.core.agents.base import AgentInput, AgentResult
        agent = AttackAgent()
        inp = AgentInput(
            root=self.tmpdir, scope=[],
            brain={"framework": "Flask"}, config={},
            extra={"msf_password": "test"},
        )
        result = AgentResult(agent_name="AttackAgent", agent_group="TEST")

        fake_msfrpc = MagicMock()
        fake_msfrpc.MsfRpcClient = MagicMock(return_value=MagicMock())
        fake_pymetasploit3 = MagicMock()
        fake_pymetasploit3.msfrpc = fake_msfrpc
        mock_run_module.side_effect = TimeoutError("simulated timeout")
        with patch.dict(sys.modules, {"pymetasploit3": fake_pymetasploit3, "pymetasploit3.msfrpc": fake_msfrpc}):
            agent._run(inp, result)


if __name__ == "__main__":
    unittest.main()
