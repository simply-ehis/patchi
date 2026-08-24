"""Tests for patchi CLI command modules."""

from pathlib import Path
from unittest.mock import MagicMock, patch


class TestStatusText:
    """Tests for agents_cmd._status_text."""

    def test_status_text_ready(self):
        from patchi.cli.commands.agents_cmd import _status_text
        from patchi.core.agents.base import AgentStatus

        result = _status_text(AgentStatus.DONE)
        assert result is not None
        assert len(str(result)) > 0

    def test_status_text_none(self):
        from patchi.cli.commands.agents_cmd import _status_text

        result = _status_text(None)
        assert result is not None
        assert len(str(result)) > 0


class TestRenderGroup:
    """Tests for agents_cmd._render_group."""

    @patch("patchi.cli.commands.agents_cmd.con")
    def test_render_group_with_agents(self, mock_con):
        from patchi.cli.commands.agents_cmd import _render_group

        mock_group = MagicMock()
        mock_group.value = "test_group"
        mock_group.ant_type.return_value = "test"
        mock_group.label.return_value = "Test Group"
        mock_agent = MagicMock()
        mock_agent.name = "agent1"
        agents = [mock_agent]
        scan_results = {"agent1": {"status": "done", "finding_count": 5, "duration_ms": 100}}

        _render_group(mock_group, agents, scan_results)
        mock_con.print.assert_called()

    @patch("patchi.cli.commands.agents_cmd.con")
    def test_render_group_empty_agents(self, mock_con):
        from patchi.cli.commands.agents_cmd import _render_group

        mock_group = MagicMock()
        mock_group.value = "test_group"

        _render_group(mock_group, [], {})
        mock_con.print.assert_called()


class TestRunList:
    """Tests for agents_cmd.run_list."""

    @patch("patchi.cli.commands.agents_cmd.list_agents")
    @patch("patchi.cli.commands.agents_cmd._render_group")
    def test_run_list_with_group(self, mock_render, mock_list):
        from patchi.cli.commands.agents_cmd import run_list

        mock_list.return_value = []
        run_list("scanner", Path("/fake/root"))
        mock_list.assert_called_once()

    @patch("patchi.cli.commands.agents_cmd.list_agents")
    @patch("patchi.cli.commands.agents_cmd._render_group")
    def test_run_list_all_groups(self, mock_render, mock_list):
        from patchi.cli.commands.agents_cmd import run_list

        mock_list.return_value = []
        run_list(None, Path("/fake/root"))
        mock_list.assert_called()


class TestRunStatus:
    """Tests for agents_cmd.run_status."""

    @patch("patchi.cli.commands.agents_cmd.con")
    def test_run_status(self, mock_con):
        from patchi.cli.commands.agents_cmd import run_status

        run_status(Path("/fake/root"))
        mock_con.print.assert_called()


class TestAiCmdRun:
    """Tests for ai_cmd.run."""

    @patch("patchi.cli.commands.ai_cmd.con")
    def test_run_with_args(self, mock_con):
        from patchi.cli.commands.ai_cmd import run

        args = MagicMock()
        args.command = "status"
        run(args)
        mock_con.print.assert_called()

    @patch("patchi.cli.commands.ai_cmd.con")
    def test_run_no_args(self, mock_con):
        from patchi.cli.commands.ai_cmd import run

        run(None)
        mock_con.print.assert_called()


class TestAiCmdStatus:
    """Tests for ai_cmd.run_status."""

    @patch("patchi.cli.commands.ai_cmd.con")
    def test_run_status(self, mock_con):
        from patchi.cli.commands.ai_cmd import run_status

        run_status(Path("/fake/root"))
        mock_con.print.assert_called()


class TestAiCmdTest:
    """Tests for ai_cmd.run_test."""

    @patch("patchi.cli.commands.ai_cmd.con")
    @patch("patchi.core.fix.base._call_ai", return_value="PATCHI AI READY")
    def test_run_test(self, mock_call_ai, mock_con):
        from patchi.cli.commands.ai_cmd import run_test

        run_test(Path("/fake/root"))
        mock_con.print.assert_called()


class TestAiCmdHordeTest:
    """Tests for ai_cmd.run_horde_test."""

    @patch("patchi.cli.commands.ai_cmd.con")
    @patch("patchi.core.ai.client._call_ai_horde", return_value="PATCHI AI READY")
    def test_run_horde_test(self, mock_horde, mock_con):
        from patchi.cli.commands.ai_cmd import run_horde_test

        run_horde_test()
        mock_con.print.assert_called()


class TestAiCmdAdd:
    """Tests for ai_cmd.run_add."""

    @patch("patchi.cli.commands.ai_cmd.con")
    @patch(
        "rich.prompt.Prompt.ask",
        side_effect=["testkey", "https://api.test.com", "test-model", "openai", "PATCHI_KEY_TEST"],
    )
    def test_run_add(self, mock_prompt, mock_con):
        from patchi.cli.commands.ai_cmd import run_add

        run_add(Path("/fake/root"))
        mock_con.print.assert_called()


class TestAiCmdRemove:
    """Tests for ai_cmd.run_remove."""

    @patch("patchi.cli.commands.ai_cmd.con")
    def test_run_remove(self, mock_con):
        from patchi.cli.commands.ai_cmd import run_remove

        run_remove(Path("/fake/root"), "test_agent")
        mock_con.print.assert_called()

    @patch("patchi.cli.commands.ai_cmd.con")
    def test_run_remove_empty_name(self, mock_con):
        from patchi.cli.commands.ai_cmd import run_remove

        run_remove(Path("/fake/root"), "")
        mock_con.print.assert_called()
