"""Phase 5.3 — AI Client tests: fallback chain, JSON parsing, cost tracking."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _clear_offline_flag():
    """These tests exercise call_ai's fallback chain with mocked transports.

    ci-audit.sh exports PATCHI_OFFLINE=1 for the whole suite (hermetic gate), but
    offline mode makes call_ai return None before any mocked urlopen runs, so the
    fallback logic under test would never execute. The tests are hermetic by
    mocking urllib, not by the offline flag — clear it for this module.
    """
    old = os.environ.pop("PATCHI_OFFLINE", None)
    yield
    if old is not None:
        os.environ["PATCHI_OFFLINE"] = old


class TestAIClientFallback(unittest.TestCase):
    """Test the call_ai fallback priority: Ollama → keys → None."""

    def setUp(self):
        self.config = {
            "ai": {
                "local_model_name": None,
                "keys": [],
            }
        }

    def test_no_ai_returns_none(self):
        from patchi.core.ai.client import call_ai

        with patch("urllib.request.urlopen", side_effect=Exception("no network")):
            result = call_ai(self.config, "system", "user prompt")
            self.assertIsNone(result)

    def test_ollama_returns_none_when_unreachable(self):
        self.config["ai"]["local_model_name"] = "llama3"
        with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
            from patchi.core.ai.client import call_ai

            result = call_ai(self.config, "system", "user prompt")
            self.assertIsNone(result)

    def test_ollama_returns_text_when_available(self):
        self.config["ai"]["local_model_name"] = "llama3"
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"response": "Hello from Ollama"}).encode()
        mock_resp.__enter__.return_value = mock_resp
        with patch("urllib.request.urlopen", return_value=mock_resp):
            from patchi.core.ai.client import call_ai

            result = call_ai(self.config, "system", "user prompt")
            self.assertEqual(result, "Hello from Ollama")

    def _mock_resp(self, data):
        m = MagicMock()
        m.read.return_value = json.dumps(data).encode()
        m.__enter__.return_value = m
        return m

    def test_api_key_fallback_works(self):
        self.config["ai"]["local_model_name"] = "llama3"
        self.config["ai"]["keys"] = [
            {
                "env_var": "TEST_KEY",
                "format": "openai",
                "base_url": "https://api.openai.com/v1",
                "model": "gpt-4o-mini",
                "status": "ok",
            }
        ]
        from patchi.core.ai.client import call_ai

        with patch.dict("os.environ", {"TEST_KEY": "sk-fake"}):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = [
                    Exception("ollama down"),
                    self._mock_resp(
                        {
                            "choices": [{"message": {"content": "Hello from API"}}],
                            "usage": {
                                "prompt_tokens": 10,
                                "completion_tokens": 5,
                                "total_tokens": 15,
                            },
                        }
                    ),
                ]
                result = call_ai(self.config, "system", "user prompt")
                self.assertEqual(result, "Hello from API")


class TestAIJsonParsing(unittest.TestCase):
    def test_direct_json(self):
        from patchi.core.ai.client import _parse_json_response

        result = _parse_json_response('{"key": "value"}')
        self.assertEqual(result, {"key": "value"})

    def test_json_in_code_block(self):
        from patchi.core.ai.client import _parse_json_response

        text = 'Here is the result:\n```json\n{"key": "value"}\n```\n'
        result = _parse_json_response(text)
        self.assertEqual(result, {"key": "value"})

    def test_json_in_unmarked_block(self):
        from patchi.core.ai.client import _parse_json_response

        text = "```\n[1, 2, 3]\n```"
        result = _parse_json_response(text)
        self.assertEqual(result, [1, 2, 3])

    def test_invalid_text_returns_none(self):
        from patchi.core.ai.client import _parse_json_response

        result = _parse_json_response("not json at all")
        self.assertIsNone(result)

    def test_nested_json_extraction(self):
        from patchi.core.ai.client import _parse_json_response

        text = 'Some text {"a": {"b": [1, 2]}} more text'
        result = _parse_json_response(text)
        self.assertEqual(result, {"a": {"b": [1, 2]}})


class TestCostTracking(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self._root = Path(self._tmp.name)
        from patchi.core.ai.cost_tracker import reset

        reset()

    def tearDown(self):
        self._tmp.cleanup()

    def test_track_and_get_stats(self):
        from patchi.core.ai.cost_tracker import get_stats, init, track

        init(self._root)
        track("gpt-4o-mini", 100, 50)
        stats = get_stats()
        self.assertEqual(stats["calls"], 1)
        self.assertEqual(stats["total_tokens"], 150)
        self.assertGreater(stats["cost_estimate"], 0)

    def test_track_multiple_models(self):
        from patchi.core.ai.cost_tracker import get_stats, init, track

        init(self._root)
        track("gpt-4o-mini", 100, 50)
        track("gemini-1.5-flash", 200, 100)
        stats = get_stats()
        self.assertEqual(stats["calls"], 2)
        self.assertEqual(stats["total_tokens"], 450)
        self.assertIn("gpt-4o-mini", stats["by_model"])
        self.assertIn("gemini-1.5-flash", stats["by_model"])

    def test_check_budget_no_limit(self):
        from patchi.core.ai.cost_tracker import check_budget, init

        init(self._root)
        result = check_budget({"ai": {"cost_limit_enabled": False}})
        self.assertIsNone(result)

    def test_check_budget_exceeded(self):
        from patchi.core.ai.cost_tracker import check_budget, init, track

        init(self._root)
        # Using a very expensive model to exceed a tiny limit
        track("gpt-4o", 50000, 10000)
        result = check_budget({"ai": {"cost_limit_enabled": True, "cost_limit": 0.01}})
        self.assertIsNotNone(result)
        self.assertIn("budget", result)
