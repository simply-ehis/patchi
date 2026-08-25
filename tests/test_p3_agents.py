"""
P3 agent modernization tests — SecretScanner (regex-free), RedTeamAgent
(scenario/playbook linkage), BrowserTestAgent (live probe wiring).

These tests assert SPECIFIC verdicts/severities/fields so regressions fail.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Trigger agent registration like the rest of the suite does
import patchi.core.agents.scanners  # noqa: F401,E402
import patchi.core.security.security_agents  # noqa: F401,E402
import patchi.core.testing.test_agents  # noqa: F401,E402

# ── SecretScanner: regex-free detection core ─────────────────────────────────


class TestEntropy:
    def test_repeated_char_is_zero(self):
        from patchi.core.security.security_taint import shannon_entropy

        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_uniform_hex_is_four(self):
        from patchi.core.security.security_taint import shannon_entropy

        # 0123456789abcdef = perfectly uniform 16-symbol alphabet -> 4 bits
        assert shannon_entropy("0123456789abcdef") == 4.0

    def test_empty_safe(self):
        from patchi.core.security.security_taint import shannon_entropy

        assert shannon_entropy("") == 0.0


class TestClassify:
    def _cls(self, name, value):
        from patchi.core.security.security_taint import SecretScanner, classify_secret

        return classify_secret(name, value, SecretScanner.__new__(SecretScanner))

    def test_aws_prefix_wins_over_example_marker(self):
        # AWS docs publish AKIAIOSFODNN7EXAMPLE — provider format must win
        verdict, label, sev = self._cls("api_key", "AKIAIOSFODNN7EXAMPLE")
        assert verdict == "provider-prefix"
        assert label == "aws_access_key"
        assert sev.value == "critical"

    def test_high_entropy_cred_assignment_critical(self):
        v = "wJalrXUtnFEMI-K7MDENGbPxRfiCYEXAMPLEKEY123"
        verdict, _, sev = self._cls("api_key", v)
        assert verdict == "credential-assignment" and sev.value == "critical"

    def test_password_assignment_at_least_high(self):
        verdict, _, sev = self._cls(
            "db_password", "Tr0ub4dor&3CorrectHorse"
        )
        assert verdict == "credential-assignment"
        assert sev.value in ("high", "critical")

    def test_hex_blob_medium_without_cred_name(self):
        v = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        verdict, _, sev = self._cls("config_value", v)
        assert verdict == "high-entropy" and sev.value == "medium"

    def test_changeme_suppressed(self):
        assert self._cls("password", "changeme")[0] is None

    def test_angle_bracket_template_suppressed(self):
        assert self._cls("api_key", "<your-api-key-here>")[0] is None

    def test_short_low_value_suppressed(self):
        assert self._cls("greeting", "hello world")[0] is None


class TestExtractors:
    def test_py_ast_names(self):
        from patchi.core.security.security_taint import extract_py_string_candidates

        src = (
            "API_KEY = 'abcdefghijklmnop'\n"
            "cfg = {'client_secret': 'qrstuvwxyz'}\n"
            "connect(api_token='mnlopqrstuvwxyz')\n"
        )
        names = {c.name for c in extract_py_string_candidates(src)}
        assert {"API_KEY", "client_secret", "api_token"} <= names

    def test_quoted_guesses_name(self):
        from patchi.core.security.security_taint import extract_quoted_candidates

        cands = extract_quoted_candidates("settings: { token: 'abcdefgh123456' }")
        assert any(c.name and "token" in c.name.lower() for c in cands)

    def test_no_regex_in_scanner_span(self):
        # Structural guard: the SecretScanner fallback must not use `re.`
        p = (
            Path(__file__).resolve().parent.parent
            / "patchi" / "core" / "security" / "security_taint.py"
        )
        text = p.read_text(encoding="utf-8")
        span = text[text.index("class SecretScanner") :]
        forbidden = ["re.compile", "re.search", "re.match", "re.findall", "_FALLBACK_PATTERNS"]
        for marker in forbidden:
            assert marker not in span.split("class ")[0], f"SecretScanner still uses {marker}"


# ── RedTeamAgent: scenario/playbook linkage ──────────────────────────────────


class TestRedTeamLinkage:
    def _agent(self):
        from patchi.core.security.red_team_agent import RedTeamAgent

        return RedTeamAgent()

    def test_link_mappings(self):
        a = self._agent()
        checks = {
            "eval() usage": "injection-command",
            "pickle deserialization": "deserialization",
            "Debug mode enabled": "security-headers",
            "ALLOWED_HOSTS set to wildcard": "security-headers",
        }
        for msg, want in checks.items():
            fam, pb = a._link_for(msg)
            assert fam == want, f"{msg}: {fam} != {want}"
            assert pb, f"{msg}: playbook empty"

    def test_unrelated_message_has_no_link(self):
        fam, pb = self._agent()._link_for("nothing matches here")
        assert fam == "" and pb == ""

    def test_run_enriches_findings_with_playbook(self, tmp_path):
        from patchi.core.agents.base import AgentGroup, AgentInput, AgentResult
        from patchi.core.security.red_team_agent import RedTeamAgent

        target = tmp_path / "app.py"
        target.write_text("import pickle\npickle.loads(b'x')\n", encoding="utf-8")

        inp = AgentInput(root=tmp_path, scope=[], brain={}, config={})
        result = AgentResult(agent_name=RedTeamAgent.name, agent_group=AgentGroup.SECURITY)
        RedTeamAgent()._run(inp, result)

        vp = [f for f in result.findings if f.type == "vulnerable_pattern" and "pickle" in f.message]
        assert vp, "pickle pattern not detected"
        f = vp[0]
        extra = getattr(f, "extra", {})
        assert extra.get("scenario_family") == "deserialization"
        assert extra.get("remediation_playbook") == "fix-deserialization-safe-load"
        assert extra.get("attack_surface") == "static"


# ── BrowserTestAgent: live probe wiring ──────────────────────────────────────


class TestBrowserProbeWiring:
    def test_registered_and_upgraded(self):
        from patchi.core.agents.base import get_agent

        cls = get_agent("BrowserTestAgent")
        assert cls is not None
        inst = cls()
        assert hasattr(inst, "_live_probe")
        assert hasattr(inst, "_probe_async")

    def test_live_probe_graceful_without_browser(self, tmp_path, monkeypatch):
        """No reachable browser pool -> probe returns None, agent doesn't crash."""
        from patchi.core.testing.browser_test_agent import BrowserTestAgent

        async def _boom(*a, **k):
            raise RuntimeError("no browser in CI")

        import patchi.core.testing.live_v2.browser_pool as bp

        monkeypatch.setattr(bp, "get_browser_pool", _boom)
        inst = BrowserTestAgent()
        out = inst._live_probe(type("I", (), {"root": tmp_path, "brain": {}})(), "http://127.0.0.1:59999")
        assert out is None
