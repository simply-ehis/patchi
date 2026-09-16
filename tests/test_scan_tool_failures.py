"""Regression tests for the field-reported scan failures on Windows.

Every test here corresponds to a real failure seen scanning a React/tauri
project: gitleaks temp-file refusals, osv-scanner JSON parse errors, the
cp1252 UnicodeDecodeError crash in subprocess reader threads, the
tree-sitter unpack TypeError in AuthZAgent/CoreScanner, the WinError 32
race on .patchi/memory/scan_results.json, bandit's silent timeout, and
CodeQL's autobuild crash on non-Python repos.
"""

from __future__ import annotations

import json
import os
import threading

from patchi.core import memory as mem
from patchi.core.agents import tool_runner
from patchi.core.agents.base import AgentInput
from patchi.core.tools_workspace import scratch_dir, scratch_file

# ── tools_workspace: project-local scratch, never pre-created ────────────────


def test_scratch_file_lives_under_patchi_tmp(tmp_path, monkeypatch):
    from patchi.core import config as cfg

    monkeypatch.setattr(cfg, "find_project_root", lambda: tmp_path)
    p = scratch_file("gitleaks-abc123.json")
    assert ".patchi" in str(p) and "tool-runs" in str(p)
    assert not p.exists(), "scratch files must never be pre-created (gitleaks refuses existing paths)"


def test_scratch_dir_falls_back_without_project(monkeypatch, tmp_path):
    from patchi.core import config as cfg

    monkeypatch.setattr(cfg, "find_project_root", lambda: None)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    d = scratch_dir()
    assert "patchi" in str(d)


# ── gitleaks: pre-created report file made the tool refuse to write ──────────


def test_run_gitleaks_does_not_precreate_report(tmp_path, monkeypatch):
    """gitleaks v8 refuses to overwrite an existing report path."""
    created = []

    def fake_run(cmd, timeout=120):
        report = cmd[cmd.index("--report-path") + 1]
        created.append(report)
        assert not os.path.exists(report), "report path must not pre-exist"
        with open(report, "w", encoding="utf-8") as f:
            json.dump([{"RuleID": "r", "File": "a.py", "StartLine": 1, "Secret": "x"}], f)
        return 0, "", ""

    monkeypatch.setattr(tool_runner, "is_tool_available", lambda name: True)
    monkeypatch.setattr(tool_runner, "_run_process", fake_run)
    out = tool_runner.run_gitleaks(tmp_path)
    assert out["tool"] == "gitleaks"
    assert len(out["findings"]) == 1
    assert created and not os.path.exists(created[0]), "report cleaned up after parse"


def test_secret_scanner_gitleaks_timeout_is_honest(tmp_path, monkeypatch):
    """A timed-out gitleaks run must be SKIPPED with a reason, not zero findings."""
    import shutil

    import patchi.core.security.security_taint as st
    from patchi.core.agents.base import AgentResult, AgentStatus
    from patchi.core.security.security_taint import SecretScanner

    agent = SecretScanner.__new__(SecretScanner)  # skip __init__ registration
    agent.timeout = 30
    result = AgentResult(agent_name="SecretScanner")

    monkeypatch.setattr(st, "_run", lambda *a, **k: {"timed_out": True, "stdout": "", "stderr": "", "returncode": -1})
    monkeypatch.setattr(st.shutil, "which", lambda _: True)
    assert shutil.which  # keep the shutil import meaningful for the reader

    agent._run_gitleaks(tmp_path, result)
    assert result.status == AgentStatus.SKIPPED
    assert result.data.get("tool_timeout") is True
    assert "inconclusive" in (result.data.get("skip_reason") or "")


# ── osv-scanner: stdout JSON + honest failure on empty output ─────────────────


def test_osv_scanner_parses_stdout_json(tmp_path, monkeypatch):
    """osv-scanner v2 prints JSON to stdout; --output was removed in v2."""
    from patchi.core.agents.base import AgentResult
    from patchi.core.security.security_probe import DependencyCVEChecker

    doc = {"results": []}
    seen = {}

    import patchi.core.security.security_probe as sp

    def fake_run(cmd, cwd, timeout=120, env=None):
        seen["cmd"] = cmd
        return {"returncode": 0, "stdout": json.dumps(doc), "stderr": "", "timed_out": False}

    monkeypatch.setattr(sp, "_run", fake_run)
    agent = DependencyCVEChecker.__new__(DependencyCVEChecker)
    agent.timeout = 120
    result = AgentResult(agent_name="DependencyCVEChecker")
    agent._run_osv_scanner(tmp_path, result)

    assert "--output" not in seen["cmd"], "v2 removed --output; stdout is the contract"
    assert result.data.get("osv_scanner_failed") is not True


def test_osv_scanner_failure_is_recorded_not_silent(tmp_path, monkeypatch):
    import patchi.core.security.security_probe as sp
    from patchi.core.agents.base import AgentResult
    from patchi.core.security.security_probe import DependencyCVEChecker

    monkeypatch.setattr(
        sp, "_run", lambda *a, **k: {"returncode": 2, "stdout": "", "stderr": "boom", "timed_out": False}
    )
    agent = DependencyCVEChecker.__new__(DependencyCVEChecker)
    agent.timeout = 120
    result = AgentResult(agent_name="DependencyCVEChecker")
    agent._run_osv_scanner(tmp_path, result)

    assert result.data.get("osv_scanner_failed") is True
    assert "boom" in (result.data.get("tool_error") or "")


# ── cp1252: reader threads must never die on non-ASCII tool output ────────────


def test_shared_run_helpers_decode_utf8(tmp_path, monkeypatch):
    """0x9d in tool output crashed cp1252 reader threads in the field."""
    import patchi.core.security.security_probe as sp
    import patchi.core.security.security_taint as st

    script = tmp_path / "out.py"
    script.write_text("import sys; sys.stdout.buffer.write(b'x\\x9dy')\n", encoding="utf-8")

    for mod in (sp, st):
        out = mod._run(["python", str(script)], tmp_path, timeout=30)
        assert out["returncode"] == 0
        assert "\ufffd" in out["stdout"], f"{mod.__name__}._run must decode with errors=replace"


# ── tree-sitter: get_parser returns ONE parser, not a tuple ───────────────────


def test_authz_treesitter_path_no_unpack_crash():
    """The old `parser, lang_obj = get_parser(lang)` raised TypeError per file."""
    from patchi.core.brain.languages import Lang
    from patchi.core.security.authz_agent import AuthZAgent

    agent = AuthZAgent.__new__(AuthZAgent)
    findings = agent._scan_treesitter_authz("def handler():\n    return user.is_admin\n", "x.py", Lang.PYTHON)
    assert isinstance(findings, list)  # no exception == the fix works


def test_core_scanner_treesitter_path_no_unpack_crash(tmp_path):
    from patchi.core.agents.core_scanner import CoreScanner
    from patchi.core.brain.languages import Lang

    agent = CoreScanner.__new__(CoreScanner)
    findings = agent._parse_with_treesitter("x.py", "x = 1\n", Lang.PYTHON)
    assert isinstance(findings, list)


# ── memory: unique tmp names (WinError 32 race) ────────────────────────────────


def test_memory_write_uses_unique_tmp_names(tmp_path, monkeypatch):
    """Concurrent writers must not share one `.tmp` sibling (Windows deny-share)."""
    seen = []
    real_replace = mem.atomic_replace

    def spy(src, dst, *a, **k):
        seen.append(src.name)
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(mem, "atomic_replace", spy)
    mem.save_scan_result("A", {"x": 1}, tmp_path)
    mem.save_scan_result("B", {"x": 2}, tmp_path)
    assert len(set(seen)) == len(seen), "each write needs its own tmp name"
    assert all(".tmp-" in n for n in seen)


def test_memory_concurrent_writers_no_error(tmp_path):
    """Smoke the actual race: 8 threads writing scan results simultaneously."""
    errors = []

    def worker(i):
        try:
            for j in range(5):
                mem.save_scan_result(f"Agent{i}", {"n": j}, tmp_path)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"concurrent writes raised: {errors[:2]}"
    data = mem.get_scan_results(tmp_path)
    assert len(data) == 8


# ── bandit: timeout recorded, report unparsable handled ────────────────────────


def test_bandit_timeout_marks_agent_skipped(tmp_path, monkeypatch):
    import subprocess

    import patchi.core.security.bandit_agent as ba
    from patchi.core.agents.base import AgentResult, AgentStatus
    from patchi.core.security.bandit_agent import BanditAgent

    agent = BanditAgent.__new__(BanditAgent)
    result = AgentResult(agent_name="BanditAgent")

    def raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="bandit", timeout=120)

    monkeypatch.setattr(ba.subprocess, "run", raise_timeout)
    # _run probes availability first — keep that probe from hitting the
    # raise_timeout stub above.
    monkeypatch.setattr(BanditAgent, "_is_bandit_available", lambda self: True)

    BanditAgent._run_bandit(agent, tmp_path)
    assert agent.timed_out is True

    BanditAgent._run(agent, AgentInput(root=tmp_path, scope=[], brain={}, config={}), result)
    assert result.status == AgentStatus.SKIPPED
    assert "inconclusive" in (result.data.get("skip_reason") or "")


# ── codeql: non-Python repo skips honestly instead of autobuild crash ─────────


def test_codeql_skips_non_python_repo(tmp_path, monkeypatch):
    """The detection lives inside _run_codeql, so exercise the real method:
    no Python sources ⇒ early return + skip flag, codeql never invoked."""
    from patchi.core.agents.base import AgentResult, AgentStatus
    from patchi.core.security.codeql_agent import CodeqlAgent

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.ts").write_text("const x = 1;\n")

    agent = CodeqlAgent.__new__(CodeqlAgent)
    agent.skip_python_sources = False

    def fail_if_called(*a, **k):
        raise AssertionError("codeql subprocess must not run on a repo with no Python sources")

    import patchi.core.security.codeql_agent as ca

    monkeypatch.setattr(ca.subprocess, "run", fail_if_called)
    findings = CodeqlAgent._run_codeql(agent, tmp_path)
    assert findings == []
    assert agent.skip_python_sources is True

    # And _run turns that flag into an honest SKIPPED with a reason.
    result = AgentResult(agent_name="CodeQLAgent")
    monkeypatch.setattr(CodeqlAgent, "_is_codeql_available", lambda self: True)
    CodeqlAgent._run(agent, AgentInput(root=tmp_path, scope=[], brain={}, config={}), result)
    assert result.status == AgentStatus.SKIPPED
    assert "no Python sources" in (result.data.get("skip_reason") or "")


# ── auto-init: keys present + onboarding incomplete ⇒ non-interactive init ────


def test_has_configured_keys_detects_keys_json(tmp_path):
    from patchi.cli.main import _has_configured_keys

    (tmp_path / ".patchi").mkdir()
    (tmp_path / ".patchi" / "keys.json").write_text(json.dumps({"PATCHI_KEY_GROQ": "gsk_x"}), encoding="utf-8")
    assert _has_configured_keys(tmp_path) is True


def test_has_configured_keys_detects_env_file(tmp_path):
    from patchi.cli.main import _has_configured_keys

    (tmp_path / ".patchi").mkdir()
    (tmp_path / ".patchi" / ".env").write_text("PATCHI_KEY_OPENAI=sk-abc\n", encoding="utf-8")
    assert _has_configured_keys(tmp_path) is True


def test_has_configured_keys_false_when_empty(tmp_path):
    from patchi.cli.main import _has_configured_keys

    (tmp_path / ".patchi").mkdir()
    assert _has_configured_keys(tmp_path) is False
    (tmp_path / ".patchi" / "keys.json").write_text("{}", encoding="utf-8")
    assert _has_configured_keys(tmp_path) is False
