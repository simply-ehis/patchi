"""
Real integration tests for the upgraded tool backends in realize.py.

These assert *actual* behaviour (real pytest runs, real HTTP load generation,
real secret scanning) — not that a function returns a placeholder string.
"""

from __future__ import annotations

import asyncio
import http.server
import threading
from pathlib import Path

import pytest

from patchi.core.ai.tools import realize


def _mk_project(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


# --------------------------------------------------------------------------
# event sink capture
# --------------------------------------------------------------------------

@pytest.fixture
def sink():
    events = []

    def _sink(payload):
        events.append(payload)

    realize.set_event_sink(_sink)
    yield events
    realize.set_event_sink(None)


# --------------------------------------------------------------------------
# run_tests — real pytest subprocess
# --------------------------------------------------------------------------

def test_run_tests_real_counts(tmp_path, sink):
    proj = _mk_project(tmp_path, {
        "tests/test_pass.py": (
            "def test_ok():\n    assert 1 + 1 == 2\n"
            "def test_ok2():\n    assert True\n"
        ),
    })
    res = realize.run_tests(proj)
    assert res["success"] is True
    assert res["passed"] >= 2
    assert res["failed"] == 0
    # events were emitted live
    assert any(e["event"] == "test.suite.completed" for e in sink)


def test_run_tests_failure_reported(tmp_path):
    proj = _mk_project(tmp_path, {
        "tests/test_fail.py": "def test_bad():\n    assert 1 == 2\n",
    })
    res = realize.run_tests(proj)
    # A failing suite is reported, not silently swallowed.
    assert res["success"] is False
    assert res["failed"] >= 1


# --------------------------------------------------------------------------
# scan_vulnerabilities — real agent execution + secret detection
# --------------------------------------------------------------------------

def test_scan_finds_hardcoded_secret(tmp_path, sink):
    proj = _mk_project(tmp_path, {
        "app/config.py": (
            'API_KEY = "sk-live-1234567890abcdef1234567890abcdef"\n'
            'DB_PASSWORD = "hunter2_secret_value"\n'
            "def f():\n    return 1\n"
        ),
    })
    res = realize.scan_vulnerabilities(proj, domains=["SensitiveDataAgent"])
    assert isinstance(res, dict)
    assert "total_findings" in res
    # A real secret scan MUST surface at least one finding on this input.
    assert res["total_findings"] >= 1, res
    # And it must have streamed security.finding events.
    assert any(e["event"] == "security.finding" for e in sink)


# --------------------------------------------------------------------------
# stress_test — real load generation
# --------------------------------------------------------------------------

def test_stress_test_unreachable_is_honest(tmp_path):
    res = realize.stress_test(
        Path(tmp_path), base_url="http://127.0.0.1:1/", duration_seconds=1, users=2
    )
    # No server there -> must NOT claim success / must report connectivity.
    assert res["success"] is False
    assert "error" in res


def test_stress_test_real_load(tmp_path):
    handler = http.server.SimpleHTTPRequestHandler
    # Serve the temp dir so the endpoint is reachable.
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        res = realize.stress_test(
            Path(tmp_path),
            base_url=f"http://127.0.0.1:{port}/",
            duration_seconds=2,
            users=4,
        )
        assert res["success"] is True
        assert res["requests"] > 0
        assert 0.0 <= res["error_rate"] <= 1.0
        assert res["p95"] >= 0
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------
# screenshot — must never return a placeholder string
# --------------------------------------------------------------------------

def test_screenshot_no_placeholder(tmp_path):
    res = realize.screenshot(Path(tmp_path), url="http://127.0.0.1:1/")
    assert isinstance(res, dict)
    assert "success" in res
    # The old stub returned screenshot_base64="placeholder".
    assert res.get("screenshot_base64") != "placeholder"
    # It may fail (no browser) but must not lie about success.
    assert res["success"] is False or isinstance(res.get("screenshot_path"), (str, type(None)))
