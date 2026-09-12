"""Contract smoke-test generation (§6): static routes → runnable pytest file."""

import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from patchi.core.testing.api_contract_agent import (
    _fill_path_params,
    extract_routes,
    generate_contract_tests,
)


def _proj() -> Path:
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    (root / "backend" / "routes").mkdir(parents=True, exist_ok=True)
    (root / "backend" / "routes" / "items.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.get("/items")\n'
        "def list_items(): return []\n"
        '@router.get("/items/{item_id}")\n'
        "def get_item(item_id: int): return {}\n"
        '@router.post("/items")\n'
        "def create_item(): return {}\n",
        encoding="utf-8",
    )
    (root / "backend" / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    return root


def test_extract_routes_finds_static_paths():
    routes = extract_routes(_proj())
    by_path = {(r["method"], r["path"]) for r in routes}
    assert ("GET", "/items") in by_path
    assert ("GET", "/items/{item_id}") in by_path
    assert ("POST", "/items") in by_path


def test_fill_path_params():
    assert _fill_path_params("/items/{item_id}") == "/items/1"
    assert _fill_path_params("/plain") == "/plain"


def test_generate_writes_runnable_file():
    root = _proj()
    summary = generate_contract_tests(root, "http://127.0.0.1:9")
    assert summary["written"] is True
    assert summary["routes"] == 3
    out = root / summary["path"]
    assert out.exists()
    src = out.read_text(encoding="utf-8")
    assert "def test_get_items_" in src
    compile(src, str(out), "exec")


def test_generate_empty_project_writes_nothing():
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    summary = generate_contract_tests(root)
    assert summary["written"] is False
    assert summary["routes"] == 0
    assert summary["path"] is None


def test_hot_tests_first_orders_without_skipping(monkeypatch):
    """Coverage prioritization: hot sources' tests first, same set."""
    import patchi.core.memory as mem
    from patchi.core.testing.unit_test_agent import UnitTestAgent

    root = Path(tempfile.mkdtemp())
    (root / "tests").mkdir(exist_ok=True)
    (root / "tests" / "test_alpha.py").write_text("def test_a(): pass\n", encoding="utf-8")
    (root / "tests" / "test_beta.py").write_text("def test_b(): pass\n", encoding="utf-8")
    monkeypatch.setattr(
        mem,
        "get_scan_results",
        lambda _r: {
            "CoveragePrioritizerAgent": {
                "data": {"hot_untested": ["src/beta.py"], "total_hot_untested": 1}
            }
        },
    )
    agent = UnitTestAgent()
    ordered = agent._hot_test_first(root, ["tests"])
    assert ordered == ["tests/test_beta.py"]
    # Unknown hot files resolve to nothing — never crash, never invent
    monkeypatch.setattr(
        mem, "get_scan_results", lambda _r: {"CoveragePrioritizerAgent": {"data": {"hot_untested": ["src/nope.py"]}}}
    )
    assert agent._hot_test_first(root, ["tests"]) == []


class _Stub(BaseHTTPRequestHandler):
    def _ok(self):
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _ok
    do_POST = _ok

    def log_message(self, *a):
        pass


def test_generated_file_passes_against_stub():
    root = _proj()
    srv = HTTPServer(("127.0.0.1", 0), _Stub)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        summary = generate_contract_tests(root, f"http://127.0.0.1:{port}")
        import os

        env = dict(os.environ, PATCHI_CONTRACT_BASE_URL=f"http://127.0.0.1:{port}")
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", summary["path"], "-q", "--timeout=30", "-p", "no:cacheprovider"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(root),
            env=env,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "3 passed" in proc.stdout
    finally:
        srv.shutdown()
