"""
Web-layer tests for the Smart Agent console + live event stream.

Uses FastAPI's TestClient. The heavy agent run is stubbed (patched) so the
test exercises the *wiring* — route registration, request handling, HTML page,
and the WebSocket broadcast path — without scanning the whole repo.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import patchi.core.ai.smart as smart_mod
from patchi.web.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Stub the agent so the background task is instant & deterministic.
    async def fake_run(self, goal, max_steps=6):
        self._emit({"event": "agent.completed",
                    "data": {"findings_count": 0, "steps": 0}})
        return {"steps_executed": [], "events": 1, "total_findings": 0,
                "steps_planned": ["scan_vulnerabilities"]}

    monkeypatch.setattr(smart_mod.SmartAgent, "run", fake_run)
    app = create_app(tmp_path)
    return TestClient(app)


def test_smart_page_renders(client):
    resp = client.get("/smart")
    assert resp.status_code == 200
    assert "Smart Agent" in resp.text
    # The page must carry the goal input + run button.
    assert "smart-goal" in resp.text
    assert "smart-run" in resp.text


def test_smart_run_route(client):
    resp = client.post("/api/smart/run",
                       json={"goal": "audit for security", "max_steps": 3})
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert "stream" in body["message"].lower() or "ws" in body["message"].lower()


def test_smart_ws_streams_events(client):
    # Connect to the WS; the server pushes at least a status frame on connect.
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_json()
        assert isinstance(msg, dict)
        assert "event" in msg
