"""WebSocketSecurityAgent verdict policy (Part 7)."""

import tempfile
from pathlib import Path

from patchi.core.agents.base import AgentInput, Severity
from patchi.core.security.websocket_security_agent import WebSocketSecurityAgent


def _run(rel: str, content: str):
    root = Path(tempfile.mkdtemp())
    (root / ".patchi").mkdir(exist_ok=True)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    res = WebSocketSecurityAgent().run(
        AgentInput(root=root, scope=[], brain={}, config={}, extra={})
    )
    return res


def _types(res):
    return [(f.type, f.severity) for f in res.findings]


def test_localhost_ws_skipped():
    res = _run("src/sock.py", "import websocket\nws = websocket.WebSocketApp('ws://localhost:8000/ws')\n")
    assert not [f for f in res.findings if f.type == "unencrypted_websocket"]


def test_remote_ws_high():
    res = _run("src/sock.py", "import websocket\nws = websocket.WebSocketApp('ws://api.example.com/ws')\n")
    assert ("unencrypted_websocket", Severity.HIGH) in _types(res)


def test_no_auth_caps_at_high():
    res = _run(
        "src/sock.py",
        "import websockets\nasync def websocket(ws):\n    await ws.send('hi')\n",
    )
    assert not [f for f in res.findings if f.severity == Severity.CRITICAL]
    assert ("websocket_no_auth", Severity.HIGH) in _types(res)


def test_handler_without_sink_demoted():
    res = _run(
        "src/sock.py",
        "import asyncio\nasync def h():\n    msg = await websocket.receive()\n    print(msg)\n",
    )
    assert ("websocket_no_input_validation", Severity.MEDIUM) in _types(res)


def test_handler_with_sink_high():
    res = _run(
        "src/sock.py",
        "import asyncio\nasync def h():\n    msg = await websocket.receive()\n    eval(msg)\n",
    )
    assert ("websocket_no_input_validation", Severity.HIGH) in _types(res)
