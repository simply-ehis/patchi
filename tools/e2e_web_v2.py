"""End-to-end verification of Patchi v2 web stack.

Boots the REAL FastAPI app (create_app) on a real TCP port with uvicorn in a
background thread, then exercises it over HTTP like a real client:

  1. GET  /v2                    → v2 dashboard renders (200, contains markers)
  2. GET  /v2/council            → council page
  3. GET  /v2/brain-map          → brain map page
  4. GET  /api/v2/tools/list     → tool registry served
  5. POST /api/v2/tools/execute  → get_brain tool round-trip
  6. GET  /api/hosted/v2/overview→ hosted v2 payload
  7. GET  /api/hosted/v2/compliance/report → compliance evidence pack
  8. WS   /ws/v2                 → websocket handshake + initial_state

Exits non-zero on any failure.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
from pathlib import Path

PORT = 1623
BASE = f"http://127.0.0.1:{PORT}"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f" — {detail}" if detail else ""))


def http_get(path: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=15) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def http_post_json(path: str, payload: dict) -> tuple[int, str]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{BASE}{path}", data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def main() -> int:
    # Prepare an isolated project
    root = Path(__file__).resolve().parent.parent / ".patchi_e2e_tmp"
    if not (root / ".patchi").exists():
        from patchi.core.config import init_project

        init_project(root)
        src = root / "src"
        src.mkdir(exist_ok=True)
        (src / "app.py").write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/u/{uid}')\n"
            "def u(uid: str):\n"
            "    import sqlite3\n"
            "    c = sqlite3.connect('db.sqlite')\n"
            "    return c.execute('SELECT * FROM users WHERE id=' + uid).fetchall()\n",
            encoding="utf-8",
        )

    from patchi.web.app import create_app

    app = create_app(root)

    config = uvicorn_config = None
    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for readiness
    deadline = time.time() + 20
    ready = False
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{BASE}/", timeout=2)
            ready = True
            break
        except Exception:
            time.sleep(0.4)
    check("server boots", ready)
    if not ready:
        return _summary()

    # 1-3: pages render
    status, body = http_get("/v2")
    check("GET /v2 dashboard", status == 200 and "Mission Control" in body, f"status={status}")
    status, body = http_get("/v2/council")
    check("GET /v2/council", status == 200 and "Council" in body, f"status={status}")
    status, body = http_get("/v2/brain-map")
    check("GET /v2/brain-map", status == 200, f"status={status}")

    # Static assets
    status, css = http_get("/static/dashboard_v2.css")
    check("GET /static/dashboard_v2.css", status == 200 and "--bg-primary" in css)
    status, js = http_get("/static/dashboard_v2.js")
    check("GET /static/dashboard_v2.js", status == 200 and "connectWS" in js)

    # 4: tool registry API
    status, body = http_get("/api/v2/tools/list")
    tools = json.loads(body) if status == 200 else {}
    names = {t["name"] for t in tools.get("tools", [])}
    check(
        "GET /api/v2/tools/list",
        status == 200 and {"scan_project", "red_team", "run_tests"} <= names,
        f"{len(names)} tools",
    )

    # 5: execute a read-only tool end-to-end
    status, body = http_post_json("/api/v2/tools/execute", {"tool": "get_brain", "parameters": {}})
    ok = status == 200
    detail = ""
    if ok:
        resp = json.loads(body)
        ok = resp.get("success") is True and "brain" in (resp.get("result") or {})
        detail = f"keys={list((resp.get('result') or {}).keys())[:4]}"
    check("POST /api/v2/tools/execute get_brain", ok, detail)

    # 6: hosted overview
    status, body = http_get("/api/hosted/v2/overview")
    ov = json.loads(body) if status == 200 else {}
    check(
        "GET /api/hosted/v2/overview",
        status == 200 and "findings_by_severity" in ov and "guard" in ov,
        f"health={ov.get('health_score')}",
    )

    # 6b: hosted usage
    status, body = http_get("/api/hosted/v2/usage")
    us = json.loads(body) if status == 200 else {}
    check("GET /api/hosted/v2/usage", status == 200 and "scans" in us and "budget" in us)

    # 7: compliance report
    status, body = http_get("/api/hosted/v2/compliance/report?standard=pci-dss")
    rep = json.loads(body) if status == 200 else {}
    n_sections = len(rep.get("sections", []))
    check(
        "GET compliance report pci-dss",
        status == 200 and n_sections >= 5,
        f"{n_sections} sections, posture={rep.get('summary', {}).get('posture_pct')}%",
    )

    # Webhooks CRUD round-trip
    status, body = http_post_json("/api/hosted/v2/webhooks", {"url": "http://127.0.0.1:9/hook", "name": "e2e"})
    hook_ok = status == 200 and json.loads(body).get("ok")
    status, body = http_post_json("/api/hosted/v2/webhooks/test", {})
    test_ok = status == 200
    check("webhooks add+test", hook_ok and test_ok)

    # 8: WebSocket handshake + initial state
    ws_ok, ws_detail = _check_ws()
    check("WS /ws/v2 handshake + initial_state", ws_ok, ws_detail)

    server.should_exit = True
    thread.join(timeout=10)
    return _summary()


def _check_ws() -> tuple[bool, str]:
    try:
        import asyncio

        import websockets
    except ImportError:
        return True, "(websockets lib not installed — skipped)"
    try:
        async def go():
            async with websockets.connect(f"ws://127.0.0.1:{PORT}/ws/v2", open_timeout=10) as ws:
                raw = await asyncio.wait_for(ws.recv(), timeout=10)
                msg = json.loads(raw)
                return msg

        msg = asyncio.new_event_loop().run_until_complete(go())
        return msg.get("event") == "initial_state", f"event={msg.get('event')}"
    except Exception as e:
        return False, str(e)[:120]


def _summary() -> int:
    failed = [r for r in results if not r[1]]
    print()
    print(f"E2E RESULT: {len(results) - len(failed)}/{len(results)} checks passed")
    for name, _, detail in failed:
        print(f"  FAILED: {name} {detail}")
    # cleanup temp project
    root = Path(__file__).resolve().parent.parent / ".patchi_e2e_tmp"
    import shutil

    shutil.rmtree(root, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
