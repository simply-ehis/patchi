"""Conflict & integrity audit for the merged Patchi web app.

Checks the things e2e happy-paths can't catch:

  A. ROUTE CONFLICTS - duplicate (method, path) pairs across all mounted
     routers. FastAPI serves the FIRST match, so duplicates silently shadow.

  B. CRITICAL ENDPOINTS - merged landing page ownership + v1 APIs/websockets
     still present after the merge.

  C. EVERY PARAM-LESS GET ROUTE RENDERS - hits each route via TestClient;
     a missing template or import error surfaces as a 5xx here.

  D. STATIC ASSETS - nav-referenced assets exist on disk.

  E. CLI PARSER HEALTH - `p web` flags build without argparse conflicts
     against every other registered command.

Exits non-zero on any failure.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

failures: list[str] = []
passed = 0


def ok(name: str, detail: str = "") -> None:
    global passed
    passed += 1
    print(f"PASS  {name}" + (f" - {detail}" if detail else ""))


def fail(name: str, detail: str) -> None:
    failures.append(f"{name}: {detail}")
    print(f"FAIL  {name} - {detail}")


def main() -> int:
    root = Path(__file__).resolve().parent.parent.parent / ".patchi_conflict_tmp"
    from patchi.core.config import init_project

    init_project(root)

    from patchi.web.app import create_app

    app = create_app(root)

    # -- A. Route conflict detection ----------------------------------------
    seen: dict[tuple[str, str], str] = {}
    dupes: list[str] = []

    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not path or not methods:
            continue  # mounts / single-method websocket routes
        for m in methods:
            key = (m, path)
            handler = getattr(route, "name", "?")
            if key in seen:
                dupes.append(f"{m} {path}: '{seen[key]}' shadowed by '{handler}'")
            else:
                seen[key] = handler

    if dupes:
        for d in dupes:
            fail("route-conflict", d)
    else:
        ok(f"route-conflicts: none across {len(seen)} unique (method, path) routes")

    # -- B. Critical endpoints present & correctly owned --------------------
    owner_by_key: dict[tuple[str, str], str] = {}
    all_paths: set[str] = set()
    for route in app.routes:
        p = getattr(route, "path", "")
        all_paths.add(p)
        for m in getattr(route, "methods", []) or []:
            owner_by_key[(m, p)] = getattr(route, "name", "")

    checks = [
        (("GET", "/"), "dashboard_v2"),  # merged landing owned by v2
        (("GET", "/findings"), None),
        (("GET", "/review"), None),
        (("GET", "/chat"), None),
        (("GET", "/guard"), None),
        (("GET", "/hosted"), None),
        (("GET", "/api/v2/tools/list"), None),
        (("GET", "/api/hosted/v2/overview"), None),
        (("GET", "/api/hosted/status"), None),  # v1 hosted API untouched
        (("GET", "/api/hosted/tokens"), None),  # v1 hosted API untouched
        (("GET", "/ws"), None),
        (("GET", "/ws/v2"), None),
    ]
    for (m, p), want in checks:
        if (m, p) in owner_by_key:
            name = owner_by_key[(m, p)]
            if want is not None and want not in name:
                fail(f"owner {m} {p}", f"expected *{want}*, got {name}")
            else:
                ok(f"{m} {p} -> {name}")
        elif p in all_paths:
            ok(f"{m} {p} (websocket/partial-methods) present")
        else:
            fail(f"endpoint {m} {p}", "MISSING after merge")

    # -- C. Every param-less GET route renders without server error ----------
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        from starlette.testclient import TestClient  # type: ignore

    client = TestClient(app, raise_server_exceptions=False)
    skipped_params = 0
    rendered = 0
    bad: list[str] = []

    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", None)
        if not methods or "GET" not in methods:
            continue
        if "{" in path:
            skipped_params += 1
            continue
        # WebSockets appear as routes without .methods; guarded above.
        resp = client.get(path)
        rendered += 1
        if resp.status_code >= 500:
            bad.append(f"{path} -> {resp.status_code}")

    if bad:
        for b in bad:
            fail("render-check", b)
    else:
        ok(f"render-check: {rendered} GET routes < 500 ({skipped_params} parameterized skipped)")

    # Spot-check merged pages return real content, not empty shells
    for p, marker in (
        ("/", "Mission Control"),
        ("/hosted", "Hosted"),
        ("/council", "Council"),
    ):
        r = client.get(p)
        if r.status_code == 200 and marker in r.text:
            ok(f"content {p} contains '{marker}'")
        else:
            fail(f"content {p}", f"status={r.status_code}, marker '{marker}' missing")

    # /v2 alias must forward to /
    r = client.get("/v2")
    ok_ = r.status_code in (200, 307) and ("Mission Control" in r.text or r.headers.get("location") == "/")
    (ok if ok_ else fail)("alias /v2", f"status={r.status_code}")

    # -- D. Static assets referenced by the unified nav ----------------------
    static_dir = Path(__file__).resolve().parent.parent.parent / "patchi" / "web" / "static"
    for asset in ("dashboard_v2.css", "dashboard_v2.js"):
        f = static_dir / asset
        (ok if f.is_file() and f.stat().st_size > 0 else fail)(f"static {asset}", "" if f.exists() else "missing")

    for tpl in (
        "dashboard_v2.html",
        "council_v2.html",
        "brain_map_v2.html",
        "attack_timeline_v2.html",
        "live_tests_v2.html",
        "hosted.html",
    ):
        f = Path(__file__).resolve().parent.parent.parent / "patchi" / "web" / "templates_v2" / tpl
        (ok if f.is_file() else fail)(f"template {tpl}", "" if f.exists() else "missing")

    # -- E. CLI parser health with `p web` flags ------------------------------
    try:
        from patchi.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["web", "--port", "9001"])
        assert args.port == 9001 and args.host == "127.0.0.1"
        parser.parse_args(["scan", "--json"])  # other command unaffected
        parser.parse_args(["web", "--help"]) if False else None
        ok("cli-parser: 'p web' flags coexist with all commands")
    except SystemExit as e:
        fail("cli-parser", f"argparse exited with {e.code}")
    except Exception as e:
        fail("cli-parser", str(e)[:120])

    # Cleanup temp project
    import shutil

    shutil.rmtree(root, ignore_errors=True)

    print()
    print(f"AUDIT RESULT: {passed} passed, {len(failures)} failed")
    for f in failures:
        print(f"  FAILED: {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
