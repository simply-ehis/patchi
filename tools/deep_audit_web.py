"""DEEP AUDIT of the unified Patchi web UI.

Goes beyond route conflicts — validates every cross-reference in the UI:

  1. TEMPLATE LINKS   - every internal href="..." in every template resolves
                        to a registered route or static file.
  2. JS/TEMPLATE FETCHES - every fetch('/...') target exists as a route.
  3. STATIC ASSETS    - every src="/static/..." exists on disk.
  4. TEMPLATES USED   - every TemplateResponse("x.html") file exists.
  5. WEBSOCKET ACTIONS- actions sent by client JS have handlers in /ws/v2.
  6. DOM CONTRACT     - element IDs referenced by dashboard_v2.js exist in
                        dashboard_v2.html.
  7. ALL ROUTES RENDER- TestClient sweep, param-less GETs < 500.
  8. MULTI-PROJECT    - live test: two projects, discover -> switch -> verify
                        the served brain actually changes.

Exits non-zero on failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

failures: list[str] = []
passed = 0


def ok(name: str, detail: str = "") -> None:
    global passed
    passed += 1
    print(f"PASS  {name}" + (f" - {detail}" if detail else ""))


def fail(name: str, detail: str) -> None:
    failures.append(f"{name}: {detail}")
    print(f"FAIL  {name} - {detail}")


TPL_V2 = ROOT / "patchi" / "web" / "templates_v2"
TPL_V1 = ROOT / "patchi" / "web" / "templates"
STATIC = ROOT / "patchi" / "web" / "static"


def extract(pattern: str, text: str) -> list[str]:
    return re.findall(pattern, text)


def main() -> int:
    # Build app once for route table + TestClient
    proj_a = ROOT / ".audit_proj_a"
    proj_b = ROOT / ".audit_proj_b"
    from patchi.core.config import init_project

    init_project(proj_a)
    init_project(proj_b)
    # Distinct brains so we can prove switching works
    (proj_a / ".patchi" / "memory" / "brain.json").write_text('{"project_purpose": "PROJECT_ALPHA"}', encoding="utf-8")
    (proj_b / ".patchi" / "memory" / "brain.json").write_text('{"project_purpose": "PROJECT_BETA"}', encoding="utf-8")

    from patchi.web.app import create_app

    app = create_app(proj_a)

    route_paths: set[str] = set()
    for r in app.routes:
        p = getattr(r, "path", "")
        if p:
            route_paths.add(p)

    def route_exists(path: str) -> bool:
        if path in route_paths:
            return True
        # parameterized match
        for rp in route_paths:
            if "{" in rp and re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", rp), path):
                return True
        # dynamically-built URL: captured part ends at a separator that is
        # followed by JS concatenation (e.g. fetch('/x/' + id)) — accept when
        # some registered route extends this prefix.
        if path.endswith("/"):
            base = path.rstrip("/")
            for rp in route_paths:
                if rp.startswith(path):
                    return True
        return False

    templates = sorted(list(TPL_V2.glob("*.html")) + list(TPL_V1.glob("*.html")))
    js_files = [STATIC / "dashboard_v2.js"]

    # ── 1+2+3: links, fetches, static refs across templates & JS ──────────
    href_re = re.compile(r'''(?:href|src)=["']([^"']+)["']''')
    fetch_re = re.compile(r"""fetch\(\s*['"`]([^'"`$]+)['"`]""")

    bad_links: list[str] = []
    n_internal = n_fetch = n_static = 0

    for f in templates + js_files:
        if not f.is_file():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        # strip jinja blocks to avoid templated URLs false-positives
        text_clean = re.sub(r"\{\{.*?\}\}", "", text)

        for href in extract(href_re, text):
            if href.startswith(("http://", "https://", "#", "mailto:", "data:", "javascript:")):
                continue
            href = href.split("#")[0]
            if not href.startswith("/"):
                continue
            if href.startswith("/static/"):
                n_static += 1
                rel = href[len("/static/"):]
                if not (STATIC / rel).is_file():
                    # allow subdirectory-less css/js already verified; report missing
                    bad_links.append(f"{f.name}: static missing {href}")
                continue
            n_internal += 1
            if "{{" in href or "{%" in href:
                continue  # templated URL can't be checked statically
            if not route_exists(href):
                bad_links.append(f"{f.name}: href {href} has no route")

        for url in extract(fetch_re, text):
            if url.startswith("http"):
                continue
            n_fetch += 1
            if "{{" in url:
                continue
            if "?" in url:
                url = url.split("?")[0]
            if not route_exists(url):
                bad_links.append(f"{f.name}: fetch {url} has no route")

    if bad_links:
        for b in bad_links:
            fail("link-check", b)
    else:
        ok(f"link-check: {n_internal} hrefs, {n_fetch} fetches, {n_static} static refs all resolve")

    # ── 4: templates referenced by code exist ──────────────────────────────
    routes_py = (ROOT / "patchi" / "web").rglob("*.py")
    tpl_re = re.compile(r'TemplateResponse\(\s*[^,]+,\s*"([^"]+\.html)"')
    missing_tpl: list[str] = []
    used = 0
    for py in routes_py:
        text = py.read_text(encoding="utf-8", errors="replace")
        for name in extract(tpl_re, text):
            used += 1
            if not ((TPL_V1 / name).is_file() or (TPL_V2 / name).is_file()):
                missing_tpl.append(f"{py.name}: {name}")
    if missing_tpl:
        for m in missing_tpl:
            fail("template-used", m)
    else:
        ok(f"template-used: {used} referenced templates all on disk")

    # ── 5: websocket action coverage ────────────────────────────────────────
    dv2_py = (ROOT / "patchi" / "web" / "routes" / "dashboard_v2.py").read_text(encoding="utf-8")
    handled = set(extract(r'action == "([a-z_.]+)"', dv2_py))
    legacy_py = (ROOT / "patchi" / "web" / "app.py").read_text(encoding="utf-8")
    handled |= set(extract(r'action == "([a-z_.]+)"', legacy_py))

    sent: set[str] = set()
    send_re = re.compile(r"send\(\s*\{\s*action:\s*['\"]([a-z_.]+)['\"]")
    body_re = re.compile(r"action:\s*['\"]([a-z_.]+)['\"]")
    for f in templates + js_files:
        if not f.is_file():
            continue
        t = f.read_text(encoding="utf-8", errors="replace")
        sent |= set(extract(send_re, t))
        # only count ones that look like WS sends (heuristic: also matches tool bodies; filter below)
        for a in extract(body_re, t):
            if a.startswith(("queue.", "status.", "fix.", "spawn.", "mode.", "scan.", "council_", "start_", "subscribe")):
                sent.add(a)

    unhandled = sorted(a for a in sent if a not in handled and a != "ping")
    # 'ping' is handled separately; ignore pure-REST triggers
    if unhandled:
        for u in unhandled:
            fail("ws-action", f"'{u}' sent by client but no handler")
    else:
        ok(f"ws-actions: all {len(sent)} client actions handled")

    # ── 6: DOM contract for dashboard_v2.js ────────────────────────────────
    js = (STATIC / "dashboard_v2.js").read_text(encoding="utf-8")
    ids_used = set(extract(r"\$\('#([A-Za-z0-9_-]+)'\)", js)) | set(
        extract(r"getElementById\('([A-Za-z0-9_-]+)'\)", js)
    )
    html = (TPL_V2 / "dashboard_v2.html").read_text(encoding="utf-8")
    ids_defined = set(extract(r'id="([A-Za-z0-9_-]+)"', html))
    # IDs created dynamically by JS itself (element.id = '...' or id='...' strings)
    dyn_ids = set(extract(r"id=\\?['\"]([A-Za-z0-9_-]+)", js))
    dyn_ids |= set(extract(r"\.id\s*=\s*['\"]([A-Za-z0-9_-]+)['\"]", js))
    missing_ids = sorted(i for i in ids_used if i not in ids_defined and i not in dyn_ids)
    # IDs only needed when their section renders (other pages use shared JS too)
    other_pages_ids = set()
    for f in TPL_V2.glob("*.html"):
        if f.name != "dashboard_v2.html":
            other_pages_ids |= set(extract(r'id="([A-Za-z0-9_-]+)"', f.read_text(encoding="utf-8", errors="replace")))
    truly_missing = [i for i in missing_ids if i not in other_pages_ids]
    if truly_missing:
        for i in truly_missing:
            fail("dom-contract", f"#{i} referenced by JS but not in any template")
    else:
        ok(f"dom-contract: {len(ids_used)} JS-referenced IDs present")

    # ── 7: all routes render ────────────────────────────────────────────────
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        from starlette.testclient import TestClient

    client = TestClient(app, raise_server_exceptions=False)
    bad_render = []
    checked = 0
    for r in app.routes:
        p = getattr(r, "path", "")
        methods = getattr(r, "methods", None)
        if not methods or "GET" not in methods or "{" in p:
            continue
        resp = client.get(p)
        checked += 1
        if resp.status_code >= 500:
            bad_render.append(f"{p} -> {resp.status_code}")
    if bad_render:
        for b in bad_render:
            fail("render", b)
    else:
        ok(f"render: {checked} GET routes healthy")

    # ── 8: multi-project discovery + live switch ────────────────────────────
    disc = client.get("/api/tenant/discover").json()
    found_paths = {d["path"] for d in disc.get("discovered", [])}
    if str(proj_b.resolve()) in found_paths or str(proj_a.resolve()) in found_paths:
        ok(f"discover: found {len(found_paths)} project(s) near active root")
    else:
        fail("discover", "did not find seeded sibling projects")

    # Switch A -> B and confirm the brain payload changes
    before = client.get("/api/v2/tools/execute", )  # warm
    sw = client.post("/api/tenant/switch", json={"path": str(proj_b)})
    if sw.status_code != 200 or not sw.json().get("success"):
        fail("switch", f"status={sw.status_code} body={sw.text[:120]}")
    else:
        page = client.get("/")
        if "PROJECT_BETA" in page.text or True:
            # brain is fetched via API/tool; check tool result instead
            tr = client.post("/api/v2/tools/execute", json={"tool": "get_brain", "parameters": {}})
            data = tr.json().get("result", {}).get("brain", {})
            if data.get("project_purpose") == "PROJECT_BETA":
                ok("switch: root swapped, served brain is now PROJECT_BETA")
            else:
                fail("switch", f"brain shows {data.get('project_purpose')!r}")

    # Safety: switching into a non-project must be refused
    nonproj = ROOT / ".audit_nonproj"
    nonproj.mkdir(exist_ok=True)
    refuse = client.post("/api/tenant/switch", json={"path": str(nonproj)})
    if refuse.status_code == 400:
        ok("switch-safety: refuses dirs without .patchi (no silent init)")
    else:
        fail("switch-safety", f"expected 400, got {refuse.status_code}")

    # cleanup
    import shutil

    for d in (proj_a, proj_b, nonproj, ROOT / ".patchi_conflict_tmp"):
        shutil.rmtree(d, ignore_errors=True)

    print()
    print(f"DEEP AUDIT RESULT: {passed} passed, {len(failures)} failed")
    for f_ in failures:
        print(f"  FAILED: {f_}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
