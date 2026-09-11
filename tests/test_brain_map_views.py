"""Brain map view-switcher overlap test.

Boots the real web server (uvicorn subprocess), drives the dashboard in a
headless Chromium via Playwright, clicks every 2D and 3D view button, and
asserts that each layout renders the full node set with ZERO overlapping
positions.

The test injects a deterministic synthetic graph (multi-root, mixed node
types) through the dashboard's own init path so it is self-contained and does
not depend on prior scan data.

Regression coverage:
  - 2D radial previously stacked all depth-0 (root) nodes at the exact
    canvas center (fixed in canvas.js).
  - 3D radial had the identical bug: every depth-0 node at (0, 0, 0)
    (fixed in brain3d.js).

Skips gracefully when Playwright is not installed.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# 2D view button ids (canvas.js switchView)
VIEWS_2D = ["view-graph", "view-tree", "view-spiral", "view-grid", "view-radial", "view-cluster"]
# 3D view button ids (BrainMap3D.switchView)
VIEWS_3D = [
    "view3d-force3d",
    "view3d-tree3d",
    "view3d-spiral3d",
    "view3d-helix3d",
    "view3d-sphere3d",
    "view3d-grid3d",
    "view3d-cluster3d",
    "view3d-radial3d",
]

# Deterministic synthetic graph: 12 roots (the radial-overlap regression case)
# + children/leaves, with mixed node types. Served through the real
# /api/brain-map/* endpoints via route interception, so the dashboard's own
# init path renders it exactly like real scan data.
def _synthetic_graph() -> tuple:
    types = ["default", "default", "default", "route_handler", "config"]
    nodes, edges = [], []
    for r in range(12):
        root_id, child_id, leaf_id = f"root{r}", f"child{r}", f"leaf{r}"
        nodes.append({"id": root_id, "path": root_id + ".py", "label": root_id,
                      "type": types[r % len(types)], "finding_count": r % 4,
                      "severity": "medium"})
        nodes.append({"id": child_id, "path": child_id + ".py", "label": child_id,
                      "type": "default", "finding_count": 0, "severity": "info"})
        nodes.append({"id": leaf_id, "path": leaf_id + ".ts", "label": leaf_id,
                      "type": "default", "finding_count": 1, "severity": "low"})
        edges.append({"from": root_id, "to": child_id})
        edges.append({"from": child_id, "to": leaf_id})
    # A few cross edges so graph/cluster layouts have more structure.
    edges.append({"from": "root0", "to": "child1"})
    edges.append({"from": "root2", "to": "leaf0"})
    return nodes, edges


SYNTH_NODES, SYNTH_EDGES = _synthetic_graph()


def _intercept_brain_api(page, nodes, edges) -> None:
    """Serve the synthetic graph through the dashboard's real API endpoints."""
    import json

    def _handle(route):
        url = route.request.url
        if url.endswith("/api/brain-map/nodes"):
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps({"nodes": nodes}))
        elif url.endswith("/api/brain-map/edges"):
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps({"edges": edges}))
        else:
            route.continue_()

    page.route("**/api/brain-map/*", _handle)

RENDER_2D_JS = """() => {
  // Walk every Konva stage; nodes are shapes carrying a nodeId attr,
  // positioned by their parent group.
  const out = {};
  (window.Konva ? Konva.stages : []).forEach(stage => {
    try {
      stage.find('Circle,Rect,RegularPolygon').forEach(sh => {
        const id = sh.getAttr('nodeId');
        if (!id) return;
        const g = sh.getParent();
        out[id] = [Math.round(g.x() * 10) / 10, Math.round(g.y() * 10) / 10];
      });
    } catch (_) {}
  });
  return out;
}"""

RENDER_3D_JS = """() => {
  const out = {};
  if (!window.BrainMap3D || !window.BrainMap3D.getPositions) return out;
  const raw = BrainMap3D.getPositions();
  Object.keys(raw).forEach(id => {
    const p = raw[id];
    out[id] = [Math.round(p[0] * 10) / 10, Math.round(p[1] * 10) / 10, Math.round(p[2] * 10) / 10];
  });
  return out;
}"""

EXPECTED_NODES = 36  # 12 roots + 12 children + 12 leaves

# Render-cap regression graph: 400 nodes (chain with cross edges) so the
# first MAX_RENDERED_NODES (300) get full shapes and the remaining 100 are
# capped to lightweight entries + tiny dim dots.
MAX_RENDERED_NODES = 300
CAP_COUNT = 100
TOTAL_NODES = 400


def _big_graph() -> tuple:
    nodes = [
        {"id": f"node{i:04d}", "path": f"mod{i // 20:02d}/node{i:04d}.py",
         "label": f"node{i:04d}", "type": "default",
         "finding_count": i % 5, "severity": "info"}
        for i in range(TOTAL_NODES)
    ]
    edges = [
        {"from": f"node{i:04d}", "to": f"node{i + 1:04d}"} for i in range(TOTAL_NODES - 1)
    ]
    # A few long-range edges so cluster layouts have real structure.
    edges += [
        {"from": "node0000", "to": "node0100"},
        {"from": "node0150", "to": "node0300"},
    ]
    return nodes, edges


BIG_NODES, BIG_EDGES = _big_graph()


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _assert_no_overlaps(name: str, positions: dict, expected_count: int) -> None:
    assert len(positions) >= expected_count, (
        f"{name}: expected >= {expected_count} rendered nodes, got {len(positions)}"
    )
    seen: dict = {}
    dupes: dict = {}
    for nid, pos in positions.items():
        key = tuple(pos)
        if key in seen:
            dupes.setdefault(key, [seen[key], nid])
        seen[key] = nid
    assert not dupes, (
        f"{name}: {len(dupes)} overlapping node position(s) — {list(dupes.items())[:5]}"
    )


# ── Capped-dot probes ────────────────────────────────────────────────────────
# 2D capped dots are raw Konva.Circle shapes on the node layer carrying the
# custom `_isCapDot` + `_capNodeId` attrs (canvas.js `_drawCappedDots`) — they
# sit at layer level (no parent group). The regression being locked in is the
# dot-count multiplication on view switches, so the probe keys dots by their
# capped node id: every capped node must own exactly one dot, whatever its
# position.
CAPPED_2D_JS = """() => {
  const byId = {};
  (window.Konva ? Konva.stages : []).forEach(stage => {
    try {
      stage.find('Circle').forEach(sh => {
        if (!sh.getAttr('_isCapDot')) return;
        const id = sh.getAttr('_capNodeId') || sh.id();
        if (id) byId[id] = (byId[id] || 0) + 1;
      });
    } catch (_) {}
  });
  return byId;
}"""

# 3D capped dots are tracked by the renderer's own audit hook getStats()
# (capped = dotGroup.children.length) — the source of truth.
CAPPED_3D_STATS_JS = """() => {
  if (!window.BrainMap3D || !window.BrainMap3D.getStats) return null;
  const s = BrainMap3D.getStats();
  return { rendered: s.rendered, capped: s.capped, total: s.nodes };
}"""

# Count capped (position-only, dim-dot) node entries: ids >= node0300 in the
# 400-node synthetic graph always fall past the 300-node cap.
CAPPED_3D_IDS_JS = """() => {
  if (!window.BrainMap3D || !window.BrainMap3D.getPositions) return [];
  const ids = [];
  try {
    const raw = BrainMap3D.getPositions();
    Object.keys(raw).forEach(id => {
      if (/^node0(3|4)/.test(id)) ids.push(id);
    });
  } catch (_) {}
  return ids;
}"""


def _count_dupes(items: list) -> list:
    seen = {}
    dupes = []
    for it in items:
        key = tuple(it)
        if key in seen:
            dupes.append(key)
        seen[key] = True
    return dupes


def _launch_browser(p):
    """Launch headless Chromium, skipping when browsers are not installed."""
    try:
        return p.chromium.launch(headless=True)
    except Exception as exc:
        msg = str(exc)
        if "Executable doesn't exist" in msg or "playwright install" in msg.lower():
            pytest.skip(f"Playwright browsers not installed: {msg[:120]}")
        raise


def test_capped_dots_stable_across_view_switches():
    """400-node graph: exactly MAX_RENDERED_NODES full shapes + the rest as
    capped dim dots, with the dot set stable across every 2D/3D view switch.

    Regression coverage (the live bugs this locks in):
      - Destroying Konva children while iterating their live array skipped
        every other dot, so dots silently multiplied on each view switch
        (100 -> 150 -> 125). Fixed by collect-then-destroy in canvas.js.
      - Capped entries never rendered, so edges to them floated into empty
        space. Both renderers now draw dim dots (canvas.js `_drawCappedDots`,
        brain3d.js capped branch).
    """
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright
    port = _find_free_port()
    base = f"http://127.0.0.1:{port}"
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "patchi.web.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "error"],
        cwd=str(REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            if server.poll() is not None:
                pytest.fail(f"server exited early with code {server.returncode}")
            try:
                with urllib.request.urlopen(base + "/health", timeout=3) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(1)
        else:
            pytest.fail("server did not become healthy in 90s")

        with sync_playwright() as p:
            browser = _launch_browser(p)
            page = browser.new_page(viewport={"width": 1500, "height": 950})
            page_errors = []
            page.on("pageerror", lambda e: page_errors.append(str(e)))
            _intercept_brain_api(page, BIG_NODES, BIG_EDGES)

            page.goto(base + "/", wait_until="domcontentloaded", timeout=60000)
            time.sleep(4)

            # The render cap is adaptive: a quick WebGL benchmark in
            # brain-ui.js picks a per-device limit (headless Chromium runs
            # SwiftShader, so the low 150-node tier is expected here). All
            # assertions below use the page's actual cap.
            cap = page.evaluate("() => window._PATCHI_RENDER_CAP || 300")
            capped_count = TOTAL_NODES - cap

            # Wait until the graph finished its first layout: exactly the cap
            # count of rendered nodes plus one dot per capped node.
            deadline = time.time() + 45
            rendered_count = None
            while time.time() < deadline:
                rendered = page.evaluate(RENDER_2D_JS)
                dots_by_id = page.evaluate(CAPPED_2D_JS)
                if len(rendered) >= cap and len(dots_by_id) == capped_count:
                    rendered_count = len(rendered)
                    break
                time.sleep(1)
            assert rendered_count == cap, (
                f"expected {cap} rendered nodes, got {rendered_count}"
            )

            # ── 2D: switch every view; the capped set must stay exactly
            # CAP_COUNT dots with one dot per capped node (the stale-dot /
            # dot-multiplication regression). Poll past the glide tween
            # (650ms + fade-in, but headless timing varies by layout).
            for vid in VIEWS_2D:
                page.click(f"#{vid}", timeout=10000)
                deadline = time.time() + 15
                while time.time() < deadline:
                    dots_by_id = page.evaluate(CAPPED_2D_JS)
                    if len(dots_by_id) == capped_count:
                        break
                    time.sleep(0.25)
                rendered = page.evaluate(RENDER_2D_JS)
                assert len(rendered) == cap, (
                    f"2D {vid}: expected {cap} rendered nodes, got {len(rendered)}"
                )
                assert len(dots_by_id) == capped_count, (
                    f"2D {vid}: expected {capped_count} capped dots, got {len(dots_by_id)}"
                )
                extra = [i for i, c in dots_by_id.items() if c != 1]
                assert not extra, (
                    f"2D {vid}: {len(extra)} capped node(s) with != 1 dot "
                    f"(dot-multiplication regression) — {extra[:5]}"
                )
                expected_ids = {f"node{i:04d}" for i in range(cap, TOTAL_NODES)}
                missing = expected_ids - set(dots_by_id)
                assert not missing, (
                    f"2D {vid}: capped nodes missing dots — {sorted(missing)[:5]}"
                )

            # ── 3D: the same cap + stability contract via getStats().
            page.click("#btn-3d", timeout=10000)
            deadline = time.time() + 30
            ready = False
            while time.time() < deadline:
                ready = page.evaluate(
                    "() => !!(window.BrainMap3D && window.BrainMap3D.getStats)"
                )
                if ready:
                    break
                time.sleep(1)
            assert ready, "BrainMap3D never initialized (3D libs failed to load)"

            page.evaluate(
                "() => BrainMap3D.loadNodes(window._brainNodes || [], window._brainEdges || [])"
            )
            time.sleep(3)

            for vid in VIEWS_3D:
                page.click(f"#{vid}", timeout=10000)
                # Poll past the 800ms transition (headless timing varies).
                deadline = time.time() + 20
                stats = None
                while time.time() < deadline:
                    stats = page.evaluate(CAPPED_3D_STATS_JS)
                    if stats and stats["capped"] == capped_count:
                        break
                    time.sleep(0.25)
                assert stats is not None, f"3D {vid}: getStats() unavailable"
                assert stats["capped"] == capped_count, (
                    f"3D {vid}: expected {capped_count} capped dots, got {stats['capped']} "
                    f"(stats={stats})"
                )
                assert stats["rendered"] == cap, (
                    f"3D {vid}: expected {cap} rendered, got {stats['rendered']}"
                )
                # All 400 node ids must still be tracked (mesh + capped entries).
                assert stats["total"] == TOTAL_NODES, (
                    f"3D {vid}: expected {TOTAL_NODES} tracked nodes, got {stats['total']}"
                )
                # Positions of the 100 capped entries must be unique.
                capped_ids = page.evaluate(CAPPED_3D_IDS_JS)
                all_pos = page.evaluate(RENDER_3D_JS)
                capped_pos = [all_pos[i] for i in capped_ids if i in all_pos]
                assert len(capped_pos) == CAP_COUNT, (
                    f"3D {vid}: expected {CAP_COUNT} capped positions, got {len(capped_pos)}"
                )
                dupes = _count_dupes(capped_pos)
                assert not dupes, f"3D {vid}: {len(dupes)} overlapping capped dots"

            assert not page_errors, f"page errors: {page_errors[:5]}"
            browser.close()
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


def test_all_brain_map_views_render_without_overlaps():
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright
    port = _find_free_port()
    base = f"http://127.0.0.1:{port}"
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "patchi.web.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "error"],
        cwd=str(REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # Wait for the server to answer /health
        deadline = time.time() + 90
        while time.time() < deadline:
            if server.poll() is not None:
                pytest.fail(f"server exited early with code {server.returncode}")
            try:
                with urllib.request.urlopen(base + "/health", timeout=3) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(1)
        else:
            pytest.fail("server did not become healthy in 90s")

        with sync_playwright() as p:
            browser = _launch_browser(p)
            page = browser.new_page(viewport={"width": 1500, "height": 950})
            page_errors = []
            page.on("pageerror", lambda e: page_errors.append(str(e)))
            # Serve the synthetic graph through the real brain-map API so the
            # dashboard's own fetch/init path renders it (same code path as
            # real scan data) without anything overwriting it afterwards.
            _intercept_brain_api(page, SYNTH_NODES, SYNTH_EDGES)

            page.goto(base + "/", wait_until="domcontentloaded", timeout=60000)
            time.sleep(4)

            # Wait for the brain map to render the synthetic graph.
            deadline = time.time() + 30
            first_count = None
            while time.time() < deadline:
                probe = page.evaluate(RENDER_2D_JS)
                if len(probe) >= EXPECTED_NODES:
                    first_count = len(probe)
                    break
                time.sleep(1)
            assert first_count, "brain map never rendered the injected graph"

            # ── 2D views ───────────────────────────────────────────────
            for vid in VIEWS_2D:
                page.click(f"#{vid}", timeout=10000)
                time.sleep(0.8)
                positions = page.evaluate(RENDER_2D_JS)
                _assert_no_overlaps(f"2D {vid}", positions, first_count)

            # ── 3D views ───────────────────────────────────────────────
            page.click("#btn-3d", timeout=10000)
            # three.js + OrbitControls load lazily from /static; poll for the API
            deadline = time.time() + 30
            while time.time() < deadline:
                ready = page.evaluate(
                    "() => !!(window.BrainMap3D && window.BrainMap3D.getPositions)"
                )
                if ready:
                    break
                time.sleep(1)
            assert ready, "BrainMap3D never initialized (3D libs failed to load)"

            # Make sure 3D has the same synthetic graph (mirrors what
            # toggle3D does with window._brainNodes).
            page.evaluate(
                "() => BrainMap3D.loadNodes(window._brainNodes || [], window._brainEdges || [])"
            )
            time.sleep(3)  # let nodes render after entering 3D

            for vid in VIEWS_3D:
                page.click(f"#{vid}", timeout=10000)
                time.sleep(1.4)  # smooth-transition duration is 800ms
                positions = page.evaluate(RENDER_3D_JS)
                _assert_no_overlaps(f"3D {vid}", positions, first_count)

            # Radial regression: depth-0 roots must not all sit at the origin.
            radial = page.evaluate(RENDER_3D_JS)
            at_origin = [i for i, p in radial.items() if p == [0.0, 0.0, 0.0]]
            assert len(at_origin) <= 1, (
                f"radial3d: {len(at_origin)} nodes stacked at (0,0,0): {at_origin[:5]}"
            )

            assert not page_errors, f"page errors: {page_errors[:5]}"
            browser.close()
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
