"""Visual regression baseline management from the terminal.

Commands:
    p vr baseline   — Capture fresh baselines for all discovered routes
    p vr compare    — Compare current screenshots against baselines
    p vr reset      — Delete all baselines (forces re-capture on next run)
    p vr list       — List baselines and evidence screenshots
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def _get_root() -> Path:
    """Find the project root by walking up for .patchi/."""
    cwd = Path.cwd()
    for p in [cwd, *cwd.parents]:
        if (p / ".patchi").is_dir():
            return p
    return cwd


def _find_server(root: Path) -> str | None:
    """Try to find a running Patchi server."""
    import urllib.request

    for port in (1612, 1700, 1701, 1702, 1703, 1704, 1705, 8000, 8080):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            return f"http://127.0.0.1:{port}"
        except Exception:
            continue
    return None


def _discover_routes(root: Path) -> list[str]:
    """Discover web routes from the app or brain map."""
    try:
        from patchi.core.testing.visual_regression_agent import discover_routes

        return discover_routes({}, {})
    except Exception:
        pass
    # Fallback: known common routes
    return ["/", "/findings", "/live-tests", "/assurance", "/chat"]


def run(
    action: str = "list",
    reset: bool = False,
    json_output: bool = False,
    **_kwargs,
) -> None:
    """Dispatch to the appropriate VR baseline subcommand."""
    root = _get_root()
    baseline_dir = root / ".patchi" / "visual_baselines"
    evidence_dir = root / ".patchi" / "evidence" / "screenshots" / "visual_regression"

    if action == "capture" or action == "baseline":
        _cmd_capture(root, baseline_dir, evidence_dir)
    elif action == "compare" or action == "diff":
        _cmd_compare(root, baseline_dir, evidence_dir, json_output)
    elif action == "reset":
        _cmd_reset(root, baseline_dir)
    elif action == "list" or action == "ls":
        _cmd_list(root, baseline_dir, evidence_dir, json_output)
    else:
        print(f"Unknown action: {action}")
        print("Usage: p vr [baseline|compare|reset|list]")
        sys.exit(1)


def _cmd_capture(
    root: Path, baseline_dir: Path, evidence_dir: Path
) -> None:
    """Capture fresh baselines for all discovered routes using Playwright."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright not installed. Run:")
        print("  pip install playwright && playwright install chromium")
        sys.exit(1)

    server_url = _find_server(root)
    if not server_url:
        print("No running Patchi server found.")
        print("Start one with: p web")
        sys.exit(1)

    routes = _discover_routes(root)
    if not routes:
        print("No routes discovered.")
        sys.exit(1)

    print(f"📸 Capturing baselines from {server_url}")
    print(f"   Routes: {len(routes)}")
    print(f"   Baseline dir: {baseline_dir}")

    baseline_dir.mkdir(parents=True, exist_ok=True)
    captured = 0
    skipped = 0

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1280, "height": 720})
        page = ctx.new_page()

        for route in routes:
            slug = route.strip("/").replace("/", "_") or "root"
            shot_path = baseline_dir / slug / "desktop.png"
            shot_path.parent.mkdir(parents=True, exist_ok=True)

            if shot_path.exists():
                skipped += 1
                print(f"   ⏭ {route} (baseline exists, use --reset to overwrite)")
                continue

            try:
                resp = page.goto(f"{server_url}{route}", wait_until="networkidle", timeout=15000)
                status = resp.status if resp else 0
                if status >= 400:
                    print(f"   ⚠ {route} — HTTP {status}")
                    continue
                # Wait for render
                page.wait_for_timeout(1000)
                page.screenshot(path=str(shot_path), full_page=True)
                size_kb = shot_path.stat().st_size // 1024
                print(f"   ✅ {route} → {shot_path.name} ({size_kb} KB)")
                captured += 1
            except Exception as e:
                print(f"   ❌ {route} — {type(e).__name__}: {e}")

        browser.close()

    print(f"\nDone: {captured} captured, {skipped} skipped (already exist)")
    if captured > 0:
        print(f"Baselines saved to: {baseline_dir}")


def _cmd_compare(
    root: Path, baseline_dir: Path, evidence_dir: Path, json_output: bool
) -> None:
    """Compare current screenshots against baselines and report diffs."""
    if not baseline_dir.is_dir():
        print("No baselines found. Run: p vr baseline")
        sys.exit(1)

    try:
        from PIL import Image
    except ImportError:
        print("Pillow not installed. Run: pip install Pillow")
        sys.exit(1)

    evidence_dir.mkdir(parents=True, exist_ok=True)
    changes = []
    clean = 0
    no_baseline = 0

    print("🔍 Comparing screenshots against baselines...\n")

    for slug_dir in sorted(baseline_dir.iterdir()):
        if not slug_dir.is_dir():
            continue
        route = "/" + slug_dir.name.replace("_", "/") if slug_dir.name != "root" else "/"
        for vp_file in slug_dir.glob("*.png"):
            vp_name = vp_file.stem
            # Look for matching current screenshot in evidence dir
            current = evidence_dir / f"{slug_dir.name}_{vp_name}.png"
            if not current.exists():
                no_baseline += 1
                continue

            try:
                base_img = Image.open(vp_file).convert("RGB")
                curr_img = Image.open(current).convert("RGB")
                # Resize to same dimensions if different
                if base_img.size != curr_img.size:
                    curr_img = curr_img.resize(base_img.size)

                # Pixel diff
                base_pixels = list(base_img.getdata())
                curr_pixels = list(curr_img.getdata())
                total = len(base_pixels)
                changed = sum(1 for b, c in zip(base_pixels, curr_pixels, strict=False) if b != c)
                pct = (changed / total) * 100 if total else 0

                if pct > 0.1:  # More than 0.1% changed
                    # Generate diff overlay
                    diff_path = evidence_dir / f"{slug_dir.name}_{vp_name}_diff.png"
                    _generate_diff_overlay(base_img, curr_img, diff_path)
                    changes.append({
                        "route": route,
                        "viewport": vp_name,
                        "changed_pct": round(pct, 2),
                        "changed_pixels": changed,
                        "total_pixels": total,
                        "diff_file": str(diff_path.name),
                    })
                    print(f"   🔴 {route} ({vp_name}): {pct:.1f}% changed — {diff_path.name}")
                else:
                    clean += 1
            except Exception as e:
                print(f"   ⚠ {slug_dir.name}/{vp_name}: {type(e).__name__}: {e}")

    if json_output:
        import json
        print(json.dumps({
            "changes": changes,
            "clean": clean,
            "no_current_screenshot": no_baseline,
            "total_changes": len(changes),
        }, indent=2))
    else:
        print(f"\nResults: {len(changes)} changed, {clean} clean, "
              f"{no_baseline} no current screenshot")
        if changes:
            print("Run `p vr baseline` to update baselines after reviewing changes.")
        else:
            print("✅ All baselines match!")


def _generate_diff_overlay(base_img, curr_img, diff_path: Path) -> None:
    """Generate a pixel-diff overlay image showing changed regions."""
    from PIL import ImageDraw

    # Downscale for faster diffing
    scale = 2
    w, h = base_img.size
    sw, sh = w // scale, h // scale
    base_small = base_img.resize((sw, sh))
    curr_small = curr_img.resize((sw, sh))

    # Create diff image: current with red overlay on changed pixels
    diff = curr_small.copy()
    draw = ImageDraw.Draw(diff)

    base_data = list(base_small.getdata())
    curr_data = list(curr_small.getdata())

    for i, (b, c) in enumerate(zip(base_data, curr_data, strict=False)):
        if b != c:
            x = i % sw
            y = i // sw
            draw.rectangle([x, y, x + scale, y + scale], fill=(255, 50, 50, 180))

    # Draw bounding boxes around changed regions
    _draw_bounding_boxes(draw, base_small, curr_small, sw, sh, scale)

    diff.save(str(diff_path))


def _draw_bounding_boxes(draw, base_img, curr_img, sw, sh, scale) -> None:
    """Draw red bounding boxes around contiguous changed regions."""

    base_data = list(base_img.getdata())
    curr_data = list(curr_img.getdata())

    # Simple flood-fill approach: mark changed pixels, find bounding boxes
    changed = [
        (i % sw, i // sw)
        for i, (b, c) in enumerate(zip(base_data, curr_data, strict=False))
        if b != c
    ]

    if not changed:
        return

    # Cluster nearby changed pixels into boxes
    visited = set()
    boxes = []

    for px, py in changed:
        if (px, py) in visited:
            continue
        # BFS to find connected component
        queue = [(px, py)]
        visited.add((px, py))
        min_x, min_y, max_x, max_y = px, py, px, py

        while queue:
            cx, cy = queue.pop(0)
            min_x = min(min_x, cx)
            min_y = min(min_y, cy)
            max_x = max(max_x, cx)
            max_y = max(max_y, cy)
            for dx, dy in [(-2, 0), (2, 0), (0, -2), (0, 2)]:
                nx, ny = cx + dx, cy + dy
                if 0 <= nx < sw and 0 <= ny < sh and (nx, ny) not in visited:
                    idx = ny * sw + nx
                    if idx < len(base_data) and base_data[idx] != curr_data[idx]:
                        visited.add((nx, ny))
                        queue.append((nx, ny))

        # Draw bounding box with padding
        pad = 4
        x0, y0 = max(0, (min_x - pad) * scale), max(0, (min_y - pad) * scale)
        x1, y1 = min(sw * scale, (max_x + pad) * scale), min(sh * scale, (max_y + pad) * scale)
        if (x1 - x0) > 5 and (y1 - y0) > 5:
            boxes.append((x0, y0, x1, y1))

    # Draw boxes on the original-size diff (upscaling coords)
    # Actually draw on the downscaled diff
    for x0, y0, x1, y1 in boxes[:20]:  # Cap at 20 boxes
        draw.rectangle([x0 // scale, y0 // scale, x1 // scale, y1 // scale],
                       outline=(255, 50, 50), width=2)


def _cmd_reset(root: Path, baseline_dir: Path) -> None:
    """Delete all baselines to force re-capture."""
    if not baseline_dir.is_dir():
        print("No baselines to reset.")
        return

    count = sum(1 for _ in baseline_dir.rglob("*.png"))
    shutil.rmtree(baseline_dir)
    print(f"🗑 Deleted {count} baseline screenshots from {baseline_dir}")
    print("Next `p vr baseline` or `p test visual` will re-create them.")


def _cmd_list(
    root: Path, baseline_dir: Path, evidence_dir: Path, json_output: bool
) -> None:
    """List baselines and evidence screenshots."""
    baselines = []
    if baseline_dir.is_dir():
        for slug_dir in sorted(baseline_dir.iterdir()):
            if not slug_dir.is_dir():
                continue
            route = "/" + slug_dir.name.replace("_", "/") if slug_dir.name != "root" else "/"
            for f in slug_dir.glob("*.png"):
                stat = f.stat()
                baselines.append({
                    "route": route,
                    "viewport": f.stem,
                    "file": str(f.relative_to(root)),
                    "size_kb": round(stat.st_size / 1024, 1),
                })

    screenshots = []
    if evidence_dir.is_dir():
        for f in sorted(evidence_dir.glob("*.png"), key=lambda x: x.stat().st_mtime, reverse=True):
            stat = f.stat()
            screenshots.append({
                "name": f.stem,
                "file": str(f.relative_to(root)),
                "size_kb": round(stat.st_size / 1024, 1),
                "is_diff": "_diff" in f.stem,
            })

    if json_output:
        import json
        print(json.dumps({
            "baselines": baselines,
            "screenshots": screenshots,
            "baseline_count": len(baselines),
            "screenshot_count": len(screenshots),
        }, indent=2))
    else:
        print("📸 Visual Regression Status\n")

        print(f"Baselines: {len(baselines)}")
        if baselines:
            for b in baselines:
                print(f"   {b['route']} ({b['viewport']}) — {b['size_kb']} KB")
        else:
            print("   No baselines. Run: p vr baseline")

        print(f"\nEvidence screenshots: {len(screenshots)}")
        diffs = [s for s in screenshots if s["is_diff"]]
        sources = [s for s in screenshots if not s["is_diff"]]
        if sources:
            print(f"   Source images: {len(sources)}")
            for s in sources[:10]:
                print(f"     {s['name']} — {s['size_kb']} KB")
            if len(sources) > 10:
                print(f"     ... and {len(sources) - 10} more")
        if diffs:
            print(f"   Diff overlays: {len(diffs)}")
            for s in diffs[:5]:
                print(f"     {s['name']} — {s['size_kb']} KB")
        if not screenshots:
            print("   No screenshots yet. Run: p test visual")
