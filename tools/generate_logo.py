"""Generate Patchi logo PNG and favicon ICO from the official design."""

import math
from pathlib import Path
from PIL import Image, ImageDraw

OUT_DIR = Path(__file__).resolve().parent.parent / "patchi" / "web" / "static"
SIZE = 1024

# Colors
BG = (245, 230, 208)        # cream
BORDER = (232, 168, 73)     # amber
BRACKET = (45, 55, 72)      # dark


def point_on_rounded_rect(x1, y1, x2, y2, r, dist):
    """Walk the perimeter of a rounded rectangle and return (x, y) at `dist`."""
    sides = []
    w = x2 - x1
    h = y2 - y1
    # top edge (left to right)
    sides.append(((x1 + r, y1), (x2 - r, y1)))
    # top-right corner
    sides.append(("arc", x2 - r, y1, x2, y1 + r, 270, 360))
    # right edge
    sides.append(((x2, y1 + r), (x2, y2 - r)))
    # bottom-right corner
    sides.append(("arc", x2 - r, y2 - r, x2, y2, 0, 90))
    # bottom edge
    sides.append(((x2 - r, y2), (x1 + r, y2)))
    # bottom-left corner
    sides.append(("arc", x1, y2 - r, x1 + r, y2, 90, 180))
    # left edge
    sides.append(((x1, y2 - r), (x1, y1 + r)))
    # top-left corner
    sides.append(("arc", x1, y1, x1 + r, y1 + r, 180, 270))

    total = 2 * (w - 2 * r) + 2 * (h - 2 * r) + 2 * math.pi * r
    dist = dist % total

    for side in sides:
        if side[0] == "arc":
            _, cx1, cy1, cx2, cy2, a_start, a_end = side
            arc_len = (a_end - a_start) / 360 * 2 * math.pi * min(cx2 - cx1, cy2 - cy1) / 2
            # approximate arc center
            arc_cx = (cx1 + cx2) / 2
            arc_cy = (cy1 + cy2) / 2
            arc_r = (cx2 - cx1) / 2
            if dist <= arc_len:
                frac = dist / arc_len
                angle = math.radians(a_start + frac * (a_end - a_start))
                return arc_cx + arc_r * math.cos(angle), arc_cy + arc_r * math.sin(angle)
            dist -= arc_len
        else:
            (sx, sy), (ex, ey) = side
            seg_len = math.hypot(ex - sx, ey - sy)
            if seg_len == 0:
                continue
            if dist <= seg_len:
                frac = dist / seg_len
                return sx + frac * (ex - sx), sy + frac * (ey - sy)
            dist -= seg_len
    return x1 + r, y1


def draw_dashed_rounded_rect(draw, x1, y1, x2, y2, r, color, width, dash, gap):
    w = x2 - x1
    h = y2 - y1
    total = 2 * (w - 2 * r) + 2 * (h - 2 * r) + 2 * math.pi * r
    step = dash + gap
    n = int(total / step)
    for i in range(n):
        d0 = i * step
        d1 = d0 + dash
        pts = []
        for j in range(9):
            t = d0 + (d1 - d0) * j / 8
            pts.append(point_on_rounded_rect(x1, y1, x2, y2, r, t))
        draw.line(pts, fill=color, width=width, joint="curve")


def generate_logo(path: Path):
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    m = 40  # outer margin
    # Filled rounded rect
    draw.rounded_rectangle([m, m, SIZE - m, SIZE - m], radius=180, fill=BG)

    # Dashed border
    bm = 80
    draw_dashed_rounded_rect(draw, bm, bm, SIZE - bm, SIZE - bm, 160, BORDER, 28, 40, 28)

    # Code brackets
    cx, cy = SIZE // 2, SIZE // 2
    off, bh, bw, lw = 140, 260, 160, 72

    # <
    draw.line(
        [(cx - off + bw // 2, cy - bh // 2), (cx - off, cy), (cx - off + bw // 2, cy + bh // 2)],
        fill=BRACKET, width=lw, joint="curve",
    )
    # >
    draw.line(
        [(cx + off - bw // 2, cy - bh // 2), (cx + off, cy), (cx + off - bw // 2, cy + bh // 2)],
        fill=BRACKET, width=lw, joint="curve",
    )

    img.save(path, "PNG")
    return img


def generate_favicon(img: Image.Image, path: Path):
    sizes = [16, 32, 48, 64, 128, 256]
    frames = [img.resize((s, s), Image.LANCZOS) for s in sizes]
    frames[0].save(path, format="ICO", sizes=[(s, s) for s in sizes], append_images=frames[1:])


if __name__ == "__main__":
    logo_path = OUT_DIR / "logo.png"
    favicon_path = OUT_DIR / "favicon.ico"
    logo = generate_logo(logo_path)
    generate_favicon(logo, favicon_path)
    print(f"Created {logo_path}")
    print(f"Created {favicon_path}")
