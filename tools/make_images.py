#!/usr/bin/env python3
"""
Render the raster images the SVG logo can't cover.

Produces:
  docs/og.png            1200x630 social preview (Twitter/Slack/iMessage/Discord)
  docs/logo-512.png      square icon for GitHub's social settings and app stores

Both are drawn here rather than exported from a design tool so the palette stays
in one place and a colour change is a one-line edit.

    python tools/make_images.py
"""

import math
import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")

BG = (10, 12, 17)
SURFACE = (23, 27, 37)
LINE = (36, 41, 56)
FG = (238, 241, 246)
MUTED = (154, 163, 181)
ACCENT = (79, 140, 255)
VIOLET = (123, 92, 255)
GOOD = (55, 211, 155)


def font(size, bold=False):
    """Segoe UI where it exists, DejaVu as the portable fallback."""
    names = (["segoeuib.ttf", "seguisb.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"] if bold
             else ["segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"])
    for n in names:
        for d in (r"C:\Windows\Fonts", "/usr/share/fonts/truetype/dejavu",
                  "/System/Library/Fonts"):
            p = os.path.join(d, n)
            if os.path.exists(p):
                try:
                    return ImageFont.truetype(p, size)
                except OSError:
                    pass
    return ImageFont.load_default()


def rounded(draw, box, r, fill, outline=None, width=1):
    draw.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)


def gradient_tile(size, c1, c2):
    """Diagonal two-stop gradient, used for the logo tile."""
    w, h = size
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            t = (x / max(w - 1, 1) + y / max(h - 1, 1)) / 2
            px[x, y] = (round(c1[0] + (c2[0] - c1[0]) * t),
                        round(c1[1] + (c2[1] - c1[1]) * t),
                        round(c1[2] + (c2[2] - c1[2]) * t))
    return img


def draw_mark(img, x, y, size):
    """The AdFree mark: Wi-Fi arcs broken by a slash, on a gradient tile."""
    s = 4  # supersample, then downscale, so the arcs and slash stay smooth
    S = size * s
    tile = gradient_tile((S, S), ACCENT, VIOLET).convert("RGBA")

    # Round the tile corners via an alpha mask.
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * 0.234), fill=255)
    tile.putalpha(mask)

    art = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(art)

    def sc(v):
        return v / 64 * S

    # Arcs, drawn as circle segments centred on the dot.
    for radius, w, alpha in ((sc(24), sc(4.6), 140), (sc(15), sc(4.6), 205)):
        bbox = [sc(32) - radius, sc(46) - radius, sc(32) + radius, sc(46) + radius]
        d.arc(bbox, start=210, end=330, fill=(255, 255, 255, alpha), width=int(w))
    d.ellipse([sc(32) - sc(3.6), sc(46) - sc(3.6), sc(32) + sc(3.6), sc(46) + sc(3.6)],
              fill=(255, 255, 255, 255))

    # Punch the slash channel out of the arcs, then draw the slash itself.
    cut = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(cut).line([sc(14), sc(52), sc(52), sc(12)],
                             fill=(0, 0, 0, 255), width=int(sc(9)))
    art = Image.composite(Image.new("RGBA", (S, S), (0, 0, 0, 0)), art,
                          cut.split()[3].point(lambda a: 255 if a > 40 else 0))
    d2 = ImageDraw.Draw(art)
    d2.line([sc(14), sc(52), sc(52), sc(12)], fill=(255, 255, 255, 255), width=int(sc(4.4)))

    tile.alpha_composite(art)
    img.paste(tile.resize((size, size), Image.LANCZOS), (x, y),
              tile.resize((size, size), Image.LANCZOS))


def make_og():
    W, H = 1200, 630
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # Soft accent glow behind the headline.
    glow = Image.new("RGB", (W, H), BG)
    gd = ImageDraw.Draw(glow)
    for i in range(70, 0, -1):
        t = i / 70
        r = int(560 * t)
        gd.ellipse([330 - r, -160 - r // 2, 330 + r, -160 + r], fill=(
            round(BG[0] + (ACCENT[0] - BG[0]) * 0.16 * (1 - t)),
            round(BG[1] + (ACCENT[1] - BG[1]) * 0.16 * (1 - t)),
            round(BG[2] + (ACCENT[2] - BG[2]) * 0.16 * (1 - t))))
    img = Image.blend(img, glow, 0.85)
    d = ImageDraw.Draw(img)

    draw_mark(img, 72, 68, 76)
    d.text((166, 92), "AdFree", font=font(38, True), fill=FG)

    d.text((72, 208), "The $10 gadget that blocks", font=font(72, True), fill=FG)
    d.text((72, 292), "ads on ", font=font(72, True), fill=FG)
    w = d.textlength("ads on ", font=font(72, True))
    d.text((72 + w, 292), "every device", font=font(72, True), fill=ACCENT)
    w2 = d.textlength("every device", font=font(72, True))
    d.text((72 + w + w2, 292), " at home", font=font(72, True), fill=FG)

    d.text((72, 402), "Plug it in next to your router. No app, no subscription,",
           font=font(30), fill=MUTED)
    d.text((72, 444), "nothing to install on your phones, laptops or TVs.",
           font=font(30), fill=MUTED)

    # Fact strip along the bottom.
    y = 520
    for i, (big, small) in enumerate([("490k", "domains blocked"),
                                      ("$0", "per month"),
                                      ("0.4 W", "power draw"),
                                      ("20 min", "one-time setup")]):
        x = 72 + i * 268
        rounded(d, [x, y, x + 244, y + 74], 14, SURFACE, LINE, 1)
        d.text((x + 20, y + 12), big, font=font(28, True), fill=GOOD if i == 0 else FG)
        d.text((x + 20, y + 46), small, font=font(18), fill=MUTED)

    out = os.path.join(DOCS, "og.png")
    img.save(out, "PNG", optimize=True)
    print(f"  {out}  ({os.path.getsize(out) // 1024} KB)")


def make_icon():
    size = 512
    img = Image.new("RGB", (size, size), BG)
    draw_mark(img, 0, 0, size)
    out = os.path.join(DOCS, "logo-512.png")
    img.save(out, "PNG", optimize=True)
    print(f"  {out}  ({os.path.getsize(out) // 1024} KB)")


if __name__ == "__main__":
    os.makedirs(DOCS, exist_ok=True)
    make_og()
    make_icon()
