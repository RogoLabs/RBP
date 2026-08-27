"""Author the site's raster brand assets. RUN BY HAND; the output is committed.

    python tools/make_brand_assets.py

THIS IS NOT ON THE PUBLISH PATH, and that is the whole point of it existing as a
script rather than as a build step.

The obvious implementation is to generate the social card during `rbp.cli build`
so it can carry the live count. Two reasons it does not:

  - It would put Pillow on the publish path. `requirements.txt` is pandas,
    pyarrow and Jinja2, `deploy.yml` installs exactly that, and PLAN.md 8e says
    "nothing new on the publish path" about a job that runs four times a day. A
    C-extension image library added so a rectangle can have a number on it is a
    bad trade against a publication that must not fail.

  - A count baked into an image goes stale. og:title already renders the live
    count ("1,691 reserved CVE IDs are public and unpublished") and unfurlers show
    it as text beside the image, so a number in the card buys nothing and risks
    the card saying 1,691 next to a title saying 1,847. That is exactly the defect
    review item B1 was about, recreated somewhere new and harder to notice.

So the card is typographic and carries no figure. Nothing in it can go out of
date, and it needs no dependency at build time: `site.build` copies `static/`
wholesale, and `favicon.ico` to the site root.

Fonts are read from the authoring machine because the output is a committed PNG;
no font has to exist on the runner. If the faces below are missing, Pillow's
default bitmap font is used and the result will look wrong -- the script says so
rather than silently shipping it.
"""
from __future__ import annotations

import os
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - authoring tool
    sys.exit("Pillow is needed to author these assets: pip install Pillow\n"
             "It is deliberately NOT in requirements.txt; see this module's docstring.")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "static", "img")

# THE SITE'S OWN PALETTE, not an approximation of it. Every value is the dark
# theme token these assets sit next to, copied from the stylesheet that defines
# it, so a card pasted into Slack beside a screenshot of the site matches it.
#   static/css/style.css   --color-bg-primary / --color-bg-content / --color-border
#                          --color-text-primary
#   static/css/rbp.css     --rbp-age (the days-public signal) / --rbp-text-muted
BG = "#0f1117"
SURFACE = "#1e2130"
BORDER = "#2d3348"
INK = "#e1e4ea"
MUTED = "#9aa3b2"
AMBER = "#D9A05B"

_FACES = {
    "bold": ["/System/Library/Fonts/HelveticaNeue.ttc",
             "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
             "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"],
    "regular": ["/System/Library/Fonts/HelveticaNeue.ttc",
                "/System/Library/Fonts/Supplemental/Arial.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"],
    "mono": ["/System/Library/Fonts/Menlo.ttc",
             "/System/Library/Fonts/Supplemental/Courier New Bold.ttf",
             "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"],
}
# HelveticaNeue.ttc is a collection; index 0 is Regular and 1 is Bold.
_INDEX = {"bold": 1, "regular": 0, "mono": 0}
_warned = set()


def font(kind, size):
    for path in _FACES[kind]:
        if os.path.exists(path):
            try:
                idx = _INDEX[kind] if path.endswith(".ttc") else 0
                return ImageFont.truetype(path, size, index=idx)
            except OSError:
                continue
    if kind not in _warned:
        print(f"  WARNING: no {kind} face found; falling back to a bitmap font. "
              "The committed asset will not look right.", file=sys.stderr)
        _warned.add(kind)
    return ImageFont.load_default()


def tracked(d, xy, text, font_, fill, tracking=0):
    """Draw text with real letter-spacing. PIL has no tracking, and an uppercase
    label without it reads as a cramped word rather than as a label."""
    x, y = xy
    for ch in text:
        d.text((x, y), ch, font=font_, fill=fill)
        x += d.textlength(ch, font=font_) + tracking
    return x


def social_card(path):
    """1200x630, the one size every unfurler crops from.

    Slack, Teams, X, LinkedIn and iMessage all want a raster here; none of them
    render an SVG og:image, which is why this is a PNG and not the vector the rest
    of the site's marks are.

    FULL-BLEED, and not a rounded card with an accent rail down one side. The
    first attempt was exactly that, which is both the most generic layout
    available and a misuse of the site's own device: on the site the amber bar is
    a row's days-public reading, so one bar framing a poster says nothing. Here
    the bars are what they are on the site -- many rows, each a different age --
    used as the texture along the base rather than as a frame.
    """
    W, H = 1200, 630
    M = 96                       # one margin, used on both sides and reused below
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)

    # THE RAILS, drawn FIRST and confined to a band along the base.
    #
    # On the site every row carries a vertical track in the surface colour with an
    # amber fill whose height is how long that ID has been public, so a band of
    # them is "many rows, each a different age" in the site's own vocabulary.
    #
    # A band rather than a full-height field: the first attempt let them span the
    # card and drew them over the type, which was illegible. They are texture, so
    # they sit under the words and out of their way.
    #
    # Deliberately not a chart. No axis, no labels, no figure anywhere near it, so
    # nothing here can be read as a data claim the way a sample CVE ID or a baked
    # in count could. The heights are a fixed pattern rather than a random source,
    # so re-running this script reproduces the asset byte for byte and a
    # regenerated card is never a spurious diff.
    band_top, band_base = 452.0, 548.0
    pattern = [7, 12, 9, 22, 15, 11, 31, 18, 13, 44, 9, 26, 16, 60, 21, 12, 35,
               19, 14, 52, 11, 28, 17, 41, 23, 13, 68, 15]
    span = W - 2 * M
    step = span / len(pattern)
    bw = step * 0.36
    for i, v in enumerate(pattern):
        bx = M + i * step
        h = (v / 68.0) * (band_base - band_top)
        d.rectangle([bx, band_top, bx + bw, band_base], fill=SURFACE)
        d.rectangle([bx, band_base - h, bx + bw, band_base], fill=AMBER)

    tracked(d, (M, 84), "RBP TRACKER", font("mono", 22), MUTED, tracking=3.2)

    d.text((M, 138), "Reserved", font=font("bold", 92), fill=INK)
    d.text((M, 230), "but Public", font=font("bold", 92), fill=AMBER)

    d.multiline_text(
        (M, 348),
        "CVE IDs that are reserved, referenced in a public\nadvisory, and still unpublished.",
        font=font("regular", 31), fill=MUTED, spacing=13)

    d.line([M, 578, W - M, 578], fill=BORDER, width=1)
    d.text((M, 592), "rbptracker.org", font=font("mono", 25), fill=INK)
    d.text((W - M, 596), "A count of a state, not of violations.",
           font=font("regular", 21), fill=MUTED, anchor="ra")

    im.save(path, "PNG", optimize=True)
    return path


# THE MARK, as ratios of the canvas so one definition serves 16px and 180px.
#
# TWO bars, bottom-aligned, one tall and one short. A single bar was the first
# attempt and at 16px it read as an amber blob rather than as anything: the
# rounded square and the bar were nearly the same shape. Two bars of different
# heights read as the site's rail band -- rows of different ages -- and stay
# distinguishable in a strip of twenty tabs, which is the only job a favicon has.
#
# Bottom-aligned and stopping short of the top, like .rail i on the site: the
# height is how long an ID has been public, and a bar that does not reach the top
# is the subject in one shape, an ID out there with the record still not landed.
_BARS = (  # (left, width, top) as fractions; all share the same base
    (0.30, 0.15, 0.24),
    (0.53, 0.15, 0.46),
)
_BASE = 0.79       # bottom of the bars
_RADIUS = 0.18     # corner radius of the ground


def _mark(size, *, transparent_ground=True):
    im = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    if transparent_ground:
        d.rounded_rectangle([0, 0, size - 1, size - 1],
                            radius=max(1, int(size * _RADIUS)), fill=BG)
    else:
        d.rectangle([0, 0, size, size], fill=BG)
    for left, width, top in _BARS:
        d.rectangle([left * size, top * size,
                     (left + width) * size, _BASE * size], fill=AMBER)
    return im


def favicon_ico(path):
    """Multi-size ICO at the SITE ROOT, because browsers request /favicon.ico
    without being told to. An SVG icon in <link> does not stop that request, so
    without this file every first visit takes a 404.

    Each size is drawn at its own resolution rather than downscaled from one
    large master: at 16px a resampled bar goes to mud, and drawing it means the
    bars land on whole pixels."""
    base = _mark(48)
    base.save(path, "ICO", sizes=[(16, 16), (32, 32), (48, 48)])
    return path


def apple_touch(path):
    """180x180, opaque and square. iOS masks and shadows the icon itself, so a
    pre-rounded one is rounded twice and a transparent ground goes black."""
    _mark(180, transparent_ground=False).convert("RGB").save(
        path, "PNG", optimize=True)
    return path


# The SVG mark, generated from the SAME ratios as the raster ones above rather
# than hand-written beside them, so the two cannot drift. Browsers that support it
# prefer this over the ICO; the ICO stays because /favicon.ico is requested
# whether or not it is linked.
#
# Deliberately single-theme. A favicon is identified by its colour in a strip of
# twenty tabs, so it must not follow the reader's theme.
def favicon_svg():
    V = 32
    bars = "\n".join(
        f'<rect x="{left * V:g}" y="{top * V:g}" '
        f'width="{width * V:g}" height="{(_BASE - top) * V:g}" fill="{AMBER}"/>'
        for left, width, top in _BARS)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {V} {V}">\n'
            f'<rect width="{V}" height="{V}" rx="{_RADIUS * V:g}" fill="{BG}"/>\n'
            f'{bars}\n</svg>\n')


def main():
    os.makedirs(IMG, exist_ok=True)
    made = [
        social_card(os.path.join(IMG, "og-card.png")),
        apple_touch(os.path.join(IMG, "apple-touch-icon.png")),
        favicon_ico(os.path.join(ROOT, "static", "favicon.ico")),
    ]
    svg = os.path.join(IMG, "favicon.svg")
    with open(svg, "w", encoding="utf-8") as fh:
        fh.write(favicon_svg())
    made.append(svg)
    for p in made:
        print(f"  wrote {os.path.relpath(p, ROOT)} "
              f"({os.path.getsize(p)} bytes)")
    print("\nCommit these. They are read at build time and generated by nobody.")


if __name__ == "__main__":
    main()
