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
TRACK = "#1a1d27"      # --color-bg-secondary: a distribution bar's empty track
SURFACE = "#1e2130"
BORDER = "#2d3348"
INK = "#e1e4ea"
SECOND = "#b6bece"     # --rbp-text-secondary
MUTED = "#9aa3b2"
AMBER = "#D9A05B"

_FACES = {
    "bold": ["/System/Library/Fonts/HelveticaNeue.ttc",
             "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
             "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"],
    "regular": ["/System/Library/Fonts/HelveticaNeue.ttc",
                "/System/Library/Fonts/Supplemental/Arial.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"],
    # SF Mono first: it is what the site's ui-monospace stack resolves to on
    # the machine this is authored on.
    "mono": ["/System/Library/Fonts/SFNSMono.ttf",
             "/System/Library/Fonts/Menlo.ttc",
             "/System/Library/Fonts/Supplemental/Courier New Bold.ttf",
             "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"],
}
# HelveticaNeue.ttc is a collection; index 0 is Regular and 1 is Bold.
_INDEX = {"bold": 1, "regular": 0, "mono": 0}
_warned = set()


# THE SITE'S OWN FACE. static/fonts/inter-latin.woff2 is what every page loads,
# so the card is set in it rather than in whatever sans the authoring machine
# has. It is a variable WOFF2, which FreeType only opens when it was built with
# brotli, so on a Pillow that cannot read it directly it is unwrapped to a TTF in
# memory with fontTools (`pip install fonttools brotli`). Neither is on the
# publish path; see the module docstring.
INTER = os.path.join(ROOT, "static", "fonts", "inter-latin.woff2")
_inter_bytes = None


def inter(size, weight):
    global _inter_bytes
    import io
    try:
        f = ImageFont.truetype(INTER, size)
    except OSError:
        if _inter_bytes is None:
            try:
                from fontTools.ttLib import TTFont
                tt = TTFont(INTER)
                tt.flavor = None
                buf = io.BytesIO()
                tt.save(buf)
                _inter_bytes = buf.getvalue()
            except Exception as exc:  # pragma: no cover - authoring tool
                sys.exit(f"cannot read {os.path.relpath(INTER, ROOT)} ({exc}).\n"
                         "pip install fonttools brotli, then re-run. The card is "
                         "set in the site's face and has no substitute.")
        f = ImageFont.truetype(io.BytesIO(_inter_bytes), size)
    f.set_variation_by_axes([weight])
    return f


def _mix(a, b, t):
    """`b` at opacity `t` over `a`, which is how the site draws a dimmed bar."""
    a = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


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


def social_card(path):
    """1200x630, the one size every unfurler crops from.

    Slack, Teams, X, LinkedIn and iMessage all want a raster here; none of them
    render an SVG og:image, which is why this is a PNG and not the vector the rest
    of the site's marks are.

    DRAWN FROM THE FRONT PAGE AS IT IS, redrawn 2026-09-29. The first card used
    vertical amber rails along its base, the per-row days-public device, and set
    everything in Helvetica. The rails left the site and the lead became a count
    beside a distribution of horizontal age bars, set in Inter, so a card pasted
    beside a link to the site looked like a different product.

    So this is the site's lead: the header bar, the name where the count sits,
    and the distribution panel's shape beside it, older buckets dimmed as the
    default view dims them. The name stands in for the count because the count
    is in og:title, which every unfurler renders as text beside this image; see
    the module docstring.

    The bars are a fixed pattern with no labels and no figures, so they read as
    the site's vocabulary rather than as a data claim, and re-running this script
    reproduces the asset byte for byte.
    """
    W, H = 1200, 630
    M = 80                       # one margin, used on both sides and reused below
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)

    # The header bar, as every page has it.
    d.rectangle([0, 0, W, 64], fill=SURFACE)
    d.line([0, 64, W, 64], fill=BORDER, width=1)
    d.text((M, 32), "RBP Tracker", font=inter(26, 700), fill=INK, anchor="lm")

    # The lead. Weight 650 is .cmd-count b's.
    d.text((M, 118), "Reserved", font=inter(92, 650), fill=INK)
    d.text((M, 218), "but Public", font=inter(92, 650), fill=AMBER)
    d.multiline_text(
        (M, 350),
        "CVE IDs that are reserved,\nreferenced in a public advisory,\nand still unpublished.",
        font=inter(28, 400), fill=SECOND, spacing=12)

    # The distribution panel: a rule over five bars on their tracks, oldest
    # bucket first as the default sort has it. The three the default window
    # holds back are drawn at .distbar.out's 0.4 opacity.
    px0, px1 = 690, W - M
    d.line([px0, 126, px1, 126], fill=INK, width=2)
    buckets = [(0.30, True), (0.13, True), (0.50, True), (1.00, False), (0.34, False)]
    y = 162
    for frac, out in buckets:
        d.rounded_rectangle([px0, y, px1, y + 22], radius=4, fill=TRACK)
        d.rounded_rectangle([px0, y, px0 + (px1 - px0) * frac, y + 22], radius=4,
                            fill=_mix(TRACK, AMBER, 0.4) if out else AMBER)
        y += 52

    d.line([M, 548, W - M, 548], fill=BORDER, width=1)
    d.text((M, 588), "rbptracker.org", font=font("mono", 26), fill=INK, anchor="lm")
    d.text((W - M, 588), "A count of a state, not of violations.",
           font=inter(22, 400), fill=MUTED, anchor="rm")

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
