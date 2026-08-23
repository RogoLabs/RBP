"""
WCAG contrast, computed from the stylesheets rather than asserted about them.

Review item 15. `tests/test_a11y.py` is 267 lines and 17 tests, every one a
`re.search` over CSS or template text, and nothing in CI had ever loaded a
document or computed a ratio. Six real failures shipped green behind it,
including every chip on the site failing AA in light theme and `chip-ok` at 2.41
being the marker that renders the nine-condition launch checklist.

The reason a grep suite could not catch them is structural, and it is worth
stating because it is the same shape as three other defects in this project: the
chips are **semi-transparent**. `.chip-must` is `rgba(220, 53, 69, 0.12)` over
whatever the row happens to be, so the effective background is not written down
anywhere in the CSS. It only exists once a colour is composited against a
context, and a regex over source text cannot composite anything.

So this module does the compositing. It is pure arithmetic over the token
values, needs no browser, runs in milliseconds, and produces the same numbers a
browser would for the flat-over-flat case that covers every text-on-background
pair the site actually renders.

WHAT IT DOES NOT COVER, stated so nobody mistakes the coverage for complete:
layout. Horizontal overflow at 375px and the 768px breakpoint collision are
genuinely rendering questions, and nothing here can see them.
"""
from __future__ import annotations

import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CSS = os.path.join(os.path.dirname(HERE), "static", "css")

# WCAG 2.1 1.4.3. Normal text needs 4.5; large text (>=18.66px, or >=14px bold)
# needs 3.0. The chips render at 11.52px/600, which is neither, so the bar for
# them is 4.5 and the "but they are bold" defence does not apply.
AA_NORMAL = 4.5
AA_LARGE = 3.0


def parse_hex(value):
    """'#rgb' or '#rrggbb' -> (r, g, b). Raises on anything else."""
    v = value.strip().lstrip("#")
    if len(v) == 3:
        v = "".join(c * 2 for c in v)
    if len(v) != 6:
        raise ValueError(f"not a hex colour: {value!r}")
    return tuple(int(v[i:i + 2], 16) for i in (0, 2, 4))


_RGBA = re.compile(r"rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*"
                   r"(?:,\s*([\d.]+)\s*)?\)")


def parse_rgba(value):
    """'rgba(r, g, b, a)' or 'rgb(r, g, b)' -> ((r, g, b), alpha)."""
    m = _RGBA.search(value)
    if not m:
        raise ValueError(f"not an rgb/rgba colour: {value!r}")
    r, g, b = (int(float(m.group(i))) for i in (1, 2, 3))
    a = float(m.group(4)) if m.group(4) is not None else 1.0
    return (r, g, b), a


def composite(fg, alpha, bg):
    """Flatten a semi-transparent colour onto an opaque one.

    THE STEP A GREP SUITE CANNOT DO, and the reason every chip failed unnoticed.
    A chip background of `rgba(220, 53, 69, 0.12)` has no fixed value in the
    stylesheet: what the eye receives depends entirely on the row underneath.
    """
    return tuple(round(f * alpha + b * (1 - alpha)) for f, b in zip(fg, bg))


def _channel(c):
    c = c / 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def luminance(rgb):
    r, g, b = (_channel(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(fg, bg):
    """WCAG contrast ratio between two OPAQUE colours, 1.0 to 21.0."""
    a, b = luminance(fg), luminance(bg)
    lo, hi = sorted((a, b))
    return round((hi + 0.05) / (lo + 0.05), 2)


def _read(name):
    with open(os.path.join(CSS, name)) as f:
        return f.read()


def tokens(theme="light"):
    """Every `--color-*` custom property for a theme, as written.

    Light is the bare `:root` block. Dark is `:root` first, then the
    `[data-theme="dark"]` overrides applied on top, which is how the cascade
    actually behaves: the dark block redefines only some tokens and inherits the
    rest, so reading it alone gives a palette the browser never renders.
    """
    css = _read("style.css") + "\n" + _read("rbp.css")
    light, dark = {}, {}
    # --rbp-* as well as --color-*: the project defines its own AA-corrected
    # tokens and rules point at either family.
    for m in re.finditer(r"([^{}]*?)\{([^{}]*)\}", css, re.S):
        selector, body = m.group(1).strip(), m.group(2)
        if "--color-" not in body and "--rbp-" not in body:
            continue
        found = re.findall(r"(--(?:color|rbp)-[\w-]+)\s*:\s*([^;]+);", body)
        if not found:
            continue
        target = dark if "data-theme=\"dark\"" in selector else (
            light if selector.endswith(":root") or ":root" in selector else None)
        if target is None:
            continue
        for name, value in found:
            target[name.strip()] = value.strip()
    if theme == "dark":
        return {**light, **dark}
    return light


def resolve(value, toks, depth=0):
    """Follow `var(--x)` to a literal. Chains are followed, not just one hop.

    One hop was not enough: `--rbp-text-secondary` is itself referenced by rules
    that a single lookup left as an unresolved `var()` string, which then raised
    and was reported as "no colour" rather than as a ratio.
    """
    if depth > 8:
        return value
    m = re.match(r"var\(\s*(--[\w-]+)\s*(?:,\s*([^)]+))?\)", value.strip())
    if not m:
        return value
    nxt = toks.get(m.group(1))
    if nxt is None:
        return (m.group(2) or value).strip()
    return resolve(nxt, toks, depth + 1)


def strip_comments(css):
    """Remove /* ... */ blocks.

    Not cosmetic. This file's own explanatory comments mention selectors by
    name, so an unstripped search for `td.unattributed` matched a COMMENT and
    then ran on to the next rule's braces, returning `.chip-none`'s colours for
    a completely different selector. The harness was confidently reporting a
    ratio for the wrong element.
    """
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def rule_colors(selector, css=None):
    """(color, background) for one selector, as the CASCADE resolves it.

    Takes the LAST matching rule, not the first. `table.rbp th` is declared at
    rbp.css:128 with the inherited token and redeclared at :375 with the
    AA-corrected one; a first-match read reported the value the browser
    overrides, so a rule that had already been fixed still read as failing.
    """
    css = css if css is not None else (_read("style.css") + "\n" + _read("rbp.css"))
    css = strip_comments(css)
    pat = re.compile(r"(?:^|[,{}])\s*" + re.escape(selector) + r"\s*(?:,[^{}]*)?\{([^{}]*)\}",
                     re.M)
    matches = list(pat.finditer(css))
    if not matches:
        return None, None
    color = bg = None
    # Later declarations win, and each property falls back independently.
    for m in matches:
        body = m.group(1)
        c_ = re.search(r"(?<!-)\bcolor\s*:\s*([^;]+);", body)
        b_ = re.search(r"\bbackground(?:-color)?\s*:\s*([^;]+);", body)
        if c_:
            color = c_.group(1).strip()
        if b_:
            bg = b_.group(1).strip()
    return color, bg


def effective_ratio(selector, page_bg, theme="light"):
    """The ratio a reader actually sees for `selector` over `page_bg`.

    `page_bg` is the opaque colour underneath, which for a chip is the table row
    and NOT the value in the chip's own rule.
    """
    toks = tokens(theme)
    color, bg = rule_colors(selector)

    # THEME OVERRIDES ARE PART OF THE CASCADE, so they are part of the ratio.
    #
    # Reading only the base rule measured the LIGHT colour against a DARK
    # background and reported every chip as failing, which is the mirror image
    # of the original defect: a harness confidently wrong about what a reader
    # sees. A dark override sets `color` and sometimes `background`, and each
    # falls back to the base rule independently, exactly as the browser does.
    if theme == "dark":
        d_color, d_bg = rule_colors(f'[data-theme="dark"] {selector}')
        color = d_color or color
        bg = d_bg or bg
    if color is None:
        raise ValueError(f"no color declared for {selector}")

    base = parse_hex(page_bg) if isinstance(page_bg, str) else page_bg
    if bg and bg.strip() not in ("transparent", "none"):
        bg_value = resolve(bg, toks)
        if bg_value.startswith("#"):
            base = parse_hex(bg_value)
        else:
            rgb, alpha = parse_rgba(bg_value)
            base = composite(rgb, alpha, base)

    fg_value = resolve(color, toks)
    if fg_value.startswith("#"):
        fg = parse_hex(fg_value)
    else:
        rgb, alpha = parse_rgba(fg_value)
        fg = composite(rgb, alpha, base)
    return ratio(fg, base)
