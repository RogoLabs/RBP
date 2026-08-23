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
    # Comments stripped. Without this a token whose declaration is followed by
    # an explanatory comment captured the comment text as part of its value.
    css = strip_comments(_read("style.css") + "\n" + _read("rbp.css"))
    light, dark = {}, {}
    # --rbp-* as well as --color-*: the project defines its own AA-corrected
    # tokens and rules point at either family.
    for m in re.finditer(r"([^{}]*?)\{([^{}]*)\}", css, re.S):
        selector, body = m.group(1).strip(), m.group(2)
        if not any(k in body for k in ("--color-", "--rbp-", "--chart-")):
            continue
        found = re.findall(r"(--(?:color|rbp|chart)-[\w-]+)\s*:\s*([^;]+);", body)
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


class Unmeasurable(ValueError):
    """The colour depends on context this module cannot see.

    `inherit` and `currentColor` resolve against the parent element, which needs
    a DOM. Raised rather than guessed, and skipped by the tests, because a
    guessed ratio is worse than an absent one.
    """


# The handful of CSS named colours the stylesheets actually use. Deliberately
# not the full list of 148: an unknown name should raise rather than silently
# resolve to something plausible.
_NAMED = {"white": "#ffffff", "black": "#000000", "transparent": None,
          "red": "#ff0000", "gray": "#808080", "grey": "#808080"}


def clean_value(value):
    """Strip `!important` and surrounding noise from a declaration value."""
    v = (value or "").strip()
    v = re.sub(r"\s*!\s*important\s*$", "", v, flags=re.I).strip()
    return v.rstrip(";").strip()


def resolve(value, toks, depth=0):
    """Follow `var(--x)` to a literal. Chains are followed, not just one hop.

    One hop was not enough: `--rbp-text-secondary` is itself referenced by rules
    that a single lookup left as an unresolved `var()` string, which then raised
    and was reported as "no colour" rather than as a ratio.
    """
    if depth > 8:
        return value
    value = clean_value(value)
    m = re.match(r"var\(\s*(--[\w-]+)\s*(?:,\s*([^)]+))?\)", value)
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
    # Print rules stripped here TOO, not only in discovery. They were excluded
    # from the selector scan and still read back during measurement, so `h1`
    # resolved to the print stylesheet's `#212529 !important` and reported 1.15
    # against a dark screen background for a rule that never runs on a screen.
    css = _strip_at_blocks(strip_comments(css), "print")
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


# Selectors whose colour is not text a reader has to read, so the 4.5 bar does
# not apply. Kept SHORT and justified one by one: every name here is a hole in
# the coverage, and the whole point of discovering selectors rather than typing
# them is that holes have to be argued for rather than arrived at by omission.
_NOT_BODY_TEXT = {
    ":root", "[data-theme=\"dark\"]",
    # Decorative or state-only rules, where colour carries no information that
    # is not also carried by text.
    "table.rbp th[data-sort]:hover",
    "table.rbp th button.sortbtn:hover",
}


def _strip_at_blocks(css, media):
    """Remove `@media <media> { ... }` blocks, braces balanced."""
    out, i = [], 0
    needle = "@media"
    while i < len(css):
        j = css.find(needle, i)
        if j == -1:
            out.append(css[i:])
            break
        head_end = css.find("{", j)
        if head_end == -1:
            out.append(css[i:])
            break
        prelude = css[j:head_end]
        if media not in prelude:
            out.append(css[i:head_end + 1])
            i = head_end + 1
            continue
        out.append(css[i:j])
        depth, k = 1, head_end + 1
        while k < len(css) and depth:
            if css[k] == "{":
                depth += 1
            elif css[k] == "}":
                depth -= 1
            k += 1
        i = k
    return "".join(out)


def _rendered_classes():
    """Every class and id the site's own templates actually use.

    style.css is inherited wholesale from cve.icu and carries components this
    site never renders: .homepage-chart-subtitle, .quick-select-btn, .stat-trend
    and dozens more. Asserting AA over all of them fails the build on dead CSS,
    and a guard that fails on a correct tree gets switched off, which is how the
    a11y suite became seventeen greps in the first place.
    """
    tpl = os.path.join(os.path.dirname(HERE), "templates")
    used = set()
    for name in sorted(os.listdir(tpl)):
        if not name.endswith(".html"):
            continue
        with open(os.path.join(tpl, name)) as f:
            body = f.read()
        for m in re.finditer(r'class="([^"]*)"', body):
            used.update(m.group(1).split())
        for m in re.finditer(r"class='([^']*)'", body):
            used.update(m.group(1).split())
        # Classes assembled in the page's own JavaScript, which is where the
        # chips are written.
        for m in re.finditer(r"chip-[\w-]+", body):
            used.add(m.group(0))
    return used


def _selector_is_rendered(selector, used):
    """True when every class the selector requires is one the templates emit.

    Element-only selectors (`td.desc`, `table.rbp th`) are kept: those elements
    exist wherever a table does.
    """
    classes = re.findall(r"\.([\w-]+)", selector)
    if not classes:
        return True
    return all(c in used for c in classes)


def text_selectors(rendered_only=True):
    """Every rule in the stylesheets that sets a text colour.

    DISCOVERED, NOT TYPED, and that distinction is the entire lesson of review
    item 15. The first fix for that finding parametrised its contrast test over a
    hand-written list of seven chips, and there are eight: `.chip-unmeasured`
    was absent and was still failing at 3.95 in light theme. A hand-typed list
    shipped inside the commit that fixed a finding about hand-typed lists, and
    the missing entry was the one the CSS itself describes as "the largest column
    on the page".

    So the list is generated. A selector that gains a `color` declaration is
    covered the moment it does, without anyone remembering.
    """
    css = strip_comments(_read("style.css") + "\n" + _read("rbp.css"))
    # @media print sets black-on-white and is measured against paper, not
    # against either screen theme. Including it reported `p`, `td` and `span` as
    # failing at 1.15 in dark, which is dark-on-dark for a rule that never runs
    # on a screen.
    css = _strip_at_blocks(css, "print")
    used = _rendered_classes() if rendered_only else None
    found = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        selector, body = m.group(1).strip(), m.group(2)
        if not re.search(r"(?<!-)\bcolor\s*:", body):
            continue
        for part in selector.split(","):
            part = part.strip()
            if not part or part.startswith("@") or part.startswith("--"):
                continue
            # Theme overrides are measured through their base selector, which
            # effective_ratio already resolves; listing both double-counts.
            part = re.sub(r'^\[data-theme="dark"\]\s*', "", part).strip()
            if not part or part in _NOT_BODY_TEXT:
                continue
            if used is not None and not _selector_is_rendered(part, used):
                continue
            if part not in found:
                found.append(part)
    return found


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
        # No colour applies in THIS theme, so the element inherits from its
        # parent, which needs a DOM. `.table` is the live example: it is styled
        # only inside [data-theme="dark"], so in light theme it simply inherits
        # from body. Unmeasurable rather than an error, because "inherits" is a
        # correct answer and treating it as a failure would fail the build on a
        # correct stylesheet.
        raise Unmeasurable(
            f"{selector} declares no colour in the {theme} theme; it inherits")

    base = parse_hex(page_bg) if isinstance(page_bg, str) else page_bg
    if bg and clean_value(bg).lower() not in ("transparent", "none", "inherit",
                                              "unset", "initial"):
        bg_value = clean_value(resolve(bg, toks))
        if bg_value.lower() in _NAMED and _NAMED[bg_value.lower()]:
            bg_value = _NAMED[bg_value.lower()]
        if bg_value.startswith("#"):
            base = parse_hex(bg_value)
        else:
            rgb, alpha = parse_rgba(bg_value)
            base = composite(rgb, alpha, base)

    fg_value = clean_value(resolve(color, toks))
    low = fg_value.lower()
    if low in ("inherit", "currentcolor", "unset", "initial"):
        raise Unmeasurable(f"{selector} inherits its colour; needs a DOM")
    if low in _NAMED:
        named = _NAMED[low]
        if named is None:
            raise Unmeasurable(f"{selector} has a transparent text colour")
        fg_value = named
    if fg_value.startswith("#"):
        fg = parse_hex(fg_value)
    else:
        rgb, alpha = parse_rgba(fg_value)
        fg = composite(rgb, alpha, base)
    return ratio(fg, base)
