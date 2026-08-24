"""
The viewport widths the render tests sweep, derived from the stylesheets.

PLAN.md 8e: "widths parsed from the `@media` preludes in both stylesheets as
{b-1, b, b+1} plus 320/375/1280, never typed".

The "never typed" is the whole point, and it is a lesson this project has
already paid for twice. The 768px defect existed because rbp.css opened its card
layout at `max-width: 767px` while style.css opened its mobile block at
`max-width: 768px`: one pixel of disagreement between two files, at the iPad
portrait width. A hand-typed list of test widths cannot find that class of
defect, because whoever types the list types the number they believe, and the
number they believe is the one that is wrong. The same shape as review item 15,
where a fix for a finding about hand-typed lists shipped a hand-typed list of
seven chips and there were eight.

So the widths come out of the CSS. Add a breakpoint anywhere in either
stylesheet and the sweep covers its two neighbours on the next run, without
anyone remembering to.

This module is deliberately in `rbp/` rather than in `tests/render/`, so the
parser itself is exercised by the OFFLINE suite. A width parser that only runs
inside the browser job is a width parser nobody notices has stopped finding
anything: it would return an empty set, the sweep would fall back to the three
fixed widths, and every render test would still pass. `tests/test_breakpoints.py`
asserts it finds the breakpoints that actually exist.
"""
from __future__ import annotations

import os
import re

from .contrast import strip_comments

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS_DIR = os.path.join(ROOT, "static", "css")

# Always swept, whatever the stylesheets say. 320 is the narrowest viewport worth
# supporting (iPhone SE and every "small Android" in the wild), 375 is the most
# common phone width, and 1280 is the desktop width the layout is designed at.
# These three are fixed because they are properties of readers, not of the CSS,
# so they must stay covered even if every @media rule were deleted.
FIXED = (320, 375, 1280)

# Sanity bounds. A `@media (min-width: 1px)` or a print-only prelude must not put
# a 0px or a 4000px viewport into the sweep.
MIN_WIDTH = 280
MAX_WIDTH = 1600


def stylesheets():
    """Every stylesheet the site serves, as (name, text). Read from disk, sorted
    so the sweep is deterministic."""
    out = []
    if os.path.isdir(CSS_DIR):
        for name in sorted(os.listdir(CSS_DIR)):
            if name.endswith(".css"):
                with open(os.path.join(CSS_DIR, name), encoding="utf-8") as fh:
                    out.append((name, fh.read()))
    return out


def preludes(css):
    """The text between `@media` and the opening brace, for every media rule."""
    return [m.group(1).strip()
            for m in re.finditer(r"@media([^{]*)\{", strip_comments(css))]


def widths(css):
    """Every px width named in any `@media` prelude in one stylesheet.

    Both `max-width` and `min-width`: the 769-to-847px nav band was found at a
    `min-width` boundary, and a parser that read only `max-width` would have
    swept straight past it.
    """
    found = set()
    for pre in preludes(css):
        for m in re.finditer(r"(?:max|min)-width:\s*(\d+)px", pre):
            found.add(int(m.group(1)))
    return found


def sweep(sheets=None, fixed=FIXED):
    """The full width sweep: {b-1, b, b+1} for every breakpoint, plus FIXED.

    b-1 and b+1 because a breakpoint is where two layouts meet and the defect
    lives on one side of the join. Testing only at b tests one of the three
    states the reader can be in.
    """
    sheets = stylesheets() if sheets is None else sheets
    bounds = set()
    for _name, css in sheets:
        bounds |= widths(css)
    out = set(fixed)
    for b in bounds:
        out |= {b - 1, b, b + 1}
    return sorted(w for w in out if MIN_WIDTH <= w <= MAX_WIDTH)


def card_layout_boundary(sheets=None):
    """The width at or below which the .rbp tables must be in card layout.

    Derived from the stylesheet rather than declared, for the same reason as the
    sweep: this number was wrong by one pixel for the whole of the project's
    first week, and the way it was wrong was that somebody typed it.

    Found as the `max-width` of the media block that actually contains
    `table.rbp thead`, which is the rule that switches the layout. If that rule
    moves to a different breakpoint, this follows it.
    """
    sheets = stylesheets() if sheets is None else sheets
    best = None
    for _name, css in sheets:
        body = strip_comments(css)
        for m in re.finditer(r"@media([^{]*)\{", body):
            block = _block(body, m.end() - 1)
            if not re.search(r"table\.rbp\s+thead\s*\{[^}]*display:\s*none", block):
                continue
            widths_here = [int(w) for w in
                           re.findall(r"max-width:\s*(\d+)px", m.group(1))]
            if widths_here:
                b = max(widths_here)
                best = b if best is None else max(best, b)
    if best is None:
        raise AssertionError(
            "no @media block contains `table.rbp thead { display: none }`, so "
            "the card layout has no breakpoint and the render sweep cannot "
            "know which widths must be in card mode")
    return best


def _block(css, open_brace):
    """The text inside a balanced brace pair starting at `open_brace`.

    `[^}]*` is wrong for a media rule, because a media rule contains rules. This
    counts depth. Comments are stripped by the caller; an unstripped comment in
    this file quotes braces and would end the block early, which is exactly the
    bug rbp/contrast.py had to fix.
    """
    depth = 0
    for i in range(open_brace, len(css)):
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                return css[open_brace + 1:i]
    return css[open_brace + 1:]
