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


# `card_layout_boundary()` WAS HERE, and it is not coming back by accident.
#
# It derived the card-mode breakpoint by parsing `table.rbp thead { display:
# none }` out of rbp.css, on the same principle as `sweep()` above: the number
# is read from the rule that switches the layout rather than typed, so moving
# the rule moves the tests with it.
#
# The rule is gone. `table.rbp` rendered on no page, live or built, and was
# deleted with the rest of the unreachable component. Nothing switches to a
# card layout any more: the front page is `<details>` rows at every width, and
# the remaining tables are `table.table-sm`, which stays tabular and scrolls
# inside its own bounded box.
#
# So there is nothing left to derive, and the honest move was to delete the
# derivation rather than repoint it. Repointing it at `table.table-sm` would
# have kept the name and measured a different property; keeping one `table.rbp`
# rule alive purely so this function had something to parse would have been a
# rule that exists to be tested, which is what the review found in the first
# place.
#
# WHAT THIS COST, stated because a deletion that quietly reduces coverage is
# the failure mode this file's docstring is about: the two card-mode assertions
# in tests/render/test_layout.py went with it. `sweep()` did not depend on this
# function and is unchanged, so every width is still swept and every other
# render check still runs at all 19 of them.
#
# If a card layout is ever reintroduced, derive its boundary again. Do not type
# the number: the 768-versus-767 defect is what this module exists for.
