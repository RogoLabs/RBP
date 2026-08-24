"""
The width sweep's own tests, which run OFFLINE.

PLAN.md 8e puts a browser on the commit path to measure layout. The widths it
measures at are parsed out of the stylesheets, and a parser that silently stops
finding anything is the worst possible failure here: `sweep()` would fall back to
the three fixed widths, every render test would still pass, and the breakpoint
that broke would be the one width nobody looked at.

So the parser is covered here, in the suite that always runs, rather than only
inside the job that needs a browser download.
"""
from __future__ import annotations

import pytest

from rbp import breakpoints


def test_the_parser_finds_the_breakpoints_that_exist():
    """Not an exact list, which would be the hand-typed list this module exists
    to avoid. The invariant is that BOTH stylesheets contribute, because the
    768px defect was a disagreement BETWEEN them and a parser reading one file
    could not have seen it."""
    sheets = dict(breakpoints.stylesheets())
    assert set(sheets) >= {"rbp.css", "style.css"}, "a stylesheet stopped being read"
    for name, css in sheets.items():
        assert breakpoints.widths(css), f"{name}: no @media width found at all"


def test_the_sweep_brackets_every_breakpoint():
    """b-1, b and b+1 for every breakpoint in either sheet. A breakpoint is where
    two layouts meet, and the defect lives on one side of the join."""
    sheets = breakpoints.stylesheets()
    got = set(breakpoints.sweep(sheets))
    bounds = set()
    for _n, css in sheets:
        bounds |= breakpoints.widths(css)
    assert bounds, "no breakpoints parsed, so the sweep is three fixed widths"
    for b in bounds:
        if breakpoints.MIN_WIDTH <= b <= breakpoints.MAX_WIDTH:
            assert {b - 1, b, b + 1} <= got, f"{b} is not bracketed"


def test_the_reader_widths_are_swept_whatever_the_css_says():
    """320, 375 and 1280 are properties of readers, not of the stylesheets, so
    they stay in the sweep even if every @media rule were deleted."""
    assert set(breakpoints.FIXED) <= set(breakpoints.sweep([("empty.css", "")]))


def test_a_comment_mentioning_a_media_query_is_not_a_breakpoint():
    """rbp.css's own comments quote `@media (max-width: 768px)` and
    `th, td { white-space: nowrap }`, braces and all. An unstripped read picks
    the comment up as a rule, which is the bug rbp/contrast.py already had to
    fix once for the same reason."""
    css = "/* @media (max-width: 4321px) { nope } */\n@media (max-width: 700px) { a{b:c} }"
    assert breakpoints.widths(css) == {700}


def test_min_width_preludes_are_parsed_too():
    """The 769-to-847px nav overflow band was found at a min-width boundary. A
    parser reading only max-width sweeps straight past it."""
    assert 769 in breakpoints.widths("@media (min-width: 769px) and (max-width: 1024px) { a{b:c} }")


def test_absurd_widths_are_excluded():
    css = "@media (min-width: 1px) { a{b:c} } @media (min-width: 4000px) { a{b:c} }"
    got = breakpoints.sweep([("x.css", css)])
    assert all(breakpoints.MIN_WIDTH <= w <= breakpoints.MAX_WIDTH for w in got)


def test_the_card_layout_boundary_is_read_from_the_rule_that_switches_it():
    """768, and the one pixel was a real failure: rbp.css opened the card layout
    at 767 while style.css opened `th, td { white-space: nowrap }` at 768, so at
    exactly 768 the card layout was off and nowrap was on."""
    assert breakpoints.card_layout_boundary() == 768


def test_the_boundary_follows_the_rule_rather_than_being_declared():
    """Move the rule, and the boundary moves with it. This is what makes the
    number impossible to type wrong."""
    css = ("@media (max-width: 640px) { table.rbp thead { display: none; } }\n"
           "@media (max-width: 900px) { .nav { gap: 0 } }")
    assert breakpoints.card_layout_boundary([("x.css", css)]) == 640


def test_a_missing_card_layout_is_an_error_rather_than_a_default():
    """If the card layout is deleted, the sweep must not quietly decide that no
    width needs to be in card mode. That is the false-green the whole job exists
    to avoid."""
    with pytest.raises(AssertionError):
        breakpoints.card_layout_boundary([("x.css", "@media (max-width: 768px) { a{b:c} }")])


def test_a_nested_media_block_does_not_end_at_the_first_brace():
    """A media rule CONTAINS rules, so `[^}]*` reads one rule and stops. The
    switch rule is not always first in its block: in rbp.css it sits after
    `.filters`, `.tablewrap` and `table.rbp`."""
    css = ("@media (max-width: 700px) { .a { b: c } .d { e: f } "
           "table.rbp thead { display: none; } }")
    assert breakpoints.card_layout_boundary([("x.css", css)]) == 700
