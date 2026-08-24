"""
Layout, measured in a real viewport (PLAN.md 8e).

Three checks, in the order the panel's own investigation put them:

  1. the document does not scroll sideways. Necessary, and famously not
     sufficient: at exactly 768px this reads 0 while three quarters of every row
     is off screen.
  2. nothing is hidden inside a nested scroll container below the mobile
     boundary. This is the one that catches 768.
  3. the thead and the cells agree about which layout is running. This is the
     one that catches the CAUSE of 768, one pixel of disagreement between two
     stylesheets.

Every width comes from `rbp.breakpoints.sweep()`, parsed out of the `@media`
preludes. Nothing here types a breakpoint.
"""
from __future__ import annotations

import pytest

from rbp import breakpoints

from _measure import (card_mode_disagreements, document_overflow, measure,
                      nested_overflow, page_paths, rbp_tables_in_card_mode)

WIDTHS = breakpoints.sweep()
BOUNDARY = breakpoints.card_layout_boundary()


@pytest.fixture(scope="session")
def paths(site_dir):
    return page_paths(site_dir)


def _load(pg, server, name):
    pg.goto(f"{server}/{name}", wait_until="load")
    return pg


# --------------------------------------------------------------------------
# 1. the document does not scroll sideways
# --------------------------------------------------------------------------

def test_no_page_scrolls_sideways_at_any_swept_width(page, server, site_dir):
    """WCAG 1.4.10 reflow. /cves had 926px of horizontal page scroll at 375px and
    /method had 1,656px, both while the card layout was correctly active, because
    style.css's `th, td { white-space: nowrap }` was never reset.

    One test over every page and every width rather than a parametrised matrix,
    because the useful output is the whole failing surface at once: this class of
    defect is a stylesheet interaction and fixing it one cell at a time is what
    made the contrast work take two passes.
    """
    failures = []
    for name in page_paths(site_dir):
        _load(page, server, name)
        for w in WIDTHS:
            over = document_overflow(measure(page, w))
            if over > 0:
                failures.append(f"{name} at {w}px: {over}px of page overflow")
    assert not failures, "horizontal page scroll:\n  " + "\n  ".join(failures)


# --------------------------------------------------------------------------
# 2. nothing hides inside a nested scroll container
# --------------------------------------------------------------------------

def test_no_row_hides_behind_a_nested_scrollbar_below_the_boundary(
        page, server, site_dir):
    """The measurement the panel's reviewer made, and the reason a document-level
    assertion was rejected as sufficient.

    `.tablewrap { overflow-x: auto }` absorbs the overflow before the document
    sees it. At 768px with the pre-fix stylesheets the page reported a clean
    `scrollWidth - clientWidth` of 0 while the wrapper hid 74% of every row.

    Scoped to `.rbp` tables and to widths at or below the boundary. The
    `table.table-sm` figures tables are DESIGNED to scroll inside their own box
    there, because a three-column figure table reads worse as stacked cards, and
    asserting over them would be asserting against a recorded decision.
    """
    failures = []
    for name in page_paths(site_dir):
        _load(page, server, name)
        for w in WIDTHS:
            if w > BOUNDARY:
                continue
            for t in nested_overflow(measure(page, w)):
                if t["rbp"]:
                    failures.append(
                        f"{name} at {w}px: table.{t['cls']} hides "
                        f"{t['hidden_px']}px ({t['hidden_pct']}% of the row) "
                        f"behind a nested scrollbar, with {t['visible_px']}px visible")
    assert not failures, ("row content hidden inside a scroll container:\n  "
                          + "\n  ".join(failures))


# --------------------------------------------------------------------------
# 3. the two stylesheets agree about which layout is running
# --------------------------------------------------------------------------

def test_the_thead_and_the_cells_agree_at_every_width(page, server, site_dir):
    """The computed-style agreement check.

    Producing this value means running the cascade, specificity resolution and
    media-query evaluation. That is why option (b), a CSS parser, was rejected:
    not on taste, on the fact that it cannot answer this question.

    The failure it exists for: rbp.css opened the card layout at `max-width:
    767px` while style.css opened `th, td { white-space: nowrap }` at
    `max-width: 768px`, so at exactly 768 the thead was still displayed and the
    cells still refused to wrap. Neither stylesheet is wrong on its own.
    """
    failures = []
    for name in page_paths(site_dir):
        _load(page, server, name)
        for w in WIDTHS:
            # AT OR BELOW THE BOUNDARY ONLY, which is the panel's own wording and
            # not a convenience. Above it, style.css applies no `nowrap` at all,
            # so `white-space` is whatever each column asked for: `.id` and `.num`
            # are deliberately nowrap and `.desc` deliberately is not. Asserting
            # agreement up there compares a media-query state against a per-column
            # design decision and reports the design as a defect, which it did on
            # /data at every width from 769px up the first time this ran.
            if w > BOUNDARY:
                continue
            for cls, disp, ws in card_mode_disagreements(measure(page, w)):
                failures.append(
                    f"{name} at {w}px: table.{cls} has thead display:{disp} "
                    f"with cells white-space:{ws}")
    assert not failures, ("the card layout and the mobile cell rules disagree:\n  "
                          + "\n  ".join(failures))


def test_every_rbp_table_is_in_card_mode_at_or_below_the_boundary(
        page, server, site_dir):
    """Agreement alone is satisfied by BOTH being off, which is the desktop
    layout at a phone width. So the boundary itself is asserted: at or below it,
    the card layout must actually be running."""
    failures = []
    for name in page_paths(site_dir):
        _load(page, server, name)
        for w in WIDTHS:
            if w > BOUNDARY:
                continue
            rbp, in_card = rbp_tables_in_card_mode(measure(page, w))
            if len(rbp) != len(in_card):
                failures.append(
                    f"{name} at {w}px: {len(rbp) - len(in_card)} of {len(rbp)} "
                    ".rbp tables are still in table layout")
    assert not failures, ("the card layout is not on at or below "
                          f"{BOUNDARY}px:\n  " + "\n  ".join(failures))


def test_every_rbp_table_is_in_table_mode_above_the_boundary(page, server, site_dir):
    """The other direction, so a stylesheet that switched the card layout on
    everywhere would fail rather than pass every check above.

    Keyed on the thead alone. `white-space` above the boundary is a per-column
    decision rather than a layout mode, so it says nothing about which layout is
    running; the thead does, because hiding it IS the card layout.
    """
    failures = []
    for name in page_paths(site_dir):
        _load(page, server, name)
        for w in WIDTHS:
            if w <= BOUNDARY:
                continue
            m = measure(page, w)
            hidden = [t for t in m["tables"]
                      if t["rbp"] and t["theadDisplay"] == "none"]
            if hidden:
                failures.append(f"{name} at {w}px: {len(hidden)} .rbp table(s) "
                                "have their column headers hidden")
    assert not failures, ("the card layout is on above the boundary:\n  "
                          + "\n  ".join(failures))


def test_the_sweep_is_not_empty_and_brackets_the_boundary(site_dir):
    """The false-green this whole file is most exposed to: a parser that stops
    finding breakpoints leaves three fixed widths, every check above passes, and
    the pixel that broke is the one nobody measured."""
    assert len(WIDTHS) >= 10, f"the width sweep collapsed to {WIDTHS}"
    assert {BOUNDARY - 1, BOUNDARY, BOUNDARY + 1} <= set(WIDTHS)
    assert page_paths(site_dir), "the build produced no pages to measure"
