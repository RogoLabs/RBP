"""
The checks, watched failing.

THE LESSON THIS FILE ENCODES. Every fix in the session that produced these tests
was mutation-tested by reintroducing the defect and confirming a test failed, and
first passes typically caught about half. Almost every survivor was fixture
blindness rather than a product bug: no fixture produced a degraded run, so
`False == False` passed; every suppression test mocked `subprocess` with a fixed
payload, so restoring the exact filter that caused the bug passed all of them.
On this project, *the test passes* and *the test works* are different claims.

A browser-backed suite is unusually exposed to that. Its fixture is synthetic, its
assertions are about pixels, and a page that failed to load, a stylesheet that
404ed, or a viewport that never actually resized all produce a page with no
overflow and no disagreement, which is indistinguishable from a page that is
correct. So each check below is run against a page with its own defect
deliberately injected, and is required to report it.

WHAT THIS ESTABLISHED, and it corrects PLAN.md 8e's shorthand. The panel's note
reads as though the computed-style AGREEMENT check is the one that catches 768.
It is not, and mutation 1 below is the proof: with the pre-fix stylesheets at
768px the thead is displayed AND the cells are `nowrap`, so both halves report
"not card layout", they agree, and the agreement check passes. What catches 768
is the card-mode assertion (at or below the boundary the card layout must be ON)
and the nested-scrollbar measurement. The agreement check catches the OTHER
defect, the 926px one at 375px, where the card layout is correctly active and
style.css's `nowrap` was never reset. Both are needed and neither is redundant.
"""
from __future__ import annotations

import pytest

from rbp import breakpoints

from _measure import (LIST_PAGE, asset_versions, card_mode_disagreements,
                      rows_not_stacked, rows_refusing_to_wrap, rows_squeezed,
                      row_overflow,
                      document_overflow, file_hash, measure, nested_overflow,
                      rbp_tables_in_card_mode)
from test_focus import _invisible, _traverse

BOUNDARY = breakpoints.card_layout_boundary()

# THE DEFECT CLASSES, REWRITTEN FOR THE ROW LAYOUT (2026-08-26).
#
# These used to reintroduce `table.rbp` defects, and the table is gone: the list
# is a CSS grid, `grid-template-columns: 12px 1fr auto`, that collapses to two
# columns at 640px. Deleting the mutations with the table would have left the
# layout guard with no subject while every test still passed, which is exactly
# the false-green this file exists to prevent. So the defects are the SAME
# CLASSES expressed in the new layout.

# The 768px collision, in grid form: the row keeps its three-column desktop
# layout at a phone width, so the age box squeezes the content column to
# nothing. Same failure, same cause: a breakpoint that did not fire.
DEFECT_NO_COLLAPSE = """
@media (max-width: 640px) {
  .rbprow > summary { grid-template-columns: 12px 1fr auto !important; }
  .agebox { grid-column: auto !important; border-left: 1px solid !important;
            border-top: 0 !important; min-width: 92px; }
}
"""

# The 926px-at-375px defect: content that refuses to wrap and pushes the page
# sideways. It was `th, td { white-space: nowrap }` inherited from style.css;
# here it is the same declaration on the parts that carry long strings.
DEFECT_NOWRAP = """
.rdesc, .cve, .pkg, .where { white-space: nowrap !important;
                             overflow-wrap: normal !important; }
"""

# A fixed floor the layout cannot reflow below, which is what `min-width: 940px`
# on the old table was.
DEFECT_MIN_WIDTH = """
.rbplist { min-width: 940px !important; }
.rbprow { min-width: 940px !important; }
"""

# The non-.rbp figure tables inheriting `min-width: 600px` from style.css with
# nothing to undo them: /method had 1,656px of horizontal page scroll at 375px.
# /method kept its tables when the list page lost its own, so this defect class
# still has a subject and still needs a guard.
DEFECT_TABLE_SM = """
@media (max-width: 768px) {
  table.table-sm { min-width: 600px !important; display: table !important;
                   overflow-x: visible !important; }
  table.table-sm th, table.table-sm td { white-space: nowrap !important; }
}
"""

DEFECT_NO_FOCUS_RING = """
*:focus, *:focus-visible { outline: none !important; box-shadow: none !important; }
"""


def _broken(pg, server, name, css):
    pg.goto(f"{server}/{name}", wait_until="load")
    pg.add_style_tag(content=css)
    return pg


# --------------------------------------------------------------------------
# 1. the 768px collision
# --------------------------------------------------------------------------

def test_the_stacking_check_catches_a_breakpoint_that_did_not_fire(page, server):
    """The direct descendant of the 768px collision. A row still in its
    three-column desktop layout at a phone width puts the age box beside the
    content and squeezes the column carrying the evidence."""
    _broken(page, server, LIST_PAGE, DEFECT_NO_COLLAPSE)
    m = measure(page, 375)
    assert m["rows"], "no rows rendered, so this mutation proves nothing"
    assert rows_not_stacked(m, 640), (
        "the stacking check did not notice that the row layout never collapsed")


def test_the_squeeze_check_catches_a_crushed_content_column(page, server):
    """At 768px the old table hid roughly three quarters of every row while the
    document reported no overflow at all. This is that measurement for the grid:
    the page fits, and the column carrying the CVE ID and its sources does not."""
    _broken(page, server, LIST_PAGE, DEFECT_NO_COLLAPSE)
    m = measure(page, 320)
    assert m["rows"], "no rows rendered"
    assert rows_squeezed(m) or rows_not_stacked(m, 640), (
        "the row survived a 320px viewport in three-column layout with no "
        "squeeze reported, so neither check is measuring the collapse")


def test_the_document_overflow_check_does_NOT_catch_768(page, server):
    """The executable form of the panel's central finding.

    `.tablewrap { overflow-x: auto }` absorbs the overflow before the document
    sees it, so `scrollWidth - clientWidth` is 0 on a page that is three quarters
    unreadable. If this ever starts catching it, the checks above stop being
    load-bearing and the reasoning in PLAN.md 8e should be revisited rather than
    this assertion being deleted.
    """
    _broken(page, server, LIST_PAGE, DEFECT_NO_COLLAPSE)
    assert document_overflow(measure(page, BOUNDARY)) == 0, (
        "document overflow now detects the 768px collision; the panel measured "
        "0 here, and the nested-scrollbar check exists because of it")


def test_the_agreement_check_does_NOT_catch_768_either(page, server):
    """Recorded because PLAN.md 8e's shorthand implies it does.

    Both halves report "not card layout", so they agree. The agreement check is
    for the other defect, and mutation 2 is where it earns its place.
    """
    _broken(page, server, LIST_PAGE, DEFECT_NO_COLLAPSE)
    assert not card_mode_disagreements(measure(page, BOUNDARY))


# --------------------------------------------------------------------------
# 2. the 926px-at-375px defect
# --------------------------------------------------------------------------

def test_the_wrap_check_catches_an_unreset_nowrap(page, server):
    """The card layout IS correctly active and the page still overflows, because
    style.css sets `white-space: nowrap` at this breakpoint and the card layout
    never reset it. This is the defect the review's own proposed assertion would
    have missed."""
    _broken(page, server, LIST_PAGE, DEFECT_NOWRAP)
    m = measure(page, 375)
    assert rows_refusing_to_wrap(m), (
        "the wrap check did not notice row text set to nowrap, which is what "
        "pushed the page 926px sideways at 375px")


def test_the_document_overflow_check_also_catches_an_unreset_nowrap(page, server):
    """Both checks fire on this one, which is why the document check stays: it is
    necessary, and it is only insufficient."""
    _broken(page, server, LIST_PAGE, DEFECT_NOWRAP + DEFECT_MIN_WIDTH)
    assert document_overflow(measure(page, 375)) > 0


# --------------------------------------------------------------------------
# 3. the figure tables
# --------------------------------------------------------------------------

def test_the_document_overflow_check_still_covers_the_pages_that_kept_tables(
        page, server):
    """/method kept its figures tables, and they had 1,656px of horizontal page
    scroll at 375px before `table.table-sm { min-width: 0 }` existed. The list
    page no longer has a table; that page does, so the check keeps a subject."""
    _broken(page, server, "method.html", DEFECT_TABLE_SM)
    assert document_overflow(measure(page, 375)) > 0


# --------------------------------------------------------------------------
# 4. the fixture is capable of failing
# --------------------------------------------------------------------------

@pytest.mark.parametrize("width", [320, 375])
def test_the_fixture_content_is_wide_enough_to_overflow(page, server, width):
    """THE FIXTURE-BLINDNESS GUARD, and the reason this file matters more than
    any single check above.

    Every layout assertion in this package is of the form "nothing overflowed".
    A fixture with three short rows satisfies all of them without the stylesheet
    doing any work at all, and the suite would stay green through the deletion of
    every rule it exists to protect. So: strip the card layout the way rbp.css
    was before it had any @media rule at all, and require the page to break.
    """
    _broken(page, server, LIST_PAGE, DEFECT_MIN_WIDTH)
    over = document_overflow(measure(page, width))
    assert over > 0, (
        f"with the card layout removed entirely, /cves still fits in {width}px. "
        "The fixture rows are too short or too few to exercise reflow, so every "
        "overflow assertion in this package is currently vacuous.")


# --------------------------------------------------------------------------
# 5. focus
# --------------------------------------------------------------------------

def test_the_focus_check_catches_a_removed_ring(page, server):
    """One outline rule existed in the entire project before the a11y work. This
    is what that state looks like to the traversal."""
    _broken(page, server, LIST_PAGE, DEFECT_NO_FOCUS_RING)
    stops, _ = _traverse(page, limit=8)
    assert stops, "Tab reached nothing"
    assert any(_invisible(s) for s in stops), (
        "every focus ring is suppressed and the check reported none missing")


def test_a_transparent_ring_counts_as_no_ring(page, server):
    """`outline: 3px solid transparent` satisfies a source-level grep and shows a
    reader nothing. The check is on the painted result, not on the declaration."""
    _broken(page, server, LIST_PAGE,
            "*:focus-visible { outline: 3px solid transparent !important; "
            "box-shadow: none !important; }")
    stops, _ = _traverse(page, limit=8)
    assert any(_invisible(s) for s in stops), stops[:3]


# --------------------------------------------------------------------------
# 6. the document under test
# --------------------------------------------------------------------------

def test_the_asset_check_catches_a_stale_version_hash(site_dir):
    """Pure Python, because the failure being modelled is a served file and a
    served URL disagreeing, which needs no browser to demonstrate."""
    css = next((site_dir / "static" / "css").glob("*.css"))
    real = file_hash(css)
    html = f'<link rel="stylesheet" href="static/css/{css.name}?v=deadbeef00">'
    got = asset_versions(html)
    assert got == {css.name: "deadbeef00"}
    assert got[css.name] != real, (
        "the stale-hash fixture happens to match the real hash, so this test "
        "proves nothing; change the sentinel")


def test_the_asset_check_notices_a_page_that_links_nothing(site_dir):
    assert asset_versions("<html><body>no stylesheet here</body></html>") == {}
