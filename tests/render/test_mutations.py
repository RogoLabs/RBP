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

from _measure import (asset_versions, card_mode_disagreements,
                      document_overflow, file_hash, measure, nested_overflow,
                      rbp_tables_in_card_mode)
from test_focus import _invisible, _traverse

BOUNDARY = breakpoints.card_layout_boundary()

# The pre-fix stylesheets, as CSS. rbp.css opened the card layout at
# `max-width: 767px`, so at exactly 768 style.css's mobile block was on and the
# card layout was not.
DEFECT_768 = f"""
@media (max-width: {BOUNDARY}px) {{
  table.rbp thead {{ display: table-header-group !important; }}
  table.rbp, table.rbp tbody, table.rbp tr {{ display: revert !important; }}
  table.rbp td {{ display: table-cell !important; white-space: nowrap !important; }}
  table.rbp {{ min-width: 600px !important; }}
  table.rbp td[data-label]::before {{ content: none !important; }}
  /* .tablewrap keeps its base `overflow: auto`. This line is the mutation's
     whole point and the first version of it left the line out, so the page
     overflowed 2,562px at the document level and the "document overflow does
     NOT catch 768" assertion below failed. The card layout releases the wrapper
     to `overflow: visible`; the pre-fix stylesheet opened that block at 767, so
     at exactly 768 the wrapper was still a scroll container and the page still
     fitted. A mutation that does not reproduce the absorption is not
     reproducing the defect. */
  .tablewrap {{ max-height: calc(100vh - 8rem) !important; overflow: auto !important; }}
}}
"""

# The 375px defect: the card layout IS active and `white-space: nowrap` was never
# reset, so stacked block cells still refuse to wrap.
DEFECT_NOWRAP = f"""
@media (max-width: {BOUNDARY}px) {{
  table.rbp td {{ white-space: nowrap !important; overflow-wrap: normal !important; }}
}}
"""

# The non-.rbp figure tables inheriting `min-width: 600px` from style.css with
# nothing to undo them: /method had 1,656px of horizontal page scroll at 375px.
DEFECT_TABLE_SM = f"""
@media (max-width: {BOUNDARY}px) {{
  table.table-sm {{ min-width: 600px !important; display: table !important;
                    overflow-x: visible !important; }}
  table.table-sm th, table.table-sm td {{ white-space: nowrap !important; }}
}}
"""

# No card layout at all, which is where rbp.css started: zero @media rules.
DEFECT_NO_CARD_LAYOUT = """
table.rbp thead { display: table-header-group !important; }
table.rbp, table.rbp tbody, table.rbp tr { display: revert !important; }
table.rbp td { display: table-cell !important; white-space: nowrap !important; }
table.rbp { min-width: 940px !important; }
.tablewrap { overflow: visible !important; }
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

def test_the_card_mode_check_catches_the_768px_collision(page, server):
    _broken(page, server, "cves.html", DEFECT_768)
    m = measure(page, BOUNDARY)
    rbp, in_card = rbp_tables_in_card_mode(m)
    assert rbp, "no .rbp table on the page, so this mutation proves nothing"
    assert len(in_card) != len(rbp), (
        "the card-mode check did not notice that the card layout is off at "
        f"{BOUNDARY}px, which is the defect this job exists to catch")


def test_the_nested_scrollbar_check_catches_the_768px_collision(page, server):
    """The measurement the panel's reviewer made: ~74% of every row hidden."""
    _broken(page, server, "cves.html", DEFECT_768)
    hidden = [t for t in nested_overflow(measure(page, BOUNDARY)) if t["rbp"]]
    assert hidden, (
        "the nested-scrollbar check reported nothing while the table is in "
        "table layout at a 768px viewport with a 600px floor and nowrap cells")
    assert max(t["hidden_pct"] for t in hidden) > 20, hidden


def test_the_document_overflow_check_does_NOT_catch_768(page, server):
    """The executable form of the panel's central finding.

    `.tablewrap { overflow-x: auto }` absorbs the overflow before the document
    sees it, so `scrollWidth - clientWidth` is 0 on a page that is three quarters
    unreadable. If this ever starts catching it, the checks above stop being
    load-bearing and the reasoning in PLAN.md 8e should be revisited rather than
    this assertion being deleted.
    """
    _broken(page, server, "cves.html", DEFECT_768)
    assert document_overflow(measure(page, BOUNDARY)) == 0, (
        "document overflow now detects the 768px collision; the panel measured "
        "0 here, and the nested-scrollbar check exists because of it")


def test_the_agreement_check_does_NOT_catch_768_either(page, server):
    """Recorded because PLAN.md 8e's shorthand implies it does.

    Both halves report "not card layout", so they agree. The agreement check is
    for the other defect, and mutation 2 is where it earns its place.
    """
    _broken(page, server, "cves.html", DEFECT_768)
    assert not card_mode_disagreements(measure(page, BOUNDARY))


# --------------------------------------------------------------------------
# 2. the 926px-at-375px defect
# --------------------------------------------------------------------------

def test_the_agreement_check_catches_an_unreset_nowrap(page, server):
    """The card layout IS correctly active and the page still overflows, because
    style.css sets `white-space: nowrap` at this breakpoint and the card layout
    never reset it. This is the defect the review's own proposed assertion would
    have missed."""
    _broken(page, server, "cves.html", DEFECT_NOWRAP)
    bad = card_mode_disagreements(measure(page, 375))
    assert bad, ("the agreement check did not notice a hidden thead beside "
                 "nowrap cells")


def test_the_document_overflow_check_also_catches_an_unreset_nowrap(page, server):
    """Both checks fire on this one, which is why the document check stays: it is
    necessary, and it is only insufficient."""
    _broken(page, server, "cves.html", DEFECT_NOWRAP)
    assert document_overflow(measure(page, 375)) > 0


# --------------------------------------------------------------------------
# 3. the figure tables
# --------------------------------------------------------------------------

def test_the_document_overflow_check_catches_the_table_sm_floor(page, server):
    """/method had 1,656px of horizontal page scroll at 375px from the coverage
    figures and the launch checklist inheriting a 600px floor."""
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
    _broken(page, server, "cves.html", DEFECT_NO_CARD_LAYOUT)
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
    _broken(page, server, "cves.html", DEFECT_NO_FOCUS_RING)
    stops, _ = _traverse(page, limit=8)
    assert stops, "Tab reached nothing"
    assert any(_invisible(s) for s in stops), (
        "every focus ring is suppressed and the check reported none missing")


def test_a_transparent_ring_counts_as_no_ring(page, server):
    """`outline: 3px solid transparent` satisfies a source-level grep and shows a
    reader nothing. The check is on the painted result, not on the declaration."""
    _broken(page, server, "cves.html",
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
