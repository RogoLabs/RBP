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


def test_an_inline_control_does_not_inflate_its_line(page, server):
    """A global mobile touch-target rule reached an INLINE button and stretched the
    sentence it sits in.

    style.css gives every `button` `min-height:44px` below 768px, which is correct
    for everything it was written for -- those are all flex or block items. The
    hedge's "Why" is the one button on the site that sits inline at the end of a
    paragraph, and a 44px inline-block inside a 19.7px line box makes that line box
    44px: the hedge rendered with a visibly wider gap above its last line than
    between any of the others, on the front page, at every width under 768px.

    Measured as LINE BOX HEIGHTS via a Range over the paragraph, because
    getBoundingClientRect on the <p> returns one box and says nothing, and because
    the defect is a gap between lines rather than anything about the button that a
    rule-level check would notice.

    The tolerance is 6px: an underlined inline-block is legitimately a couple of
    pixels taller than the text around it, and this is a test about a 24px
    discrepancy, not about pixel-perfect leading.
    """
    pg = page
    pg.set_viewport_size({"width": 375, "height": 812})
    _load(pg, server, "index.html")

    heights = pg.evaluate("""() => {
      const p = document.querySelector('.viewnote');
      if (!p) { return null; }
      const r = document.createRange();
      r.selectNodeContents(p);
      return [...r.getClientRects()].map(x => x.height);
    }""")
    assert heights, (
        "no .viewnote on the list page, so this test is vacuous. It renders only "
        "when the default view is hiding rows; if the fixture stopped spanning the "
        "90-day boundary this check would silently measure nothing.")
    assert len(heights) > 1, (
        "the hedge rendered as a single box, so a per-line comparison sees nothing")

    spread = max(heights) - min(heights)
    assert spread <= 6, (
        f"the hedge's line boxes range {min(heights):.0f}..{max(heights):.0f}px. An "
        "inline control is stretching the line it sits in, which shows as an "
        "uneven gap in the middle of a sentence.")


def test_a_prose_card_is_centred_rather_than_left_aligned(page, server):
    """`.card-prose` caps the measure at 78ch, which was the right fix for the
    half-empty card it replaced. With no auto margin it left /about-this-count as
    the only page whose cards stopped two thirds of the way across: the border
    ended at 869px inside a 1,199px container with 330px of void beside it, while
    the nav and footer spanned the full width. It read as a broken layout rather
    than as a chosen measure.

    Asserted as a SYMMETRY property rather than against a pixel value, so it
    survives a change to the measure or to the container.
    """
    pg = page
    pg.set_viewport_size({"width": 1440, "height": 900})
    _load(pg, server, "about-this-count.html")

    box = pg.evaluate("""() => {
      const c = document.querySelector('.container');
      const card = document.querySelector('.card.card-prose');
      if (!c || !card) { return null; }
      const cr = c.getBoundingClientRect(), kr = card.getBoundingClientRect();
      return {left: kr.left - cr.left, right: cr.right - kr.right,
              cardW: kr.width, containerW: cr.width};
    }""")
    assert box, "no .card.card-prose on the About page, so this test is vacuous"
    assert box["cardW"] < box["containerW"] - 40, (
        "the prose card is not narrower than its container, so the measure cap is "
        "not applying and this test proves nothing")
    assert abs(box["left"] - box["right"]) <= 2, (
        f"the prose card sits {box['left']:.0f}px from the left and "
        f"{box['right']:.0f}px from the right of its container. A capped measure "
        "with no auto margin reads as a broken layout.")


def test_the_skip_link_is_completely_off_screen_until_focused(page, server):
    """It was parked at `top: -40px` and computes to 41.6px tall, so 1.6px of it
    sat in the top-left corner of every page: a small blue bar, visible in every
    screenshot taken during the 2026-08-27 review.

    Asserted at both ends. Off-screen means fully off-screen, and focused means
    fully on: a skip link that cannot be seen when focused is worse than none,
    because a keyboard user is told it exists by the focus ring and nothing else.
    """
    pg = page
    _load(pg, server, "index.html")

    resting = pg.evaluate("""() => {
      const r = document.querySelector('.skip-link').getBoundingClientRect();
      return {top: r.top, bottom: r.bottom, h: r.height};
    }""")
    assert resting["h"] > 0, "the skip link has no height, so it cannot be focused"
    assert resting["bottom"] <= 0.5, (
        f"{resting['bottom']:.1f}px of the skip link is on screen when it is not "
        "focused. The off-screen offset must derive from its own height rather "
        "than be a guessed constant.")

    # THE MOVE IS TRANSITIONED, so it cannot be read in the same task as the
    # focus() that starts it.
    #
    # The first version did exactly that and was flaky: locally Chrome resolved
    # the layout to the focused position immediately and the test passed, and in
    # CI the same code returned the resting position (-41.6) and it failed. Which
    # value a synchronous getBoundingClientRect() sees depends on whether the
    # style engine has started the transition yet, which is timing, not behaviour.
    #
    # Polled rather than slept: it returns as soon as the link has arrived instead
    # of always costing a guessed interval, and if it never arrives the timeout
    # says so rather than an assertion reporting a half-finished animation.
    #
    # This is the second time in one sitting: tests/render/test_focus.py's
    # disclosure-chevron check was caught the same way, reading a rotation in the
    # task that started it. Any assertion about a transitioned property has to
    # wait for it.
    pg.evaluate("() => document.querySelector('.skip-link').focus()")
    pg.wait_for_function(
        "() => document.querySelector('.skip-link').getBoundingClientRect().top"
        " >= -0.5",
        timeout=3000)

    focused = pg.evaluate("""() => {
      const r = document.querySelector('.skip-link').getBoundingClientRect();
      return {top: r.top, bottom: r.bottom, h: r.height};
    }""")
    assert focused["bottom"] > 0 and focused["h"] > 0, (
        f"the skip link arrived on screen but has no visible box: {focused}")
    assert pg.evaluate(
        "() => document.activeElement === document.querySelector('.skip-link')"), (
        "the skip link moved but is not the focused element, so something else "
        "moved it and this test is measuring the wrong thing")


def test_the_mobile_menu_can_be_closed(page, server):
    """It could be opened and not closed.

    The toggle flipped a class and set aria-expanded, and that was all: no Escape,
    no click outside, no focus management. On a 375x812 viewport the menu is 470px
    of an 812px screen, so a reader who opened it by accident had to find the same
    small button again with two thirds of the page covered.

    All four exits are asserted because they fail independently, and aria-expanded
    is checked alongside the class every time: a control that reports the wrong
    state to a screen reader is worse than one that reports none.
    """
    pg = page
    pg.set_viewport_size({"width": 375, "height": 812})
    _load(pg, server, "index.html")

    def state():
        return pg.evaluate("""() => ({
          open: document.querySelector('.nav-menu').classList.contains('active'),
          aria: document.querySelector('.nav-toggle').getAttribute('aria-expanded'),
        })""")

    def open_menu():
        pg.click(".nav-toggle")
        st = state()
        assert st["open"] and st["aria"] == "true", f"the menu did not open: {st}"

    open_menu()
    pg.keyboard.press("Escape")
    st = state()
    assert not st["open"] and st["aria"] == "false", f"Escape did not close it: {st}"
    assert pg.evaluate(
        "() => document.activeElement === document.querySelector('.nav-toggle')"), (
        "Escape closed the menu and left focus on document.body, so the next Tab "
        "restarts at the top of the page")

    open_menu()
    # A real pointer click at a point BELOW the open menu. The menu is ~470px of
    # an 812px viewport starting under the header, so clicking an element by
    # selector lands on the menu itself and Playwright waits forever for it.
    menu_bottom = pg.evaluate(
        "() => document.querySelector('.nav-menu').getBoundingClientRect().bottom")
    pg.mouse.click(180, menu_bottom + 80)
    st = state()
    assert not st["open"] and st["aria"] == "false", (
        f"a click outside the menu did not close it: {st}")

    open_menu()
    # The navigation is suppressed, not the click. A real click here would leave
    # the page and destroy the execution context before the state can be read;
    # what is under test is that the handler runs, not that the browser navigates.
    closed_on_link = pg.evaluate("""() => {
      const a = document.querySelector('.nav-menu a');
      const stop = (e) => e.preventDefault();
      document.addEventListener('click', stop, true);
      a.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true}));
      document.removeEventListener('click', stop, true);
      return !document.querySelector('.nav-menu').classList.contains('active');
    }""")
    assert closed_on_link, (
        "following a link left the menu open, so it is open over the next page "
        "and open again over the previous one after a Back")

    # Crossing the breakpoint with it open left `active` on a menu that is a
    # horizontal bar again.
    open_menu()
    pg.set_viewport_size({"width": 1280, "height": 900})
    pg.wait_for_timeout(150)
    assert not state()["open"], (
        "the menu stayed 'active' after the viewport crossed the breakpoint")


# --------------------------------------------------------------------------
# the deck (/slides.html)
# --------------------------------------------------------------------------

# THE SIZES A PROJECTOR ACTUALLY RUNS AT, typed here rather than taken from
# `breakpoints.sweep()`, and that is the one place in this package where typing a
# number is right. The sweep is derived from the @media preludes in the site's
# stylesheets, which /slides.html does not load: it carries its own styles inline
# and has no breakpoints for the sweep to find. What constrains a slide is the
# room's display mode, and 1280x720 is the single most common one.
#
# HEIGHT IS THE AXIS THAT MATTERS, which no other test in this file measures. The
# deck read perfectly at 1280x800 and overflowed by 81px at 1280x720: the same
# width, a shorter screen, and the sources table ran under the chrome bar. A
# presenter cannot scroll a slide mid-sentence, and the failure shows up on the
# projector rather than on the laptop it was written on.
PROJECTOR_SIZES = ((1280, 720), (1366, 768), (1920, 1080), (1440, 900), (1024, 768))

# THE ROW COUNT THE LIVE SOURCES TABLE ACTUALLY HAS. The deck's tallest slides
# render a bar per feed that evidenced a row, and on 2026-09-02 that was twelve.
LIVE_SOURCE_ROWS = 12


@pytest.fixture(scope="session")
def dense_deck(tmp_path_factory):
    """A served deck built from a snapshot as DENSE as the one that ships.

    ITS OWN SNAPSHOT, and that is the point of this fixture rather than an aside.
    The shared `_sitefixture` build is deliberately small, and a deck built from
    it does not overflow at 1280x720 EVEN WITH BOTH LAYOUT DEFECTS REINTRODUCED:
    measured, both mutations passed. Its sources table was ten bars where the
    live one is twelve, and two bars is most of the 81px that was the original
    bug. A layout assertion made against that is vacuous in the precise way this
    repository keeps paying for.

    So the density is stated here, in the test that depends on it, and
    `test_the_overflow_sweep_measures_a_deck_as_dense_as_the_live_one` fails if
    it ever stops being met.
    """
    import functools
    import http.server
    import json
    import pathlib
    import socketserver
    import threading

    import _sitefixture as F

    root = pathlib.Path(tmp_path_factory.mktemp("dense"))
    snaps, data = F.write_snapshots(root)
    latest = sorted(pathlib.Path(snaps).iterdir())[-1]

    # One row per configured feed, sole-sourced, so every feed gets a bar and the
    # sole-source table beside it is populated too. Written OVER the fixture's own
    # rows rather than appended, so summary.json's totals still match the backlog
    # and `site._assert_consistent` does not refuse the build.
    rows = json.loads((latest / "backlog.json").read_text())
    feeds = json.loads((latest / "summary.json").read_text())["feeds"]["requested"]
    assert len(feeds) >= LIVE_SOURCE_ROWS, (
        f"the fixture requests {len(feeds)} feeds; the live deck renders "
        f"{LIVE_SOURCE_ROWS} bars and this sweep cannot reach that density")
    for i, feed in enumerate(feeds):
        rows[i]["sources"] = feed
        rows[i]["feed_count"] = 1
    (latest / "backlog.json").write_text(json.dumps(rows))

    out = F.build_at(root / "site", snaps, data, launched=True)

    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=str(out))
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


def _slide_overflow(browser, base, width, height):
    """Every slide's overflow at one viewport.

    Measured by switching the `on` class rather than by clicking through: a click
    sequence that desynchronises silently measures the same slide fourteen times
    and passes.
    """
    pg = browser.new_page(viewport={"width": width, "height": height})
    try:
        pg.goto(f"{base}/slides.html", wait_until="load")
        return pg.evaluate("""() => {
          const out = [], slides = [...document.querySelectorAll('.slide')];
          slides.forEach((s, i) => {
            slides.forEach(x => x.classList.remove('on'));
            s.classList.add('on');
            s.getBoundingClientRect();                 // force layout
            const h = s.querySelector('h1, h2');
            out.push({n: i + 1, title: (h ? h.textContent : '?').slice(0, 40),
                      vOver: s.scrollHeight - s.clientHeight,
                      hOver: document.documentElement.scrollWidth
                           - document.documentElement.clientWidth,
                      bars: s.querySelectorAll('.bars tbody tr').length});
          });
          return out;
        }""")
    finally:
        pg.close()


@pytest.mark.parametrize("size", PROJECTOR_SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
def test_no_slide_overflows_at_any_projector_size(browser, dense_deck, size):
    """Every slide fits its viewport, in both axes, at every size a room runs."""
    width, height = size
    bad = [s for s in _slide_overflow(browser, dense_deck, width, height)
           if s["vOver"] > 1 or s["hOver"] > 0]
    assert not bad, (
        f"at {width}x{height}, {len(bad)} slide(s) do not fit: {bad}. A slide the "
        "presenter has to scroll is a slide the room does not see.")


def test_the_overflow_sweep_measures_a_deck_as_dense_as_the_live_one(browser,
                                                                    dense_deck):
    """THE GUARD ON THE SWEEP ABOVE, and the reason this file grew a fixture.

    The sweep asserts an ABSENCE, so it passes on a deck with no slides, on a
    deck whose tables are empty, and on a deck two bars shorter than the one that
    ships. All three look identical to green.
    """
    slides = _slide_overflow(browser, dense_deck, 1280, 720)
    assert len(slides) >= 12, (
        f"the deck rendered {len(slides)} slides; the sweep is vacuous")
    widest = max(s["bars"] for s in slides)
    assert widest >= LIVE_SOURCE_ROWS, (
        f"the densest slide carries {widest} bars and the live deck carries "
        f"{LIVE_SOURCE_ROWS}. This sweep is measuring a shorter page than the one "
        "that ships, which is how both of the original layout defects passed it.")
