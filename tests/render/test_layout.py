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

from _measure import (document_overflow, measure, page_paths, row_overflow,
                      rows_not_stacked, rows_refusing_to_wrap, rows_squeezed)

WIDTHS = breakpoints.sweep()


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

def test_no_row_hides_its_content_at_any_swept_width(page, server, site_dir):
    """The measurement the panel's reviewer made, and the reason a document-level
    assertion was rejected as sufficient.

    `.tablewrap { overflow-x: auto }` absorbs the overflow before the document
    sees it. At 768px with the pre-fix stylesheets the page reported a clean
    `scrollWidth - clientWidth` of 0 while the wrapper hid 74% of every row.

    THE SUBJECT MOVED FROM THE TABLE TO THE ROWS. This was scoped to `.rbp`
    tables inside a `.tablewrap`, and that component rendered on no page and has
    been deleted. Rewritten rather than deleted with it, because the defect it
    was written for is a property of the page and not of the markup that
    happened to carry it: the page fits, and the column carrying the evidence
    does not.

    AND IT CLOSES TWO GAPS. `rows_not_stacked` and `rows_squeezed` existed
    before this and were called from test_mutations.py only, which proves the
    detectors FIRE on a page deliberately broken. Nothing asserted they stay
    quiet on the page the site actually builds, so a real regression in the row
    layout had no check standing in front of it at any width. `row_overflow`
    was worse: written as the row equivalent of the nested-scrollbar
    measurement and never called from anywhere, by this test or any other.

    The figures tables are deliberately not in scope. `table.table-sm` is
    DESIGNED to scroll inside its own box below 768, because a three-column
    figure table reads worse as stacked cards, and asserting over it would be
    asserting against a recorded decision.
    """
    failures = []
    for name in page_paths(site_dir):
        _load(page, server, name)
        for w in WIDTHS:
            m = measure(page, w)
            total = len(m.get("rows", []))
            # 640 is the grid's own collapse, and it is passed in rather than
            # read from the CSS for the same reason test_mutations.py passes it:
            # `rows_not_stacked` answers "below THIS width, are the rows
            # stacked", so the width is the question, not an implementation
            # detail to be derived. It is bracketed by the sweep either way.
            #
            # REPORTED PER WIDTH AND NOT PER ROW. Each of these returns a list
            # of rows, and the list page renders 54 of them at 19 widths: a
            # failure appended per row buries the one fact that identifies the
            # defect, which width it starts at, under four figures of near
            # identical lines. The count and one worst example carry it.
            unstacked = rows_not_stacked(m, 640)
            if unstacked:
                failures.append(
                    f"{name} at {w}px: {len(unstacked)} of {total} rows are "
                    f"still in the {unstacked[0]['cols']}-column desktop layout")
            squeezed = rows_squeezed(m)
            if squeezed:
                worst = min(r["bodyWidth"] for r in squeezed)
                failures.append(
                    f"{name} at {w}px: {len(squeezed)} of {total} rows have "
                    f"their content column crushed, narrowest {worst}px")
            nowrap = rows_refusing_to_wrap(m)
            if nowrap:
                failures.append(
                    f"{name} at {w}px: {len(nowrap)} of {total} row "
                    "descriptions are set to nowrap and will push the page "
                    "sideways")
            clipped = row_overflow(m)
            if clipped:
                worst = max(r["hidden_px"] for r in clipped)
                failures.append(
                    f"{name} at {w}px: {len(clipped)} of {total} rows are "
                    f"wider than the row box, worst {worst}px, so content is "
                    "clipped with nothing saying so")
    assert not failures, ("row content is hidden or crushed:\n  "
                          + "\n  ".join(failures))


# --------------------------------------------------------------------------
# 3. the two stylesheets agree about which layout is running
# --------------------------------------------------------------------------
#
# THREE TESTS STOOD HERE AND ALL THREE HAVE BEEN DELETED, not moved.
#
# They asked whether `table.rbp`'s thead and its cells agreed about which layout
# was running, which is how the 768px defect was caught: rbp.css opened the card
# layout at `max-width: 767px` while style.css opened `th, td { white-space:
# nowrap }` at `max-width: 768px`, so at exactly 768 the thead was displayed and
# the cells refused to wrap, and neither stylesheet was wrong on its own.
#
# That component rendered on no page, live or built, and has been deleted. There
# is no card layout left anywhere on the site: the front page is `<details>`
# rows at every width and the remaining tables are `table.table-sm`, which stays
# tabular and scrolls inside its own box. Kept, these three would have iterated
# over an empty list of `.rbp` tables and reported green at every width, which
# reads identically to coverage.
#
# THE DEFECT CLASS DID NOT GO WITH THEM. "A breakpoint that did not fire, so a
# narrow viewport keeps the wide layout" is asserted for the layout that
# actually renders, by `rows_not_stacked()` and `rows_squeezed()` in check 2
# above, and reintroduced as `DEFECT_NO_COLLAPSE` in test_mutations.py. What is
# genuinely no longer covered is the two-stylesheet DISAGREEMENT that made 768
# possible, because it took two files declaring a layout mode for the same
# element and only style.css does that now.


def test_the_sweep_is_not_empty_and_brackets_the_joins(site_dir):
    """The false-green this whole file is most exposed to: a parser that stops
    finding breakpoints leaves three fixed widths, every check above passes, and
    the pixel that broke is the one nobody measured.

    Bracketing was asserted against `card_layout_boundary()` until that
    derivation was deleted with the component it parsed. It is asserted against
    the three joins the site actually has instead: the row grid's collapse at
    640, style.css's mobile block at 768, and the nav band at 900. All come out
    of `sweep()`, so none is typed here in the sense that matters; naming them
    is how this test says which joins it believes exist, and it fails if any
    stops being parsed. 640 is the one the checks above depend on: it is the
    boundary they pass to `rows_not_stacked()`.
    """
    assert len(WIDTHS) >= 10, f"the width sweep collapsed to {WIDTHS}"
    for b in (640, 768, 900):
        assert {b - 1, b, b + 1} <= set(WIDTHS), (
            f"{b} is no longer bracketed by the sweep")
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
