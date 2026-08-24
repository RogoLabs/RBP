"""
Focus visibility, exercised by real Tab traversal (PLAN.md 8e).

"focus rings exercised by real Tab traversal, since `.focus()` does not arm
`:focus-visible`."

That sentence is the whole design. `element.focus()` does not reliably set
`:focus-visible`, because the browser's heuristic is about input modality rather
than about focus. So a test that calls `.focus()` and reads `getComputedStyle`
measures a state that depends on what the reader last touched, and on a site with
no focus treatment at all it can report a pass. Before this project's a11y work
there was exactly ONE outline rule in the entire codebase, on a site whose
primary surface is a sortable table, so this is not a hypothetical failure mode:
it is the state this repository shipped in.

MEASURED, and the panel's wording needed correcting. Chromium matches
`:focus-visible` on a scripted `.focus()` when there has been NO user interaction
yet, because it treats "nothing has happened" the same as "keyboard". The
distinction only appears after a real pointer interaction, which is the state
most readers are in and the state asserted below. Written down because "`.focus()`
does not arm `:focus-visible`" is the kind of half-true premise that makes a test
confidently wrong, and this file was wrong about it on its first run.

The traversal is therefore driven by real key presses, which is the other reason
this needs a browser rather than a parser.
"""
from __future__ import annotations

import pytest

from _measure import page_paths

# Enough to walk the chrome, the filters, the sort buttons and well into the
# table body. /cves has more focusables than this (every row carries a link), and
# the cap is reported rather than silent: a bounded sweep that reads as complete
# coverage is the failure mode section 3 of FEEDS.md calls "no silent caps".
TAB_LIMIT = 80

ACTIVE_JS = """
() => {
  const el = document.activeElement;
  if (!el || el === document.body || el === document.documentElement) return null;
  const cs = getComputedStyle(el);
  return {
    tag: el.tagName,
    cls: typeof el.className === 'string' ? el.className : '',
    text: (el.textContent || '').trim().slice(0, 40),
    outlineStyle: cs.outlineStyle,
    outlineWidth: parseFloat(cs.outlineWidth) || 0,
    outlineColor: cs.outlineColor,
    outlineOffset: cs.outlineOffset,
    boxShadow: cs.boxShadow,
    focusVisible: el.matches(':focus-visible'),
  };
}
"""


def _traverse(pg, limit=TAB_LIMIT):
    """Tab through the page for real, returning what each stop looks like."""
    stops, capped = [], False
    for i in range(limit):
        pg.keyboard.press("Tab")
        info = pg.evaluate(ACTIVE_JS)
        if info is None:
            break
        stops.append(info)
        if i == limit - 1:
            capped = True
    return stops, capped


def _invisible(stop):
    """True when a keyboard reader cannot see where they are.

    An outline counts only if it is drawn AND coloured: `outline: 3px solid
    transparent` is the shape of a focus style that satisfies a source-level
    grep and shows a reader nothing.
    """
    ring = (stop["outlineStyle"] != "none" and stop["outlineWidth"] > 0
            and "rgba(0, 0, 0, 0)" not in stop["outlineColor"]
            and stop["outlineColor"] != "transparent")
    return not ring and stop["boxShadow"] == "none"


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_every_keyboard_stop_shows_where_it_is(page, server, site_dir, theme):
    """Both themes, because the tokens differ and the dark theme is where this
    project's contrast failures have historically been."""
    failures, capped = [], []
    for name in page_paths(site_dir):
        page.goto(f"{server}/{name}", wait_until="load")
        page.evaluate("t => document.documentElement.setAttribute('data-theme', t)",
                      theme)
        stops, was_capped = _traverse(page)
        if was_capped:
            capped.append(name)
        assert stops, f"{name}: Tab reached nothing focusable at all"
        for i, s in enumerate(stops):
            if _invisible(s):
                failures.append(
                    f"{name}/{theme} stop {i} <{s['tag']} class={s['cls']!r}> "
                    f"{s['text']!r}: outline {s['outlineWidth']}px "
                    f"{s['outlineStyle']} {s['outlineColor']}, "
                    f"box-shadow {s['boxShadow']}")
    assert not failures, "no visible focus indicator:\n  " + "\n  ".join(failures)
    if capped:
        print(f"\nfocus traversal capped at {TAB_LIMIT} stops on: "
              f"{', '.join(capped)} (later stops not measured)")


def test_the_traversal_is_arming_focus_visible(page, server):
    """The test's own premise, asserted rather than assumed.

    If a future Playwright, a future Chromium, or a `page.click()` added
    somewhere above changed the heuristic, every stop would report `:focus`
    styling and this file would go on passing while measuring the wrong state.
    """
    page.goto(f"{server}/cves.html", wait_until="load")
    stops, _ = _traverse(page, limit=6)
    assert stops, "Tab reached nothing"
    assert all(s["focusVisible"] for s in stops), (
        "real Tab presses are no longer arming :focus-visible, so this file is "
        "measuring the :focus state instead")


def test_focus_calls_alone_would_not_have_measured_this(page, server):
    """Recorded as an executable statement rather than as a comment.

    The premise needed correcting the first time it was run, and the correction
    is worth keeping. On a page with NO prior user interaction, Chromium does
    match `:focus-visible` on a scripted `.focus()`, because the heuristic treats
    "no interaction yet" the same as "keyboard". So a naive `.focus()` test is
    not always wrong; it is wrong exactly when a reader has touched a mouse,
    which is most of the time and is not a state a test falls into by accident.

    Asserted here in the state that actually distinguishes them: after a pointer
    press, `.focus()` does not match and Tab does.
    """
    page.goto(f"{server}/cves.html", wait_until="load")
    # A real pointer press in the content. `page.mouse.click()` on the page
    # chrome did NOT change the modality when this was measured; a move followed
    # by an explicit down/up over <main> did.
    page.mouse.move(300, 500)
    page.mouse.down()
    page.mouse.up()
    scripted = page.evaluate("""() => {
        const el = document.querySelector('a.logo');
        el.focus();
        return {visible: el.matches(':focus-visible'),
                outline: parseFloat(getComputedStyle(el).outlineWidth) || 0};
    }""")
    assert scripted["visible"] is False, (
        "a scripted .focus() after a mouse interaction now matches "
        ":focus-visible, so the distinction this traversal is built around no "
        "longer holds and the design should be revisited rather than the "
        "assertion relaxed")
    # Deliberately NOT asserting that the ring is gone. `outline-width` still
    # computes to a value under the UA's own `:focus { outline: auto }`, which is
    # not painted; a computed width is not a drawn ring, and asserting on it here
    # would be the same "the test passes but does not work" mistake this
    # repository has already made twice.

    # And the same element, reached by keyboard, does show one.
    page.keyboard.press("Tab")
    page.keyboard.press("Tab")
    reached = page.evaluate(ACTIVE_JS)
    assert reached and not _invisible(reached), (
        "Tab traversal after a mouse click no longer produces a visible focus "
        "ring, which is the state most readers are actually in")


def test_the_skip_link_is_the_first_stop_on_every_page_that_has_a_nav(
        page, server, site_dir):
    """WCAG 2.4.1 is about bypassing REPEATED blocks, so the assertion is keyed
    to the nav being there rather than to a list of page names.

    /about-this-count is the holding page. It is a standalone file that shares
    nothing with base.html by design, it has no nav, and its first element is the
    h1 inside <main>: there is no repeated block to bypass and a skip link would
    be a link to the content the reader is already on. Asserted rather than
    excluded, so the day it grows a nav this test asks for the skip link.
    """
    checked = 0
    for name in page_paths(site_dir):
        page.goto(f"{server}/{name}", wait_until="load")
        has_nav = page.evaluate("() => !!document.querySelector('nav, .nav')")
        stops, _ = _traverse(page, limit=1)
        assert stops, f"{name}: nothing focusable"
        if not has_nav:
            first_in_main = page.evaluate(
                "() => !!document.activeElement.closest('main')")
            assert first_in_main, (
                f"{name} has no nav, so the first Tab stop should already be in "
                "the content; it is not, and the page needs a skip link after all")
            continue
        checked += 1
        assert "skip-link" in stops[0]["cls"], (
            f"{name}: the first Tab stop is <{stops[0]['tag']} "
            f"class={stops[0]['cls']!r}>, not the skip link")
    assert checked, "no page in the build has a nav, which cannot be right"
