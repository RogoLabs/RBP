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

from _measure import LIST_PAGE, page_paths

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
    page.goto(f"{server}/{LIST_PAGE}", wait_until="load")
    stops, _ = _traverse(page, limit=6)
    assert stops, "Tab reached nothing"
    assert all(s["focusVisible"] for s in stops), (
        "real Tab presses are no longer arming :focus-visible, so this file is "
        "measuring the :focus state instead")


def test_the_site_styles_focus_on_focus_visible_not_focus(page, server):
    """WHY THE TRAVERSAL IS DRIVEN BY REAL KEY PRESSES.

    This replaced a test that pressed the mouse and then asserted a scripted
    `.focus()` did NOT match `:focus-visible`. That assertion passed locally and
    failed on the CI runner, and it deserved to: it was measuring CHROMIUM'S
    input-modality heuristic, not this site. The coordinates it pressed land on
    different content at a different viewport, so what it actually tested varied
    by where it ran.

    A test whose result depends on the machine is not a test, which is the same
    conclusion tests/conftest.py reaches about ambient environment variables.

    So the premise is now asserted where it is actually true and stable: in the
    stylesheet. The site's focus treatment is written as `:focus-visible` rules,
    which a scripted focus is not guaranteed to match and a real Tab press is.
    That is the whole reason `_traverse` presses keys, and it is checkable
    without depending on a heuristic that browsers are free to change.

    The behavioural half is still covered, twice: real Tab presses arm
    :focus-visible, and every stop shows a ring.
    """
    import pathlib as _p
    css = (_p.Path(__file__).parent.parent.parent
           / "static" / "css" / "rbp.css").read_text()
    assert ":focus-visible" in css, "no :focus-visible rule in the project stylesheet"
    # And the ring is not defined ONLY on plain :focus, which would make the
    # distinction moot and this whole traversal unnecessary.
    import re as _re
    visible_rules = _re.findall(r"[^{}]*:focus-visible[^{}]*\{([^}]*)\}", css)
    assert any("outline" in r for r in visible_rules), (
        "the :focus-visible rules draw no outline, so the traversal is measuring "
        "something the stylesheet does not set")

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


# --------------------------------------------------------------------------
# the slide-over is a MODAL, and had to start behaving like one
# --------------------------------------------------------------------------

def test_tab_cannot_walk_out_of_the_open_panel(page, server):
    """The panel declares role="dialog" aria-modal="true" and nothing enforced it
    for the keyboard.

    aria-modal tells a screen reader to hide the rest of the document. It does
    nothing to Tab order. So a keyboard reader could tab straight out of the open
    dialog into the list behind the scrim, focus and activate controls they cannot
    see, and have no way back to the close button short of cycling the whole page.
    A dialog that announces itself as modal and is not is worse than one that
    never claimed to be, because assistive technology acts on the claim.

    Needs a browser twice over: Tab order is a rendered property, and `offsetParent`
    visibility filtering only means anything once the cascade has run.
    """
    pg = page
    pg.goto(f"{server}/{LIST_PAGE}")
    # A real pointer press first, so focus behaviour is the one most readers get
    # rather than the no-interaction-yet special case this file documents.
    pg.click("#panel-open")
    assert pg.evaluate("() => !document.getElementById('panel').hidden"), (
        "the panel did not open")

    inside = """
    () => {
      const p = document.getElementById('panel');
      const el = document.activeElement;
      return { in: !!el && p.contains(el), tag: el ? el.tagName : null,
               text: el ? (el.textContent || '').trim().slice(0, 40) : null };
    }
    """
    # Well past the number of focusables the panel holds, so a trap that only
    # holds for one lap is not enough.
    for i in range(60):
        pg.keyboard.press("Tab")
        st = pg.evaluate(inside)
        assert st["in"], (
            f"Tab #{i + 1} left the open dialog and landed on "
            f"{st['tag']} {st['text']!r}, which is behind the scrim")

    # And backwards, which is the direction a wrap is usually forgotten in.
    for i in range(20):
        pg.keyboard.press("Shift+Tab")
        st = pg.evaluate(inside)
        assert st["in"], (
            f"Shift+Tab #{i + 1} left the open dialog and landed on "
            f"{st['tag']} {st['text']!r}")


def test_escape_closes_the_panel_and_returns_focus(page, server):
    """Focus has to come back somewhere the reader can act from. Left on
    document.body, the next Tab restarts at the top of the page, which for a
    reader who opened the panel from a row halfway down the list means losing
    their place entirely."""
    pg = page
    pg.goto(f"{server}/{LIST_PAGE}")
    pg.click("#panel-open")
    pg.keyboard.press("Escape")
    assert pg.evaluate("() => document.getElementById('panel').hidden"), (
        "Escape did not close the panel")
    assert pg.evaluate(
        "() => document.activeElement === document.getElementById('panel-open')"), (
        "focus was not returned to the control that opened the panel")


def test_the_page_behind_the_panel_is_not_scrollable_through_it(page, server):
    """`body.locked` exists for this; it is asserted because a class that is
    applied and styles nothing looks identical to one that works."""
    pg = page
    pg.goto(f"{server}/{LIST_PAGE}")
    pg.click("#panel-open")
    overflow = pg.evaluate(
        "() => getComputedStyle(document.body).overflow")
    assert overflow in ("hidden", "clip"), (
        f"the page behind the open dialog still scrolls (body overflow: {overflow})")


def test_the_panel_opens_at_the_top_however_it_was_left(page, server):
    """A reader who read the panel through, closed it, and pressed "What is this?"
    again landed 2,627px down a 3,528px panel: the end of a policy argument, under
    a button that had just asked them a question.

    The panel is its own scroll container and kept its position across opens. Two
    things fix it and BOTH are needed, which is why this asserts the outcome rather
    than the implementation: `scrollTop = 0`, and `focus({preventScroll: true})`.
    Focusing a tall element that is its own scrollport makes the browser scroll it
    to reveal the focused thing, and here the focused thing IS the scrollport, so
    without preventScroll the focus call undoes the reset on the very next line.

    Three openings, because they fail differently: the first is trivially at zero,
    the second is the one that regressed, and the third catches a page-scroll
    interaction that a fresh-load test cannot see.
    """
    pg = page
    pg.goto(f"{server}/{LIST_PAGE}")

    def open_and_read_top():
        pg.click("#panel-open")
        return pg.evaluate("() => document.getElementById('panel').scrollTop")

    assert open_and_read_top() == 0, "the panel does not open at the top on a fresh load"

    # Read it to the end, close, reopen. This is the case that shipped broken.
    pg.evaluate("() => { const p = document.getElementById('panel');"
                " p.scrollTop = p.scrollHeight; }")
    scrolled = pg.evaluate("() => document.getElementById('panel').scrollTop")
    assert scrolled > 0, (
        "the fixture panel is too short to scroll, so this test cannot see the "
        "defect it exists for")
    pg.click("#panel-close")
    assert open_and_read_top() == 0, (
        "the panel reopened where it was left; a reader who read it through gets "
        "the end of it when they ask the question again")

    # And with the page itself scrolled, which is how focus() misbehaves.
    pg.click("#panel-close")
    pg.evaluate("() => window.scrollTo(0, 1200)")
    assert open_and_read_top() == 0, (
        "the panel is scrolled away from its top when opened from down the page")
    assert pg.evaluate(
        "() => document.getElementById('panel').querySelector('h2')"
        ".getBoundingClientRect().top >= 0"), (
        "the panel's first heading is above the viewport on open")


def test_every_row_shows_that_it_opens(page, server):
    """`list-style:none` plus a hidden ::-webkit-details-marker removed the native
    disclosure triangle and nothing replaced it, so a row looked like a static card
    and `cursor:pointer` was the only hint -- which needs a mouse already on the row.

    Everything behind that interaction is the evidence: the per-feed first-seen
    dates and the "open advisory" links. On the primary page of a site built to be
    cited, the citations sat behind a control a reader had no way to know existed.

    Measured as a rendered box rather than as the presence of a CSS rule, because
    the affordance is a ::after drawn from two borders and a rule that computes to
    zero size, transparent, or off-screen would satisfy any source-level check.
    """
    pg = page
    pg.goto(f"{server}/{LIST_PAGE}")

    marker = pg.evaluate("""() => {
      const s = document.querySelector('.rbprow > summary');
      if (!s) { return null; }
      const cs = getComputedStyle(s, '::after');
      return {
        w: parseFloat(cs.width) || 0,
        h: parseFloat(cs.height) || 0,
        display: cs.display,
        borderRight: cs.borderRightWidth,
        colour: cs.borderRightColor,
        transform: cs.transform,
      };
    }""")
    assert marker, "no row rendered, so there is nothing to check"
    assert marker["display"] != "none", "the disclosure affordance is display:none"
    assert marker["w"] >= 5 and marker["h"] >= 5, (
        f"the disclosure affordance renders at {marker['w']}x{marker['h']}px, which "
        "is not a control anyone can see")
    assert parseable_px(marker["borderRight"]) >= 1, (
        "the chevron is drawn from borders and has no border width")
    assert "rgba(0, 0, 0, 0)" not in marker["colour"], (
        f"the chevron is transparent ({marker['colour']})")

    # And it has to CHANGE, or it reads as decoration rather than as state.
    closed = marker["transform"]
    pg.evaluate("() => { document.querySelector('.rbprow').open = true; }")
    # The rotation is transitioned, so the computed value immediately after the
    # attribute changes is still the OLD one. Polled rather than slept: a fixed
    # wait is a guess about how long the transition takes, and the skip-link check
    # in test_layout.py was flaky in CI for exactly this class of reason.
    pg.wait_for_function(
        "(prev) => getComputedStyle(document.querySelector('.rbprow > summary'),"
        " '::after').transform !== prev",
        arg=closed, timeout=3000)
    opened = pg.evaluate("""() => getComputedStyle(
        document.querySelector('.rbprow > summary'), '::after').transform""")
    assert opened != closed, (
        "the affordance looks identical open and closed, so it says a row is "
        "expandable but never that it is expanded")


def parseable_px(value):
    try:
        return float(str(value).replace("px", "").strip() or 0)
    except ValueError:
        return 0.0


def test_the_open_dialog_is_modal_to_the_POINTER_not_only_to_TAB(page, server):
    """The panel declares role="dialog" aria-modal="true", and for the pointer it
    was not one.

    `.scrim` was z-index 30 and `.panel` 31 against a `.header` at **1000**, so the
    site header painted over both: undimmed, and its nav links and theme toggle
    still hittable through the scrim. The keyboard trap in list.html was added for
    exactly this concern and only ever covered Tab, so a page that announces the
    rest of the document as hidden left it operable by mouse.

    It also put the panel's own Close button underneath the theme toggle, which is
    how this surfaced: a Playwright click on Close timed out reporting that
    `#themeToggle` was intercepting.

    Asserted with elementFromPoint rather than by reading z-index values, because
    the numbers are only meaningful relative to every other stacking context on the
    page and the question is simply whether a click lands in the dialog.
    """
    pg = page
    pg.goto(f"{server}/{LIST_PAGE}")
    pg.click("#panel-open")

    hits = pg.evaluate("""() => {
      const at = (el) => {
        const r = el.getBoundingClientRect();
        const hit = document.elementFromPoint((r.left + r.right) / 2,
                                             (r.top + r.bottom) / 2);
        return hit ? (hit.closest('#panel, #scrim') ? 'modal' : hit.tagName +
                      (hit.id ? '#' + hit.id : '')) : 'nothing';
      };
      const out = {};
      const close = document.querySelector('.closebtn');
      out.close = (() => {
        const r = close.getBoundingClientRect();
        const hit = document.elementFromPoint((r.left + r.right) / 2,
                                              (r.top + r.bottom) / 2);
        return hit === close ? 'close' : (hit ? hit.tagName + '#' + hit.id : 'nothing');
      })();
      for (const [k, sel] of [['toggle', '.theme-toggle'], ['logo', '.logo'],
                              ['nav', '.nav-menu a']]) {
        const el = document.querySelector(sel);
        if (el) { out[k] = at(el); }
      }
      return out;
    }""")

    assert hits["close"] == "close", (
        f"the dialog's own Close button is not the topmost element at its own "
        f"coordinates; {hits['close']} is on top of it")
    for part in ("toggle", "logo", "nav"):
        assert hits.get(part, "modal") == "modal", (
            f"the header's {part} is hittable through the open dialog "
            f"({hits[part]}), so aria-modal=\"true\" is not true for a pointer")


def test_the_close_button_stays_reachable_when_the_panel_is_scrolled(page, server):
    """`.closebtn` was `position:absolute` inside a `position:fixed` panel that is
    its own scroll container, so it was placed against the panel's padding box
    including the scrolled-away part and rode off the top on the first scroll.

    The panel is ~3,500px against a 900px viewport, so past the first screen the
    only VISIBLE way out of a modal dialog was gone. Escape and the scrim still
    worked, which is why it went unnoticed: the keyboard route was fine and the
    one a mouse user can see was not.
    """
    pg = page
    pg.goto(f"{server}/{LIST_PAGE}")
    pg.click("#panel-open")

    scrolled = pg.evaluate("""() => {
      const p = document.getElementById('panel');
      p.scrollTop = p.scrollHeight;
      return p.scrollTop;
    }""")
    assert scrolled > 0, (
        "the fixture panel is too short to scroll, so this test cannot see the "
        "defect it exists for")

    box = pg.evaluate("""() => {
      const r = document.querySelector('.closebtn').getBoundingClientRect();
      return {top: r.top, bottom: r.bottom, h: window.innerHeight};
    }""")
    assert box["top"] >= 0 and box["bottom"] <= box["h"], (
        f"Close sits at {box['top']:.0f}..{box['bottom']:.0f} in a "
        f"{box['h']}px viewport after the panel is scrolled, so it is off screen")
    # And it must still actually take the click.
    pg.click("#panel-close")
    assert pg.evaluate("() => document.getElementById('panel').hidden"), (
        "Close was on screen but did not close the panel")


def test_the_heading_keeps_its_unit_on_a_phone(page, server):
    """`.cmd-count span{display:none}` below 640px took "reserved, public,
    unpublished" out of the layout AND out of the accessibility tree, so the page's
    only h1 was the bare string "1,691" -- no unit, no subject -- on the viewport
    where most shared links are opened and for every screen reader on a phone.

    Asserted on the h1's TEXT CONTENT AS RENDERED rather than on the CSS, because
    the failure mode is a display rule three hundred lines away from the markup,
    and because `display:none` and `visibility:hidden` and a zero-height clip all
    look different in CSS and identical to a reader.
    """
    pg = page
    pg.set_viewport_size({"width": 375, "height": 812})
    pg.goto(f"{server}/{LIST_PAGE}", wait_until="load")

    h1 = pg.evaluate("""() => {
      const h = document.querySelector('h1');
      return h ? {text: h.innerText.trim(), rect: h.getBoundingClientRect().height}
               : null;
    }""")
    assert h1, "no h1 on the list page"
    assert "reserved" in h1["text"].lower() and "unpublished" in h1["text"].lower(), (
        f"at 375px the h1 reads {h1['text']!r}. A bare number is not a heading: it "
        "names no unit and no subject.")
    assert h1["rect"] > 0, "the h1 renders at zero height"


def test_every_advisory_link_names_its_own_row(page, server):
    """A screen reader's link list read "OSV" 44 times and "open advisory" more
    than that, each pointing somewhere different.

    The visible label is the feed, which is right on screen because the CVE ID is
    two lines above it, and useless out of that context. Fixed with aria-label
    rather than visible text, so a sighted reader is not shown the id twice.

    Asserted on the COMPUTED accessible name -- what aria-label actually resolves
    to -- and as a uniqueness property over the whole rendered list rather than as
    the presence of an attribute on one element.
    """
    pg = page
    pg.goto(f"{server}/{LIST_PAGE}", wait_until="load")

    links = pg.evaluate("""() => {
      const rows = [...document.querySelectorAll('.rbprow')];
      rows.forEach(r => { r.open = true; });
      return [...document.querySelectorAll('.rbprow a[href]')].map(a => ({
        name: a.getAttribute('aria-label') || a.textContent.trim(),
        href: a.getAttribute('href'),
      }));
    }""")
    assert links, "no links rendered in the list, so this test is vacuous"

    # THE PROPERTY IS "same name implies same destination", not "every name is
    # unique". A row renders each feed twice on purpose -- once as a chip in the
    # summary and once as "open advisory" in the expanded detail -- and both go to
    # the same advisory, so sharing a name is correct there. What WCAG 2.4.4 is
    # about, and what shipped, is one name over several destinations: "OSV" 44
    # times and "open advisory" more than that, each pointing somewhere different.
    by_name = {}
    for link in links:
        by_name.setdefault(link["name"], set()).add(link["href"])
    ambiguous = {n: sorted(h)[:3] for n, h in by_name.items() if len(h) > 1}
    assert not ambiguous, (
        f"{len(ambiguous)} link name(s) point at more than one destination, e.g. "
        f"{list(ambiguous.items())[:2]}. Out of the row's visual context they are "
        "indistinguishable to anyone navigating by links.")

    for link in links:
        assert "CVE-" in link["name"], (
            f"the link name {link['name']!r} does not identify its row")


def test_the_default_view_is_announced_and_reversible(page, server):
    """The front page opens on the last 90 days rather than on everything.

    Sorted oldest-first with no filter, the first ten rows were all Android: eight
    `platform/*` packages and two more with no package, every one from OSV alone,
    every one at 572 days. A site that refuses to name a CNA opened on ten
    near-identical rows naming one vendor's platform.

    THE COST is that the rows it hides are the OLDEST, which are the strongest
    evidence the site has, and that is the mechanism rather than a side effect. So
    this asserts the default is ANNOUNCED, not merely applied: the notice has to
    carry the number hidden and the full total, and offer a control that clears it.
    A default that quietly drops the oldest rows would be the site editing its own
    evidence.

    The total matters twice over. og:title renders `summary.total`, so a reader
    arriving from a link preview saw a number the page would otherwise no longer
    show anywhere.
    """
    pg = page

    # 1. A bare URL gets the default, and says so.
    pg.goto(f"{server}/{LIST_PAGE}", wait_until="load")
    state = pg.evaluate("""() => {
      const n = document.getElementById('viewnote');
      return {age: document.getElementById('age').value,
              shown: document.getElementById('n').textContent,
              noticeHidden: n.hidden, notice: n.innerText,
              total: JSON.parse(document.getElementById('rows').textContent).length};
    }""")
    assert state["age"] == "90-", (
        f"the front page did not open on the default view (age={state['age']!r})")
    assert not state["noticeHidden"], (
        "the default view is applied and not announced, so rows are missing with "
        "nothing on the page saying so")
    assert "oldest" in state["notice"].lower(), (
        f"the notice does not say the hidden rows are the oldest: {state['notice']!r}")
    assert f"{state['total']:,}" in state["notice"], (
        f"the notice does not carry the full total {state['total']:,}, which is the "
        f"number og:title shows a reader before they arrive: {state['notice']!r}")

    # 2. The control clears it, and the cleared state survives a reload.
    pg.click("#showall")
    after = pg.evaluate("""() => ({
      url: location.search,
      age: document.getElementById('age').value,
      shown: document.getElementById('n').textContent,
      noticeHidden: document.getElementById('viewnote').hidden,
    })""")
    assert after["age"] == "any", "Show all did not clear the age filter"
    assert after["noticeHidden"], "the notice still shows after the filter was cleared"
    assert after["url"], (
        "Show all left the URL empty, which is the URL the default applies to, so "
        "a reload would silently put the filter back on")

    pg.goto(f"{server}/{LIST_PAGE}{after['url']}", wait_until="load")
    assert pg.evaluate("() => document.getElementById('age').value") == "any", (
        "the cleared view did not survive a reload of its own URL")

    # 3. A shared link is NEVER overridden by the default.
    pg.goto(f"{server}/{LIST_PAGE}?age=365%2B", wait_until="load")
    assert pg.evaluate("() => document.getElementById('age').value") == "365+", (
        "the default overrode a filter someone had shared, so a link did not mean "
        "what it said")
