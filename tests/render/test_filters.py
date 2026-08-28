"""The filters, and whether a link to a filtered view means what it says.

WHY A BROWSER. Every assertion here is about what a <select> does with a value
the page did not put in it, which is a DOM behaviour and not a property of the
source text: assigning a select a value it has no option for neither throws nor
sticks. `value` reads back "" and `selectedIndex` becomes -1, and the filter that
was supposed to be applied is simply not applied. No parser sees that. The
offline half of this file is tests/test_filter_links.py, which asserts the
structure that makes the behaviour possible; it is weaker and it gates the
publication, which is why both exist.

THE DEFECT THAT PRODUCED IT, measured on 2026-08-28 before the fix:
`?src=mozilla&age=any` rendered 60 of 60 rows in this fixture, and the review that
reported it measured all 1,672 of 1,672 on the live page. The source options are
built from the slugs in today's rows, `mozilla` and `arch` have contributed zero
rows since they merged, and so the one control whose stated purpose is that a view
can be cited turned a citation of a quiet feed into a link showing everything.

The same measurement found the empty state concatenating the reader's own filter
text into innerHTML unescaped, so `?q=<img src=x onerror=...>` matched no rows,
rendered the tag and ran the handler. Both are tested here, because both are
reached by the same act: pasting a URL.
"""
from __future__ import annotations

import re
import urllib.parse

import pytest

from _measure import LIST_PAGE


def _shipped_feed_slugs(site_dir):
    """The feed slugs the shipped page has a display name for.

    Read out of the built bytes rather than listed here: the point of the test is
    what a reader can put in a URL, and what a reader can put in a URL is any
    slug the site itself uses. A hardcoded list is also how this suite once ended
    up pointing at a deleted page.
    """
    body = (site_dir / LIST_PAGE).read_text()
    m = re.search(r"var NAMES = \{(.*?)\};", body, re.S)
    assert m, "the list page carries no NAMES map; this test has stopped reading it"
    slugs = re.findall(r'(?:"([a-z0-9-]+)"|\b([a-z][a-z0-9]*))\s*:', m.group(1))
    found = {a or b for a, b in slugs}
    assert len(found) >= 10, f"only {len(found)} feed slugs parsed out of NAMES: {found}"
    return found


def _state(pg):
    return pg.evaluate("""() => {
      const src = document.getElementById('src'), age = document.getElementById('age');
      const empty = document.querySelector('.empty');
      return {
        url: location.search,
        shown: +document.getElementById('n').textContent.replace(/,/g, ''),
        rows: document.querySelectorAll('.rbprow').length,
        total: JSON.parse(document.getElementById('rows').textContent).length,
        days: [...document.querySelectorAll('.agenum')].map(e => +e.textContent),
        src: src.value,
        srcIndex: src.selectedIndex,
        srcLabel: src.selectedOptions[0] ? src.selectedOptions[0].textContent : null,
        age: age.value,
        ageIndex: age.selectedIndex,
        emptyText: empty ? empty.innerText : null,
        emptyTags: empty ? [...empty.querySelectorAll('*')].map(e => e.tagName) : null,
      };
    }""")


def _goto(pg, server, query=""):
    pg.goto(f"{server}/{LIST_PAGE}{query}", wait_until="load")
    return _state(pg)


def test_a_link_to_a_feed_with_no_rows_shows_no_rows(page, server, site_dir):
    """The reported defect, and the promise it broke.

    A feed that is configured, polled, and contributing nothing is the NORMAL
    state of two of the thirteen: round 7 measured `mozilla` at 607 ids a run and
    `arch` at 62, both with zero published rows, and /status now says so in three
    cells. So "a slug with no option" is not an edge case reachable only by
    fuzzing; it is what a link to either of those feeds is, and it rendered every
    row on the site.

    A positive control runs first. Without it, a page that returned zero rows for
    EVERY filter would satisfy every assertion below.
    """
    pg = page
    _goto(pg, server, "")
    present = pg.evaluate("""() => {
      const s = new Set();
      JSON.parse(document.getElementById('rows').textContent)
        .forEach(r => (r.sources || '').split(',').forEach(x => x && s.add(x)));
      return [...s].sort();
    }""")
    assert present, "no row in the fixture names a source; every assertion here is vacuous"

    # THE POSITIVE CONTROL: a feed that IS in the data filters to something.
    live = _goto(pg, server, f"?src={present[0]}&age=any")
    assert live["src"] == present[0], (
        f"a link to {present[0]!r}, which is in the data, did not even set the control")
    assert live["rows"] > 0, (
        f"?src={present[0]} rendered nothing, so this test cannot tell a working "
        "filter from a broken one")

    absent = sorted(_shipped_feed_slugs(site_dir) - set(present))
    assert absent, (
        "every feed the site names has rows in this fixture, so the state this test "
        "is about cannot arise: a link naming a feed with no rows. Two of the "
        "thirteen live feeds are in that state, so the fixture has stopped "
        "resembling the data")
    slug = absent[0]

    st = _goto(pg, server, f"?src={slug}&age=any")
    assert st["rows"] == 0 and st["shown"] == 0, (
        f"?src={slug} names a feed with no rows and rendered {st['rows']} of "
        f"{st['total']}. A select silently discards a value it has no option for, "
        "so the filter stopped applying and a citation of a quiet feed became a "
        "link showing everything")
    assert st["src"] == slug and st["srcIndex"] >= 0, (
        f"the control does not carry {slug!r} (value={st['src']!r}, "
        f"selectedIndex={st['srcIndex']}), so the page shows a filtered view with "
        "nothing on screen saying which filter")
    assert st["srcLabel"] and _display_name(site_dir, slug) in st["srcLabel"], (
        "the control does not name the feed the reader linked to: "
        f"{st['srcLabel']!r}")
    assert slug in st["url"], "the view stopped being linkable at the URL it arrived on"
    assert st["emptyText"], "zero rows and no empty state, so the page reads as broken"


def test_the_option_for_an_absent_feed_is_marked_as_absent(page, server, site_dir):
    """The dropdown is a list of the feeds behind today's rows.

    An option added because a URL asked for it is not one of those, and offering
    it unmarked beside the feeds that do have rows states something false about
    the data in the one control a reader uses to explore it.

    The exact wording is not asserted, only that it differs from the plain display
    name, so this does not break on a copy edit.
    """
    pg = page
    _goto(pg, server, "")
    present = pg.evaluate("""() => {
      const s = new Set();
      JSON.parse(document.getElementById('rows').textContent)
        .forEach(r => (r.sources || '').split(',').forEach(x => x && s.add(x)));
      return [...s].sort();
    }""")
    absent = sorted(_shipped_feed_slugs(site_dir) - set(present))
    assert absent, "the fixture no longer has a feed with no rows; see the test above"

    _goto(pg, server, f"?src={absent[0]}&age=any")
    plain = pg.evaluate("""(slug) => {
      const o = [...document.getElementById('src').options].find(o => o.value === slug);
      return o ? o.textContent : null;
    }""", absent[0])
    assert plain and plain != _display_name(site_dir, absent[0]), (
        f"the option for {absent[0]!r} reads {plain!r}, the same as a feed with rows "
        "would, so the dropdown presents a feed contributing nothing as one of today's")


def _display_name(site_dir, slug):
    body = (site_dir / LIST_PAGE).read_text()
    m = re.search(rf'"?{re.escape(slug)}"?\s*:\s*"([^"]+)"', body)
    return m.group(1) if m else slug


def test_an_age_bound_the_control_does_not_offer_still_filters(page, server):
    """`?age=45+` is not in the dropdown and is a real view.

    The offered thresholds are the boundaries of `summary.age_buckets`, so a
    reader reproducing a published bucket count uses one of them. A reader asking
    a question of their own does not, and 45 is as legitimate a bound as 90. It
    used to render everything.

    The partition is asserted at the same time, because it is the property the
    template claims: "no row satisfies both and no row satisfies neither".
    """
    pg = page
    total = _goto(pg, server, "?age=any")["total"]

    over = _goto(pg, server, "?age=45%2B")
    assert over["age"] == "45+" and over["ageIndex"] >= 0, (
        f"the control did not take the bound from the URL (value={over['age']!r})")
    assert over["rows"] < total, (
        f"?age=45+ rendered all {total} rows, so the bound was dropped and the URL "
        "described a view the page was not showing")
    assert over["days"] and min(over["days"]) >= 45, (
        f"a row younger than the bound is in the view: {sorted(over['days'])[:5]}")

    under = _goto(pg, server, "?age=45-")
    assert under["days"] and max(under["days"]) < 45, (
        f"a row at or past the bound is in the under-45 view: {sorted(under['days'])[-5:]}")
    assert over["shown"] + under["shown"] == total, (
        f"45+ ({over['shown']}) and under 45 ({under['shown']}) do not partition "
        f"{total} rows, so one of the two bounds is not being applied")


def test_a_bound_that_parses_as_nothing_falls_back_to_everything_visibly(page, server):
    """A blank select is the failure this whole file is about, in miniature.

    `?age=soon` cannot be honoured. The old behaviour left the control empty and
    the filter off: a page showing everything while its one age control displayed
    no value at all, which reads as "some filter is on and I cannot see which".
    The explicit everything state is a state the control HAS.
    """
    for query in ("?age=soon", "?age="):
        st = _goto(page, server, query)
        assert st["age"] == "any" and st["ageIndex"] >= 0, (
            f"{query} left the age control at {st['age']!r} "
            f"(selectedIndex={st['ageIndex']}), so it displays nothing while "
            "filtering nothing")
        # min(total, PAGE): the list renders a page at a time, so "everything"
        # is the first window of it rather than every row in the DOM.
        assert st["shown"] == st["total"] and st["rows"] == min(st["total"], 100), (
            f"{query} did not fall back to everything: {st['shown']} of {st['total']}")


@pytest.mark.parametrize("param", ["q", "src"])
def test_the_empty_state_never_renders_markup_from_the_url(page, server, param):
    """The empty state is the one place a reader's own text is drawn on the page.

    It was concatenated into innerHTML raw, and both filters that carry text are
    read from the query string, so `?q=<img src=x onerror=...>` matched no rows,
    rendered the tag and ran the handler. Measured on 2026-08-28 in this fixture:
    `window.__rbp_xss` was set.

    Parametrised over both channels rather than only the one that was reported.
    They reach the same string by the same route, and fixing one is not fixing the
    other.
    """
    pg = page
    payload = '<img src=x onerror="window.__rbp_xss=1">'
    query = f"?{param}={urllib.parse.quote(payload)}&age=any"
    st = _goto(pg, server, query)

    assert st["emptyText"] is not None, (
        f"?{param}=<markup> matched rows, so the empty state never rendered and "
        "this test proves nothing about it")
    assert not pg.evaluate("() => '__rbp_xss' in window"), (
        f"markup in ?{param} EXECUTED on the page. A URL that runs script under "
        "this origin is the most expensive defect available to a site whose whole "
        "product is a link other people are asked to trust")
    assert "IMG" not in (st["emptyTags"] or []), (
        f"markup in ?{param} was parsed as markup in the empty state: "
        f"{st['emptyTags']}")
    assert "img" in st["emptyText"], (
        "the reader's own filter text is not shown back to them as text: "
        f"{st['emptyText']!r}")


def test_a_hostile_src_cannot_stretch_the_command_bar(page, server):
    """The option label for an unknown slug comes from the query string.

    Rendered whole it is a control as wide as the string, which is a layout defect
    handed to anyone who can get a link clicked. The label is bounded; the VALUE is
    not, because the filter still has to mean exactly what the URL said.
    """
    pg = page
    slug = "a" * 5000
    st = _goto(pg, server, f"?src={slug}&age=any")
    assert st["src"] == slug, "the value was truncated, so the filter no longer means the URL"
    assert st["rows"] == 0, "a slug no feed uses matched rows"
    assert len(st["srcLabel"]) <= 48, (
        f"the option label is {len(st['srcLabel'])} characters, so the command bar "
        "is as wide as whatever a link puts in the query string")


@pytest.mark.parametrize("width,chars", [(1280, 400), (375, 80)])
def test_a_long_filter_value_does_not_scroll_the_page_sideways(page, server, width, chars):
    """Reached by TYPING, which is why it is measured here rather than assumed
    from the URL cases above.

    The empty state is the one box on the site that draws text the reader
    supplied, and it had no wrapping rule: `overflow-wrap: anywhere` was declared
    for `.mono, code, pre` inside the 768px media query and nothing covered this.
    400 characters pasted into the filter scrolled the document 2,466px sideways
    at 1280 wide; 80 did it at 375. A pasted package coordinate or token is enough,
    and the fixture's own package name is 88 characters.

    Both widths, because the rule that was missing existed only below 768 and the
    defect is worse above it.
    """
    pg = page
    pg.set_viewport_size({"width": width, "height": 812})
    _goto(pg, server, "?age=any")
    pg.fill("#q", "z" * chars)
    pg.wait_for_timeout(200)
    state = pg.evaluate("""() => ({
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      empty: !!document.querySelector('.empty'),
    })""")
    assert state["empty"], (
        f"{chars} characters matched a row, so the empty state never rendered and "
        "this measures nothing")
    assert state["overflow"] <= 1, (
        f"a {chars}-character filter value scrolls the page sideways by "
        f"{state['overflow']}px at {width}px wide")


def test_reading_a_filter_from_the_url_never_throws(page, server):
    """Nothing here is worth a dead page.

    The URL readers are keyed on the control map and iterated from it, and a
    control with no reader throws deliberately, so a page-level error is the one
    outcome that must not reach a reader. `pageerror` rather than console: an
    uncaught exception in the IIFE stops the rest of it, which means no rows.
    """
    pg = page
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    for query in ("", "?src=mozilla&age=any", "?age=45%2B", "?age=soon",
                  "?q=%3Cimg%3E&src=%3Cb%3E&age=any", "?minage=45",
                  "?src=constructor&age=any", "?src=__proto__&age=any"):
        st = _goto(pg, server, query)
        assert st["total"] > 0, f"the row island is empty on {query!r}"
    assert not errors, f"the list page threw while reading a URL: {errors}"
