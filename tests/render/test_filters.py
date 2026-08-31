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
    """Everything the assertions below read, in one round trip.

    `src` IS NO LONGER A SELECT. It is a hidden input holding the chosen slug,
    with the visible controls drawn as buttons from the CONFIGURED feed list, so
    there is no `selectedIndex` and no `selectedOptions` to read. That is the
    point of the change: a select silently discards a value it has no option for,
    which is how `?src=mozilla` came to render every row, and a hidden input
    cannot discard anything.

    So the equivalents are read off the buttons: `srcChips` is every control the
    reader can see, `srcOn` is the one that reports itself pressed, and `srcZero`
    is the set drawn as contributing nothing.
    """
    return pg.evaluate(r"""() => {
      const src = document.getElementById('src'), age = document.getElementById('age');
      const empty = document.querySelector('.empty');
      const chips = [...document.querySelectorAll('#srcgrid [data-src]')];
      const on = chips.find(c => c.getAttribute('aria-pressed') === 'true');
      const label = el => (el.querySelector('.srcname') || el)
                          .textContent.replace(/\s+/g, ' ').trim();
      return {
        url: location.search,
        shown: +document.getElementById('n').textContent.replace(/,/g, ''),
        rows: document.querySelectorAll('.rbprow').length,
        total: JSON.parse(document.getElementById('rows').textContent).length,
        days: [...document.querySelectorAll('.agenum')].map(e => +e.textContent),
        src: src.value,
        srcOn: on ? on.getAttribute('data-src') : null,
        srcLabel: on ? label(on) : null,
        srcChips: chips.map(c => c.getAttribute('data-src')),
        srcLabels: chips.map(label),
        srcZero: chips.filter(c => c.classList.contains('zero'))
                      .map(c => c.getAttribute('data-src')),
        srcWidest: Math.max(0, ...chips.map(c => c.getBoundingClientRect().width)),
        groups: [...document.querySelectorAll('.grouphead span')].map(e => e.textContent),
        bars: [...document.querySelectorAll('.distbar')].map(b => ({
          bucket: b.getAttribute('data-bucket'),
          out: b.classList.contains('out'),
          n: +b.querySelector('u').textContent.replace(/,/g, ''),
        })),
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
    assert st["src"] == slug and st["srcOn"] == slug, (
        f"the control does not carry {slug!r} (value={st['src']!r}, "
        f"pressed={st['srcOn']!r}), so the page shows a filtered view with "
        "nothing on screen saying which filter")
    assert st["srcLabel"] and _display_name(site_dir, slug) in st["srcLabel"], (
        "the control does not name the feed the reader linked to: "
        f"{st['srcLabel']!r}")
    assert slug in st["url"], "the view stopped being linkable at the URL it arrived on"
    assert st["emptyText"], "zero rows and no empty state, so the page reads as broken"


def test_a_feed_with_no_rows_is_hidden_until_a_link_names_it(page, server, site_dir):
    """Two rules that only make sense together.

    A control that leads nowhere is not a control: two feeds of thirteen return
    nothing on a normal run, and a search narrows most of the rest to zero on
    almost any term, so an inventory that drew all of them would be mostly dead
    chips. They are not drawn.

    THE EXCEPTION IS THE ONE THAT MATTERS. `?src=mozilla` names a feed that
    returns nothing, and the point of moving off the <select> is that such a link
    filters honestly instead of falling through to every row. If its chip were
    hidden too, the page would apply a filter with nothing on screen saying which
    filter, which breaks the same promise from the other end. So the chip for the
    CURRENT selection is always drawn, at zero, and marked.

    And the count of feeds that were READ has to survive the hiding, or the page
    goes back to being unable to say whether the inventory is complete. It moves
    into the note rather than into a row of chips nobody can click.
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
    slug = absent[0]

    st = _goto(pg, server, "?age=any")
    assert slug not in st["srcChips"], (
        f"{slug!r} has no rows and is still drawn as a control, so the inventory "
        "offers a chip that can only lead to an empty page")
    assert not st["srcZero"], (
        f"controls drawn at zero with nothing selected: {st['srcZero']}")
    assert set(present) <= set(st["srcChips"]), (
        "a feed WITH rows is missing from the inventory: "
        f"{sorted(set(present) - set(st['srcChips']))}")

    # The note still says how many feeds were read, which is the disclosure the
    # hidden chips used to carry.
    note = pg.eval_on_selector("#seennote", "e => e.textContent")
    assert re.search(r"\d+\s+of\s+\d+", note), (
        f"the inventory no longer says how many of the configured feeds have rows: "
        f"{note!r}. Without it nothing on the page distinguishes a complete "
        "inventory from a truncated one, which is the defect the whole control "
        "was rebuilt for")

    # And a link to the quiet feed shows its control rather than filtering blind.
    st = _goto(pg, server, f"?src={slug}&age=any")
    assert st["rows"] == 0 and st["shown"] == 0, f"?src={slug} rendered rows"
    assert slug in st["srcChips"] and st["srcOn"] == slug, (
        f"a link to {slug!r} filters to nothing and draws no control for it, so "
        "the page shows a filtered view with nothing saying which filter")
    assert slug in st["srcZero"], (
        f"the control for {slug!r} is not marked as contributing nothing")


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


@pytest.mark.parametrize("width", [320, 375])
def test_a_source_label_at_its_cap_does_not_scroll_the_page_sideways(page, server, width):
    """No control in the source inventory is wider than the viewport, at the
    longest label the code will produce.

    The labels are data: a feed's display name, or a CSAF publisher's own name out
    of the advisory document, capped at 44 and 56 characters respectively. This
    drives the cap from the URL rather than trusting the fixture to contain a name
    long enough to reach it, and asserts the chip stays inside the viewport.

    WHAT THIS DOES NOT CATCH, stated because the first version of it claimed
    otherwise: the publisher-name defect that prompted it. That one was a clipped
    COUNT, not a page overflow -- `overflow:hidden` on the button was already
    stopping the name reaching the page scroll width, so no reflow assertion of
    any kind could see it. The horizontal-scroll defect on the same page was the
    row DESCRIPTION, and it is caught by the sweep in test_layout.py now that the
    fixture carries a repository-advisory line, which is the shape of 1,173 of
    2,037 live rows and was missing from it entirely.
    """
    pg = page
    pg.set_viewport_size({"width": width, "height": 812})
    # A csaf facet, so it takes the longer of the two label caps.
    st = _goto(pg, server, "?age=any&src=csaf:" + "W" * 80)
    assert st["srcOn"], "no control was drawn for the linked source, so nothing is measured"
    assert st["srcWidest"] <= width, (
        f"a source control is {st['srcWidest']:.0f}px wide in a {width}px viewport")
    over = pg.evaluate(
        "() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
    assert over <= 1, (
        f"a source label at its cap scrolls the page sideways by {over}px at "
        f"{width}px wide")


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


def test_the_csaf_publishers_are_offered_separately(page, server):
    """CSAF IS A TRANSPORT, NOT A PUBLISHER, and the control treated it as one.

    Measured on the live site 2026-08-29: 143 rows read over CSAF, from five
    different publishers, all collapsed into one entry reading "CSAF Advisory".
    Every other entry in this control is already a named publisher, several of
    them certified CNAs; CSAF was the only feed whose publishers were hidden, and
    they were hidden by how the row was fetched rather than by any decision.

    The consequence was concrete: eight CVE ids referenced in public CISA
    advisories were on the site and there was no way to find them or to send
    anyone a link to them."""
    page.goto(f"{server}/?age=any")
    vals = page.eval_on_selector_all(
        "#srcgrid [data-src]", "els => els.map(e => e.getAttribute('data-src'))")
    facets = [o for o in vals if o.startswith("csaf:")]
    assert len(facets) >= 2, (
        f"the control offers {facets} as CSAF publishers; with fewer than two it "
        "cannot be distinguished from the roll-up")
    assert "csaf" in vals, "the csaf roll-up was dropped"


def test_a_publisher_link_selects_only_that_publishers_rows(page, server):
    """The point of the facet is a citable URL. `?src=csaf:cisa` must select the
    rows whose advisory CISA published and no others."""
    page.goto(f"{server}/?age=any")
    facet = page.evaluate(
        "[...document.querySelectorAll('#srcgrid [data-src]')]"
        ".map(e=>e.getAttribute('data-src')).filter(v=>v.indexOf('csaf:')===0)[0]")
    page.goto(f"{server}/?age=any&src={facet}")
    page.wait_for_selector("#list .rbprow")
    n_facet = page.eval_on_selector_all("#list .rbprow", "els => els.length")

    page.goto(f"{server}/?age=any&src=csaf")
    page.wait_for_selector("#list .rbprow")
    n_roll = page.eval_on_selector_all("#list .rbprow", "els => els.length")

    assert 0 < n_facet < n_roll, (
        f"filtering to one publisher showed {n_facet} rows against {n_roll} for "
        "the whole transport; the facet is not narrowing anything")


def test_the_csaf_rollup_link_still_means_what_it_said(page, server):
    """Every ?src=csaf link already shared has to keep working. The roll-up
    selects every row read over CSAF, publishers included."""
    page.goto(f"{server}/?age=any&src=csaf")
    page.wait_for_selector("#list .rbprow")
    n = page.eval_on_selector_all("#list .rbprow", "els => els.length")
    assert n > 0, "?src=csaf now selects nothing; a shared link has been broken"


def test_a_chip_names_the_publisher_not_the_file_format(page, server):
    """"CSAF Advisory" told a reader the serialisation the advisory arrived in
    and nothing about who wrote it, which is the one thing the chip is for."""
    page.goto(f"{server}/?age=any&src=csaf")
    page.wait_for_selector("#list .rbprow")
    labels = set(page.eval_on_selector_all(
        "#list .rbprow .where .chip", "els => els.map(e => e.textContent.trim())"))
    # NAMED, not merely "not one of two other feeds". The first version of this
    # assertion allowed any chip that was not OSV or GitHub, so "Debian" and
    # "Ubuntu" satisfied it and reverting the chip to "CSAF Advisory" left it
    # green. Confirmed by mutation on 2026-08-29.
    #
    # The fixture publishes under two names on purpose (see _sitefixture); at
    # least one has to reach the chip, and the format label must be gone.
    assert labels & {"CISA", "Siemens ProductCERT"}, (
        f"no chip names the publisher the advisory states: {sorted(labels)}")
    assert "CSAF Advisory" not in labels, (
        "the chip still names the serialisation rather than the publisher")


def test_the_feed_list_stays_alphabetical_and_the_publishers_group(page, server):
    """SORTING, and the first version got it backwards.

    Every CSAF entry was sorted to the TOP of the control and the grouping was
    faked with two figure spaces. Three things went wrong at once: the
    alphabetical feed list started halfway down, so a reader looking for Debian
    met five CSAF publishers first; "Red Hat Product Security" sat at the top
    while "Red Hat" sat near the bottom with nothing saying they are different
    feeds; and the indent was invisible to a screen reader, which was read a flat
    list of sixteen peers.

    The <optgroup> that fixed it is gone with the <select>, so the same three
    properties are asserted against what replaced it: the feeds are alphabetical,
    the publishers sit in a container that declares itself a group WITH A NAME,
    and they are alphabetical inside it. `role="group"` plus `aria-label` is what
    carries the grouping to a screen reader now; an indent alone would be exactly
    the regression this test was written for.
    """
    page.goto(f"{server}/?age=any")
    top = page.eval_on_selector_all(
        "#srcgrid .srcrow:not(.sub) .srcchip .srcname",
        "els => els.map(e => e.textContent.trim())")
    feeds_only = [t for t in top if t and t != "All sources"]
    assert feeds_only == sorted(feeds_only), (
        f"the feed list is not in alphabetical order: {feeds_only}")

    label = page.eval_on_selector_all(
        "#srcgrid [role='group']", "els => els.map(e => e.getAttribute('aria-label'))")
    assert label and any(l and "CSAF" in l for l in label), (
        f"the publishers are not in a named group: {label}. An indent is invisible "
        "to a screen reader, which is the defect the optgroup existed to fix")

    grouped = page.eval_on_selector_all(
        "#srcgrid .srcrow.sub .srcchip .srcname",
        "els => els.map(e => e.textContent.trim())")
    assert len(grouped) >= 2, grouped
    assert grouped == sorted(grouped), (
        f"the publishers are not in alphabetical order: {grouped}")
    assert not any(g.startswith(" ") for g in grouped), (
        "a publisher label still carries the faked figure-space indent")


def test_a_publisher_name_is_not_cut_mid_word(page, server):
    """The longest real publisher name is "Bundesamt fur Sicherheit in der
    Informationstechnik" at 50 characters, and the 44-char cap cut it to
    "Bundesamt fur Sicherheit in der Informati...".

    That cap exists because an unknown slug arrives from the QUERY STRING and
    could be five thousand characters. These names come from the advisory
    documents and are bounded by them, so a publisher gets a longer cap."""
    page.goto(f"{server}/?age=any")
    grouped = page.eval_on_selector_all(
        "#srcgrid .srcrow.sub .srcchip .srcname",
        "els => els.map(e => e.textContent.trim())")
    for label in grouped:
        assert len(label) <= 56, f"{label!r} exceeds the publisher cap"
    # The fixture publishes under CERT-Bund's real 50-character name precisely so
    # this can be asserted: at the old 44 it came back ending in an ellipsis.
    assert any(len(g) > 44 for g in grouped), (
        "no fixture publisher name is long enough to be truncated, so this test "
        "cannot see the cap at all")
    assert not any(g.endswith("\u2026") for g in grouped), (
        f"a publisher name is still being cut mid-word: {grouped}")
    # and the control still refuses an unbounded label from the URL
    page.goto(f"{server}/?age=any&src=csaf:" + "z" * 500)
    names = page.eval_on_selector_all(
        "#srcgrid .srcname", "els => els.map(e => e.textContent)")
    assert all(len(o) <= 60 for o in names), (
        "a value from the query string rendered an unbounded control label")


# --------------------------------------------------------------------------
# F2: a reader who arrives holding one CVE ID
# --------------------------------------------------------------------------

def _oldest_id(page, server):
    page.goto(f"{server}/?age=any")
    return page.evaluate(
        "JSON.parse(document.getElementById('rows').textContent)"
        ".slice().sort((a,b)=>(b.days_public||0)-(a.days_public||0))[0].cve_id")


def test_searching_an_old_id_from_the_front_door_finds_it(page, server):
    """THE BUG, and it is the likeliest way a reader bounces off this site.

    Land on `/`, paste a CVE ID public for more than 90 days, and the page said
    "Nothing matches" for a row that IS in the list, because DEFAULT_AGE was
    still applied alongside the search. Someone following a link from an
    outreach email or from cisagov/CSAF#466 holds exactly one id and does
    exactly this.

    Typed rather than navigated: a shared `?q=` link already worked, because any
    parameter suppresses the default. Only the live typing path was broken, so
    only typing can see it."""
    target = _oldest_id(page, server)
    page.goto(f"{server}/")                      # the front door, default applied
    page.fill("#q", target)
    page.wait_for_timeout(120)
    rows = page.eval_on_selector_all("#list .rbprow", "els => els.length")
    assert rows >= 1, (
        f"typing {target} at the front door found nothing, though it is in the "
        "published data; the 90-day browsing default is being applied to a search")


def test_the_url_a_search_produces_does_not_carry_an_age_nobody_chose(page, server):
    """`?q=CVE-x&age=90-` bakes the wrong answer into a link the reader may send
    on. An age nobody picked is not part of the view they are looking at."""
    target = _oldest_id(page, server)
    page.goto(f"{server}/")
    page.fill("#q", target)
    page.wait_for_timeout(120)
    assert "age=" not in page.evaluate("location.search"), (
        f"a typed search serialised an unchosen age: {page.evaluate('location.search')}")


def test_an_age_the_reader_picked_survives_typing(page, server):
    """The complement. The default steps aside for a search; a choice does not."""
    page.goto(f"{server}/?age=365%2B")
    page.fill("#q", "CVE")
    page.wait_for_timeout(120)
    assert page.eval_on_selector("#age", "e => e.value") == "365+", (
        "a deliberately chosen age bound was overridden by typing")
    assert "age=365" in page.evaluate("location.search")


def test_the_empty_state_does_not_imply_an_unlisted_id_is_published(page, server):
    """A site that reads a minority of CNAs cannot tell a reader their id is
    fine, and "Try a different term" reads as exactly that to someone holding
    one. Absence here is a fact about this site's feeds."""
    page.goto(f"{server}/?age=any&q=CVE-1999-0001")
    page.wait_for_selector(".empty")
    text = page.eval_on_selector(".empty", "e => e.textContent")
    assert "does not mean it has been published" in text, text
    assert "Try a different term" not in text, (
        "the empty state still offers browsing advice to a reader holding one id")


def test_the_remedy_does_not_throw_away_the_search_term(page, server):
    """The one control the reader deliberately filled was the one thing the
    remedy blanked, so the button that promised to help lost their id."""
    page.goto(f"{server}/?age=any&q=CVE-1999-0001")
    page.wait_for_selector(".empty")
    assert page.eval_on_selector(".empty .morebtn", "e => e.textContent.trim()") \
        == "Search All Rows"
    page.click(".empty .morebtn")
    page.wait_for_timeout(120)
    assert page.eval_on_selector("#q", "e => e.value") == "CVE-1999-0001", (
        "pressing the remedy discarded the reader's search term")


def test_an_age_picked_with_the_control_also_survives_typing(page, server):
    """The sibling test sets the age from the URL, which marks it chosen in
    `readUrl`. That leaves the CHANGE-listener path untested, and flipping its
    `ageChosen = true` to false left the suite green. Confirmed by mutation.

    Using the control is how most readers pick an age, so it is the path that
    matters most."""
    page.goto(f"{server}/")
    page.select_option("#age", "365+")
    page.wait_for_timeout(120)
    page.fill("#q", "CVE")
    page.wait_for_timeout(120)
    assert page.eval_on_selector("#age", "e => e.value") == "365+", (
        "an age chosen with the control was overridden by typing")
