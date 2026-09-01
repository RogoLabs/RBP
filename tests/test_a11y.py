"""
Accessibility (review item 17).

Two reviewers measured ten AA failures independently and one called them
disqualifying for a federal reader: a documented WCAG failure on the primary data
table is a bar to citing or embedding a third-party resource from official
guidance, whatever the data quality.

The contrast ratios are computed here rather than asserted from a spreadsheet, so
a token change fails the build instead of a later audit. And they are measured
against every background the text actually renders on, not against white: half the
rows are not white, which is the mistake the false comment in rbp.css already
documented making.

THE OTHER HALF LIVES IN tests/render/. Contrast needs no browser and is settled
here. Layout does: horizontal overflow at a given viewport, and the 768px
breakpoint collision, cannot be answered without running the cascade and the
media queries for real. This file asserts those STRUCTURALLY, on the text of the
stylesheet, which is weaker than measuring a viewport and is why PLAN.md 8e put a
browser on the commit path. The two are complementary and neither replaces the
other: the structural assertions here still run offline in about ten seconds and
still gate the publication, and tests/render never touches the publish path.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).parent.parent
CSS = ROOT / "static" / "css" / "rbp.css"
TEMPLATES = ROOT / "templates"

# Backgrounds the body text renders on, per theme, from the inherited tokens.
LIGHT_BG = {"content": "#ffffff", "secondary": "#e9ecef", "hover": "#f8f9fa"}
DARK_BG = {"content": "#1e2130", "secondary": "#1a1d27", "hover": "#252838"}

AA = 4.5


def _lum(hexs):
    hexs = hexs.lstrip("#")
    parts = [int(hexs[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    conv = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in parts]
    return 0.2126 * conv[0] + 0.7152 * conv[1] + 0.0722 * conv[2]


def ratio(fg, bg):
    a, b = _lum(fg), _lum(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def _token(name, dark=False):
    """Read a project token out of rbp.css.

    Matches the selector followed IMMEDIATELY by a brace. Splitting on the bare
    selector string picks up a mention inside a comment (there is one) and, for the
    dark theme, matches `[data-theme="dark"] .chip-late {` forty lines earlier.
    """
    css = CSS.read_text()
    sel = r'\[data-theme="dark"\]\s*\{' if dark else r":root\s*\{"
    blocks = [m for m in re.finditer(sel + r"([^}]*)\}", css)]
    assert blocks, f"no {'dark' if dark else ':root'} token block found"
    for b in blocks:
        m = re.search(rf"--{name}:\s*(#[0-9a-fA-F]{{6}})", b.group(1))
        if m:
            return m.group(1)
    raise AssertionError(
        f"token --{name} not defined in the {'dark' if dark else 'light'} block")


@pytest.mark.parametrize("token", ["rbp-text-secondary", "rbp-text-muted", "rbp-link"])
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_project_text_tokens_clear_aa_on_every_background(token, theme):
    """Measured, not asserted. The inherited tokens failed on the striped row this
    project introduced and had never been re-audited against it:

        text-muted   on the stripe   1.75   <- td.unattributed, most rows
        text-secondary               3.95   <- column headers, qualifier, desc
        primary                      3.80   <- every link on every even row

    The 1.75 is the one that matters most semantically: the site's own abstention
    marker was the least legible cell on the page, so its conservatism was the part
    a reader could not see.
    """
    colour = _token(token, dark=(theme == "dark"))
    bgs = DARK_BG if theme == "dark" else LIGHT_BG
    for label, bg in bgs.items():
        r = ratio(colour, bg)
        assert r >= AA, (
            f"{token} ({colour}) on {theme}/{label} ({bg}) is {r:.2f}:1, below AA")


def test_the_abstention_marker_is_not_the_least_legible_cell():
    """The semantic point. td.unattributed is the site's own statement that it does
    not know, on the majority of rows, and it was rendered at 1.75:1."""
    for theme, bgs in (("light", LIGHT_BG), ("dark", DARK_BG)):
        muted = _token("rbp-text-muted", dark=(theme == "dark"))
        worst = min(ratio(muted, bg) for bg in bgs.values())
        assert worst >= AA, f"{theme}: abstention marker worst case {worst:.2f}:1"


def test_the_table_header_has_its_own_fill():
    """A sticky header that shares the even-row stripe token scrolls over rows of
    the same colour."""
    css = CSS.read_text()
    block = css[css.index("table.rbp thead th {"):]
    block = block[:block.index("}")]
    assert "background:" in block


def test_the_sticky_header_can_actually_stick():
    """`.tablewrap { overflow-x: auto }` made the wrapper a scroll container on both
    axes, so `position: sticky; top: 0` bound to a scrollport with no max-height
    that never scrolls. Proven at 4000px of scroll: the th sat at -3,630px, so a
    table 44,000px tall at live scale was read with no column labels visible at any
    point, and the first columns lost are Inferred owner, Confidence and Rule, the
    three that carry all the hedging."""
    css = CSS.read_text()
    wrap = re.search(r"\.tablewrap\s*\{([^}]*)\}", css)
    assert wrap, ".tablewrap rule not found"
    body = wrap.group(1)
    assert "max-height" in body, (
        "sticky needs a bounded scrollport; without max-height the wrapper never "
        "scrolls and the header never sticks")
    assert "overflow: auto" in body or "overflow:auto" in body


def _handler_body(src, eid):
    """The body of the click handler bound to `#eid`, by brace matching.

    Regex to the opening brace of the callback and count from there. A lazy regex
    stops at the first `}` inside, which for both delegating handlers here is an
    early-return `if`.
    """
    m = re.search(rf'\$\("{re.escape(eid)}"\)\.addEventListener\("click",[^{{]*\{{', src)
    if not m:
        return ""
    depth, i = 0, m.end() - 1
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.end():i]
        i += 1
    return ""


def test_every_click_handler_is_bound_to_something_focusable():
    """SC 2.1.1, level A, generalised from the defect that produced it.

    The original: sorting was a click listener on a non-focusable `th`, so seven
    columns were unreachable without a pointer while `aria-sort` was maintained
    correctly, meaning the state was announceable and the control was inoperable.
    The table is gone since 2026-08-26, and the RULE is not: every click listener
    on the list page must be bound to an element a keyboard can reach.

    Discovered from the handlers rather than checked against a list of controls,
    because the failure mode is someone ADDING a handler, not someone deleting
    one. The previous version of this test read templates/cves.html for the whole
    time that template was no longer being rendered.
    """
    # The page AS ASSEMBLED: list.html plus what it includes. `panel-close` is
    # declared in _panel.html and bound in list.html, so reading either file alone
    # gets a wrong answer, and the wrong answer from reading only the binding side
    # is a false FAILURE, which at least fails loudly. The reverse split would be
    # silent.
    src = (TEMPLATES / "list.html").read_text()
    for inc in re.findall(r'{%\s*include\s+"([^"]+)"', src):
        src += "\n" + (TEMPLATES / inc).read_text()

    # One level of indirection: `var panel = $("panel")` then `panel.addEventListener`.
    # Not anchored on `var`, because the declarations are comma-chained and only
    # the first binding on the line carries the keyword.
    alias = dict(re.findall(r'(\w+)\s*=\s*\$\("([^"]+)"\)', src))
    targets = set(re.findall(r'\$\("([^"]+)"\)\.addEventListener\("click"', src))
    for name in re.findall(r'\b(\w+)\.addEventListener\("click"', src):
        if name in alias:
            targets.add(alias[name])
        elif name not in ("document", "window"):
            targets.add(name)
    assert targets, "no click handlers found; this test has stopped reading the page"

    # The modal backdrop is deliberately NOT focusable. It duplicates the close
    # button and Escape, both of which are reachable, and a focusable backdrop
    # between the dialog and the page is a keyboard trap rather than a control.
    exempt = {"scrim"}
    for eid in sorted(targets - exempt):
        focusable = re.search(
            rf'<button[^>]*\bid="{re.escape(eid)}"'
            rf'|<\w+[^>]*\bid="{re.escape(eid)}"[^>]*\btabindex='
            rf'|<\w+[^>]*\btabindex=[^>]*\bid="{re.escape(eid)}"', src)
        if focusable:
            continue
        # DELEGATION IS THE OTHER LEGITIMATE SHAPE, and the first version of this
        # test could not tell it apart from the defect.
        #
        # The source inventory and the distribution bars are redrawn on every
        # render, so binding per control would rebind a dozen buttons on every
        # keystroke; the handler goes on the container instead. The container is
        # not the control and has no business being focusable. What matters is
        # that the thing the handler acts on is a real button.
        #
        # So a non-focusable target is allowed only when its handler resolves a
        # control with .closest(), and the attribute it closes on is rendered on a
        # <button>. That keeps the original rule -- every click target is
        # keyboard-reachable -- while admitting the pattern, and it still fails if
        # someone binds a handler to a div and acts on the div.
        body = _handler_body(src, eid)
        assert body, (
            f"a click handler is bound to #{eid}, which is not a <button> and "
            "declares no tabindex, so it is unreachable without a pointer")
        sel = re.search(r'\.closest\(\s*"\[([\w-]+)\]"', body)
        assert sel, (
            f"the click handler on #{eid} does not delegate with .closest(), and "
            f"#{eid} is not focusable, so whatever it acts on cannot be reached "
            "without a pointer")
        attr = sel.group(1)
        assert re.search(rf'<button[^>]*{re.escape(attr)}=', src), (
            f"the handler on #{eid} delegates to [{attr}], but nothing renders a "
            f"<button> carrying {attr}, so the control it acts on is not a button")

    # And the rows open with the keyboard, which is why they are <details>/<summary>
    # rather than a div carrying a handler.
    assert '<details class="rbprow">' in src


def test_a_filter_matching_nothing_announces_something():
    """render() replaced the list wholesale with no aria-live anywhere, so a filter
    that matched nothing announced nothing at all.

    Repointed to list.html on 2026-08-26. The rule survived the pivot; the file it
    was reading did not.
    """
    src = (TEMPLATES / "list.html").read_text()
    assert 'aria-live="polite"' in src
    assert 'class="empty"' in src, "no explicit empty state for a filter that matches nothing"
    # The announcement has to carry the NUMBER, not just fire. "Results updated"
    # tells a screen-reader user nothing they could not already assume.
    assert 'rows shown' in src


def test_every_table_header_cell_declares_a_scope():
    """`<th` is a prefix of `<thead`, which is exactly how the bulk edit that added
    these attributes broke 14 thead tags across 7 templates into
    `<th scope="col"ead>`. So this pattern requires a word boundary, and the next
    test asserts the tags survived, because a source-text check cannot see a
    malformed tag the parser then discards."""
    for tpl in TEMPLATES.glob("*.html"):
        body = tpl.read_text()
        unscoped = [m.group(0)[:60]
                    for m in re.finditer(r"<th(?![a-z])(?![^>]*\bscope=)", body)]
        assert not unscoped, f"{tpl.name}: {len(unscoped)} th without scope"


def test_no_template_has_a_malformed_table_tag():
    """The bug the browser caught and every source-level test missed.

    A regex that edits markup needs a check on the PARSED result, not on the text
    it just wrote. `<th scope="col"ead>` renders, passes every string assertion, and
    silently breaks sticky positioning, screen-reader table semantics and the mobile
    `thead { display: none }` rule all at once, because the parser discards the
    thead and reparents the cells."""
    for tpl in TEMPLATES.glob("*.html"):
        body = tpl.read_text()
        assert 'scope="col"ead' not in body, f"{tpl.name}: mangled thead"
        # Every opening thead/tbody must be a bare tag, and they must balance.
        for tag in ("thead", "tbody", "table"):
            opens = len(re.findall(rf"<{tag}[ >]", body))
            closes = len(re.findall(rf"</{tag}>", body))
            assert opens == closes, (
                f"{tpl.name}: {opens} <{tag}> vs {closes} </{tag}>")


def test_no_built_page_repeats_a_heading(built_site, built_site_launched):
    """Two headings with the same text on one page is a copy-paste artefact.

    `_panel.html` carried the literal line `<h2>The data</h2>  <h2>The data</h2>`
    and shipped it, so the live front page rendered "The data" twice in a row
    above one paragraph. No test looked: tests/test_a11y.py counts occurrences of
    the h1 tag to catch a SECOND h1 being added, and nothing anywhere counted h2s
    at all.

    Asserted over both postures because the panel renders on the dashboard, which
    is /overview.html pre-launch and / once launched.

    Repeated heading text is also a real navigation defect and not only untidy: a
    screen-reader user listing the headings on the page hears the same label twice
    with no way to tell which section is which.
    """
    import collections
    import html as _html
    seen_pages = 0
    for out in (built_site, built_site_launched):
        for page in sorted(out.glob("*.html")):
            body = re.sub(r"<script.*?</script>", "", page.read_text(), flags=re.S)
            texts = [re.sub(r"\s+", " ",
                            _html.unescape(re.sub(r"<[^>]+>", "", m))).strip()
                     for m in re.findall(r"<h[1-6][^>]*>(.*?)</h[1-6]>", body, re.S)]
            texts = [t for t in texts if t]
            seen_pages += 1
            dupes = [t for t, n in collections.Counter(texts).items() if n > 1]
            assert not dupes, (
                f"{page.name} renders {len(dupes)} repeated heading(s): {dupes}. "
                "Two headings with one label give a screen reader no way to tell "
                "the sections apart.")
    assert seen_pages >= 8, (
        f"only {seen_pages} page(s) checked across both builds; this test is "
        "not reading the site it is about")


def test_the_front_page_makes_its_two_qualifications_somewhere_reachable(built_site,
                                                                           built_site_launched):
    """INVERTED 2026-08-27. This asserted the hedge was BEFORE the rows.

    The hedge said "A floor, not a total. Only configured feeds are read... It
    does not say which CNA reserved any of these IDs" and sat above the first row
    deliberately: it had been a <caption> on the old table, so the qualifier
    travelled with a copy, a print or a screen-reader pass of the list. Jerry
    removed it on 2026-08-27.

    So the strong claim is gone and this asserts the weaker one that is still
    true: both qualifications are in the page's HTML, and neither is behind a
    conditional. They are in the panel, which is a hidden dialog.

    THE COST IS NAMED HERE rather than left in a commit message, because this test
    is where someone will look: a reader who selects the rows and pastes them into
    a ticket now carries the rows and neither qualification. That was the whole
    reason for the old position, and it was given up knowingly.

    What this still catches is the two claims disappearing altogether, which would
    leave the site publishing a bare count of a state it declines to qualify.
    """
    for out, name in ((built_site, "overview.html"),
                      (built_site_launched, "index.html")):
        body = (out / name).read_text()
        low = body.lower()
        assert "floor" in low, (
            f"{name} does not say anywhere that the count is a floor")
        assert "does not say which cna" in low or "names no cna" in low or \
               "no cna is named" in low, (
            f"{name} does not say anywhere that it names no CNA")
        # Not behind the JS: it has to be in the served HTML, or a reader without
        # scripts and every non-rendering crawler sees an unqualified count.
        island = body.index('<script id="rows"')
        assert "floor" in body[:island].lower(), (
            f"{name} states the floor claim only after the row data, or only from "
            "script; it must be in the served markup")

def test_the_front_page_has_exactly_one_h1():
    """document.querySelectorAll('h1') was empty on the page that will be ranked
    and linked most, and the outline started at H2."""
    src = (TEMPLATES / "list.html").read_text()
    assert src.count("<h1") == 1, (
        "the front page has no h1, or has more than one. It had NONE from the "
        "2026-08-26 pivot until this test was repointed at the template that is "
        "actually rendered: the outline started at the panel's h2, inside a "
        "hidden dialog, on the most-linked page on the site")
    assert "{% block og_title %}" in src, "no og_title override on the front page"
    title = re.search(r"\{% block title %\}(.*?)\{% endblock %\}", src)
    assert title and title.group(1).strip() != "RBP Tracker", (
        "the front page still has the generic title")


def test_there_is_a_mobile_breakpoint_at_all():
    """rbp.css contained ZERO @media rules, so the table laid out at 2,488px
    min-content inside a 351px wrapper: a 7.1x overflow that min-width guaranteed
    could never reflow, so 86% of every row was off screen and Inferred owner was
    never visible on a phone."""
    css = CSS.read_text()
    # 768, not 767. style.css opens its own mobile block at max-width: 768px with
    # `table { min-width: 600px }` and `th, td { white-space: nowrap }`, so a card
    # layout starting at 767 left EXACTLY 768px, the iPad portrait width, with the
    # card layout off and both of those on.
    assert "@media (max-width: 768px)" in css
    assert "@media (max-width: 767px)" not in css, (
        "the card layout reopened one pixel below style.css's mobile block, "
        "which leaves 768px with nowrap on and no card layout")
    mob = css[css.index("@media (max-width: 768px)"):]
    assert "min-width: 0" in mob, "the table's min-width is never released"
    assert "data-label" in mob, "no per-cell labels for the card layout"
    # And the inherited nowrap has to be undone IN THE CARD-LAYOUT RULE, or
    # stacked block cells still refuse to wrap and push the page sideways.
    # Scoped to that rule rather than to the whole media block: `white-space:
    # normal` appears twice, so a bare substring check passed with the one that
    # matters deleted.
    # The STANDALONE rule, not the combined `table.rbp, ... , table.rbp td {`
    # display rule that appears first and only sets display and width.
    # Comments stripped FIRST. The comment inside this very rule quotes
    # `th, td { white-space: nowrap }`, braces and all, so an unstripped
    # `[^}]*` stops inside the comment and reads half a rule. Exactly the bug
    # rbp/contrast.py had to fix for the same reason.
    import re as _re
    m = _re.search(r"(?:^|\n)\s*table\.rbp td \{([^}]*)\}",
                   contrast.strip_comments(mob))
    assert m, "no standalone `table.rbp td` rule in the card layout"
    card_td = m.group(1)
    assert "white-space: normal" in card_td, (
        "the card layout never resets style.css's `th, td { white-space: nowrap }`")


def test_no_table_keeps_a_min_width_floor_at_narrow_widths():
    """WCAG 1.4.10. The .rbp tables get the card layout; the OTHER tables, the
    coverage figures and the launch checklist, are table.table-sm and were
    inheriting `min-width: 600px` and `nowrap` from style.css with nothing to
    undo them. /cves had 926px of horizontal page scroll at 375px and /method had
    1,656px."""
    css = CSS.read_text()
    mob = css[css.index("@media (max-width: 768px)"):]
    assert "table.table-sm" in mob, (
        "the non-.rbp tables are never released from the 600px floor")
    block = mob[mob.index("table.table-sm"):]
    assert "min-width: 0" in block
    # They stay tabular but scroll inside their own box, so the PAGE does not.
    assert "overflow-x: auto" in block


def test_every_value_in_a_row_is_labelled_next_to_itself():
    """A hedge has to sit next to the claim it qualifies, at every width.

    This was a table with `thead { display: none }` on mobile and `data-label`
    on each cell. Since 2026-08-26 the rows are <details> blocks with no header
    row at ANY width, so the labels are not a mobile affordance any more: they
    are the only thing naming each value, and a bare number with no unit beside
    it is the defect the original test existed to prevent.
    """
    src = (TEMPLATES / "list.html").read_text()
    # Rendered in rowHtml(), so they are on every row rather than in a header.
    #
    # CASE-INSENSITIVE since 2026-08-27, when the UI chrome went to title case and
    # this broke on ">days public<" becoming ">Days Public<". The concern is that
    # the number carries a UNIT, not how the unit is capitalised, and a guard that
    # fails on a styling change is a guard people learn to edit without reading.
    assert re.search(r'>\s*days public\s*<', src, re.I), (
        "the age number has no unit next to it")
    assert re.search(r'>\s*showing up in\s*<', src, re.I), (
        "the source chips have no label")
    # And the detail panel names what its dates are.
    assert re.search(r'where it surfaced, and when', src, re.I)


def test_print_preserves_the_certainty_vocabulary():
    """The inherited print block forces `color: #212529 !important` on td, th, span
    and a, collapsing the whole certainty vocabulary to one ink: a candidate MUST
    becomes indistinguishable from a SHOULD and the abstention marker loses its
    distinction. It also never reset .tablewrap's overflow or the table's
    min-width, so an overflow box with no scrollbar clipped the page."""
    css = CSS.read_text()
    assert "@media print" in css
    pr = css[css.index("@media print"):]
    assert "chip-must::after" in pr, "MUST is not distinguishable in one ink"
    assert "chip-unmeasured::after" in pr
    assert "unattributed::after" in pr
    assert "overflow: visible !important" in pr, "the overflow box still clips"
    assert "min-width: 0 !important" in pr


def test_reduced_motion_is_respected():
    assert "prefers-reduced-motion" in CSS.read_text()


def test_focus_is_visible_somewhere():
    """One outline rule existed in the entire project, so no focus treatment was
    ever designed, on a site whose primary surface is a sortable table."""
    css = CSS.read_text()
    assert ":focus-visible" in css
    assert "outline:" in css[css.index(":focus-visible"):]


def test_the_empty_state_is_not_styled_as_a_warning():
    """Empty is not a warning, and launch day is empty by design.

    Repointed to list.html on 2026-08-26. The zero state moved with the front
    page and then was DROPPED in the move: the pivot left the list page with a
    filter-matched-nothing state and no snapshot-has-no-rows state at all, so an
    epoch set on launch morning would have rendered "0" over a blank page. This
    test read templates/index.html throughout and passed.
    """
    assert ".empty-state" in CSS.read_text()
    src = (TEMPLATES / "list.html").read_text()
    assert "{% if not summary.total %}" in src, (
        "the list page has no zero state; with an epoch set this is launch day")
    block = src[src.index("{% if not summary.total %}"):]
    block = block[:block.index("{% endif %}")]
    assert "empty-state" in block, "the zero state is styled as something else"
    assert "caveat warn" not in block, "the zero state is styled as a warning"
    assert "not a fault" in block


# --------------------------------------------------------------------------
# contrast, COMPUTED (review item 15)
# --------------------------------------------------------------------------
#
# Every test above this line is a re.search over CSS or template text. None of
# them could see the six real failures the review found, and the reason is
# structural rather than an oversight: the chips are semi-transparent, so their
# rendered background does not exist anywhere in the stylesheet. It comes into
# being only when a colour is composited over whatever the row happens to be,
# and a regex cannot composite anything.
#
# rbp/contrast.py does the compositing. These tests assert the ratios.

import pytest

from rbp import contrast

# The opaque surfaces a chip or a line of prose actually lands on. Taken from
# the real tokens rather than invented: --color-bg-primary, --color-bg-content
# and --color-bg-secondary in each theme.
#
# THE STRIPED ROW IS ONE OF THEM, and its absence here is how a 2.6:1 failure on
# every even table row of /method and /status survived a suite whose own docstring
# says the ratios are "measured against every background the text actually renders
# on, not against white: half the rows are not white". Half the rows were not
# white and this list did not have the colour they were.
#
# --color-bg-secondary IS the stripe now, in both themes, because style.css was
# corrected to use the token instead of a hardcoded translucent fill. Listed
# separately anyway rather than deduplicated, so that if the stripe is ever given
# its own colour again the sweep has somewhere to put it.
_STRIPE = {"light": "#e9ecef", "dark": "#1a1d27"}
SURFACES = {
    "light": ("#f8f9fa", "#ffffff", "#e9ecef", _STRIPE["light"]),
    "dark": ("#0f1117", "#151821", "#1e2130", _STRIPE["dark"]),
}

# DISCOVERED, NOT TYPED. This list used to be seven chips written by hand, in
# the commit that fixed a review finding ABOUT hand-typed lists. There are eight
# chips. `.chip-unmeasured` was the missing one and was still failing at 3.95 in
# light theme, and it is the marker the stylesheet itself calls the largest
# column on the page. The same omission also left td.desc, blockquote,
# .nav-menu a and every footer link on the uncorrected tokens.
#
# contrast.text_selectors() scans both stylesheets for every rule that sets a
# text colour and filters to the ones this site's templates actually render, so
# a selector is covered the moment it gains a colour and nobody has to remember.
CONTRAST_SELECTORS = contrast.text_selectors()


def test_the_selector_list_is_discovered_and_not_empty():
    """An empty or collapsed scan would make every parametrised test below
    vacuously pass, which is the failure mode this file exists to stop being."""
    assert len(CONTRAST_SELECTORS) >= 60, (
        f"only {len(CONTRAST_SELECTORS)} selectors discovered; the scan has "
        "collapsed and the AA tests below are asserting almost nothing")
    # The specific miss that motivated the change.
    assert ".chip-unmeasured" in CONTRAST_SELECTORS
    # And every chip, since they are written by page JavaScript rather than
    # appearing in template markup as literal class attributes.
    # Every chip a template still emits. `.chip-block` is deliberately absent:
    # it was the owner-tier marker and v1 publishes no attribution, so the rule
    # was dead CSS and was deleted rather than left to pad a coverage list.
    for chip in ("must", "should", "ok", "late", "corrob", "none", "unmeasured"):
        assert f".chip-{chip}" in CONTRAST_SELECTORS, chip


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("selector", CONTRAST_SELECTORS)
def test_text_meets_aa_on_every_surface_it_lands_on(selector, theme):
    """WCAG 2.1 1.4.3 at the normal-text bar of 4.5.

    Chips render at 11.52px/600, which is neither >=18.66px nor >=14px bold, so
    the large-text exemption of 3.0 does not apply to them.

    My earlier version of this test was deleted along with the hand-typed list
    it was parametrised over, which took the assertion count from 26 to 0 while
    the suite still reported green. That is the same class of defect as
    everything else in this file's history: a check that stopped checking and
    looked exactly like one that had nothing to report.
    """
    try:
        worst = min(contrast.effective_ratio(selector, bg, theme)
                    for bg in SURFACES[theme])
    except contrast.Unmeasurable as e:
        # `inherit` and `currentColor` resolve against the parent element, which
        # needs a DOM. Skipped rather than guessed: a guessed ratio is worse
        # than an absent one, and this is the honest boundary of a static
        # harness. It is also exactly what a browser-backed check would cover.
        pytest.skip(str(e))
    assert worst >= contrast.AA_NORMAL, (
        f"{selector} renders at {worst} in {theme} theme, below "
        f"{contrast.AA_NORMAL}")


# The most cases the sweep above may decline to measure.
#
# ONE, and it is named below. The number is a ceiling on how blind this harness
# is allowed to be, and it is deliberately not slack: a skip and a pass are
# indistinguishable in a green run, so every skip is a selector whose contrast
# nobody is checking while the suite reports coverage of it.
MAX_UNMEASURABLE = 1


def test_the_contrast_sweep_is_not_quietly_skipping_itself():
    """The hole the skip channel reopened, and the second time this file has lost
    its own coverage without going red.

    The first time, the parametrised list was hand-typed and got deleted with the
    selectors it named: 26 assertions to 0, still green. That was fixed by
    DERIVING the list from the stylesheet. The skip channel then did the same
    thing from the other end. `contrast.rule_colors` required a trailing semicolon
    on the `color:` declaration, which is optional CSS that nobody writes when
    minifying, so every minified rule the 2026-08-26 pivot added parsed as
    declaring no colour at all. Fourteen cases skipped, saying the selectors
    "inherit", which was false of all fourteen: `a.chip`, `a.chip:hover`,
    `a.chip:focus-visible` and `span.chip.nolink` are the front page's only
    interactive elements and every one of them declares its own colour.

    So the count is asserted, the way ci.yml asserts that the render suite
    collected something. RBP_RENDER_TESTS turns a skip into a failure in the
    browser job; nothing did the equivalent here.
    """
    unmeasurable = []
    for selector in CONTRAST_SELECTORS:
        for theme in ("light", "dark"):
            try:
                min(contrast.effective_ratio(selector, bg, theme)
                    for bg in SURFACES[theme])
            except contrast.Unmeasurable:
                unmeasurable.append(f"{selector} ({theme})")
    assert len(unmeasurable) <= MAX_UNMEASURABLE, (
        f"{len(unmeasurable)} contrast cases cannot be measured, above the "
        f"ceiling of {MAX_UNMEASURABLE}. Each one is a selector this suite "
        f"reports on and does not check:\n  " + "\n  ".join(unmeasurable) +
        "\n\nA selector that genuinely inherits is a correct answer; a selector "
        "the PARSER cannot read is a defect in rbp/contrast.py. Check which "
        "before raising the ceiling.")


def test_the_only_permitted_skip_is_the_one_that_genuinely_inherits():
    """The ceiling above bounds the COUNT. This names the case, so raising the
    count silently is not enough to hide a new one: `.table` is styled only inside
    [data-theme="dark"], so in light theme it inherits from body, which needs a
    DOM. That is a correct answer from a static harness rather than a gap in it.
    """
    unmeasurable = set()
    for selector in CONTRAST_SELECTORS:
        for theme in ("light", "dark"):
            try:
                min(contrast.effective_ratio(selector, bg, theme)
                    for bg in SURFACES[theme])
            except contrast.Unmeasurable:
                unmeasurable.add((selector, theme))
    assert unmeasurable <= {(".table", "light")}, (
        f"an unexpected selector cannot be measured: {sorted(unmeasurable)}")


def test_a_root_override_does_not_silently_undo_the_dark_theme():
    """The equal-specificity trap, which cost nine selectors and hid behind a
    harness that agreed with itself.

    `:root` and `[data-theme="dark"]` both have specificity (0,1,0), so between
    them SOURCE ORDER decides. rbp.css loads after style.css. So when rbp.css
    corrects a token at `:root` and does not also re-assert it for dark, the
    light-theme value wins in dark theme, and nothing about the light theme looks
    wrong.

    That happened to `--color-text-secondary`: corrected to #5a6168 at `:root`,
    solved against the light surfaces, beating style.css's dark #9ca3b4. Measured
    in a browser at 2.54:1 across `.text-muted`, `.nav-menu a`, `.footer`,
    `.footer a`, `blockquote`, `.chip-unmeasured`, `.metric-label`,
    `.theme-toggle` and `.page-header small`. `contrast.tokens` returned
    `{**light, **dark}` and reported 7.02 for all of them.

    The rbp.css comment argues that overriding the TOKEN "cannot be missed by
    omission", against repointing rules one at a time. It is right, and this is
    its one failure mode: the omission moves from the rules to the other theme.

    Structural, so it fires on the NEXT token rather than on this one.
    """
    import re as _re
    style = contrast.strip_comments((pathlib.Path(contrast.CSS) / "style.css").read_text())
    rbp = contrast.strip_comments((pathlib.Path(contrast.CSS) / "rbp.css").read_text())

    def decls(css, selector):
        out = {}
        for m in _re.finditer(r"([^{}]*?)\{([^{}]*)\}", css, _re.S):
            sel = m.group(1).strip()
            if selector == "root" and (':root' not in sel or 'data-theme' in sel):
                continue
            if selector == "dark" and 'data-theme="dark"' not in sel:
                continue
            for name, value in _re.findall(
                    r"(--(?:color|rbp|chart)-[\w-]+)\s*:\s*([^;]+);", m.group(2)):
                out[name.strip()] = value.strip()
        return out

    style_dark = decls(style, "dark")
    rbp_root = decls(rbp, "root")
    rbp_dark = decls(rbp, "dark")

    # A token that style.css themes, that rbp.css then overrides at :root, and
    # that rbp.css does NOT re-assert for dark. rbp.css loads second, so its
    # :root value wins in BOTH themes and the dark value is dead.
    clobbered = sorted(t for t in rbp_root
                       if t in style_dark and t not in rbp_dark)
    assert not clobbered, (
        "rbp.css overrides these at :root, style.css themes them for dark, and "
        "rbp.css does not re-assert them there. rbp.css loads second and :root "
        "has the same specificity as [data-theme=\"dark\"], so the LIGHT value "
        f"wins in dark theme: {clobbered}")


def test_no_table_stripe_is_a_translucent_fill_without_a_dark_override():
    """The defect the SURFACES list could not see, asserted at its source.

    A translucent stripe has no rendered colour in the stylesheet: it exists only
    once composited over whatever is beneath it, which is a different colour in
    each theme. `rgba(248, 249, 250, 0.5)` with no dark override composited to
    #8b8d95 over the dark card and carried body text at 2.6:1 and links at 1.56:1.

    rbp.css already described this defect in a comment and restated the rule
    correctly, SCOPED to `table.rbp`, and left the unscoped original in place. So
    the correction covered one table and the bug covered every other one, and then
    the pivot deleted the pages `table.rbp` was on.

    Asserted on the rule rather than on a ratio, because the ratio depends on what
    the stripe lands over and the point is that a stripe must not depend on that.
    """
    for name in ("style.css", "rbp.css"):
        css = contrast.strip_comments((pathlib.Path(contrast.CSS) / name).read_text())
        for m in re.finditer(r'([^{}]*nth-child\([^)]*\)[^{}]*)\{([^{}]*)\}', css):
            sel, body = m.group(1).strip(), m.group(2)
            bg = re.search(r'background(?:-color)?\s*:\s*([^;}]+)', body)
            if not bg:
                continue
            value = bg.group(1).strip()
            assert not value.startswith("rgba"), (
                f"{name}: `{sel}` stripes with the translucent fill {value!r}. "
                "A stripe has to be an opaque token, or it has no colour until it "
                "is composited and no theme override can reach it.")


def test_the_harness_reproduces_the_ratios_the_review_measured():
    """A calibration test, and the reason to trust the numbers above.

    These are the values the adversarial review measured independently, in a
    browser, against the pre-fix stylesheet. If this module's arithmetic drifts
    from a browser's, the tests above become confidently wrong in the same way
    the grep suite was, and nothing would say so.
    """
    # chip-none was --color-text-muted (#adb5bd) on --color-bg-secondary.
    assert contrast.ratio(contrast.parse_hex("#adb5bd"),
                          contrast.parse_hex("#e9ecef")) == 1.75
    # chip-ok was #2f9e6b composited over rgba(25,135,84,0.14) on #e9ecef.
    base = contrast.composite((25, 135, 84), 0.14, contrast.parse_hex("#e9ecef"))
    assert contrast.ratio(contrast.parse_hex("#2f9e6b"), base) == 2.41
    # And the sanity anchors: identical colours are 1.0, black on white is 21.
    assert contrast.ratio((0, 0, 0), (0, 0, 0)) == 1.0
    assert contrast.ratio((0, 0, 0), (255, 255, 255)) == 21.0


def test_the_selector_lookup_ignores_comments_and_honours_the_cascade():
    """Two harness bugs that made it confidently wrong, both found by using it.

    Comments in rbp.css mention selectors by name, so an unstripped search for
    `td.unattributed` matched prose and ran on to the next rule's braces,
    returning a different element's colours. And `table.rbp th` is declared
    twice, so a first-match read reported the value the browser overrides and a
    rule that had already been fixed still read as failing.
    """
    css = """
    /* a comment mentioning .fake-sel and its history */
    .fake-sel { color: #111111; }
    .fake-sel { color: #222222; }
    """
    # The LAST declaration wins, as the browser does it.
    assert contrast.rule_colors(".fake-sel", css) == ("#222222", None)
    # And the comment is gone, so its mention of the selector cannot be matched
    # as though it were a rule.
    stripped = contrast.strip_comments(css)
    assert "history" not in stripped and "comment" not in stripped
    assert ".fake-sel {" in stripped


def test_effective_ratio_actually_composites_the_translucent_background():
    """The step that makes this harness different from a grep, asserted in the
    path that uses it.

    Skipping the composite call and measuring the text against the bare page
    background still passed every ratio assertion above, because the corrected
    colours clear 4.5 either way. So nothing proved the compositing happened,
    and a harness that silently stopped doing it would go on reporting numbers
    that look right and are not the ones a reader sees.

    `.chip-must` is `rgba(220, 53, 69, 0.12)`: a red wash that LIGHTENS a white
    surface slightly and therefore changes the ratio. If the two agree, the
    background was ignored.
    """
    composited = contrast.effective_ratio(".chip-must", "#ffffff", "light")
    color, _bg = contrast.rule_colors(".chip-must")
    naive = contrast.ratio(contrast.parse_hex(color),
                           contrast.parse_hex("#ffffff"))
    assert composited != naive, (
        "effective_ratio measured against the bare surface; the translucent "
        "chip background was not composited, which is the whole point")

    # And the composite itself moves in the right direction and the right amount.
    assert contrast.composite((255, 255, 255), 0.5, (0, 0, 0)) == (128, 128, 128)
    assert contrast.composite((10, 20, 30), 1.0, (200, 200, 200)) == (10, 20, 30)
    assert contrast.composite((10, 20, 30), 0.0, (200, 200, 200)) == (200, 200, 200)


def test_the_sort_buttons_have_a_focus_indicator_that_wins():
    """`all: unset` on table.rbp th button.sortbtn is specificity (0,2,3) and
    beat the project's single focus rule, so seven keyboard-operable controls
    had no visible focus indicator at all. SC 2.4.7, on the control a keyboard
    user reaches first on the page the site most wants cited.

    Asserted on the SELECTOR, not just on the presence of an outline somewhere:
    a focus rule that loses the cascade is the same as no focus rule, and that
    is precisely what was there."""
    css = contrast.strip_comments(CSS.read_text())
    assert "table.rbp th button.sortbtn:focus-visible" in css, (
        "no focus rule at the sort button's own specificity; a lower-specificity "
        "rule loses to `all: unset`")
    block = css[css.index("table.rbp th button.sortbtn:focus-visible"):]
    block = block[:block.index("}")]
    assert "outline" in block and "none" not in block


def test_every_scroll_container_is_keyboard_reachable():
    """A scrollable region with no tab stop is unreachable without a pointer,
    SC 2.1.1 at Level A. Nine .tablewrap containers existed and exactly one, on
    /cves, carried tabindex. The other eight hid table content behind a scroll
    only a mouse could move."""
    import re as _re
    for tpl in TEMPLATES.glob("*.html"):
        body = tpl.read_text()
        for m in _re.finditer(r'<div class="tablewrap"([^>]*)>', body):
            attrs = m.group(1)
            for a in ("tabindex", "role=", "aria-label"):
                assert a in attrs, (
                    f"{tpl.name}: a scroll container is missing {a}; it cannot "
                    "be reached or announced without a pointer")


def test_the_nav_can_wrap_rather_than_overflowing_the_page():
    """72 to 79px of horizontal page overflow was measured across 769 to 847px
    on seven of nine pages, with the theme toggle entirely off screen. The
    mobile menu collapses at 768px and the full nav does not fit until the high
    840s, leaving an 80px band where neither layout works. WCAG 1.4.10.

    Asserted on `flex-wrap`, not on a breakpoint number: the exact width at
    which the nav stops fitting is font-metric dependent, so a number would be
    correct on the machine it was measured on and wrong on the next one. Wrap is
    the mechanism and it holds at every width."""
    css = contrast.strip_comments(CSS.read_text())
    import re as _re
    m = _re.search(r"(?:^|\n)\.nav\s*\{([^}]*)\}", css)
    assert m, "no .nav rule in rbp.css to allow wrapping"
    assert "flex-wrap: wrap" in m.group(1), (
        "the nav is a non-wrapping flex row, so it overflows the page rather "
        "than reflowing when it does not fit")
