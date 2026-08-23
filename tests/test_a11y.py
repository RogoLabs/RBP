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


def test_sorting_is_reachable_without_a_pointer():
    """Sorting was a click listener on a non-focusable th: seven columns unreachable
    without a pointer (SC 2.1.1, level A), while aria-sort was maintained correctly,
    so the state was announceable and the control was inoperable."""
    src = (TEMPLATES / "cves.html").read_text()
    sortable = len(re.findall(r'<th[^>]*data-sort=', src))
    buttons = len(re.findall(r'class="sortbtn"', src))
    assert sortable > 0
    assert buttons >= sortable, (
        f"{sortable} sortable columns, {buttons} focusable controls")
    # And the listener must be bound to the button, not the th.
    assert "querySelector('button.sortbtn')" in src


def test_the_scroll_container_is_reachable_and_named():
    src = (TEMPLATES / "cves.html").read_text()
    m = re.search(r'<div class="tablewrap"([^>]*)>', src)
    assert m, "tablewrap not found"
    attrs = m.group(1)
    for a in ("tabindex", "role=", "aria-label"):
        assert a in attrs, f"the scroll container has no {a}"


def test_a_filter_matching_nothing_announces_something():
    """render() replaced #body.innerHTML wholesale with no aria-live anywhere, so a
    filter that matched nothing announced nothing at all."""
    src = (TEMPLATES / "cves.html").read_text()
    assert 'aria-live="polite"' in src
    assert "empty-state" in src, "no explicit empty-state row"


def test_export_links_are_hidden_on_a_zero_row_table():
    """They produce a header-only file."""
    src = (TEMPLATES / "cves.html").read_text()
    assert "getElementById('exports')" in src


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


def test_the_primary_table_has_a_caption_carrying_the_hedge():
    """So the qualifier travels with the table into a copy, a print or a screen
    reader rather than living in a caveat block below it."""
    src = (TEMPLATES / "cves.html").read_text()
    assert "<caption>" in src
    cap = src[src.index("<caption>"):src.index("</caption>")]
    # Was "inferred": the hedge used to be that the OWNER was inferred. v1
    # publishes no owner, so the hedge the caption must carry is the stronger
    # one, that the site does not attribute these rows at all.
    assert "does not say which cna" in cap.lower()
    assert "floor" in cap.lower()


def test_the_front_page_has_exactly_one_h1():
    """document.querySelectorAll('h1') was empty on the page that will be ranked
    and linked most, and the outline started at H2."""
    src = (TEMPLATES / "index.html").read_text()
    assert src.count("<h1") == 1
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


def test_the_mobile_layout_labels_every_cell():
    """With thead hidden, a hedge has to sit next to the claim it qualifies."""
    src = (TEMPLATES / "cves.html").read_text()
    for label in ("CVE ID", "Days public", "Rule", "Package",
                  "Independent sources", "Sources", "Advisory summary"):
        assert f'data-label="{label}"' in src, label


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
    """Empty is not a warning. /changes shipped as an h1 plus one grey sentence,
    167 characters of <main>, as item four of seven in the primary nav, and that is
    also what launch day looks like."""
    assert ".empty-state" in CSS.read_text()
    changes = (TEMPLATES / "changes.html").read_text()
    assert "empty-state" in changes
    assert "caveat warn" not in changes.split("empty-state")[1][:400]


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
SURFACES = {
    "light": ("#f8f9fa", "#ffffff", "#e9ecef"),
    "dark": ("#0f1117", "#151821"),
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
