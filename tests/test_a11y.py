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
    for tpl in TEMPLATES.glob("*.html"):
        body = tpl.read_text()
        unscoped = [m.group(0)[:60] for m in re.finditer(r"<th(?![^>]*\bscope=)", body)]
        assert not unscoped, f"{tpl.name}: {len(unscoped)} th without scope"


def test_the_primary_table_has_a_caption_carrying_the_hedge():
    """So the qualifier travels with the table into a copy, a print or a screen
    reader rather than living in a caveat block below it."""
    src = (TEMPLATES / "cves.html").read_text()
    assert "<caption>" in src
    cap = src[src.index("<caption>"):src.index("</caption>")]
    assert "inferred" in cap.lower()
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
    assert "@media (max-width: 767px)" in css
    mob = css[css.index("@media (max-width: 767px)"):]
    assert "min-width: 0" in mob, "the table's min-width is never released"
    assert "data-label" in mob, "no per-cell labels for the card layout"


def test_the_mobile_layout_labels_every_cell():
    """With thead hidden, a hedge has to sit next to the claim it qualifies."""
    src = (TEMPLATES / "cves.html").read_text()
    for label in ("CVE ID", "Days public", "Rule", "Inferred owner", "Package",
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
