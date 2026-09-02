"""
/status, and what must NOT be on the front page any more.

WHY THIS FILE EXISTS. The degraded-run banner rendered four lines of explanation
about feed truncation above the first CVE, on every page, and the detail moved to
/status on 2026-08-26. Two things then have to stay true at once, and they pull in
opposite directions:

  - the DISCLOSURE stays on every page, because PLAN.md's rule is "never publish a
    degraded run without a banner" and a count that is a lower floor than usual has
    to say so where the count is;
  - the EXPLANATION does not, because a reader who came for a list of CVE IDs met a
    paragraph about page caps first.

A change that satisfies either one alone is easy and wrong. So the tests below
assert both directions: the notice is present and short on the list page, and the
full explanation is present on /status and absent from the list page.

EVERY TEST HERE BUILDS A DEGRADED RUN. The shared fixture produces a clean one, on
purpose, because that is the normal state. That makes the degraded branch of every
template invisible to it, which is this project's most expensive recurring bug in
its most recent form: "no fixture produced a degraded run, so False == False
passed". `degraded_build` below is the fixture that does.
"""
from __future__ import annotations

import importlib
import json
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import _sitefixture

REASONS = ["1 feed(s) failed", "1 feed(s) returned far fewer ids than last run"]


def _build(root, launched, mutate=None):
    """A site built from the shared fixture with the summary mutated first.

    Not `_sitefixture.build`, because that writes the snapshots and builds in one
    call and the point here is to change the summary in between.
    """
    from rbp import site as _site

    root = pathlib.Path(root)
    snaps, data = _sitefixture.write_snapshots(root)
    latest = sorted(p for p in snaps.iterdir() if p.is_dir())[-1]
    summary = json.loads((latest / "summary.json").read_text())
    if mutate:
        mutate(summary)
    (latest / "summary.json").write_text(json.dumps(summary))

    out = root / ("launched" if launched else "prelaunch")
    mp = pytest.MonkeyPatch()
    mp.setenv("RBP_LAUNCHED", "1" if launched else "")
    site = importlib.reload(_site)
    try:
        site.build(str(out), str(snaps), str(data))
    finally:
        mp.undo()
        importlib.reload(_site)
    return out


def _degrade(summary):
    summary["degraded"] = True
    summary["degraded_reasons"] = REASONS
    summary["feeds"]["shrunk"] = ["ghsa: 3321 -> 41 ids (-98.8%)"]
    summary["feeds"]["withdrawn"] = [
        "msrc: newest advisory moved BACKWARD, 2026-08-11 -> 2026-07-14; the "
        "source withdrew advisories it had already served",
        "msrc: 2026-08 held 1,637 ids and holds 0 now (100% of that month "
        "withdrawn)"]
    summary["feeds"]["failures"] = ["ubuntu: HTTP 503"]
    summary["feeds"]["detail"] = {
        "osv": {"status": "ok", "detail": "", "rows": 1200, "ok": True},
        "ghsa": {"status": "capped", "detail": "40-page cap", "rows": 41, "ok": False},
        "ubuntu": {"status": "failed", "detail": "HTTP 503", "rows": None, "ok": False},
        "debian": {"status": "truncated", "detail": "stopped at 12 pages",
                   "rows": 88, "ok": False},
    }
    summary["limitations"] = ["ghsa: 40-page cap reached"]


@pytest.fixture(scope="module")
def degraded_build(tmp_path_factory):
    return _build(tmp_path_factory.mktemp("degraded"), launched=True, mutate=_degrade)


@pytest.fixture(scope="module")
def degraded_prelaunch(tmp_path_factory):
    return _build(tmp_path_factory.mktemp("degraded_pre"), launched=False, mutate=_degrade)


# --------------------------------------------------------------------------
# the page exists, in both postures
# --------------------------------------------------------------------------

def test_status_is_built_in_both_postures(built_site, built_site_launched):
    """It is in the nav on every page, so it must exist on every build. A nav
    entry pointing at a page the build does not write is a 404 sitewide, which is
    how /cnas shipped after its template was deleted."""
    for out in (built_site, built_site_launched):
        assert (out / "status.html").exists(), f"{out.name} wrote no status.html"


def test_status_is_reachable_from_the_nav_without_a_failure_first(built_site):
    """A status page you can only find when something is already broken cannot be
    used to check whether anything is broken. It is in the nav on a CLEAN run,
    which is the run this asserts against."""
    body = (built_site / "overview.html").read_text()
    assert json.loads(_rows_island(body)), "the fixture built no rows"
    assert 'href="status.html">Status</a>' in body


def _rows_island(body):
    m = re.search(r'<script id="rows" type="application/json">(.*?)</script>', body, re.S)
    assert m, "no row island on the page"
    return m.group(1)


# --------------------------------------------------------------------------
# a clean run says so, rather than saying nothing
# --------------------------------------------------------------------------

def test_a_clean_run_states_that_it_was_clean(built_site):
    """Absence of a warning is not the same as a statement that nothing is wrong,
    and on a page whose whole job is answering "is this working" it has to be the
    second one. A blank status page reads as a broken status page."""
    body = (built_site / "status.html").read_text()
    assert "The last run was complete" in body
    assert "This run is incomplete" not in body


def test_a_clean_run_carries_no_notice_on_the_list_page(built_site):
    """The other half of the rule. The notice must not be furniture: a warning
    that is always on trains a reader to ignore the one that matters, which is
    exactly what happened when configured page caps were recorded as
    truncation."""
    assert "This run is incomplete" not in (built_site / "overview.html").read_text()


# --------------------------------------------------------------------------
# a degraded run: the disclosure stays, the explanation moves
# --------------------------------------------------------------------------

def test_a_degraded_run_puts_nothing_on_the_list_page(
        degraded_build, degraded_prelaunch):
    """THE ACTUAL CHANGE, and it is an absence, so it has to be asserted.

    A banner rendered above the first CVE on every page whenever a feed failed,
    stopped early or shrank. It had two versions: four lines explaining feed
    truncation, then one line plus a link. Both were the same decision, that the
    reader of a list of CVE IDs should be interrupted by the state of the build
    that produced it. Jerry's call, 2026-08-26: they should not.

    PLAN.md's rule reads "never publish a degraded run without a banner". It was
    written when /method was three clicks away and no page had the run as its
    subject. The condition is still disclosed, in four places, none of them a
    banner: /status, `degraded` in rbp.json, the standing floor hedge above the
    rows, and the staleness banner for the different failure of a stopped
    pipeline.

    Asserted in BOTH postures, because the front page has a different filename in
    each and a rule that only holds for index.html is half a rule.
    """
    for out, front in ((degraded_build, "index.html"),
                       (degraded_prelaunch, "overview.html")):
        body = (out / front).read_text()
        assert "This run is incomplete" not in body, (
            f"{out.name}/{front}: the degraded banner is back on the list page")
        assert "degraded-banner" not in body
        for reason in REASONS:
            assert reason not in body, (
                f"{front} lists the degradation reason {reason!r}; that is /status")


def test_the_list_page_still_says_the_count_is_a_floor(degraded_build):
    """The other half, and the reason removing the degraded banner is defensible.

    REWRITTEN 2026-08-27, and weakened, deliberately and with the cost recorded.

    It used to assert the hedge above the rows: unconditional, ahead of the first
    CVE, and travelling with a copy of the list. That hedge was removed on Jerry's
    call, so this can no longer make the strong claim, and pretending otherwise by
    deleting the test would leave the argument for dropping the degraded
    banner resting on something that no longer exists.

    What is still true and is asserted here: the floor claim is in the page's
    HTML, unconditional, on a degraded run. It is in the panel, which is a hidden
    dialog rather than prose above the rows, so it does NOT travel with a
    selection or a paste.

    The gap that leaves is real: on a degraded run a reader who copies the rows
    carries neither the floor claim nor a note that the count is lower than
    usual. /status, `degraded` in rbp.json and the staleness banner are the three
    disclosures that remain.

    Stated here rather than cited from NEXT.md. It used to read "is named in
    NEXT.md", and when that file was cut back to what is actually open the
    sentence it pointed at stopped existing, leaving a test whose stated
    justification was a dangling reference. A test should carry its own reason.
    """
    body = (degraded_build / "index.html").read_text()
    assert "floor" in body.lower(), (
        "the list page no longer says the count is a floor ANYWHERE, which is the "
        "claim the case for removing the degraded banner rests on")
    # Unconditional: it must not have become something that only renders on a
    # clean run, which would make it useless on precisely the runs it is for.
    assert "every number here is a floor" in body.lower() or \
           "counts are a floor" in body.lower() or \
           "a floor, never a census" in body.lower(), (
        "the floor claim is present but not in a form this test recognises; "
        "check it is still unconditional rather than gated on a clean run")
    # And the machine-readable copy is unambiguous, which is what a consumer
    # reusing the count actually reads.
    payload = json.loads((degraded_build / "data" / "rbp.json").read_text())
    assert payload["degraded"] is True
    assert payload["degraded_reasons"] == REASONS


def test_the_explanation_is_on_status_in_full(degraded_build):
    """The receiving end. Moving copy off a page is only correct if it landed."""
    body = (degraded_build / "status.html").read_text()
    assert "This run is incomplete" in body
    for reason in REASONS:
        assert reason in body, f"/status does not give the reason {reason!r}"
    assert "lower floor than usual" in body
    assert "A run is marked incomplete when" in body


def test_only_status_reports_the_degradation(degraded_build):
    """One page owns this. The banner lived in base.html, so it appeared on all
    four; removing it from there removes it from all four, and /status must be the
    one that still says so.

    Both directions, because "no page mentions it" would also pass the first half
    and would mean the site had stopped disclosing a degraded run entirely.
    """
    for page in ("index.html", "method.html", "policy.html"):
        assert "This run is incomplete" not in (degraded_build / page).read_text(), (
            f"{page} still reports the run state; that is /status's job now")
    assert "This run is incomplete" in (degraded_build / "status.html").read_text(), (
        "no page reports the degraded run at all")


def test_status_is_reachable_from_every_page_on_a_degraded_run(degraded_build):
    """Removing the banner removes the only prompt a reader got. The nav link is
    what replaces it, so it has to be on every page, and it is deliberately there
    on clean runs too: a status page you can only find when something is already
    broken cannot be used to check whether anything is broken."""
    for page in ("index.html", "method.html", "policy.html", "status.html"):
        assert 'href="status.html">Status</a>' in (degraded_build / page).read_text(), page


# --------------------------------------------------------------------------
# what the page has to actually report
# --------------------------------------------------------------------------

def test_every_feed_appears_in_the_per_feed_table_with_its_state(degraded_build):
    """One row per feed, not two prose caveats naming only the failures. The old
    /method card said "no feed failed outright this run" while a feed sat at a
    page cap, because the failure list and the truncation list were rendered by
    separate blocks and a capped feed was in neither."""
    body = (degraded_build / "status.html").read_text()
    table = body[body.index("Feeds read on this run"):]
    for feed, state in (("osv", "ok"), ("ghsa", "capped"),
                        ("ubuntu", "failed"), ("debian", "truncated")):
        assert feed in table, f"{feed} is missing from the per-feed table"
        # Case-insensitive since 2026-08-27: the status chips went to title case
        # and this broke on ">ok<" becoming ">OK<". What matters is that the state
        # is rendered, not how it is capitalised.
        assert re.search(rf">\s*{state}\s*<", table, re.I), (
            f"no feed renders the {state} state")


def test_a_silent_shrink_is_named_not_just_counted(degraded_build):
    """`degraded_reasons` says "1 feed(s) returned far fewer ids than last run"
    and drops WHICH. The per-feed magnitudes are in the summary and were reaching
    no surface at all, so the one failure a status field cannot show was also the
    one a reader could not look up."""
    body = (degraded_build / "status.html").read_text()
    assert "ghsa: 3321 -&gt; 41 ids (-98.8%)" in body or \
           "ghsa: 3321 -> 41 ids (-98.8%)" in body, \
        "the shrink is reported as a count with no feed named"


def test_withdrawn_history_is_named_not_just_counted(degraded_build):
    """Same argument as the silent shrink above, and the same failure if it is
    skipped. `degraded_reasons` can only say HOW MANY feeds withdrew history; the
    fact a reader needs is WHICH PERIOD stopped being evidenced, because that is
    what tells them which rows to distrust.

    Both findings render, because they are different claims: the horizon moving
    backward says the source deleted its most recent advisories, and the month
    bucket says which period went with them.
    """
    body = (degraded_build / "status.html").read_text()
    assert "moved BACKWARD" in body, (
        "a feed withdrew history and the page names no feed and no date")
    assert "2026-08 held 1,637 ids and holds 0 now" in body, (
        "the withdrawn month is counted but not named")
    assert "withdrew history it had already served" in body


def test_a_configured_cap_is_reported_apart_from_a_degradation(degraded_build):
    """A cap fires every run by design. Recording it as truncation made `degraded`
    permanently true and the banner permanent furniture. It has to appear, and it
    has to appear somewhere other than the degraded block."""
    body = (degraded_build / "status.html").read_text()
    assert "Standing limitations" in body
    assert "40-page cap reached" in body
    incomplete = body.index("This run is incomplete")
    standing = body.index("Standing limitations")
    assert standing > incomplete, "the standing caps are inside the degraded block"


def test_the_page_and_the_payload_cannot_disagree(degraded_build):
    """The published JSON and the rendered page describe the same run. They said
    opposite things once: rbp.json carried `degraded: false` while the page
    rendered "This run is incomplete" on the same build."""
    env = json.loads((degraded_build / "data" / "rbp.json").read_text())
    body = (degraded_build / "status.html").read_text()
    assert env["degraded"] is True
    assert env["degraded_reasons"] == REASONS
    assert ("This run is incomplete" in body) == env["degraded"]


def test_status_names_no_cna(degraded_build):
    """v1 publishes no attribution, and a page added late is exactly where that
    gets forgotten. The per-feed table is keyed on FEED names, which are not CNA
    names, and the movement card renders bare CVE IDs.

    Whole-token, because `publish._roster_names_in_text` uses whole-CELL equality
    and this is prose: "Go", "Linux" and "curl" are all certified CNA short names,
    so a substring scan over an HTML page reports every one of them inside an
    unrelated word. Scoped to the rendered TEXT rather than the source, so class
    names, ids and comment blocks do not count as the page naming anyone.

    FEED NAMES ARE ALLOWED, and the overlap is not a coincidence: `debian`,
    `redhat`, `ubuntu` and `mozilla` are simultaneously feeds this site reads and
    certified CNA short names. Saying "this site read the Debian feed and it
    truncated" attributes nothing to anybody; it is a fact about this site's own
    machinery, and /method has printed the same list since before the pivot. What
    must never appear is a roster name that is NOT a feed, because the only way
    one gets onto this page is by escaping from a row.

    This caught a real one: the copy read "the reservation oracle dropped rows",
    and `oracle` is a certified CNA short name.
    """
    from rbp import feeds, roster
    body = (degraded_build / "status.html").read_text()
    text = re.sub(r"<script.*?</script>|<style.*?</style>|<!--.*?-->", " ",
                  body, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    tokens = set(re.findall(r"[A-Za-z0-9_.-]+", text))
    allowed = set(feeds.ADAPTERS)
    named = sorted((tokens & set(roster.load()["names"])) - allowed)
    assert not named, (
        f"/status names {named}, which are certified CNA short names and not "
        "feeds this site reads")


# --------------------------------------------------------------------------
# Round 7 B4: ids fetched is not rows published, and the page has to say so
# --------------------------------------------------------------------------

def test_the_feed_table_separates_ids_read_from_rows_published(built_site):
    """`/status` published one number per feed, ids fetched, and let a reader
    infer the other two.

    Measured on the 2026-08-27 snapshot: `arch` returned 62 ids and `mozilla`
    607, on every run since they merged, and NEITHER appeared in any of the 1,709
    published rows. The table rendered them beside csaf's 2,695 with nothing to
    tell them apart, and csaf is the only source for 22 rows while those two are
    the only source for none. Three different questions, one column.
    """
    body = (built_site / "status.html").read_text()
    table = body[body.index("Feeds read on this run"):]
    for header in ("IDs read", "Rows", "Only source"):
        assert header in table, f"the feed table has no {header!r} column"


def test_a_feed_that_accounts_for_no_published_rows_renders_an_explicit_zero(built_site):
    """`{% if h.rows_published %}` would render zero as the same blank a snapshot
    that never measured it renders. Those are opposite claims, and the zero is
    the entire finding."""
    body = (built_site / "status.html").read_text()
    table = body[body.index("Feeds read on this run"):]
    row = re.search(r'<td class="mono">arch</td>.*?</tr>', table, re.S)
    assert row, "the fixture no longer carries a feed with zero published rows"
    cells = re.findall(r'<td class="num">(.*?)</td>', row.group(0))
    assert cells[:3] == ["62", "0", "0"], (
        f"arch reads {cells[:3]}: 62 ids and no rows must render as an explicit "
        "zero, not as a blank or a dash")


def test_the_ubuntu_cap_reaches_the_reader_in_days(built_site):
    """A cap stated in pages is not a unit a reader has. The line it replaces
    would have read identically whether the cap cost one day or three years."""
    body = (built_site / "status.html").read_text()
    assert "37-day window" in body and "2024-01-01" in body, \
        "the standing cap is still reported only as a page count"


def test_the_feed_table_and_the_published_payload_report_the_same_contribution(built_site):
    """The rendered column and the published JSON must not be able to disagree,
    which is the failure `test_the_page_and_the_payload_cannot_disagree` exists
    for one field further up.

    Against `data/summary.json`, not `data/rbp.json`. The envelope publishes a
    deliberately curated subset for consumers of the ROWS and carries no `feeds`
    block at all, so a tool holding rbp.json cannot learn that 60% of those rows
    rest on a single feed. That is round 7's D4 and it is a decision, not a
    defect: leaving it here as a silently-passing assertion against an empty dict
    was the actual defect, and this test failed on exactly that.
    """
    detail = ((json.loads((built_site / "data" / "summary.json").read_text())
               .get("feeds") or {}).get("detail") or {})
    assert detail, "the published summary carries no per-feed detail"
    for name, h in detail.items():
        assert "rows_published" in h, f"{name} publishes no contribution count"
        assert "rows_only" in h, f"{name} publishes no only-source count"
        assert h["rows_only"] <= h["rows_published"], (
            f"{name}: only-source ({h['rows_only']}) exceeds rows touched "
            f"({h['rows_published']}), which is arithmetically impossible")


# --------------------------------------------------------------------------
# the providers behind a fan-out feed, and the cap this site imposes on them
# --------------------------------------------------------------------------

def _capped_csaf(summary):
    """A csaf feed of three providers: one capped hard, one capped lightly, one
    read whole. Shaped exactly as `feeds.health_detail` nests them."""
    summary["feeds"]["detail"] = {
        "osv": {"status": "ok", "detail": "1200 ids", "rows": 1200, "ok": True,
                "rows_published": 12, "rows_only": 3},
        "csaf": {
            "status": "capped", "rows": 2992, "ok": False,
            "rows_published": 11, "rows_only": 4,
            "detail": ("17/17 providers read; 2992 ids; advisory cap hit on 2 of "
                       "17 providers, newest only: cisa.gov 120/2,243 advisories, "
                       "suse.com 120/83,091 advisories"),
            "parts": {
                "suse.com": {
                    "status": "capped", "rows": 883, "ok": False,
                    "rows_published": None, "rows_only": None,
                    "detail": ("883 ids in scope, 286 new; read the newest 120 of "
                               "83,091 advisories this provider lists in the window")},
                "cisa.gov": {
                    "status": "capped", "rows": 600, "ok": False,
                    "rows_published": None, "rows_only": None,
                    "detail": ("600 ids in scope, 203 new; read the newest 120 of "
                               "2,243 advisories this provider lists in the window")},
                "psirt.abb.com": {
                    "status": "ok", "rows": 77, "ok": True,
                    "rows_published": None, "rows_only": None,
                    "detail": "77 ids in scope, 60 new"},
                # NO CONTRIBUTION KEYS AT ALL, which is not a hypothetical: it
                # is the shape of every part in every snapshot written before
                # 2026-08-28, and those snapshots are still on the data branch
                # and still rendered by /status through the archive. A fixture
                # that sets the key to None on every part cannot see the bug
                # that absent and None are different to Jinja, which is exactly
                # how this survived its first mutation pass.
                "legacy.example": {
                    "status": "ok", "rows": 5, "ok": True,
                    "detail": "5 ids in scope, 5 new"},
            },
        },
    }


@pytest.fixture(scope="module")
def capped_build(tmp_path_factory):
    return _build(tmp_path_factory.mktemp("capped"), launched=True, mutate=_capped_csaf)


def _feed_table(out):
    body = (pathlib.Path(out) / "status.html").read_text()
    m = re.search(r"<caption[^>]*>Every configured advisory feed.*?</tbody>", body, re.S)
    assert m, "the feed table is not on the page"
    return m.group(0)


def test_the_providers_behind_a_fan_out_feed_are_on_the_page(capped_build):
    """COMPUTED EVERY RUN, RENDERED NOWHERE, for as long as `parts` existed.

    `csaf` is seventeen publishers, each fetched separately and each recorded
    separately in `summary.feeds.detail.csaf.parts`. The table iterated only the
    top level, so all seventeen shared one status line and one row count. This
    project's own standard for that is written into feeds.py: a disclosure that
    reaches no page is not a disclosure."""
    table = _feed_table(capped_build)
    for provider in ("csaf:suse.com", "csaf:cisa.gov", "csaf:psirt.abb.com"):
        assert provider in table, f"{provider} is recorded and not rendered"


def test_a_capped_provider_says_how_much_of_it_was_read(capped_build):
    """The number is the disclosure. "Capped" alone tells a reader something was
    cut and not whether it was 1% or 99%, and the honest answers here are 5.3%
    and 0.1%."""
    table = _feed_table(capped_build)
    assert "read the newest 120 of 2,243 advisories" in table, table[:400]
    assert "read the newest 120 of 83,091 advisories" in table, table[:400]


def test_a_provider_read_in_full_is_not_marked_capped_on_the_page(capped_build):
    """A word that appears on every row carries nothing. `psirt.abb.com` was read
    whole and must read OK beside two that were not."""
    table = _feed_table(capped_build)
    abb = re.search(r"csaf:psirt\.abb\.com.*?</tr>", table, re.S).group(0)
    assert "chip-ok" in abb, abb
    assert "Capped" not in abb, abb


def test_the_page_says_the_cap_is_this_sites_limit_and_not_the_providers(capped_build):
    """FRAMING, AND IT IS THE POINT OF SAYING ANY OF THIS.

    A row reading "Capped" beside a vendor's name is easy to read as a fact
    about the vendor. It is a fact about this site: the provider published
    83,091 advisories and this site asked for 120 of them. The page has to say
    which way round that is, or the disclosure creates a worse impression than
    the silence it replaced."""
    body = (pathlib.Path(capped_build) / "status.html").read_text()
    assert "a limit this site sets rather than anything the provider did" in body
    assert "hold more" in body, (
        "the page does not say the count is a floor for exactly this reason")


def test_a_measured_zero_is_still_a_zero_and_not_a_dash(capped_build):
    """The other direction, and the reason the dash cannot simply be "falsy".

    `arch` returns 62 ids per run and accounts for none of the published list.
    That zero was measured and is the finding. Rendering it as a dash would hide
    round 7's B4 result behind the fix for this one."""
    table = _feed_table(capped_build)
    csaf = re.search(r'<td class="mono">csaf</td>.*?</tr>', table, re.S).group(0)
    cells = re.findall(r'<td class="num">(.*?)</td>', csaf, re.S)
    assert cells[1].strip() == "11", cells
    assert cells[2].strip() == "4", cells


def test_a_provider_sub_row_has_no_column_it_can_never_fill(capped_build):
    """D7. `rows_published` and `rows_only` are permanently null for a part:
    `rows_by_source` reads the `sources` string on a published row and that
    string names the FEED, never the provider inside it.

    They rendered as bare em dashes in a numeric column, under a paragraph
    ending "a feed can return tens of thousands of IDs while accounting for none
    of the list", so the available reading was "none". A screen reader announced
    nothing at all: one punctuation character with no text alternative, which a
    legend would not have reached either.

    Replaces two earlier tests that asserted the same branch on two shapes
    `.get()` collapses into one."""
    table = _feed_table(capped_build)
    sub = re.search(r"csaf:psirt\.abb\.com.*?</tr>", table, re.S).group(0)
    assert "&mdash;" not in sub, f"a sub-row still renders a bare dash: {sub}"
    assert len(re.findall(r'<td class="num">', sub)) == 1, (
        "a sub-row still carries a column it can never fill")
    assert 'colspan="3"' in sub, "the note column does not span the deleted cells"

    parent = re.search(r'<td class="mono">csaf</td>.*?</tr>', table, re.S).group(0)
    assert len(re.findall(r'<td class="num">', parent)) == 3, (
        "the parent feed row lost columns that are real for a feed")
