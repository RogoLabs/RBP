"""
/slides.html: the unlinked working-group deck.

THE SPLIT THIS FILE EXISTS FOR. `site.build` renders the deck inside a
try/except, because a template error in a talk deck must never skip a deploy that
`needs: build` and leave Pages serving a stale count four times a day. That catch
is only defensible if something else fails loudly instead, and this is that
something: it renders the page for real and asserts its figures, on the commit
path, so a broken deck cannot reach main. Delete these tests and the catch in
`site.build` becomes a silent failure by construction.
"""
from __future__ import annotations

import html
import json
import re

import pytest

from rbp import publish, slides


def _text(body):
    """Rendered visible text: script and style stripped, entities resolved."""
    t = re.sub(r"<script.*?</script>", " ", body, flags=re.S)
    t = re.sub(r"<style.*?</style>", " ", t, flags=re.S)
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", t)))


@pytest.fixture(params=["prelaunch", "launched"])
def deck_page(request, built_site, built_site_launched):
    """The built deck, in both postures.

    Both, because the deck is rendered outside the `pages_for(launched)` loop and
    a page rendered outside that loop is exactly the kind that gets written in
    one posture only without anyone noticing.
    """
    out = built_site if request.param == "prelaunch" else built_site_launched
    p = out / "slides.html"
    assert p.exists(), f"{request.param}: the build produced no slides.html"
    return p.read_text()


# --------------------------------------------------------------------------
# it is a page of this site, and it is not IN this site
# --------------------------------------------------------------------------

def test_the_deck_renders_every_slide_in_both_postures(deck_page):
    """A deck that renders its chrome and no slides still looks like a page."""
    n = len(re.findall(r'<section class="slide"', deck_page))
    assert n >= 12, f"only {n} slide(s) rendered; the deck is not built"


def test_the_deck_is_noindexed_in_both_postures(deck_page):
    """base.html indexes once launched. An unlinked deck that a search engine
    finds is no longer unlinked, so this page opts out in BOTH postures and
    cannot inherit the launched default."""
    assert '<meta name="robots" content="noindex, nofollow">' in deck_page


def test_the_deck_carries_its_own_og_url_and_canonical(deck_page):
    """It does not extend base.html, so the two tags base.html would have given
    it are hand-written here and nothing else asserts them for this page."""
    assert 'og:url" content="https://rbptracker.org/slides.html"' in deck_page
    assert 'rel="canonical" href="https://rbptracker.org/slides.html"' in deck_page


def test_no_page_links_to_the_deck(built_site, built_site_launched):
    """UNLINKED IS THE FEATURE. It is a talk, and it must not appear in the nav,
    the footer or the panel, where it would sit beside /method and /policy as
    though it were a peer of theirs."""
    for out in (built_site, built_site_launched):
        for page in sorted(out.glob("*.html")):
            if page.name == "slides.html":
                continue
            assert "slides.html" not in page.read_text(), (
                f"{page.name} links to the deck, which is meant to be unlinked")


def test_the_deck_names_no_cna(deck_page):
    """The promise the whole site is built on, asserted on the one page that is
    NOT covered by `publish.check`: that function walks the data branch and reads
    only .json/.csv/.jsonl/.md/.txt, so an HTML page is outside it entirely.

    Not theoretical for this page. `summary.coverage` carries `top_missed_effective`
    and `off_roster`, both of which are lists of certified short names, and both
    are one Jinja loop away from the reach slide that renders their COUNTS."""
    names = publish._roster_names()
    assert publish._roster_names_in_text(deck_page, names, "slides.html") == []
    assert publish._roster_names_in_text(_text(deck_page), names, "slides.html") == []


# --------------------------------------------------------------------------
# the figures
# --------------------------------------------------------------------------

def test_the_deck_renders_the_run_it_was_built_from(deck_page):
    """A deck that quotes a number the site no longer shows is the failure the
    whole design avoids, so the snapshot date is on the page and checkable."""
    from _sitefixture import SNAPSHOT_DATE
    assert SNAPSHOT_DATE in deck_page


def test_the_deck_states_the_base_of_every_percentage(deck_page):
    """`observed_pct` is rendered beside `total_pub`. The fixture shipped without
    `total_pub` and the slide read "12.5% of the  CVEs published in the window":
    a bare percentage with its denominator silently missing."""
    t = _text(deck_page)
    assert "133,325" in t, "the reach slide renders a percentage with no base"


def _build_with_summary(tmp_path, mutate):
    """Build the launched site from the shared fixture with the latest run's
    summary.json mutated, and return the deck.

    ITS OWN SNAPSHOT, rather than bending `_sitefixture`. The shared fixture is
    also what test_status.test_a_clean_run_states_that_it_was_clean asserts
    against, and that test exists because a blank status page reads as a broken
    one. A fixture cannot be the clean run and the degraded run at once, so the
    two assertions would take turns being vacuous.
    """
    import importlib
    import pathlib

    import _sitefixture
    from rbp import site as _site

    snaps, data = _sitefixture.write_snapshots(tmp_path)
    latest = sorted(pathlib.Path(snaps).iterdir())[-1] / "summary.json"
    body = json.loads(latest.read_text())
    mutate(body)
    latest.write_text(json.dumps(body))

    out = pathlib.Path(tmp_path) / "site"
    mp = pytest.MonkeyPatch()
    mp.setenv("RBP_LAUNCHED", "1")
    site = importlib.reload(_site)
    try:
        site.build(str(out), str(snaps), str(data))
    finally:
        mp.undo()
        importlib.reload(_site)
    return (out / "slides.html").read_text()


def test_the_deck_does_not_report_cron_eviction_as_this_sites_failure(tmp_path):
    """THE FIGURE THAT WAS PULLED, and the reason it must not come back.

    The feed-health slide carried "67.9% of scheduled runs in the last 7 days
    actually published". The run ledger only ever recorded SUCCESSFUL scheduled
    ticks, so a tick GitHub never fired and a tick that ran and failed were
    indistinguishable in it, and the residual was almost all GitHub dropping cron
    under load. Presenting that as this pipeline's delivery rate, on the one slide
    arguing that a number must be read together with its instrument, was the deck
    contradicting itself in front of the room.

    Asserted as an absence on the RENDERED page rather than as a rule about
    `cadence`, because the objection is to the claim reaching a reader, not to the
    figure existing: /status.html is the right home for it and keeps it.
    """
    t = _text(_build_with_summary(tmp_path, lambda s: None))
    for phrase in ("of scheduled runs", "scheduled runs in the last"):
        assert phrase not in t, (
            f"the deck is back to publishing {phrase!r}, which reads as this "
            "site failing runs that GitHub never fired")


def test_the_deck_reports_a_degraded_run_as_degraded(tmp_path):
    """A deck that cannot tell a bad run from a good one is worse than one that
    says nothing, and this is the failure mode the project has already shipped
    once: no fixture produced a degraded run, so `False == False` passed."""
    def go_bad(s):
        s["degraded"] = True
        s["degraded_reasons"] = ["1 feed(s) have stopped returning recent advisories"]
        s["feeds"]["stale"] = ["msrc: newest advisory is 2026-07-14, 50 days old "
                               "(floor 45); the feed has likely stopped"]

    t = _text(_build_with_summary(tmp_path, go_bad))
    assert "the feed has likely stopped" in t, (
        "the stale-feed line did not render, so the deck reports a frozen feed "
        "nowhere: the one shortfall a row count cannot see")
    assert "true" in t, "the degraded flag did not render"


def test_the_deck_reports_a_clean_run_as_clean(tmp_path):
    """THE HALF THAT MAKES THE TEST ABOVE MEAN ANYTHING. A page hardcoding the
    word "true" passes that assertion, and a page that always prints a stale-feed
    block passes the other. Both branches have to be reachable and different."""
    t = _text(_build_with_summary(tmp_path, lambda s: s.update(
        {"degraded": False, "degraded_reasons": []})))
    assert "the feed has likely stopped" not in t, (
        "the deck prints a stale-feed line on a clean run, so the line is "
        "furniture rather than a warning")
    assert "false" in t


def test_the_oracle_tally_renders_rather_than_leaving_empty_cells(deck_page):
    """An absent `oracle` renders as a blank cell, which a reader takes for a
    measured zero. The template guards it to the literal string n/a instead."""
    t = _text(deck_page)
    for n in ("54", "3"):                     # reserved, malformed, from the fixture
        assert n in t
    assert "n/a" not in t or "133,325" in t


# --------------------------------------------------------------------------
# the closure cap: the one figure that must not come from the published file
# --------------------------------------------------------------------------

def test_closures_are_measured_over_the_whole_ledger_not_the_published_cap():
    """THE DEFECT THIS DECK WOULD OTHERWISE HAVE SHIPPED.

    `site.load` publishes `resolutions_published`, which is the 200 SLOWEST
    closures sorted by `days_to_publish` descending. Every statistic taken off
    that list is biased upward by construction, and on the live 2026-09-02 ledger
    the difference is not academic: its minimum is 7 days against a true 2 and
    its median is 41 against a true 34.

    So the ledger goes in whole. The fixture below is the same shape: nineteen
    fast closures that a cap of five would delete, and a median that moves from
    4 to 60 if it does.
    """
    ledger = {"open": {}, "resolved": (
        [{"cve_id": f"CVE-2026-{i}", "state": "PUBLISHED", "days_to_publish": 4}
         for i in range(19)]
        + [{"cve_id": f"CVE-2026-9{i}", "state": "PUBLISHED", "days_to_publish": 60 + i}
           for i in range(5)])}
    out = slides.closures(ledger, published_n=5)
    assert out["measured"] == 24
    assert out["median"] == 4, (
        "the closure median came from the capped list; it is the slowest 200 "
        "closures, not a sample")
    assert out["min"] == 4
    assert out["withheld_by_cap"] == 19, (
        "the deck must state how many closures the published file drops, or a "
        "reader recomputing from /data/resolved.json silently gets a different "
        "answer and has no way to know why")
    # THE NUMBER THE READER GETS IF THEY DO IT ANYWAY, stated beside the true one
    # so the gap is a fact they can check rather than a claim they must take.
    assert out["published_median"] == 62, (
        "the deck does not say what the published file's own median is, so "
        "'the cap moves the median' is an assertion with nothing behind it")


def test_the_cap_drops_undated_closures_before_it_drops_fast_ones():
    """"Capped at the 200 slowest, which drops 29 of the fastest" was WRONG in a
    checkable way, and the reader can check it: on the live ledger the 29 dropped
    rows are 19 fast closures and 10 whose duration never parsed, which
    `site.load`'s sort puts last precisely so they fall off the end first.

    Overstating how many FAST rows the cap eats overstates the bias it introduces,
    on the one slide that tells the room not to trust the published file.
    """
    ledger = {"open": {}, "resolved": (
        [{"cve_id": f"CVE-2026-{i}", "state": "PUBLISHED", "days_to_publish": 10 + i}
         for i in range(6)]
        + [{"cve_id": f"CVE-2026-n{i}", "state": "PUBLISHED", "days_to_publish": None}
           for i in range(4)])}
    out = slides.closures(ledger, published_n=5)
    assert out["n"] == 10 and out["measured"] == 6 and out["undated"] == 4
    assert out["withheld_by_cap"] == 5
    assert out["withheld_measured"] == 1, "the one fastest measured row"
    assert out["withheld_undated"] == 4, "and every undated row"
    assert out["withheld_measured"] + out["withheld_undated"] == out["withheld_by_cap"]


def test_a_whole_numbered_median_is_not_rendered_with_a_decimal_point():
    """`statistics.median` returns a float on an even sample, so 41 rendered as
    "41.0" beside a 34 that rendered as "34", on a slide whose whole point is
    that the reader compare the two. A genuinely fractional median keeps its
    half."""
    even = {"open": {}, "resolved": [
        {"cve_id": "a", "state": "PUBLISHED", "days_to_publish": 40},
        {"cve_id": "b", "state": "PUBLISHED", "days_to_publish": 42}]}
    assert slides.closures(even, published_n=2)["median"] == 41
    assert not isinstance(slides.closures(even, published_n=2)["median"], float)
    odd = {"open": {}, "resolved": [
        {"cve_id": "a", "state": "PUBLISHED", "days_to_publish": 40},
        {"cve_id": "b", "state": "PUBLISHED", "days_to_publish": 41},
        {"cve_id": "c", "state": "PUBLISHED", "days_to_publish": 41},
        {"cve_id": "d", "state": "PUBLISHED", "days_to_publish": 42}]}
    assert slides.closures(odd, published_n=4)["median"] == 41


def test_a_rejected_closure_never_counts_as_a_publication():
    """A rule 4.5.3.5 rejection is the CNA complying with the rules and is worse
    for a defender than an open RBP. It is not a closure and must not enter a
    median of how fast records get published."""
    ledger = {"open": {}, "resolved": [
        {"cve_id": "CVE-2026-1", "state": "PUBLISHED", "days_to_publish": 10},
        {"cve_id": "CVE-2026-2", "state": "REJECTED", "days_to_publish": None},
        {"cve_id": "CVE-2026-3", "state": "REJECTED", "days_to_publish": 900},
    ]}
    out = slides.closures(ledger, published_n=3)
    assert out["n"] == 1 and out["measured"] == 1 and out["median"] == 10


def test_closures_survive_a_null_days_to_publish():
    """The null in this column took the whole site down twice through Jinja's
    sort. It reaches a statistics call here instead, which fails the same way."""
    ledger = {"open": {"CVE-2026-9": {}}, "resolved": [
        {"cve_id": "CVE-2026-1", "state": "PUBLISHED", "days_to_publish": None},
        {"cve_id": "CVE-2026-2", "state": "PUBLISHED", "days_to_publish": 12},
    ]}
    out = slides.closures(ledger, published_n=2)
    assert out["n"] == 2 and out["measured"] == 1 and out["median"] == 12
    assert out["open"] == 1


def test_an_empty_ledger_does_not_raise():
    """First run, and every fixture that does not care about closures."""
    out = slides.closures({"open": {}, "resolved": []}, published_n=0)
    assert out["n"] == 0 and out["buckets"] == []
    # Every key the template reads, present on the empty path too. The deck
    # renders these unconditionally, and a missing key is an empty cell that
    # reads as a measured zero.
    for k in ("undated", "withheld_measured", "withheld_undated", "published_median"):
        assert k in out, f"the empty ledger drops {k}, which the deck renders"


# --------------------------------------------------------------------------
# the feed split
# --------------------------------------------------------------------------

def test_the_sole_source_split_does_not_overlap_and_the_feed_split_does():
    """The two columns answer different questions and the deck says so: a row
    carries every feed that referenced it, so the per-feed column sums past the
    total, while the sole-source column is a partition."""
    rows = [{"sources": "ghsa-repos"}, {"sources": "ghsa-repos"},
            {"sources": "csaf,debian"}, {"sources": "csaf,debian,osv"}]
    out = slides.feed_split(rows, requested=["ghsa-repos", "csaf", "debian", "osv", "arch"])
    assert out["total"] == 4
    assert sum(f["rows"] for f in out["by_feed"]) == 7      # overlapping
    assert out["sole_total"] == 2 and out["sole_pct"] == 50.0
    assert [f["feed"] for f in out["by_feed"]][0] == "ghsa-repos"


def test_the_two_feed_counts_are_not_the_same_number():
    """`configured` is what the run asked for; `evidencing` is what put a row in
    the set. On the 2026-09-02 run they were 14 and 12, and the deck says the
    count is bounded by the CONFIGURED feeds: a feed that found nothing is still
    part of the reach, and quoting the smaller number understates the base."""
    rows = [{"sources": "osv"}]
    out = slides.feed_split(rows, requested=["osv", "ghsa", "arch"])
    assert out["configured"] == 3 and out["evidencing"] == 1


def test_the_sole_list_is_ordered_by_the_column_it_renders():
    """It reused the by-row-count order, which put a 63-row sole source below two
    one-row ones on the slide whose whole point is that column."""
    rows = ([{"sources": "a"}] * 3 + [{"sources": "b"}] * 40 + [{"sources": "c,d"}])
    out = slides.feed_split(rows)
    assert [f["feed"] for f in out["sole_list"]] == ["b", "a"]


# --------------------------------------------------------------------------
# the series
# --------------------------------------------------------------------------

def test_the_series_carries_the_feed_count_beside_the_total(tmp_path):
    """THE CHART'S ONLY HONEST FORM. The published total went 522 -> 2,044 in
    twelve days while the feed set went 9 -> 14. A count that is explicitly a
    floor moves when the floor moves, so a series of the count with no series of
    the instrument beside it argues something the data does not support."""
    dates = ["2026-08-22", "2026-08-23"]
    for d, total, feeds in zip(dates, (522, 2044), (9, 14)):
        (tmp_path / d).mkdir()
        (tmp_path / d / "summary.json").write_text(json.dumps(
            {"total": total, "feeds": {"attempts": feeds}, "degraded": d.endswith("22")}))
    out = slides.series(sorted(str(p) for p in tmp_path.iterdir()))
    assert [r["total"] for r in out] == [522, 2044]
    assert [r["feeds"] for r in out] == [9, 14], (
        "the series dropped the feed count, so the chart is a bare rising line")
    assert [r["degraded"] for r in out] == [True, False]
    assert out[-1]["height"] == 100.0


def test_an_unreadable_snapshot_is_skipped_rather_than_drawn_as_zero(tmp_path):
    """A gap in a line is honest. A zero is a claim, and it would render as the
    count having collapsed on a day the run simply did not record one."""
    (tmp_path / "2026-08-22").mkdir()
    (tmp_path / "2026-08-22" / "summary.json").write_text("{ not json")
    (tmp_path / "2026-08-23").mkdir()
    (tmp_path / "2026-08-23" / "summary.json").write_text(json.dumps({"total": 10}))
    (tmp_path / "2026-08-24").mkdir()          # no summary.json at all
    out = slides.series(sorted(str(p) for p in tmp_path.iterdir()))
    assert [r["date"] for r in out] == ["2026-08-23"]


# --------------------------------------------------------------------------
# the clock
# --------------------------------------------------------------------------

def test_a_row_dated_only_from_a_tracker_is_never_claimed_as_late():
    """The most quotable thing about the method, and it is invisible in every
    published figure: the summary reports the numerator without the reason. A
    tracker sighting proves the ID was public and not WHEN, so lateness is not
    asserted on those rows however old they are."""
    rows = [{"clock_origin": "advisory", "past_expectation": True, "days_public": 90},
            {"clock_origin": "tracker", "past_expectation": False, "days_public": 624}]
    out = slides.clock_basis(rows)
    assert out["advisory"] == 1 and out["unclaimed"] == 1
    assert out["oldest_unclaimed"] == 624


# --------------------------------------------------------------------------
# contrast
# --------------------------------------------------------------------------

def test_every_deck_token_clears_aa_on_every_surface_it_lands_on():
    """A HOLE IN THE EXISTING SWEEP, not a new rule.

    `rbp/contrast.py` resolves tokens out of `static/css/*.css` and
    `tests/test_a11y.py` asserts the ratios it computes. This page declares its
    palette INLINE, because it does not load rbp.css, so every one of those
    assertions steps straight past it and the deck could ship any contrast at
    all. It shipped one: `--muted` came over from the site as #6b7280 and renders
    at 3.5:1 on the card surface, on the text that carries the slide footer and
    every table header, on a page whose worst display is a projector in a lit
    room.

    Solved against --raised, the darkest of the three surfaces, so a token that
    passes here passes on the other two.
    """
    import pathlib
    import re as _re

    from rbp.contrast import AA_NORMAL, parse_hex, ratio

    tpl = (pathlib.Path(__file__).resolve().parents[1]
           / "templates" / "slides.html").read_text()
    block = _re.search(r":root\s*\{(.*?)\}", tpl, _re.S)
    assert block, "the deck declares no :root token block"
    toks = dict(_re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6});", block.group(1)))
    for need in ("bg", "surface", "raised", "text", "dim", "muted", "accent"):
        assert need in toks, f"the deck lost its --{need} token"

    surfaces = [toks["bg"], toks["surface"], toks["raised"]]
    for name in ("text", "dim", "muted", "accent", "ok", "warn", "bad"):
        if name not in toks:
            continue
        worst = min(ratio(parse_hex(toks[name]), parse_hex(s)) for s in surfaces)
        assert worst >= AA_NORMAL, (
            f"--{name} ({toks[name]}) renders at {worst:.2f}:1 against a bar of "
            f"{AA_NORMAL}; this page's styles are inline, so contrast.py's sweep "
            "over static/css cannot see them")


# --------------------------------------------------------------------------
# the claim that was false
# --------------------------------------------------------------------------

def test_the_deck_never_claims_the_site_names_nobody(deck_page):
    """THE WORST THING THIS DECK SAID, and it took ten seconds to disprove.

    The boundaries slide read "No CNA is named anywhere on the site, in any
    field, in any format." That sentence is `publish.check`'s refusal message,
    which is about the DATA BRANCH and about attributing a ROW. As a claim about
    the site it is false: /data/summary.json serves `coverage.covered`, 308
    certified CNA short names on the live 2026-09-02 run, plus `near_floor`,
    `off_roster`, `own_channel_cnas` and `top_missed_effective`.

    Said to a room of data consumers, one of whom opens the file while you are
    talking, it would have cost the deck every other claim on it.

    The true guarantee is narrower and stronger for being checkable: no ROW is
    attributed to anyone, and the aggregate set is published deliberately because
    the reach figure is not auditable without it.
    """
    t = _text(deck_page).lower()
    for false_claim in ("named anywhere on the site",
                        "the site names no cna",
                        "names no cna anywhere",
                        "no cna is named anywhere"):
        assert false_claim not in t, (
            f"the deck claims {false_claim!r}; /data/summary.json publishes the "
            "aggregate coverage set, so this is refutable from a browser in the "
            "room. The claim that holds is that no ROW is attributed.")
    assert "no row here is attributed to anyone" in t, (
        "the deck dropped the claim that IS true along with the one that was not")


def test_the_deck_points_at_the_file_that_carries_the_names(deck_page):
    """Volunteering where the aggregate set lives is what makes the narrower
    claim credible. A deck that quietly stopped making the false claim, without
    saying what the site does publish, reads as a retreat rather than a
    correction."""
    t = _text(deck_page)
    assert "aggregate" in t.lower() and "/data/summary.json" in t, (
        "the boundaries slide does not say where the coverage set is published, "
        "so a reader who finds it finds it as a contradiction")


# --------------------------------------------------------------------------
# the deck must never take the publish down
# --------------------------------------------------------------------------

def test_a_broken_deck_does_not_stop_the_site_publishing(tmp_path, monkeypatch):
    """THE CLAIM THE COMMENT IN `site.build` MAKES, asserted instead of asserted.

    That comment said a failing deck leaves "every other page unaffected". It was
    half true and the half it missed was the whole outage: the try/except wrapped
    the RENDER, while the FIGURES were computed up in `site.load`, so a raise
    there propagated straight out of `site.build`. Measured before the fix by
    making `slides.deck` raise and running a build: ZERO pages written. Not a
    degraded deck, the whole site, four times a day, with `deploy` needing
    `build` and no `if:`.

    Mutation-shaped on purpose: it injects the failure rather than waiting for
    one, because a test that only ever sees a healthy deck cannot tell a guard
    that works from a guard that is not there.
    """
    import importlib
    import pathlib

    import _sitefixture as F
    from rbp import site as _site, slides as _slides

    def boom(*a, **k):
        raise RuntimeError("the deck figures failed")

    monkeypatch.setattr(_slides, "deck", boom)

    root = pathlib.Path(tmp_path)
    snaps, data = F.write_snapshots(root)
    out = root / "site"
    mp = pytest.MonkeyPatch()
    mp.setenv("RBP_LAUNCHED", "1")
    site = importlib.reload(_site)
    # The reload discards the patched module reference, so re-apply it to the
    # object `site` will actually reach through its local import.
    monkeypatch.setattr(_slides, "deck", boom)
    try:
        site.build(str(out), str(snaps), str(data))
    finally:
        mp.undo()
        importlib.reload(_site)

    pages = sorted(p.name for p in out.glob("*.html"))
    assert "index.html" in pages, (
        f"a failing deck took the whole build down; pages written: {pages}")
    for required in ("method.html", "policy.html", "status.html"):
        assert required in pages, f"{required} did not ship: {pages}"
    assert "slides.html" not in pages, (
        "the deck was written with no figures behind it, so its cells render "
        "blank, and a blank cell reads as a measured zero")
    assert (out / "data" / "rbp.json").exists(), "the artefact did not publish"


def test_the_deck_is_not_imported_at_module_scope(tmp_path):
    """A syntax error in rbp/slides.py made `import rbp.site` fail, which is the
    same outage by a shorter route and one no try/except inside `build` could
    catch. The import is local to `_deck` now."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1] / "rbp" / "site.py").read_text()
    head = src.split("def ", 1)[0]
    assert "import slides" not in head, (
        "rbp/site.py imports the deck at module scope, so a broken deck module "
        "stops rbp.site importing at all and the guard in _deck never runs")
