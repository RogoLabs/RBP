"""
The feed scorecard's own tests.

FEEDS.md section 3 exists because two estimates in that document have already
been cancelled by measurement, in opposite directions, and the conclusion drawn
was that the harness has to be built before the second feed rather than after the
thirtieth. A harness that is itself unverified would be the same mistake at one
more remove: a number nobody checked, arriving with more authority than the
estimate it replaced.

Everything here runs offline against a synthetic corpus. The adapters are not
called; `scorecard` takes `rows` so the scoring logic can be exercised without a
network, which is also how a candidate is re-scored against a new baseline
without re-fetching it.
"""
from __future__ import annotations

import json

import pandas as pd
import pytest

from rbp import feedlab

FLOOR = feedlab.MIN_SIGHTINGS


def corpus(rows):
    return pd.DataFrame(rows, columns=["cve_id", "state", "assigner",
                                       "date_published", "vendor", "product"])


# A corpus with two roster CNAs. `apache` and `redhat` are real roster short
# names, because the scorecard maps assigner strings onto the pinned roster and a
# fixture using invented names would exercise the mapping's failure path only.
CORPUS = corpus(
    [(f"CVE-2025-1{n:03d}", "PUBLISHED", "apache", "2025-06-01", "a", "p")
     for n in range(10)]
    + [(f"CVE-2025-2{n:03d}", "PUBLISHED", "redhat", "2025-06-01", "r", "q")
       for n in range(10)]
    + [(f"CVE-2025-9{n:03d}", "RESERVED", "", "", "", "") for n in range(5)])


def row(cid, date="2025-06-01"):
    return {"cve_id": cid, "public_date": date, "source_ref": "x",
            "product": "", "description": ""}


EMPTY_BASE = {"feeds": [], "scored_at": None, "ids": [], "sightings": {},
              "effective": []}


# --------------------------------------------------------------------------
# admissibility test 1: marginal CNA yield
# --------------------------------------------------------------------------

def test_marginal_yield_counts_cnas_the_baseline_could_not_see(monkeypatch):
    rows = [row(f"CVE-2025-1{n:03d}") for n in range(FLOOR)]
    card = feedlab.scorecard("x", {2025}, CORPUS, base=EMPTY_BASE, rows=rows, stats={})
    assert card["cnas_new_effective"] == 1
    assert card["cnas_new_effective_names"] == ["apache"]


def test_a_cna_the_baseline_already_covers_is_not_marginal():
    """The whole point of the word. A feed reaching 53 CNAs that every distro
    feed already covers scores zero, which is what the 29 extra OSV ecosystems
    actually did."""
    base = {**EMPTY_BASE, "sightings": {"apache": FLOOR}, "effective": ["apache"]}
    rows = [row(f"CVE-2025-1{n:03d}") for n in range(FLOOR + 5)]
    card = feedlab.scorecard("x", {2025}, CORPUS, base=base, rows=rows, stats={})
    assert card["cnas_new_effective"] == 0


def test_a_feed_that_pushes_a_cna_over_the_floor_does_count():
    """The case a naive "CNAs it reaches alone" metric misses, and the reason the
    combination is recomputed rather than differenced. The baseline sees `apache`
    twice, below the floor; one more sighting makes it observable, and the feed
    that supplied it is why."""
    base = {**EMPTY_BASE, "ids": ["CVE-2025-1001", "CVE-2025-1002"],
            "sightings": {"apache": FLOOR - 1}, "effective": []}
    card = feedlab.scorecard("x", {2025}, CORPUS, base=base, live=None,
                             rows=[row("CVE-2025-1000")], stats={})
    assert card["cnas_new_effective_names"] == ["apache"]
    assert card["combine"] == "union"


def test_a_reference_the_baseline_already_has_does_not_manufacture_a_sighting():
    """THE MIRROR THAT ADMISSIBILITY TEST 1 EXISTS TO REFUSE, admitted by the
    arithmetic that measured it.

    A sighting is a PUBLISHED CVE THIS SITE SAW. `coverage.compute` counts
    distinct ids, so two feeds referencing the same CVE are ONE sighting there.
    The combination here added the two per-CNA counts instead, so a feed that
    re-referenced what the merged set already had was credited with pushing a CNA
    over the floor: `apache` at 2 in the baseline, one duplicate row from the
    candidate, and the harness reported a marginal CNA that no id had earned.

    Measured on the 2026-09-06 baseline, ten of the fifteen committed cards
    carried marginal CNAs manufactured this way: `alas` 2 -> 0, `debian` 4 -> 0,
    `ubuntu-osv` 4 -> 0, `ghsa` 3 -> 0, `alpine` 1 -> 0, `osv` 5 -> 1, `redhat`
    6 -> 3, `csaf` 84 -> 80. Every one of them in the permissive direction.
    """
    base = {**EMPTY_BASE, "ids": ["CVE-2025-1001", "CVE-2025-1002"],
            "sightings": {"apache": FLOOR - 1}, "effective": []}
    card = feedlab.scorecard("x", {2025}, CORPUS, base=base, live=None,
                             rows=[row("CVE-2025-1001")], stats={})
    assert card["cnas_new_effective_names"] == [], (
        "a duplicate of an id the baseline already holds is not a new sighting")


def test_a_baseline_that_kept_no_ids_says_how_it_was_combined():
    """The union needs the baseline's ids. A base carrying only counts cannot be
    combined that way, and the card records which arithmetic ran rather than
    presenting two different numbers under one name."""
    base = {**EMPTY_BASE, "sightings": {"apache": FLOOR - 1}, "effective": []}
    card = feedlab.scorecard("x", {2025}, CORPUS, base=base, live=None,
                             rows=[row("CVE-2025-1000")], stats={})
    assert card["combine"] == "sum"


def test_sightings_below_the_floor_do_not_credit_a_cna():
    rows = [row(f"CVE-2025-1{n:03d}") for n in range(FLOOR - 1)]
    card = feedlab.scorecard("x", {2025}, CORPUS, base=EMPTY_BASE, rows=rows, stats={})
    assert card["cnas_new_effective"] == 0
    assert card["cnas_reached"] == 1, "the sighting is still recorded, just not credited"


def test_the_floor_is_the_same_one_inference_uses_to_name_a_cna():
    """Not a separate constant. A gate that clears on CNAs the site would refuse
    to name is a gate measuring something else."""
    from rbp import inference
    assert feedlab.MIN_SIGHTINGS is inference.MIN_SIGHTINGS


# --------------------------------------------------------------------------
# the pinned live profile: marginal to the set the SITE has
# --------------------------------------------------------------------------
#
# The harness reads what this machine can reach. The site reads what every run
# before it banked, and on 2026-09-06 that was 20,141 more `csaf` ids and 16 more
# effective roster CNAs. A card measured only against the local baseline credits
# a candidate for making a CNA observable that the site has been reading for
# weeks, and nothing on the card said so.

LIVE = {"sources": ["alas"],
        "fetched": "2026-09-06",
        "generated_at": "2026-09-06T20:51:44+00:00",
        "source_commit": "9a1bba54ceaf",
        "sightings": {"apache": FLOOR},
        "effective": ["apache"],
        "feed_rows": {"alas": 100}}


def test_a_card_with_no_pin_reports_nothing_rather_than_zero():
    """"Not measured" and "measured zero" are the same value and must not be the
    same outcome. The same distinction `unmeasurable` exists to draw."""
    rows = [row(f"CVE-2025-1{n:03d}") for n in range(FLOOR)]
    card = feedlab.scorecard("x", {2025}, CORPUS, base=EMPTY_BASE, rows=rows,
                             stats={}, live=None)
    assert card["live"]["pinned"] is False
    assert card["live"]["cnas_new_effective"] is None
    assert "pin-live" in card["live"]["reason"]


def test_a_cna_the_live_run_already_covers_is_not_marginal():
    """THE DEFECT ITEM 1 NAMES, at the size it was measured.

    Thirteen roster CNAs sat below the sighting floor in the 2026-09-06 baseline
    and were already effective in the live run, because the live `csaf` state is
    as deep as every run before it and a local state is as deep as the runs that
    happened locally. A candidate reaching one of those twelve scored a marginal
    CNA here and would have added nothing at all to the site.
    """
    rows = [row(f"CVE-2025-1{n:03d}") for n in range(FLOOR)]
    card = feedlab.scorecard("x", {2025}, CORPUS, base=EMPTY_BASE, rows=rows,
                             stats={}, live=LIVE)
    assert card["cnas_new_effective"] == 1, "marginal to what this machine saw"
    assert card["live"]["cnas_new_effective"] == 0, (
        "and marginal to nothing at all, against the set the site has")


def test_the_verdict_follows_the_live_figure_when_there_is_one():
    """The verdict is a claim about what merging this feed would do to the SITE.
    A feed that adds a CNA here and none there is not detecting."""
    rows = [row(f"CVE-2025-1{n:03d}") for n in range(FLOOR)] + [row("CVE-2025-9000")]
    card = feedlab.scorecard("x", {2025}, CORPUS, base=EMPTY_BASE, rows=rows,
                             stats={}, live=LIVE)
    assert card["verdict"] == "redundant"
    without = feedlab.scorecard("x", {2025}, CORPUS, base=EMPTY_BASE, rows=rows,
                                stats={}, live=None)
    assert without["verdict"] == "detecting", (
        "with no pin the local figure decides, which is the state the harness "
        "was in for its whole life")


def test_a_feed_already_in_the_live_profile_has_no_live_marginal_figure():
    """It cannot be marginal to a set that contains it. Every card `audit`
    produces is in this state, and reporting 0 there would read as "adds
    nothing" rather than "the question does not apply"."""
    card = feedlab.scorecard("alas", {2025}, CORPUS, base=EMPTY_BASE,
                             rows=[row("CVE-2025-1000")], stats={}, live=LIVE)
    assert card["live"]["already_merged"] is True
    assert card["live"]["cnas_new_effective"] is None


def test_only_ids_the_baseline_has_never_seen_can_add_a_live_sighting():
    """The live half publishes counts, not ids, so the candidate's overlap with
    the live set cannot be removed exactly. Its overlap with the LOCAL baseline
    can be, and is: an id the baseline already holds has already been counted on
    the live side too, because the live set is deeper than the local one."""
    base = {**EMPTY_BASE, "ids": [f"CVE-2025-2{n:03d}" for n in range(FLOOR)],
            "sightings": {"redhat": FLOOR}, "effective": ["redhat"]}
    live = {**LIVE, "sightings": {"redhat": FLOOR - 1}, "effective": []}
    rows = [row(f"CVE-2025-2{n:03d}") for n in range(FLOOR)]
    card = feedlab.scorecard("x", {2025}, CORPUS, base=base, rows=rows,
                             stats={}, live=live)
    assert card["live"]["cnas_new_effective"] == 0, (
        "every id in this feed is one the baseline already had, so none of them "
        "is a sighting the live run is missing")


def test_a_baseline_colder_than_the_live_run_says_so_on_the_card():
    """WHAT NOTHING SAID BEFORE. The feed list matched the pipeline and the state
    behind one of those feeds did not, so the figure was an upper bound and the
    card presented it as a measurement."""
    base = {**EMPTY_BASE, "per_feed_rows": {"csaf": 42659}}
    live = {**LIVE, "feed_rows": {"csaf": 62800}}
    card = feedlab.scorecard("x", {2025}, CORPUS, base=base,
                             rows=[row("CVE-2025-1000")], stats={}, live=live)
    assert card["live"]["upper_bound"] is True
    assert card["live"]["ids_short"] == 20141
    assert card["live"]["rows_short"] == {"csaf": 20141}
    assert "20,141" in card["live"]["reason"]


def test_a_baseline_deeper_than_the_live_run_is_not_a_shortfall():
    """A feed drains and a local read can be ahead of the last published run:
    `ghsa-repos` was 12,784 here against 12,774 live. Only the permissive
    direction is a finding."""
    base = {**EMPTY_BASE, "per_feed_rows": {"ghsa-repos": 12784}}
    live = {**LIVE, "feed_rows": {"ghsa-repos": 12774}}
    card = feedlab.scorecard("x", {2025}, CORPUS, base=base,
                             rows=[row("CVE-2025-1000")], stats={}, live=live)
    assert card["live"]["rows_short"] == {}
    assert card["live"]["upper_bound"] is False


def test_the_pin_rekeys_the_live_sightings_onto_the_roster(monkeypatch):
    """Two alphabets. The live artefact counts by corpus assigner string and this
    harness counts by roster short name, so `Hitachi Energy` upstream is
    `Hitachi_Energy` here. Compared raw, eight CNAs read as "effective locally,
    missing live" that were the same eight CNAs spelled twice."""
    body = {"generated_at": "t", "source_commit": "c", "source_dirty": False,
            "feeds": {"detail": {"alas": {"rows": 5}}},
            "coverage": {"sightings": {"Hitachi Energy": 4, "JFROG": 2,
                                       "not a cna at all": 99},
                         "sources": ["alas"], "recent_years": [2026],
                         "min_sightings": 3, "cnas_effective": 1}}
    monkeypatch.setattr(feedlab.feeds, "_get", lambda *a, **k: (body, 200, {}))
    pinned = feedlab.pin_live("https://example.invalid/summary.json")
    assert pinned["sightings"] == {"Hitachi_Energy": 4, "JFrog": 2}, (
        "off-roster assigners are dropped exactly as sightings_by_cna drops them")
    assert pinned["effective"] == ["Hitachi_Energy"]
    assert pinned["source_commit"] == "c"


def test_a_published_summary_with_no_sightings_is_refused_rather_than_pinned(
        monkeypatch):
    """An empty pin would be indistinguishable from a live run that covers
    nothing, and every candidate scored against it would look marginal to
    everything."""
    monkeypatch.setattr(feedlab.feeds, "_get",
                        lambda *a, **k: ({"coverage": {}}, 200, {}))
    with pytest.raises(SystemExit):
        feedlab.pin_live("https://example.invalid/summary.json")


def test_the_csaf_depth_is_counts_rather_than_a_sentence(tmp_path):
    """`_record_csaf_health` already said "3 still catching up" in a health
    string, which no test can read and no card can subtract."""
    p = tmp_path / "csaf_state.json"
    p.write_text(json.dumps({
        "_version": 3,
        "a.example": {"refs": {"CVE-1": "x", "CVE-2": "x"}, "listed": 2, "behind": 0},
        "b.example": {"refs": {"CVE-2": "x"}, "listed": 900, "behind": 899}}))
    d = feedlab.csaf_depth(str(p))
    assert d["providers"] == 2
    assert d["ids"] == 2, "unique across providers, which is what a feed row is"
    assert d["behind"] == 899 and d["providers_behind"] == ["b.example"]


# --------------------------------------------------------------------------
# admissibility test 2: disclosure lead
# --------------------------------------------------------------------------

def test_an_advisory_before_publication_is_a_lead():
    _a, state, published = feedlab._corpus_maps(CORPUS)
    d = feedlab.disclosure_lead([row("CVE-2025-1000", "2025-05-01")],
                                published, state)
    assert d["lead_n"] == 1 and d["lead_max_days"] == 31
    assert d["mirror_n"] == 0


def test_an_advisory_after_publication_is_a_mirror():
    """The structural point of FEEDS.md section 2: a feed that only lists CVEs
    after they are published credits its CNAs on the coverage number and can
    never surface the thing the site exists to publish."""
    _a, state, published = feedlab._corpus_maps(CORPUS)
    d = feedlab.disclosure_lead([row("CVE-2025-1000", "2025-07-01")],
                                published, state)
    assert d["lead_n"] == 0 and d["mirror_n"] == 1


def test_an_advisory_on_the_day_of_publication_is_a_mirror_not_a_lead():
    """Zero days is not lead. A boundary written down because `>=` here would
    make every same-day mirror look like detection, and same-day is the common
    case for a coordinated release."""
    _a, state, published = feedlab._corpus_maps(CORPUS)
    d = feedlab.disclosure_lead([row("CVE-2025-1000", "2025-06-01")],
                                published, state)
    assert d["lead_n"] == 0 and d["mirror_n"] == 1


def test_a_reserved_id_counts_as_unpublished_rather_than_as_lead():
    _a, state, published = feedlab._corpus_maps(CORPUS)
    d = feedlab.disclosure_lead([row("CVE-2025-9000")], published, state)
    assert d["unpublished_n"] == 1 and d["lead_n"] == 0


def test_an_id_absent_from_the_corpus_counts_as_unpublished():
    _a, state, published = feedlab._corpus_maps(CORPUS)
    d = feedlab.disclosure_lead([row("CVE-2026-4242")], published, state)
    assert d["unpublished_n"] == 1


def test_an_implausible_lead_is_discarded_rather_than_banked():
    """A feed dated by package release, or a failed date parse landing on 1970,
    would otherwise read as three decades of prescience and admit a mirror on one
    bad row."""
    _a, state, published = feedlab._corpus_maps(CORPUS)
    d = feedlab.disclosure_lead([row("CVE-2025-1000", "1970-01-01")],
                                published, state)
    assert d["lead_n"] == 0 and d["mirror_n"] == 1


def test_an_undated_advisory_is_counted_separately_from_a_mirror():
    """"Cannot tell" and "no lead" are different answers and must not read the
    same way, which is the same distinction feeds.record_feed draws between a
    failed feed and an empty one."""
    _a, state, published = feedlab._corpus_maps(CORPUS)
    d = feedlab.disclosure_lead([row("CVE-2025-1000", "")], published, state)
    assert d["undated_n"] == 1 and d["mirror_n"] == 0 and d["lead_n"] == 0


def test_lead_pct_is_over_dated_references_only():
    """An undated row must not dilute the percentage: a feed with one lead and
    nine undated rows is 100% of what could be measured, not 10%."""
    _a, state, published = feedlab._corpus_maps(CORPUS)
    rows = [row("CVE-2025-1000", "2025-05-01")] + [row(f"CVE-2025-1{n:03d}", "")
                                                   for n in range(1, 10)]
    d = feedlab.disclosure_lead(rows, published, state)
    assert d["lead_pct"] == 100.0


# --------------------------------------------------------------------------
# the verdict
# --------------------------------------------------------------------------

def _lead(**kw):
    """A disclosure result, with `dated_n` defaulting to something MEASURED.

    Defaulting it to 0 would make every one of these tests exercise the
    unmeasurable branch and none of them exercise the verdict they are named
    after, which is how the classifier shipped with the bug below in the first
    place.
    """
    return {"lead_n": 0, "unpublished_n": 0, "dated_n": 100, "undated_n": 0, **kw}


def test_coverage_without_detection_is_corroborating_not_detecting():
    """The verdict FEEDS.md section 2 was written to make possible: a feed that
    raises coverage and is structurally incapable of surfacing an unpublished
    id."""
    v, why = feedlab.classify(4, _lead())
    assert v == "corroborating"
    assert "mirror" in why


def test_detection_without_coverage_is_redundant_not_corroborating():
    """THE WORD THAT WAS DOING TWO JOBS, and the pipeline read the wrong one.

    FEEDS.md section 2 defines the exclusion on one combination: "A feed that
    clears (1) and fails (2) ... is then tagged `corroborating` and excluded from
    the coverage numerator." This is the OPPOSITE shape, fails (1) and clears
    (2), and the same document already said what happens to it: "`mozilla` is
    corroborating rather than mirroring ... it clears admissibility test 2, so it
    stays in the numerator."

    It did not stay in the numerator. `corroborating_feeds` reads the verdict
    string, so `mozilla`, `samsung` and `ubuntu` were all in the live run's
    published exclusion list on 2026-09-06 with lead references apiece and not a
    mirror among them.
    """
    v, why = feedlab.classify(0, _lead(lead_n=3, unpublished_n=1))
    assert v == "redundant"
    assert "mirror" in why and "NUMERATOR" in why


def test_only_a_mirror_leaves_the_coverage_numerator(tmp_path):
    """The exclusion set is read from the verdicts, so the split has to reach it.

    Both feeds here add no marginal CNA. One references unpublished ids and one
    never has, and only the second is a publication mirror. Excluding the first
    is how five of the site's largest feeds nearly dropped out of its own
    coverage numerator when the marginal figures were corrected.
    """
    p = tmp_path / "_audit.json"
    p.write_text(json.dumps({"feeds": {
        "detects": {"verdict": feedlab.classify(0, _lead(unpublished_n=4))[0]},
        "mirrors": {"verdict": feedlab.classify(2, _lead())[0]}}}))
    assert feedlab.corroborating_feeds(str(p)) == {"mirrors"}


def test_neither_is_a_reject():
    v, _why = feedlab.classify(0, _lead())
    assert v == "reject"


def test_both_is_detecting():
    v, _why = feedlab.classify(2, _lead(lead_n=5))
    assert v == "detecting"


def test_an_unpublished_reference_alone_satisfies_the_detection_half():
    """A brand-new feed has no history to show a historical lead in, and an id
    that is reserved RIGHT NOW is stronger evidence than one that used to be."""
    v, _why = feedlab.classify(2, _lead(dated_n=0, unpublished_n=1))
    assert v == "detecting"


def test_a_feed_that_dates_nothing_is_unmeasurable_not_rejected():
    """THE BUG THE FIRST REAL AUDIT FOUND, on 2026-08-24.

    `arch` returns 62 references and dates none of them, so its historical lead
    is 0 out of 0. The classifier read that as "no disclosure lead" and returned
    `reject`, which is a claim about a feed that the data cannot support. Same
    distinction feeds.record_feed already draws between a FAILED feed and an
    empty one, and the same one inference draws with "not separately
    measurable".
    """
    v, why = feedlab.classify(0, _lead(dated_n=0, undated_n=62))
    assert v == "unmeasurable"
    assert "undated" in why


def test_an_unmeasured_feed_is_not_excluded_from_the_numerator():
    """Why the distinction is load-bearing rather than tidy. FEEDS.md excludes
    PUBLICATION MIRRORS from the coverage numerator. A feed nobody has measured
    is not a proven mirror, and excluding it would lower a launch gate on the
    strength of a missing date field."""
    _v, why = feedlab.classify(3, _lead(dated_n=0, undated_n=9))
    assert "must not be excluded" in why


def test_dated_n_is_the_denominator_and_is_published():
    """0 of 0 and 0 of 5,000 are different findings and must not print the same."""
    _a, state, published = feedlab._corpus_maps(CORPUS)
    d = feedlab.disclosure_lead([row("CVE-2025-1000", "")], published, state)
    assert d["dated_n"] == 0 and d["undated_n"] == 1


# --------------------------------------------------------------------------
# the harness's own failure modes
# --------------------------------------------------------------------------

def test_a_corpus_without_publication_dates_refuses_to_score(tmp_path):
    """The failure this guard exists for is silent and total: with no dates every
    candidate scores zero lead, every one is classified a publication mirror, and
    the harness rejects the entire expansion with a straight face."""
    bad = pd.DataFrame([("CVE-2025-1000", "PUBLISHED", "apache", "a", "p")],
                       columns=["cve_id", "state", "assigner", "vendor", "product"])
    with pytest.raises(SystemExit, match="date_published"):
        feedlab._corpus_maps(bad)


def test_scoring_an_unwired_feed_is_refused():
    """Being scoreable and being runnable must be the same condition, or the
    scorecard in the merge diff describes something the pipeline will not run."""
    with pytest.raises(SystemExit, match="unknown feed"):
        feedlab.fetch("not-a-real-feed", {2025})


def test_every_merged_feed_is_scoreable():
    """The other direction, so a feed cannot be in the profile the cron runs
    while being invisible to the harness that is supposed to police it."""
    from rbp import feeds
    from rbp.cli import PROFILES
    for profile in PROFILES.values():
        for name in profile.split(","):
            assert name in feeds.ADAPTERS, f"{name} is in a profile but not an adapter"


def test_stability_needs_more_than_one_fetch():
    """FEEDS.md asks for ids on three fetches 24h apart. One invocation cannot
    produce that, and returning a number anyway is how a scorecard field becomes
    decoration."""
    assert feedlab.stability([{"ids": 100}]) is None
    assert feedlab.stability([]) is None


def test_stability_reports_the_widest_swing():
    got = feedlab.stability([{"ids": 100}, {"ids": 60}, {"ids": 90}])
    assert got["swing_pct"] == 40.0 and got["fetches"] == 3


def test_a_fetch_history_accumulates_across_runs(tmp_path):
    """The FILE keeps every fetch. What `stability` may read from it is a
    separate question, asserted below: these two are recorded in the same
    instant, so they are one observation and the swing between them is null
    rather than 50%."""
    path = tmp_path / "x.fetches.json"
    feedlab.record_fetch("x", {"a", "b"}, years={2026}, path=str(path))
    hist = feedlab.record_fetch("x", {"a"}, years={2026}, path=str(path))
    assert [h["ids"] for h in hist] == [2, 1]
    assert [h["years"] for h in hist] == [[2026], [2026]]
    assert feedlab.stability(hist) is None


def test_two_fetches_in_one_session_are_one_observation(tmp_path):
    """`feedlab score jvn` and a baseline rebuild ran thirty minutes apart in one
    session, both returned 1,117, and the next `audit` would have committed
    `swing_pct: 0.0` to jvn's card. Ten of the fifteen committed cards already
    carried a 0.0% from a pair four hours apart.

    build_baseline's own comment says why that is worse than null: "null says
    not measured, and 0% says measured, and perfect". FEEDS.md asks for three
    fetches 24 hours apart and nothing enforced the interval.
    """
    w = [2025, 2026]
    same_session = [{"at": "2026-09-06T18:05:00+00:00", "ids": 1117, "years": w},
                    {"at": "2026-09-06T18:35:00+00:00", "ids": 1117, "years": w}]
    assert feedlab.stability(same_session) is None
    # A day later is the observation FEEDS.md asks for, and it reports.
    spaced = same_session + [{"at": "2026-09-07T19:00:00+00:00", "ids": 1000,
                              "years": w}]
    got = feedlab.stability(spaced)
    assert got["fetches"] == 2 and got["swing_pct"] == 10.5


def test_a_swing_across_two_windows_is_the_window_moving_not_the_feed(tmp_path):
    """The defect this whole change is about, arriving in the one field that
    would have recorded it as feed volatility.

    Every `*.fetches.json` was written while the harness gathered two years. The
    first rebuild at four gathers roughly twice the ids, and against an unstamped
    history that reads as a 43% swing -- past FEEDS.md's 40% "no usable shrink
    baseline" line, for a feed that did not move at all. `csaf` had already shown
    the shape one level down: its committed 29.3% is sixteen CSAF providers
    against eighteen.
    """
    hist = [{"at": "2026-08-31T15:42:00+00:00", "ids": 1117, "years": [2025, 2026]},
            {"at": "2026-09-06T18:07:00+00:00", "ids": 1968,
             "years": [2023, 2024, 2025, 2026]}]
    assert feedlab.stability(hist) is None, (
        "a count from a two-year gather and one from a four-year gather were "
        "compared as if they measured the same thing")
    hist.append({"at": "2026-09-08T18:00:00+00:00", "ids": 1900,
                 "years": [2023, 2024, 2025, 2026]})
    got = feedlab.stability(hist)
    assert got["fetches"] == 2 and got["swing_pct"] == 3.5
    assert got["years"] == [2023, 2024, 2025, 2026], (
        "the swing does not say which window it was measured over, which is how "
        "this went unnoticed the first time")


def test_an_unstamped_history_is_still_readable(tmp_path):
    """Every fetch recorded before the window was stamped has no `years`. They
    are comparable to each other -- they were all gathered at two years -- and
    must not be silently dropped or silently mixed with stamped ones."""
    old = [{"at": "2026-08-31T15:42:00+00:00", "ids": 100},
           {"at": "2026-09-06T18:07:00+00:00", "ids": 90}]
    got = feedlab.stability(old)
    assert got["swing_pct"] == 10.0 and got["years"] is None


def test_a_scorecard_round_trips_as_json(tmp_path):
    """It goes in the merge commit, so it has to be a file a reviewer can read
    and a diff can show."""
    card = feedlab.scorecard("x", {2025}, CORPUS, base=EMPTY_BASE,
                             rows=[row("CVE-2025-1000")], stats={"wall_seconds": 1.0,
                                                                 "bytes": 10})
    p = tmp_path / "x.json"
    feedlab.write(card, str(p))
    assert json.loads(p.read_text())["feed"] == "x"


def test_the_scorecard_names_the_baseline_it_was_measured_against():
    """A marginal number without its baseline is not a number. The 29 OSV
    ecosystems scored +0 against the merged nine and would have scored +25
    against nothing."""
    card = feedlab.scorecard("x", {2025}, CORPUS,
                             base={**EMPTY_BASE, "feeds": ["debian", "osv"],
                                   "scored_at": "2026-08-24T00:00:00+00:00"},
                             rows=[row("CVE-2025-1000")], stats={})
    assert card["baseline"]["feeds"] == ["debian", "osv"]
    assert card["baseline"]["scored_at"] == "2026-08-24T00:00:00+00:00"


def test_the_feeds_read_every_year_the_coverage_figure_is_measured_over():
    """THE GAP THIS CLOSES, and the previous version of this test pinned it open.

    `cli.run` gathered {this year, last year} and measured coverage over three
    years, so the site reported reach across 2024-2026 while reading advisories
    only from 2025-2026. Every 2024 CNA counted as covered was measured against
    ids the pipeline could not surface, and the launch gate sat on top of that.

    The old test asserted the literal string `recent_years=(cyr - 2, cyr - 1,
    cyr)` was present in cli.run's source, which kept feedlab in step with the
    inconsistency rather than removing it.

    Now there is one definition and this asserts the property instead: whatever
    window coverage measures, the feeds read the same one."""
    import datetime as _dt
    from rbp import coverage
    y = _dt.date.today().year
    assert feedlab.coverage_years() == coverage.window(y)

    # DERIVED FROM THE CONSTANT, not written out. These assertions used to pin
    # the literal (2024, 2025, 2026), which meant widening the window failed the
    # test that exists to check the two sides agree -- the test reported a
    # disagreement that was not there, and the real property it names in its own
    # docstring, "whatever window coverage measures, the feeds read the same
    # one", is independent of how wide that window is.
    def expect(end):
        return tuple(range(end - coverage.WINDOW_YEARS + 1, end + 1))

    assert coverage.window(2026) == expect(2026)
    assert len(coverage.window(2026)) == coverage.WINDOW_YEARS
    assert coverage.window(2026)[-1] == 2026
    # A YEAR THAT IS NOT THIS ONE, because the assertions above cannot tell a
    # derived window from one hardcoded to the current year. Replacing feedlab's
    # body with such a literal left them all green. Confirmed by mutation on
    # 2026-08-30, and the reason these two stay even though they now derive their
    # expectation: what they catch is feedlab ignoring its argument.
    assert feedlab.coverage_years("2031-04-01") == expect(2031)
    assert feedlab.coverage_years("2024-12-31") == expect(2024)


def test_cli_gathers_the_same_years_it_measures_coverage_over():
    """The seam, asserted on behaviour rather than on source text. `cmd_run`
    derives both from `coverage.window`, so a change to one cannot silently
    leave the other behind."""
    import inspect
    from rbp import cli, coverage
    src = inspect.getsource(cli.cmd_run)
    assert "coverage.window(cyr)" in src, (
        "cli.run no longer derives its coverage window from the shared definition")
    assert "_coverage.window(int(today[:4]))" in src, (
        "cli.run no longer derives its FEED window from the shared definition")
    # The shared definition produces a contiguous window ending at the year asked
    # for. Not a literal: the width is `coverage.WINDOW_YEARS`'s business, and
    # this test is about the seam between cli and coverage, not about the width.
    assert coverage.window(2026) == tuple(
        range(2026 - coverage.WINDOW_YEARS + 1, 2027))


def test_only_published_cves_in_the_window_can_credit_a_cna():
    """A RESERVED id cannot credit its CNA as observable: coverage counts
    sightings of PUBLISHED CVEs, which is the asymmetry the whole detecting /
    corroborating split turns on."""
    eligible = feedlab.eligible_published(CORPUS, (2024, 2025, 2026))
    assert "CVE-2025-1000" in eligible
    assert "CVE-2025-9000" not in eligible


def test_an_id_outside_the_window_does_not_credit_a_cna():
    old = corpus([("CVE-2019-0001", "PUBLISHED", "apache", "2019-01-01", "a", "p")])
    assert feedlab.eligible_published(old, (2024, 2025, 2026)) == set()


# --------------------------------------------------------------------------
# the CSAF provider sweep
# --------------------------------------------------------------------------

ENTRY = {
    "shortName": "apache",
    "securityAdvisories": {"advisories": [{"url": "https://psirt.acme.example/advisories"}],
                           "alerts": []},
    "contact": [{"contact": [{"url": "https://www.acme.example/security"}]}],
    "disclosurePolicy": [{"url": "https://hackerone.com/acme"}],
}


def test_hosts_come_from_urls_the_cna_published_not_from_its_name():
    """"Dell Technologies" to dell.com is a guess that is right often enough to
    feel safe and wrong in exactly the cases that matter. Only URLs the CNA gave
    the Program are used."""
    hosts = feedlab._hosts_for(ENTRY)
    assert hosts[0] == "psirt.acme.example"
    assert "www.acme.example" in hosts


def test_shared_platforms_are_not_probed():
    """A CSAF document at hackerone.com is not this CNA's channel, and probing
    the shared platforms once per CNA is several hundred requests at one host."""
    assert not any("hackerone" in h for h in feedlab._hosts_for(ENTRY))


def test_a_cna_with_no_published_url_is_reported_rather_than_guessed():
    assert feedlab._hosts_for({"shortName": "x"}) == []


def test_the_probe_uses_one_path_and_does_not_search():
    """A probe that walks candidate paths is a scanner. This one asks the single
    location the RFC defines and takes the answer."""
    assert feedlab.CSAF_WELL_KNOWN == "/.well-known/csaf/provider-metadata.json"


def test_a_refusal_stays_legible_as_a_refusal():
    """Dell answered 403 when FEEDS.md sampled it. That is a finding, not an
    error: the vendor publishes CSAF and has chosen not to serve it to automated
    clients, and FEEDS.md is explicit that this plan does not authorise working
    around it."""
    import urllib.error
    e = urllib.error.HTTPError("https://x", 403, "Forbidden", {}, None)
    assert feedlab._short(e) == "403"


def test_the_probe_sends_the_projects_own_user_agent():
    """Belt and braces on the sentence above. The probe goes through feeds._get,
    which sends UA and nothing else, so a browser string cannot be introduced
    here without editing the shared fetch path where it would be noticed."""
    from rbp import feeds
    import inspect
    src = inspect.getsource(feedlab.probe_csaf)
    assert "feeds._get(" in src
    assert "User-Agent" not in src and "Mozilla" not in src
    assert feeds.UA == {"User-Agent": "rbp-cves/1.0 (+https://rbptracker.org)"}


def test_the_user_agent_identifies_us_and_impersonates_nobody():
    """The UA changed on 2026-08-26 and the reason matters more than the string.

    Cisco's edge answered 403 to `rbp-cves/1.0 (CVE quality research)`. The
    reflex fix is a browser string, and it is the one thing that does NOT work:
    a full Chrome UA is refused as well. What the edge wants is an ordinary
    crawler self-identification, a scheme-qualified contact URL, so the fix was
    to say who we are and where to complain rather than to pretend to be
    something else.

    This test exists so the next 403, from any vendor, cannot be answered by
    quietly pasting in a browser string. If a provider ever demands one, that is
    a decision to take deliberately and disclose, not a one-word edit here."""
    from rbp import feeds
    ua = feeds.UA["User-Agent"]
    assert ua.startswith("rbp-cves/"), "we identify as ourselves, not as a tool"
    for impersonation in ("Mozilla", "AppleWebKit", "Chrome", "Safari", "Gecko",
                          "Edg/", "curl/", "Wget/"):
        assert impersonation not in ua, (
            f"the User-Agent claims to be {impersonation}, which it is not")
    assert "https://" in ua, (
        "a bot with no contact route in its UA is one a vendor can only block")


# --------------------------------------------------------------------------
# where the artefacts live
# --------------------------------------------------------------------------

def test_scorecards_go_somewhere_git_can_see():
    """FEEDS.md section 3: "the merge commit includes it. No feed is merged
    without its scorecard in the diff."

    That rule was unenforceable as written, because it named `data/feedlab/` and
    `.gitignore` line 3 is `data/`, for the 583 MB corpus. A scorecard written
    there can never appear in any diff, so the rule would have been decorative
    from the day it was written.
    """
    import pathlib
    import subprocess
    root = pathlib.Path(feedlab.ROOT)
    assert pathlib.Path(feedlab.LAB).parent == root, (
        "the scorecard directory moved back under an ignored parent")
    probe = subprocess.run(
        ["git", "check-ignore", "-q", str(pathlib.Path(feedlab.LAB) / "x.json")],
        cwd=str(root), capture_output=True)
    assert probe.returncode != 0, (
        "git ignores the scorecard directory, so no scorecard can ever be in a "
        "merge diff and the rule it enforces is decorative")


def test_the_baseline_working_state_stays_out_of_the_repo():
    """The other half. The baseline holds every referenced id from every merged
    feed, tens of thousands of them, and a diff containing all of them is a diff
    nobody reads."""
    import subprocess
    probe = subprocess.run(
        ["git", "check-ignore", "-q", feedlab.BASELINE],
        cwd=feedlab.ROOT, capture_output=True)
    assert probe.returncode == 0, (
        "the multi-megabyte baseline is no longer ignored")


def test_the_baseline_summary_drops_the_id_list_and_keeps_the_provenance():
    """What a reviewer needs is which feeds, when, how long and how many CNAs.
    Not 32,000 ids."""
    base = {"feeds": ["a", "b"], "scored_at": "2026-08-24T00:00:00+00:00",
            "ids": ["CVE-2025-1", "CVE-2025-2"],
            "per_feed": {"a": {"rows": [{"cve_id": "CVE-2025-1"}]},
                         "b": {"rows": [{"cve_id": "CVE-2025-2"}]}},
            "effective": ["apache"], "wall_seconds": 12.0}
    out = feedlab.baseline_summary(base)
    assert "ids" not in out and "per_feed" not in out
    assert out["ids_n"] == 2
    assert out["per_feed_rows"] == {"a": 1, "b": 1}
    assert out["feeds"] == ["a", "b"] and out["wall_seconds"] == 12.0


def test_a_feed_that_failed_is_named_in_the_baseline_rather_than_omitted():
    """A baseline silently missing a feed makes every later candidate look better
    than it is, and the whole value of a marginal number is what it is marginal
    to."""
    import inspect
    src = inspect.getsource(feedlab.build_baseline)
    assert '"failed": failed' in src
    assert "failed[name]" in src


# --------------------------------------------------------------------------
# Round 7 H3: near the floor is not the same kind of miss as never sighted
# --------------------------------------------------------------------------

class _Roster:
    """Minimal roster stand-in: normalise lowercases, index maps to itself."""
    @staticmethod
    def normalise(n):
        return n.lower().replace("-", "").replace("_", "")


def _idx(*names):
    return {_Roster.normalise(n): n for n in names}


def test_near_floor_names_the_cnas_that_are_two_sightings_from_counting():
    """The cheapest headroom on the board, and nothing computed it.

    `top_missed_effective` and `top_missed` were both published and the
    DIFFERENCE between them is exactly this set, so it was derivable and never
    derived. On 2026-08-27 the eight top-50 misses split three to five: `dell`,
    `TR-CERT` and `sap` at one sighting each against a floor of three, and five
    at zero, which is a parser apiece.
    """
    from rbp import coverage
    sightings = {"dell": 1, "sap": 1, "TR-CERT": 1, "Axis": 2,
                 "redhat": 900, "huawei": 0}
    out = coverage._near_floor(sightings, _idx("dell", "sap", "TR-CERT", "Axis",
                                               "redhat", "huawei"), _Roster)
    names = [r["cna"] for r in out]

    assert "redhat" not in names, "a CNA above the floor is not near it"
    assert "huawei" not in names, (
        "a CNA sighted zero times is a parser, not two sightings: putting it in "
        "this list is the error the list exists to prevent")
    # Closest first, so the list reads in priority order without recomputing.
    assert names[0] == "Axis" and out[0]["short_by"] == 1
    assert {r["cna"] for r in out if r["short_by"] == 2} == {"TR-CERT", "dell", "sap"}


def test_near_floor_is_ordered_stably_across_runs():
    """Sightings move every six hours. A list that reshuffles cannot be diffed
    by whoever is deciding what to write next, so ties break on name."""
    from rbp import coverage
    idx = _idx("b", "a", "c")
    first = coverage._near_floor({"b": 2, "a": 2, "c": 2}, idx, _Roster)
    second = coverage._near_floor({"c": 2, "a": 2, "b": 2}, idx, _Roster)
    assert [r["cna"] for r in first] == [r["cna"] for r in second] == ["a", "b", "c"]


def test_near_floor_excludes_off_roster_assigners():
    """Off-roster names are already excluded from the coverage numerator, so
    promoting one buys nothing and listing it would send someone to write a
    parser for a CNA the gate cannot count."""
    from rbp import coverage
    out = coverage._near_floor({"crafter": 2, "dell": 2}, _idx("dell"), _Roster)
    assert [r["cna"] for r in out] == ["dell"]


def test_the_floor_the_report_uses_is_the_one_inference_uses():
    """`MIN_SIGHTINGS` is deliberately the same constant inference uses to decide
    whether it will attach a CNA's name to a row. A near-floor report keyed on a
    different number would invite loosening one to shorten the other, which is
    the single change FEEDS.md section 0 forbids outright."""
    from rbp import coverage, inference
    assert coverage.MIN_SIGHTINGS is inference.MIN_SIGHTINGS


# --------------------------------------------------------------------------
# Round 7 B1 and B2: the harness has to describe the feed set that actually runs
# --------------------------------------------------------------------------
#
# THE TESTS BELOW ARE MARKED `harness_artefact` AND THAT IS A DEPLOY
# DECISION, not a hint about strength. Each compares a committed artefact under
# `feedlab/` to the code, so each fails on a change that is CORRECT but
# unaccompanied by a 26-minute rebuild: a feed added to the profile, a window
# widened, a calendar year turning over. `deploy.yml` gates the live site's
# four-times-daily publish on this suite, and `rbp/feedlab.py` is imported by
# nothing the site builds, so without the marker a stale scorecard could halt
# publication while being unable to make any page wrong. ci.yml runs them
# unfiltered on every pull request and every push to main, which is where the
# staleness is actually someone's to fix. Reasoning in full in pyproject.toml.

def _lab():
    import pathlib
    return pathlib.Path(__file__).parent.parent / "feedlab"


def _profile_feeds():
    from rbp.cli import PROFILES
    return [x for x in PROFILES["weekly"].split(",") if x]


@pytest.mark.harness_artefact
def test_every_feed_in_the_running_profile_has_a_scorecard():
    """feedlab/README.md, line 3: "no feed is merged without its scorecard in
    the diff."

    The rule was written, tested against the twelve feeds that predate it, and
    broken by the first feed merged after it. `ghsa-repos` shipped 2026-08-26 and
    within a day was carrying 1,188 of 1,709 published rows and was the SOLE
    source for 1,015 of them, 59% of the headline, with no `cnas_new_effective`,
    no `lead_n`, no `unpublished_n` and no verdict.

    This is not a claim it would fail. It is that the number is not in the diff,
    so nothing can be compared against it later, and the one feed whose collapse
    would take six tenths of the site has no recorded baseline to collapse from.
    """
    missing = [f for f in _profile_feeds() if not (_lab() / f"{f}.json").exists()]
    assert not missing, (
        "these feeds run in the weekly profile with no scorecard committed: "
        f"{missing}. Run `python -m rbp.feedlab score <name>`, or rebuild the "
        "baseline and run `audit`, and commit the result.")


@pytest.mark.harness_artefact
def test_every_committed_scorecard_measures_the_window_the_pipeline_reads():
    """The DAMAGE from a stale `--years`, as opposed to its cause.

    `test_the_harness_cli_defaults_to_the_window_it_measures` catches the next
    one at the argparse default and this catches the fifteen cards already on
    disk. Nothing compared a card's own `years` field to `coverage.window()`, so
    every scorecard in the repo sat at [2025, 2026] for a day after the pipeline
    went to four years, each one internally consistent and every marginal figure
    in them an understatement: `jvn` 1,117 ids where the live run read 1,968.

    Scoped to feeds the profile actually runs. A card for a candidate that was
    measured and NOT merged is a record of what was measured then, and rewriting
    it would cost a fetch to say nothing new.
    """
    import datetime as dt
    from rbp import coverage
    want = sorted(coverage.window(dt.date.today().year))
    stale = {}
    for feed in _profile_feeds():
        path = _lab() / f"{feed}.json"
        if not path.exists():
            continue  # the scorecard's own test above owns that failure
        got = sorted(json.loads(path.read_text()).get("years") or [])
        if got != want:
            stale[feed] = got
    assert not stale, (
        f"these merged feeds are scored over a window the pipeline does not "
        f"read (it reads {want}): {stale}. Their marginal figures are marginal "
        "to the wrong merged set. Rebuild the baseline and re-run "
        "`python -m rbp.feedlab audit`.")


@pytest.mark.harness_artefact
def test_the_recorded_baseline_describes_the_profile_that_actually_runs():
    """A stale baseline does not make the harness cautious. It makes it permissive.

    `_baseline.json` was scored 2026-08-24 with `ghsa` at 3,321 rows. `8e3479d`
    then replaced the page cap with a windowed read and ghsa returned 10,832, and
    `ghsa-repos` (9,861) did not exist at all. Every marginal figure a later
    `score` produced was marginal to a merged set roughly 20,000 ids smaller than
    the real one.

    The direction is what makes it a blocker: a baseline that is too SMALL makes a
    candidate look like it reaches CNAs nobody else reaches, because the feeds
    that already reach them were measured before they could. The next scorecard
    it produces is the one that decides whether a new parser is worth two days.
    """
    path = _lab() / "_baseline.json"
    assert path.exists(), "no recorded baseline"
    recorded = set(json.loads(path.read_text()).get("feeds") or [])
    profile = set(_profile_feeds())
    assert recorded == profile, (
        f"the baseline describes a feed set the pipeline does not run.\n"
        f"  in the profile, not the baseline: {sorted(profile - recorded)}\n"
        f"  in the baseline, not the profile: {sorted(recorded - profile)}\n"
        "Re-run `python -m rbp.feedlab baseline`.")


def _live():
    return json.loads((_lab() / "_live.json").read_text())


@pytest.mark.harness_artefact
def test_the_pinned_live_run_is_the_profile_the_pipeline_runs():
    """THE TEST ABOVE, ONE LEVEL DOWN, WHICH IS WHERE THE DEFECT WAS.

    The feed LIST matched the pipeline and the STATE behind one of those feeds
    did not: `csaf` returned 42,659 rows here against the live run's 62,800 on
    the same commit and the same window, worth 16 effective roster CNAs, and the
    test above passed throughout because it compares names.

    A pin taken from a run with a different feed set cannot be subtracted from
    this baseline at all, so that is what this checks. HOW MUCH colder the
    baseline is, is recorded on every card rather than asserted here: a local
    state drains over successive runs by design, and failing on a legitimate
    backlog would make the fix be "stop running the harness".
    """
    live = _live()
    pinned, profile = set(live.get("sources") or []), set(_profile_feeds())
    assert pinned == profile, (
        f"the pinned live run reads a different feed set than this repo runs.\n"
        f"  in the profile, not the pin: {sorted(profile - pinned)}\n"
        f"  in the pin, not the profile: {sorted(pinned - profile)}\n"
        "Re-pin after the merge lands live: `python -m rbp.feedlab pin-live`.")
    recorded = json.loads((_lab() / "_baseline.json").read_text())
    assert sorted(live.get("years") or []) == sorted(recorded.get("years") or []), (
        f"the pin measures {sorted(live.get('years') or [])} and the baseline "
        f"gathered {sorted(recorded.get('years') or [])}. A marginal figure "
        "across two windows is the window moving, not the feed.")
    assert live.get("min_sightings") == FLOOR, (
        f"the pinned run counts a CNA effective at {live.get('min_sightings')} "
        f"sightings and this harness at {FLOOR}. Two floors is two questions.")


@pytest.mark.harness_artefact
def test_the_pinned_live_run_is_not_stale():
    """A pin that silently ages is the roster problem again: a number nobody is
    measuring, believed because it is committed. The site rebuilds four times a
    day, so a fortnight is a release cycle rather than a moved figure."""
    live = _live()
    age = feedlab.live_age_days(live)
    assert age is not None, "the pin carries no fetch date"
    assert age <= feedlab.LIVE_MAX_AGE_DAYS, (
        f"the pinned live run is {age} days old, above "
        f"{feedlab.LIVE_MAX_AGE_DAYS}. Re-pin: `python -m rbp.feedlab "
        "pin-live`. Every scorecard is marginal to it.")


@pytest.mark.harness_artefact
def test_the_recorded_baseline_records_how_cold_its_csaf_read_was():
    """The depth, as counts, in the artefact that carries the figures it bounds.

    `_record_csaf_health` has always said "3 still catching up" in a health
    string. A sentence in a health record is not something a card can subtract or
    a test can read, which is why the gap survived a rebuild, an audit and a
    passing suite.
    """
    depth = json.loads((_lab() / "_baseline.json").read_text()).get("csaf_state")
    assert depth, (
        "the baseline records no csaf read depth. Re-run `python -m rbp.feedlab "
        "baseline --rescore`, which is offline and fills it in from the read "
        "marks without refetching anything.")
    for k in ("providers", "ids", "behind", "providers_behind"):
        assert k in depth, f"csaf_state records no {k}"


@pytest.mark.harness_artefact
def test_every_committed_scorecard_declares_the_depth_it_was_measured_at():
    """"AND NOTHING SAID SO" is the half of item 1 a test can hold.

    A local state is as deep as the runs that happened locally, and that is not a
    defect. Presenting a figure measured against it as though it were measured
    against the site IS. So every committed card carries the pin it was scored
    with and the shortfall at the time, and the two have to agree with the
    artefacts beside them, or the cards are describing a baseline that is no
    longer the one on disk.
    """
    live = _live()
    base = json.loads((_lab() / "_baseline.json").read_text())
    want = {k: v for k, v in feedlab.depth_shortfall(base, live).items() if v > 0}
    stale = []
    for feed in _profile_feeds():
        card = json.loads((_lab() / f"{feed}.json").read_text())
        blk = card.get("live") or {}
        if not blk.get("pinned"):
            stale.append(f"{feed}: scored with no pinned live run")
        elif blk.get("rows_short") != want:
            stale.append(f"{feed}: says {blk.get('rows_short')}, the artefacts "
                         f"say {want}")
    assert not stale, (
        "these scorecards do not declare the depth the baseline beside them was "
        f"measured at: {stale}. Re-run `python -m rbp.feedlab audit`, which is "
        "offline.")


@pytest.mark.harness_artefact
def test_the_baseline_gathers_the_years_the_pipeline_gathers():
    """THE RECORDED BASELINE READS THE PIPELINE'S WINDOW, whatever it is.

    The previous version asserted the hand-written pair `{now, now - 1}` and it
    PASSED THROUGH the defect it was written to catch. `coverage.WINDOW_YEARS`
    became 4 on 2026-09-05, `a6332c0` unified the gather and coverage windows,
    and `feedlab`'s three `--years` defaults stayed at the literal "2025,2026".
    The baseline was rebuilt with that stale default, so the assertion agreed
    with it: two files internally consistent, the contradiction only between
    them and the pipeline. Measured on the same commit, the harness saw 1,117
    `jvn` ids and 208 effective CNAs where the live run saw 1,968 and 263.

    So this derives the expectation instead, from the one definition both sides
    read. A hand-written window here is the defect, not the test.
    """
    import datetime as dt
    from rbp import coverage
    recorded = json.loads((_lab() / "_baseline.json").read_text())
    years = sorted(recorded.get("years") or [])
    want = sorted(coverage.window(dt.date.today().year))
    assert years == want, (
        f"the baseline gathered {years}; the pipeline gathers {want}. Every "
        "marginal figure scored against it is marginal to the wrong merged "
        "set. Re-run `python -m rbp.feedlab baseline`.")

    # THE SAME CONTRADICTION, VISIBLE INSIDE ONE FILE. The stale baseline
    # recorded years [2025, 2026] beside coverage_years [2023, 2024, 2025, 2026]
    # and nothing compared the two, which is the whole defect sitting in a
    # committed artefact in plain sight. There is one window now; a baseline
    # whose own two fields disagree was gathered by something that still thinks
    # there are two.
    assert sorted(recorded.get("coverage_years") or []) == years, (
        f"the baseline gathered {years} and measured coverage over "
        f"{sorted(recorded.get('coverage_years') or [])}. Those are one window "
        "since a6332c0.")


def test_the_harness_cli_defaults_to_the_window_it_measures():
    """The seam the test above sits downstream of.

    The baseline assertion can only fail AFTER a wrong baseline has been
    gathered, which costs half an hour and fifteen third-party fetches. This one
    fails on the argparse default itself, and it is the thing that was actually
    wrong: `--years` was a literal in three subcommands, so widening the window
    in `coverage.py` left the harness reading the old one with no test between
    them.

    `audit` is absent on purpose: it scores `base["years"]` from the recorded
    baseline, so the `--years` it used to accept reached no code at all.
    """
    import datetime as dt
    from rbp import coverage, feedlab as fl
    want = sorted(coverage.window(dt.date.today().year))
    assert sorted(fl._years(fl._default_years())) == want

    ap = fl._build_parser()
    for argv in (["baseline"], ["score", "x"]):
        got = sorted(fl._years(ap.parse_args(argv).years))
        assert got == want, (
            f"`feedlab {argv[0]}` defaults to {got}, not the pipeline's {want}")
    with pytest.raises(SystemExit):
        ap.parse_args(["audit", "--years", "2025,2026"])


def test_deep_is_an_alias_of_weekly_not_a_copy_of_it():
    """Two identical string literals are a config duplicate waiting to drift.

    The last time `weekly` and `deep` meant different things, the gate was
    measured on a profile the cron did not run, and `siemens` showed as an
    uncovered top-50 CNA while already being a configured CSAF provider. Adding a
    feed to one literal and not the other would recreate that silently.
    """
    from rbp.cli import PROFILES
    assert PROFILES["deep"] is PROFILES["weekly"], (
        "deep is a separate string. Alias it, so the two cannot diverge without "
        "someone meaning it.")


def corpus_df_with(rows):
    """A corpus frame from (cve_id, state, assigner) triples."""
    return corpus([{"cve_id": c, "state": st, "assigner": a,
                    "date_published": "2026-01-01", "vendor": "", "product": ""}
                   for c, st, a in rows])


# --------------------------------------------------------------------------
# Round 7 H2: the corroborating rule, enforced rather than only written
# --------------------------------------------------------------------------

def test_a_corroborating_feed_cannot_credit_a_cna_as_observable():
    """FEEDS.md section 2 and feedlab/README.md both said this and no code read it.

    "It can strengthen a row it did not find; it cannot credit a CNA as
    observable. Crediting a CNA on a feed that is structurally incapable of
    surfacing an unpublished ID is how a launch gate clears while the site's
    actual claim gets weaker."

    `mozilla` has verdict `corroborating` and `unpublished_n` 0, and contributed
    605 sightings to the gate figure like any other feed.
    """
    from rbp import coverage
    corpus = corpus_df_with(
        [("CVE-2026-1", "PUBLISHED", "apache"), ("CVE-2026-2", "PUBLISHED", "apache"),
         ("CVE-2026-3", "PUBLISHED", "apache")])
    refs = {f"CVE-2026-{i}": {"sources": {"mozilla"}} for i in (1, 2, 3)}

    counted = coverage.compute(corpus, refs, recent_years=(2026,), sources=["mozilla"])
    assert counted["cnas_effective"] == 1, (
        "the fixture no longer demonstrates a CNA crossing the floor")

    excluded = coverage.compute(corpus, refs, recent_years=(2026,),
                                sources=["mozilla"], corroborating=["mozilla"])
    assert excluded["cnas_effective"] == 0, (
        "a CNA seen ONLY through a feed that has never surfaced an unpublished "
        "id is still being credited as observable")
    assert excluded["corroborating_feeds"] == ["mozilla"], (
        "the exclusion is a quiet subtraction unless it is named")


def test_a_row_a_corroborating_feed_merely_corroborates_still_counts():
    """The other half of the same sentence, and the half that is easy to break.

    "It CAN strengthen a row it did not find." A CVE seen by both a detecting
    feed and a corroborating one must keep counting: excluding the id rather than
    the feed would make adding a corroborating feed REDUCE coverage, which is
    absurd and is the obvious wrong implementation.
    """
    from rbp import coverage
    corpus = corpus_df_with(
        [(f"CVE-2026-{i}", "PUBLISHED", "apache") for i in (1, 2, 3)])
    refs = {f"CVE-2026-{i}": {"sources": {"debian", "mozilla"}} for i in (1, 2, 3)}
    out = coverage.compute(corpus, refs, recent_years=(2026,),
                           sources=["debian", "mozilla"], corroborating=["mozilla"])
    assert out["cnas_effective"] == 1, (
        "corroboration was treated as contamination: a row a detecting feed "
        "found stopped counting because a corroborating feed also carried it")


def test_the_exclusion_narrows_the_gate_figure_and_nothing_else():
    """`sightings`, `covered` and `observed_*` describe what this site actually
    saw and are honest as they stand. Narrowing them to satisfy a rule about a
    different question would make the site under-report its own reach."""
    from rbp import coverage
    corpus = corpus_df_with(
        [(f"CVE-2026-{i}", "PUBLISHED", "apache") for i in (1, 2, 3)])
    refs = {f"CVE-2026-{i}": {"sources": {"mozilla"}} for i in (1, 2, 3)}
    out = coverage.compute(corpus, refs, recent_years=(2026,),
                           sources=["mozilla"], corroborating=["mozilla"])
    assert out["cnas_effective"] == 0
    assert out["cnas_sighted"] == 1, "cnas_sighted was narrowed too"
    assert out["observed_ids"] == 3, "observed coverage was narrowed too"


def test_an_unreadable_verdict_file_excludes_nothing_and_does_not_raise():
    """Permissive on failure, because this refines one figure and must never be
    the reason a publication stops. The guard that keeps the verdicts PRESENT is
    test_every_feed_in_the_running_profile_has_a_scorecard, not this."""
    assert feedlab.corroborating_feeds("/nonexistent/_audit.json") == set()


def test_unmeasurable_is_not_treated_as_corroborating(tmp_path):
    """`arch`'s verdict is `unmeasurable`: it published nothing datable to score.
    That is an absence of evidence, not evidence it cannot detect, and conflating
    them would quietly demote any new feed whose first scorecard was thin."""
    p = tmp_path / "_audit.json"
    p.write_text(json.dumps({"feeds": {
        "arch": {"verdict": "unmeasurable"}, "mozilla": {"verdict": "corroborating"},
        "debian": {"verdict": "detecting"}}}))
    assert feedlab.corroborating_feeds(str(p)) == {"mozilla"}


# --------------------------------------------------------------------------
# Round 7 M2: stability was decoration on every merged feed
# --------------------------------------------------------------------------

def test_stability_is_null_until_there_are_two_real_fetches():
    """README: "returning one anyway is how a scorecard field becomes
    decoration." Null is the honest answer to one observation."""
    assert feedlab.stability([]) is None
    assert feedlab.stability([{"ids": 100}]) is None
    assert feedlab.stability([{"ids": 100}, {"ids": 90}])["swing_pct"] == 10.0


def test_the_audit_reads_the_fetch_history_and_never_appends_to_it():
    """`audit` replays ONE baseline's stored rows. If it appended, every audit
    run would add an identical id count and `stability` would report a 0% swing
    over N "fetches" that were a single fetch.

    A fabricated perfect reading is worse than null: null says "not measured",
    0% says "measured, and perfect". That is the same distinction the freshness
    guard draws between unmeasurable and fine, and the one this project keeps
    having to relearn.
    """
    import pathlib
    src = (pathlib.Path(feedlab.__file__)).read_text()
    audit = src[src.index('if args.cmd == "audit":'):]
    assert "_read_fetches(name)" in audit, (
        "audit does not read the recorded history, so stability stays null")
    assert "record_fetch(" not in audit, (
        "audit appends to the fetch history, manufacturing stability out of one "
        "real fetch")


def test_a_baseline_rebuild_records_one_observation_per_feed(tmp_path, monkeypatch):
    """The only place a real fetch of every feed happens, so the only place an
    honest observation can come from -- AND the window it happened over.

    Run rather than read. The source-text version of this test passed while
    `build_baseline` recorded a bare `{at, ids}`, which is the seam that let two
    windows' counts into one history: `record_fetch` was proved and its only
    real caller was not. Deleting the argument here leaves every other assertion
    in this file green.
    """
    from rbp import feeds
    monkeypatch.setattr(feedlab, "STATE", str(tmp_path))
    monkeypatch.setitem(feeds.ADAPTERS, "fake",
                        lambda years: [row(f"CVE-{y}-1000") for y in sorted(years)])
    base = feedlab.build_baseline(["fake"], {2023, 2024, 2025, 2026}, CORPUS)
    assert base["feeds"] == ["fake"]
    hist = json.loads((tmp_path / "fake.fetches.json").read_text())
    assert [h["ids"] for h in hist] == [4]
    assert hist[0]["years"] == [2023, 2024, 2025, 2026], (
        "the rebuild recorded a count with no window beside it, so the next "
        "window change reads as the feed swinging")


def test_reading_a_missing_fetch_history_is_empty_not_an_error(tmp_path):
    assert feedlab._read_fetches("nope", str(tmp_path / "nope.json")) == []
