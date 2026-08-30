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
    base = {**EMPTY_BASE, "sightings": {"apache": FLOOR - 1}, "effective": []}
    card = feedlab.scorecard("x", {2025}, CORPUS, base=base,
                             rows=[row("CVE-2025-1000")], stats={})
    assert card["cnas_new_effective_names"] == ["apache"]


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


def test_detection_without_coverage_is_still_corroborating():
    v, _why = feedlab.classify(0, _lead(lead_n=3, unpublished_n=1))
    assert v == "corroborating"


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
    path = tmp_path / "x.fetches.json"
    feedlab.record_fetch("x", {"a", "b"}, path=str(path))
    hist = feedlab.record_fetch("x", {"a"}, path=str(path))
    assert [h["ids"] for h in hist] == [2, 1]
    assert feedlab.stability(hist)["swing_pct"] == 50.0


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
    assert coverage.window(2026) == (2024, 2025, 2026)
    assert len(coverage.window(2026)) == coverage.WINDOW_YEARS
    # A YEAR THAT IS NOT THIS ONE, because the assertions above cannot tell a
    # derived window from a hardcoded (2024, 2025, 2026) while the current year
    # is 2026. Replacing feedlab's body with that literal left them all green.
    # Confirmed by mutation on 2026-08-30.
    assert feedlab.coverage_years("2031-04-01") == (2029, 2030, 2031)
    assert feedlab.coverage_years("2024-12-31") == (2022, 2023, 2024)


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
    assert coverage.window(2026) == (2024, 2025, 2026)


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

def _lab():
    import pathlib
    return pathlib.Path(__file__).parent.parent / "feedlab"


def _profile_feeds():
    from rbp.cli import PROFILES
    return [x for x in PROFILES["weekly"].split(",") if x]


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


def test_the_baseline_gathers_the_years_the_pipeline_gathers():
    """`coverage_years` (2024-2026) and the GATHER years (2025-2026) are different
    windows and it is easy to pass one for the other.

    Done exactly once while rebuilding this baseline: `--years 2024,2025,2026`
    looked like the site's window, took alas from 11,674 rows to 16,026, and would
    have recorded a merged set the pipeline never reads. Which is B2's defect
    arriving inside B2's fix.
    """
    import datetime as dt
    recorded = json.loads((_lab() / "_baseline.json").read_text())
    years = set(recorded.get("years") or [])
    now = dt.date.today().year
    assert years == {now, now - 1}, (
        f"baseline gathered {sorted(years)}; the pipeline gathers "
        f"{sorted({now, now - 1})}. coverage_years is the other window.")


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


def test_a_baseline_rebuild_records_one_observation_per_feed():
    """The only place a real fetch of every feed happens, so the only place an
    honest observation can come from."""
    import pathlib
    src = (pathlib.Path(feedlab.__file__)).read_text()
    build = src[src.index("def build_baseline("):src.index("def baseline_summary(")]
    assert "record_fetch(" in build, (
        "a baseline rebuild fetches every feed for real and records none of it, "
        "so stability can never accrue")


def test_reading_a_missing_fetch_history_is_empty_not_an_error(tmp_path):
    assert feedlab._read_fetches("nope", str(tmp_path / "nope.json")) == []
