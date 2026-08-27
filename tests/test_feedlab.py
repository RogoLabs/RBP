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


def test_the_scorecard_uses_the_same_window_the_gate_is_measured_on():
    """cli.run gathers {this year, last year} and measures coverage over three.
    The gate IS the coverage figure, so a scorecard on the narrower window would
    be marginal to a different denominator, which is one more estimate wearing a
    measurement's clothes."""
    import inspect
    from rbp import cli
    src = inspect.getsource(cli.cmd_run)
    assert "recent_years=(cyr - 2, cyr - 1, cyr)" in src, (
        "cli.run's coverage window changed; feedlab.coverage_years must follow it")
    assert feedlab.coverage_years("2026-08-24") == (2024, 2025, 2026)


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
    "shortName": "acme",
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
