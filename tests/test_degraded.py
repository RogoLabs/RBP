"""
Degraded runs must not read as clean ones (review item 15).

"The one direction of error this project cannot afford is a silent shrink,
because a shrinking count reads as the Program improving."

Two mechanisms produced one, and both were invisible from outside:

    An ERROR'd id was tallied and never appended to the backlog, so it vanished
    from the snapshot, became a fake departure in no_longer_listed, and stayed
    open in the ledger forever. A brownout at the reservation endpoint would have
    shrunk the headline AND manufactured departures.

    health_summary returned only FAILED entries, so cli's `if failures:` could
    never fire on truncation. Ubuntu truncates every single run, so the live
    snapshot published `failures: []` beside `truncated: ["ubuntu"]` and the
    DEGRADED warning never printed once.
"""
from __future__ import annotations

import json
import os

import pandas as pd
import pytest

from rbp import classify, cli, feeds
from rbp.attribution import Attributor


@pytest.fixture(autouse=True)
def _clean_health():
    feeds.reset_health()
    classify.RATE_LIMITED.clear()
    yield
    feeds.reset_health()
    classify.RATE_LIMITED.clear()


def _corpus():
    ids = [f"CVE-2026-{1000 + i}" for i in range(6)]
    return pd.DataFrame({"cve_id": ids, "state": ["PUBLISHED"] * 6,
                         "assigner": ["acme"] * 6, "vendor": ["Acme"] * 6,
                         "product": ["widget"] * 6})


def _refs(*cids):
    return {c: {"public_date": "2026-07-01", "sources": {"debian"},
                "refs": {f"debian:{c}"}, "product": "widget",
                "description": "a flaw", "dates": {}} for c in cids}


def _run(monkeypatch, tmp_path, states, previous=()):
    """Resolve two ids with a scripted oracle."""
    monkeypatch.setattr(classify, "_get",
                        lambda cid, attempts=3: {"state": states[cid],
                                                 "assigner": "[REDACTED]"})
    refs = _refs(*states)
    return classify.classify(refs, _corpus(), Attributor(_corpus()),
                             str(tmp_path / "c.json"), workers=2,
                             today="2026-08-20", previous_reserved=previous)


# --------------------------------------------------------------------------
# carry-forward
# --------------------------------------------------------------------------

def test_an_unresolved_id_known_reserved_last_run_is_carried_not_dropped(monkeypatch, tmp_path):
    states = {"CVE-2026-2001": "RESERVED", "CVE-2026-2002": "ERROR"}
    bl, _, health = _run(monkeypatch, tmp_path, states,
                         previous={"CVE-2026-2002"})
    assert len(bl) == 2, "the unresolved id vanished from the backlog"
    assert health["unresolved"] == 1
    assert health["carried_forward"] == 1
    assert health["dropped"] == 0
    carried = next(r for r in bl if r["cve_id"] == "CVE-2026-2002")
    assert carried["state_verified_this_run"] is False


def test_a_carried_row_is_marked_and_a_verified_row_is_too(monkeypatch, tmp_path):
    """The field must be present on every row. Absent on some and False on others
    is how a missing value gets read as a healthy default."""
    states = {"CVE-2026-2001": "RESERVED", "CVE-2026-2002": "ERROR"}
    bl, _, _ = _run(monkeypatch, tmp_path, states, previous={"CVE-2026-2002"})
    assert all("state_verified_this_run" in r for r in bl)
    verified = next(r for r in bl if r["cve_id"] == "CVE-2026-2001")
    assert verified["state_verified_this_run"] is True


def test_an_unresolved_id_never_seen_before_is_not_invented(monkeypatch, tmp_path):
    """Carry-forward only carries. An id with no prior RESERVED observation must
    not be added to the count on the strength of a failed lookup."""
    states = {"CVE-2026-2001": "RESERVED", "CVE-2026-2002": "ERROR"}
    bl, _, health = _run(monkeypatch, tmp_path, states, previous=set())
    assert [r["cve_id"] for r in bl] == ["CVE-2026-2001"]
    assert health["unresolved"] == 1
    assert health["carried_forward"] == 0
    assert health["dropped"] == 1


def test_a_total_brownout_carries_the_whole_previous_backlog(monkeypatch, tmp_path):
    """The scenario that motivated this: the endpoint is down, every lookup fails,
    and the old code published a backlog of zero as though the problem had been
    solved overnight."""
    states = {"CVE-2026-2001": "ERROR", "CVE-2026-2002": "ERROR"}
    bl, _, health = _run(monkeypatch, tmp_path, states,
                         previous={"CVE-2026-2001", "CVE-2026-2002"})
    assert len(bl) == 2
    assert health["dropped"] == 0
    assert all(r["state_verified_this_run"] is False for r in bl)


def test_a_published_id_is_not_carried_forward(monkeypatch, tmp_path):
    """Carry-forward must never resurrect a row that genuinely resolved. A record
    that published is the outcome this site exists to encourage."""
    states = {"CVE-2026-2001": "PUBLISHED", "CVE-2026-2002": "RESERVED"}
    bl, fresh, health = _run(monkeypatch, tmp_path, states,
                             previous={"CVE-2026-2001", "CVE-2026-2002"})
    assert [r["cve_id"] for r in bl] == ["CVE-2026-2002"]
    assert fresh == 1
    assert health["carried_forward"] == 0


def test_never_allocated_is_counted_and_published_not_just_logged(monkeypatch, tmp_path):
    """A genuinely valuable data-quality population: ids cited by a downstream
    advisory that were never allocated at all. Printed and discarded before."""
    states = {"CVE-2026-2001": "RESERVED", "CVE-2026-2002": classify._NOT_FOUND}
    bl, _, health = _run(monkeypatch, tmp_path, states)
    assert health["never_allocated"] == 1
    assert len(bl) == 1, "a never-allocated id is not an RBP"


def test_the_health_block_accounts_for_every_lookup(monkeypatch, tmp_path):
    states = {"CVE-2026-2001": "RESERVED", "CVE-2026-2002": "PUBLISHED",
              "CVE-2026-2003": classify._NOT_FOUND, "CVE-2026-2004": "ERROR"}
    _, _, h = _run(monkeypatch, tmp_path, states, previous={"CVE-2026-2004"})
    assert h["lookups_attempted"] == 4
    assert (h["reserved"] + h["published"] + h["rejected"]
            + h["never_allocated"] + h["unresolved"]) == 4
    assert h["carried_forward"] + h["dropped"] == h["unresolved"]


# --------------------------------------------------------------------------
# _previous_reserved
# --------------------------------------------------------------------------

def test_previous_reserved_reads_the_latest_snapshot_before_today(tmp_path):
    for date, ids in (("2026-08-18", ["CVE-1"]), ("2026-08-19", ["CVE-2", "CVE-3"])):
        d = tmp_path / date
        d.mkdir()
        (d / "backlog.json").write_text(json.dumps([{"cve_id": i} for i in ids]))
    assert cli._previous_reserved(str(tmp_path), "2026-08-20") == {"CVE-2", "CVE-3"}


def test_previous_reserved_ignores_today_and_the_future(tmp_path):
    """Reading today's own half-written snapshot would make carry-forward
    self-referential."""
    for date in ("2026-08-20", "2026-08-21"):
        d = tmp_path / date
        d.mkdir()
        (d / "backlog.json").write_text(json.dumps([{"cve_id": "CVE-X"}]))
    assert cli._previous_reserved(str(tmp_path), "2026-08-20") == set()


def test_previous_reserved_is_tolerant_of_a_missing_or_corrupt_snapshot(tmp_path):
    """First run is the normal empty case, and a corrupt snapshot must not stop a
    publication: degrading to the old drop behaviour is reported, not fatal."""
    assert cli._previous_reserved(str(tmp_path), "2026-08-20") == set()
    d = tmp_path / "2026-08-19"
    d.mkdir()
    (d / "backlog.json").write_text("{not json")
    assert cli._previous_reserved(str(tmp_path), "2026-08-20") == set()


# --------------------------------------------------------------------------
# feed health: truncation is neither success nor failure
# --------------------------------------------------------------------------

def test_health_summary_reports_truncation_separately_from_failure():
    feeds.record_feed("ubuntu", feeds.TRUNCATED, "hit the 200-page cap")
    feeds.record_feed("debian", feeds.FAILED, "connection reset")
    feeds.record_feed("alpine", feeds.OK, "40 ids", rows=40)
    failures, truncated, attempts, _capped = feeds.health_summary()
    assert len(failures) == 1 and "debian" in failures[0]
    assert len(truncated) == 1 and "ubuntu" in truncated[0]
    assert attempts == 3


def test_a_truncated_only_run_is_still_degraded():
    """The live case. Ubuntu truncates every run, so this is the state the site is
    actually in, and `if failures:` reported it as clean."""
    feeds.record_feed("ubuntu", feeds.TRUNCATED, "hit the 200-page cap")
    failures, truncated, _, _capped = feeds.health_summary()
    assert failures == []
    assert truncated, "a truncated run must be visible to the caller"
    assert bool(failures or truncated) is True


def test_a_fully_clean_run_is_not_degraded():
    feeds.record_feed("alpine", feeds.OK, "40 ids", rows=40)
    failures, truncated, _, _capped = feeds.health_summary()
    assert not failures and not truncated


# --------------------------------------------------------------------------
# rate limiting
# --------------------------------------------------------------------------

def test_backoff_honours_retry_after_when_offered():
    assert classify._backoff(0, "5") == 5.0
    assert classify._backoff(0, "600") == 30.0, "clamped, not obeyed indefinitely"
    assert classify._backoff(0, "not-a-number") > 0, "falls back to jitter"


def test_backoff_is_jittered_so_24_workers_do_not_retry_in_lockstep():
    """`time.sleep(2 ** i)` on 24 threads turned one 429 into 24 simultaneous
    retries against an endpoint this project depends on and does not own."""
    delays = {classify._backoff(2) for _ in range(50)}
    assert len(delays) > 40, "backoff is deterministic; the convoy is intact"
    assert all(2.0 <= d <= 6.0 for d in delays), sorted(delays)[:3]


# --------------------------------------------------------------------------
# the frozen corpus (review item 15, last bullet)
# --------------------------------------------------------------------------

def test_corpus_freshness_canary_passes_on_a_current_corpus():
    from rbp import cvelist
    df = pd.DataFrame({"cve_id": ["CVE-1"], "date_published": ["2026-08-21"]})
    assert cvelist.assert_corpus_current(df, today="2026-08-22") == 1


def test_corpus_freshness_canary_catches_a_frozen_corpus():
    """The one check that looks at the data rather than at the plumbing. Every
    other health surface describes the feeds or the reservation endpoint, so all
    of them read green while the corpus is stuck, and a stuck corpus stops closure
    detection entirely: already-published records keep accruing days_public
    against named CNAs."""
    from rbp import cvelist
    df = pd.DataFrame({"cve_id": ["CVE-1"], "date_published": ["2026-07-01"]})
    with pytest.raises(SystemExit) as e:
        cvelist.assert_corpus_current(df, today="2026-08-22")
    msg = str(e.value)
    assert "frozen corpus rather than a quiet period" in msg
    assert "--reindex" in msg, "the error must say what to do"


def test_corpus_canary_tolerates_a_weekend_plus_a_slow_release():
    from rbp import cvelist
    df = pd.DataFrame({"cve_id": ["CVE-1"], "date_published": ["2026-08-19"]})
    assert cvelist.assert_corpus_current(df, today="2026-08-22") == 3


def test_corpus_canary_refuses_a_corpus_with_no_usable_dates():
    from rbp import cvelist
    df = pd.DataFrame({"cve_id": ["CVE-1"], "date_published": [None]})
    with pytest.raises(SystemExit):
        cvelist.assert_corpus_current(df, today="2026-08-22")


def test_a_delta_day_that_contributes_nothing_warns_rather_than_blocking(monkeypatch, tmp_path, capsys):
    """The first version of this fix raised when `wanted` was non-empty and
    `applied` was empty. It false-positived at once, because `_delta_rows` returns
    [] both when the archive layout changed AND when a day genuinely carried no
    records, and refresh_corpus cannot tell those apart. Blocking a publication on
    an ambiguous plumbing signal is the class-2-as-class-1 mistake in PLAN 8b.

    So this warns, and assert_corpus_current does the blocking: it asks the data
    whether it is current instead of asking the fetch loop whether it felt
    successful, which is a question a layout change cannot lie about."""
    from rbp import cvelist

    monkeypatch.setattr(cvelist, "survey_releases",
                        lambda: ("2026-08-22", "http://x.invalid/b.zip",
                                 {"2026-08-21": "u1", "2026-08-22": "u2"}))
    monkeypatch.setattr(cvelist, "apply_deltas",
                        lambda d, w: (pd.DataFrame({"cve_id": ["CVE-1"]}), []))
    monkeypatch.setattr(cvelist, "_read_state",
                        lambda d: {"corpus_date": "2026-08-21",
                                   "schema": cvelist.SCHEMA})
    monkeypatch.setattr(cvelist, "_write_state", lambda d, **kw: None)
    monkeypatch.setattr(cvelist.pd, "read_parquet", lambda p: pd.DataFrame())
    (tmp_path / "corpus.parquet").write_text("x")

    cvelist.refresh_corpus("base.zip", str(tmp_path))   # must not raise
    out = capsys.readouterr().out
    assert "contributed no records" in out
    assert "freshness canary" in out, "the warning must name what will catch it"


def test_the_canary_is_what_actually_stops_a_frozen_corpus():
    """The division of labour: the fetch loop warns, the data check blocks."""
    from rbp import cvelist
    frozen = pd.DataFrame({"cve_id": ["CVE-1"], "date_published": ["2026-06-01"]})
    with pytest.raises(SystemExit):
        cvelist.assert_corpus_current(frozen, today="2026-08-22")


# --------------------------------------------------------------------------
# the silent shrink that actually happened (review item 15, deferred bullet)
# --------------------------------------------------------------------------

def test_the_live_ubuntu_collapse_is_flagged():
    """The real incident, with the real numbers.

    2026-08-21: ubuntu status `truncated`, 3,995 ids, headline 558.
    2026-08-22: ubuntu status `ok`,        1,079 ids, headline 458.

    The status signal IMPROVED while the data got worse, undated rows rose 84 to
    147, and `degraded` was False. This is the exact failure the project calls the
    one direction of error it cannot afford, because a shrinking count reads as the
    CVE Program improving.

    I deferred this guard on the reasoning that it needed per-feed id-set recording
    that did not exist. It did exist: record_feed has carried `rows` all along and
    it reaches summary.json. The work was comparing two numbers."""
    prev = {"ubuntu": {"rows": 3995, "status": "truncated"},
            "debian": {"rows": 17115, "status": "ok"},
            "alas": {"rows": 11369, "status": "ok"}}
    cur = {"ubuntu": {"rows": 1079, "status": "ok"},
           "debian": {"rows": 17328, "status": "ok"},
           "alas": {"rows": 11470, "status": "ok"}}
    found = feeds.compare_magnitudes(prev, cur)
    assert len(found) == 1
    assert "ubuntu" in found[0] and "73% fewer" in found[0]


def test_normal_day_to_day_movement_is_not_flagged():
    """Real figures across the same two runs: debian +1.2%, alas +0.9%. A guard
    that fires on those would be noise and would be ignored within a week."""
    prev = {"debian": {"rows": 17115}, "alas": {"rows": 11369},
            "osv": {"rows": 11651}, "arch": {"rows": 62}}
    cur = {"debian": {"rows": 17328}, "alas": {"rows": 11470},
           "osv": {"rows": 11600}, "arch": {"rows": 60}}
    assert feeds.compare_magnitudes(prev, cur) == []


def test_a_feed_that_grows_is_never_flagged():
    assert feeds.compare_magnitudes({"a": {"rows": 100}}, {"a": {"rows": 500}}) == []


def test_a_first_run_with_no_previous_snapshot_is_not_flagged():
    """Everything looks like a change against nothing."""
    assert feeds.compare_magnitudes({}, {"a": {"rows": 100}}) == []
    assert feeds.compare_magnitudes(None, {"a": {"rows": 100}}) == []


def test_a_new_feed_is_not_flagged():
    """Adding a source must not read as a collapse of a feed that was never there."""
    assert feeds.compare_magnitudes({"a": {"rows": 100}},
                                    {"a": {"rows": 100}, "b": {"rows": 5}}) == []


def test_a_collapsed_sub_fetch_is_caught_even_when_the_parent_looks_flat():
    """THIS TEST ASSERTED THE OPPOSITE until 2026-08-23, and pinned the blindness
    as correct behaviour.

    The old rationale: "osv:npm rolls up to osv. Comparing both double-counts one
    feed and lets a single ecosystem's normal variation trip the guard." The
    first half is true. The second is the wrong trade, and the fixture it was
    written with proves it: npm going 5,000 -> 100 while the osv TOTAL moves
    11,651 -> 11,600 means another ecosystem grew by ~4,850 and masked the
    collapse. That is the silent-shrink signature the whole function exists to
    catch, arriving in the one shape it was told to ignore, on a component
    contributing about a quarter of osv's ids.

    Compared at PART_DROP rather than MAGNITUDE_DROP, so a single noisy
    ecosystem has to clearly collapse rather than merely dip.
    """
    prev = {"osv": {"rows": 11651, "parts": {"npm": {"rows": 5000}}}}
    cur = {"osv": {"rows": 11600, "parts": {"npm": {"rows": 100}}}}
    found = feeds.compare_magnitudes(prev, cur)
    assert found, "a 98% collapse in one ecosystem went unreported"
    assert any("osv:npm" in f for f in found), found
    # The parent is flat and must NOT also be reported, or one failure is two.
    assert not any(f.startswith("osv:") is False and f.startswith("osv") for f in found)


def test_an_ordinary_dip_in_one_sub_fetch_is_not_reported():
    """The old rationale's real concern, kept: one ecosystem is noisier than a
    whole feed, so the part threshold is deliberately looser."""
    prev = {"osv": {"rows": 11651, "parts": {"npm": {"rows": 5000}}}}
    cur = {"osv": {"rows": 11400, "parts": {"npm": {"rows": 3000}}}}
    assert feeds.compare_magnitudes(prev, cur) == []


def test_a_magnitude_drop_marks_the_run_degraded_in_the_cli():
    """Grep-style: the finding has to reach `degraded`, or it is a log line nobody
    reads. Every other health signal on this project was computed and then not
    wired to anything at least once."""
    import pathlib
    from rbp import cli
    src = (pathlib.Path(__file__).parent.parent / "rbp" / "cli.py").read_text()
    assert "compare_magnitudes" in src

    # Behavioural now rather than grep-style. The computation was extracted from
    # cli.run into degraded_state precisely so this could stop being a substring
    # search over source, which passes on code that never runs.
    on, reasons = cli.degraded_state(
        failures=[], truncated=[], capped=[], dropped=0,
        shrunk=["osv: 11,000 -> 400 ids (96% fewer)"], stale=[])
    assert on is True and any("fewer ids" in r for r in reasons), (
        "a magnitude drop does not reach degraded, so no banner renders")


def test_a_configured_cap_alone_does_not_degrade_the_run():
    """The banner was permanent furniture because ubuntu's page cap fires every
    run and was folded into `degraded`. A warning that is always on is not a
    warning."""
    from rbp import cli
    on, reasons = cli.degraded_state(
        failures=[], truncated=[], capped=["ubuntu: hit the 200-page cap"],
        dropped=0, shrunk=[], stale=[])
    assert on is False and reasons == []


def test_every_other_signal_still_degrades_the_run():
    """Excluding caps must not quietly exclude anything else."""
    from rbp import cli
    for kw in ({"failures": ["debian: 500"]}, {"truncated": ["ghsa: reset"]},
               {"dropped": 12},
               {"shrunk": ["osv: fewer"]},
               # A feed that has stopped updating. Added 2026-08-27; without it
               # this loop asserted that four of five signals still degrade.
               {"stale": ["mozilla: newest advisory is 118 days old"]}):
        args = {"failures": [], "truncated": [], "capped": [], "dropped": 0,
                "shrunk": [], "stale": [], **kw}
        on, reasons = cli.degraded_state(**args)
        assert on is True and reasons, kw


# --------------------------------------------------------------------------
# why pagination ended
# --------------------------------------------------------------------------

def test_ubuntu_records_truncation_when_the_year_heuristic_fires(monkeypatch):
    """`if stop: break` exited without setting `capped`, so the else-clause never
    ran and gather stamped `ok`. The heuristic assumes the feed is ordered by
    publish date descending; when it fires, rows beyond that page were not read,
    which is truncation whether or not the assumption held."""
    pages = [
        {"cves": [{"id": "CVE-2026-1", "published": "2026-08-01T00:00:00Z"}]},
        {"cves": [{"id": "CVE-2019-9", "published": "2019-01-01T00:00:00Z"}]},
    ]
    calls = {"n": 0}

    def fake_get(url, timeout=None):
        i = calls["n"]
        calls["n"] += 1
        return (pages[i] if i < len(pages) else {"cves": []}), 200, {}

    monkeypatch.setattr(feeds, "_get", fake_get)
    feeds.feed_ubuntu({2026})
    h = feeds.health_detail().get("ubuntu") or {}
    assert h.get("status") == feeds.TRUNCATED, h
    assert "year heuristic" in (h.get("detail") or "")


def test_ubuntu_does_not_launder_a_404_into_the_end_of_data(monkeypatch):
    """`_get` returns (None, 404, {}) on a retired path or a WAF block, and every
    paginated caller bound `code` and never read it, so a 404 ended pagination
    through the ordinary empty-page branch and was recorded as a healthy feed."""
    monkeypatch.setattr(feeds, "_get", lambda url, timeout=None: (None, 404, {}))
    feeds.feed_ubuntu({2026})
    h = feeds.health_detail().get("ubuntu") or {}
    assert h.get("status") == feeds.TRUNCATED, h
    assert "404" in (h.get("detail") or "")


def test_ubuntu_retries_a_failed_page_before_truncating(monkeypatch):
    """Three consecutive scheduled runs truncated on Ubuntu's API, at offsets 0,
    1280 and 3000, on 503s and a connection reset. `_get` already retried three
    times at 1.5s, 3s and 4.5s, so more of the same was not the answer: 200 back
    to back requests to one host hits load shedding, and shedding needs a longer
    wait than four and a half seconds.

    So the retry is at the PAGINATION level, on top of `_get`'s, and this asserts
    the loop RESUMES rather than that a request eventually succeeds: the defect
    was that one bad page abandoned the whole sweep and threw away every page
    after it.

    Waits are monkeypatched to zero. A test that actually slept 25 seconds to
    prove a retry happened would be removed by the first person in a hurry.
    """
    sleeps = []
    monkeypatch.setattr(feeds.time, "sleep", lambda s: sleeps.append(s))

    pages = [
        {"cves": [{"id": "CVE-2026-1", "published": "2026-08-01T00:00:00Z"}]},
        {"cves": [{"id": "CVE-2026-2", "published": "2026-08-01T00:00:00Z"}]},
        {"cves": []},
    ]
    state = {"n": 0, "failed": False}

    def fake_get(url, timeout=None):
        # Fail the SECOND page once, then serve it. The first page is already in
        # `out`, so a version that abandons the sweep keeps one row and truncates.
        if state["n"] == 1 and not state["failed"]:
            state["failed"] = True
            raise OSError("HTTP Error 503: Service Unavailable")
        page = pages[state["n"]] if state["n"] < len(pages) else {"cves": []}
        state["n"] += 1
        return page, 200, {}

    monkeypatch.setattr(feeds, "_get", fake_get)
    out = feeds.feed_ubuntu({2026})

    assert sleeps, "no wait between attempts; the retry is not backing off"
    ids = sorted(r["cve_id"] for r in out)
    assert ids == ["CVE-2026-1", "CVE-2026-2"], (
        f"the sweep did not resume after the failed page; got {ids}")

    h = feeds.health_detail().get("ubuntu") or {}
    # It completed, so it is NOT truncated. But a feed carried by retries must say
    # so: otherwise the fix looks identical on /status to the fault never having
    # happened, and nobody can tell a healthy endpoint from one being propped up.
    assert h.get("status") != feeds.TRUNCATED, h
    detail = (h.get("detail") or "")
    assert "recovered 1 page(s) on retry" in detail, (
        f"a feed that only completed because it waited did not report it: {h}. "
        "The count is pages RECOVERED, not retries attempted.")


def test_ubuntu_still_truncates_when_a_page_fails_every_attempt(monkeypatch):
    """The other half, and the one that keeps the retry honest. Retrying must not
    turn a genuinely broken endpoint into a silent partial feed: that would be the
    silent-shrink failure this project has already had twice, reintroduced by the
    fix for a loud one."""
    monkeypatch.setattr(feeds.time, "sleep", lambda s: None)

    calls = {"n": 0}

    def always_503(url, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"cves": [{"id": "CVE-2026-1",
                              "published": "2026-08-01T00:00:00Z"}]}, 200, {}
        raise OSError("HTTP Error 503: Service Unavailable")

    monkeypatch.setattr(feeds, "_get", always_503)
    out = feeds.feed_ubuntu({2026})

    assert len(out) == 1, "the rows read before the failure were discarded"
    h = feeds.health_detail().get("ubuntu") or {}
    assert h.get("status") == feeds.TRUNCATED, (
        f"a page that failed every attempt was not reported as truncation: {h}")
    assert "503" in (h.get("detail") or "")
    assert calls["n"] >= 1 + feeds.UBUNTU_PAGE_RETRIES, (
        f"the page was not retried the configured number of times: {calls['n']}")

    # AND IT MUST NOT CLAIM A RECOVERY IT DID NOT MAKE.
    #
    # The first version of this counted retries ATTEMPTED and reported them as
    # pages recovered, so the 2026-08-27 rehearsal produced the line
    # "error at offset 20: HTTP Error 504 ...; recovered 2 page(s) on retry":
    # a claim of success on the same line as the failure that caused it. Nothing
    # was recovered; Ubuntu 503'd twice and then 504'd.
    #
    # That is the defect this function's own docstring exists to warn about -- the
    # health signal improving while the data got worse -- reintroduced by the fix
    # for it, and only visible against a server that really was down.
    detail = (h.get("detail") or "")
    assert "recovered" not in detail, (
        f"a feed that failed every attempt reports a recovery: {detail!r}")
    assert "did not recover" in detail, (
        f"the retry ran and the detail does not say it failed to help: {detail!r}. "
        "A reader has to be able to tell a retry that was never needed from one "
        "that was not enough.")


def test_the_ubuntu_retry_budget_is_bounded(monkeypatch):
    """Ubuntu is already 486s of a 784s gather. A run that retried every page
    would overrun the six-hour cadence while producing a WORSE feed than one that
    gives up and says so, so the retrying is bounded and the reason is recorded as
    the budget rather than as the page simply failing."""
    monkeypatch.setattr(feeds.time, "sleep", lambda s: None)
    monkeypatch.setattr(feeds, "_get",
                        lambda url, timeout=None: (_ for _ in ()).throw(
                            OSError("HTTP Error 503: Service Unavailable")))
    feeds.feed_ubuntu({2026}, retry_budget_s=0)
    h = feeds.health_detail().get("ubuntu") or {}
    assert h.get("status") == feeds.TRUNCATED, h
    assert "budget" in (h.get("detail") or "").lower(), (
        f"the budget cut the retries short and the reason does not say so: {h}")


def test_a_genuine_end_of_data_is_still_recorded_as_healthy(monkeypatch):
    """The guard must not turn every normal run into a degraded one, which is the
    class-2-as-class-1 mistake this project has already made twice."""
    monkeypatch.setattr(feeds, "_get",
                        lambda url, timeout=None: ({"cves": []}, 200, {}))
    feeds.feed_ubuntu({2026})
    assert "ubuntu" not in feeds.health_detail(), (
        "a clean exhaustion recorded a health entry it should not have")


# --------------------------------------------------------------------------
# the adapters have to REPORT their own incompleteness (item 14)
# --------------------------------------------------------------------------

def test_ghsa_records_its_page_cap(monkeypatch):
    """feed_ghsa exhausted `for _ in range(page_cap)` with no record_feed call,
    twelve lines below feed_ubuntu which does exactly that. gather then stamped
    it `ok` with the truncated count, so the live summary read
    {status: "ok", detail: "3321 ids"} on a feed that had stopped reading.

    Worse than a one-off miss: a fixed cap returns a roughly CONSTANT count every
    run, so compare_magnitudes reads stable truncation as a healthy feed. GHSA
    sources roughly 300 of 522 rows."""
    page = [{"cve_id": "CVE-2026-1", "ghsa_id": "GHSA-x", "published_at":
             "2026-08-01T00:00:00Z", "summary": "s"}]

    def fake_get(url, timeout=60, headers=None):
        # Always another page, so the cap is what ends the loop.
        return page, None, {"Link": '<https://api.github.com/next>; rel="next"'}
    monkeypatch.setattr(feeds, "_get", fake_get)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    feeds.feed_ghsa([2026], page_cap=3)
    h = feeds.FEED_HEALTH.get("ghsa")
    assert h, "feed_ghsa recorded no health at all after hitting its cap"
    assert h["status"] == feeds.CAPPED
    assert "3-page cap" in h["detail"]


def test_ghsa_reaching_the_window_is_not_reported_as_incomplete(monkeypatch):
    """The complement, so the previous test cannot be satisfied by recording a
    cap unconditionally."""
    def fake_get(url, timeout=60, headers=None):
        return ([{"cve_id": "CVE-2026-1", "ghsa_id": "GHSA-x",
                  "published_at": "2026-08-01T00:00:00Z", "summary": "s"}],
                None, {})            # no next link: the data ran out
    monkeypatch.setattr(feeds, "_get", fake_get)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    feeds.feed_ghsa([2026], page_cap=40)
    assert "ghsa" not in feeds.FEED_HEALTH, (
        "a feed that read everything must not report itself incomplete")


def test_every_osv_part_records_its_row_count(monkeypatch):
    """record_feed(f"osv:{eco}", ...) never passed rows=, so every part carried
    rows: null and compare_magnitudes could not compare it even once it learned
    to look inside parts. npm alone is about 25% of osv's ids."""
    import io
    import zipfile

    def fake_stream(url):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.json", json.dumps(
                {"id": "GHSA-a", "aliases": ["CVE-2026-1"],
                 "affected": [{"package": {"name": "p", "ecosystem": "npm"}}]}))
        buf.seek(0)
        # feed_osv unlinks the temp path in its finally block, so hand it a real
        # one rather than None.
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        return zipfile.ZipFile(buf), path, 1000

    monkeypatch.setattr(feeds, "_stream_zip", fake_stream)
    monkeypatch.setattr(feeds, "_url_ok", lambda u: True)
    feeds.feed_osv([2026], ecosystems=("npm",))

    part = feeds.FEED_HEALTH.get("osv:npm")
    assert part, "the osv part recorded no health"
    assert isinstance(part["rows"], int), (
        "osv parts carry rows: null, so a collapsed ecosystem is invisible to "
        "compare_magnitudes however carefully it looks")
    assert part["rows"] >= 1


def test_samsung_dates_each_cve_from_its_own_release(monkeypatch):
    """One page carries every SMR back several years, split by "SMR <Mon>-<Year>"
    headings. Taking one date for the whole document would put a 2019 bulletin's
    CVEs on today, which is precisely the clock error review item 10 is about:
    a date that is not the date the thing became public."""
    html = ('<p>SMR Aug-2026</p> CVE-2026-1111, CVE-2026-2222 '
            '<p>SMR Jan-2025</p> CVE-2025-3333')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=60: html)
    rows = {r["cve_id"]: r for r in feeds.feed_samsung([2025, 2026])}
    assert rows["CVE-2026-1111"]["public_date"] == "2026-08-01"
    assert rows["CVE-2026-2222"]["public_date"] == "2026-08-01"
    assert rows["CVE-2025-3333"]["public_date"] == "2025-01-01"
    assert rows["CVE-2025-3333"]["source_ref"] == "SMR-Jan-2025"


def test_samsung_reports_a_changed_page_shape_rather_than_returning_nothing(monkeypatch):
    """The silent-shrink signature. A redesign that drops the SMR headings would
    otherwise return zero rows and be recorded as a healthy feed with nothing to
    report, which is the one error this project says it cannot tolerate."""
    monkeypatch.setattr(feeds, "_get_text",
                        lambda u, timeout=60: "<p>no headings here</p> CVE-2026-1")
    rows = feeds.feed_samsung([2026])
    assert rows == []
    h = feeds.FEED_HEALTH.get("samsung")
    assert h and h["status"] == feeds.TRUNCATED
    assert "page shape changed" in h["detail"]


def test_samsung_is_an_advisory_origin_not_a_tracker():
    """An SMR is a published advisory with its own identifier and release date,
    so it may start the 72-hour clock. A tracker entry may not."""
    from rbp import clock
    assert clock.origin_kind("samsung") == "advisory"


# The independent-origin assertion that used to sit here went with `report._indep`
# on 2026-08-27. It read: samsung + osv must count as TWO origins, because Samsung
# shipping a fix is a separate public event from Google shipping one, unlike OSV
# re-publishing GHSA. Nothing collapses mirrors any more, so there is no count for
# it to be an assertion about, and the concern it protected is now carried by the
# line above: samsung must be classified as an `advisory` rather than a tracker,
# which is what still changes a published field.
# tests/test_pipeline.py::test_no_independent_origin_count_is_computed_or_published
# pins the removal itself.


def test_every_adapter_that_the_gate_depends_on_is_in_the_cron_profile():
    """The gate is measured on the profile the CRON runs, which is condition 1's
    whole point. csaf and msrc were 'deep' only for weeks, on a monthly cadence
    that existed in no cron, so siemens read as an uncovered top-50 CNA while
    already being a configured provider.

    samsung is the CNA that takes top-50 coverage from 39 to 40 and clears the
    gate, so it being absent from `weekly` would leave the gate uncleared with
    the code to clear it sitting in the repo unused."""
    from rbp import cli
    weekly = set(cli.PROFILES["weekly"].split(","))
    for src in ("samsung", "csaf", "msrc", "osv", "ghsa"):
        assert src in weekly, (
            f"{src} is not in the profile the cron runs, so it contributes "
            "nothing to the gate the launch decision reads")
    # And every profile names only real adapters.
    for name, spec in cli.PROFILES.items():
        unknown = set(spec.split(",")) - set(feeds.ADAPTERS)
        assert not unknown, f"profile {name} names non-existent adapters: {unknown}"


# --------------------------------------------------------------------------
# gather must not erase what an adapter recorded (found 2026-08-24)
# --------------------------------------------------------------------------

def test_gather_preserves_a_cap_an_adapter_recorded(monkeypatch):
    """The bug the two tests above could not see, because both call the adapter
    DIRECTLY and the pipeline never does.

    `gather` re-stamped every feed whose recorded status was not in
    `(TRUNCATED, FAILED)`. CAPPED was missing from that tuple, so a cap was
    recorded by the adapter and overwritten with `ok` by its caller in the same
    call chain. `health_summary`'s `capped` list could therefore never be
    non-empty, and `stats["limitations"]`, the field the site publishes to say
    which feeds are read over a shorter window than the trackers, was
    permanently empty. The live 2026-08-20 snapshot reads `ghsa ok 3321 ids`.

    Asserted through `gather`, which is the only place the defect exists.
    """
    monkeypatch.setitem(feeds.ADAPTERS, "fake", lambda years: (
        feeds.record_feed("fake", feeds.CAPPED, "hit the 3-page cap")
        or [{"cve_id": "CVE-2026-1", "source": "fake", "source_ref": "x",
             "public_date": "2026-08-01", "product": "", "description": ""}]))
    feeds.gather(["fake"], {2026})
    h = feeds.FEED_HEALTH.get("fake")
    assert h["status"] == feeds.CAPPED, (
        "gather overwrote the adapter's cap with ok, so the standing limit is "
        "invisible to health_summary and to the site")
    assert h["rows"] == 1, "the row count still has to be filled in"
    _f, _t, _n, capped = feeds.health_summary()
    assert capped and "fake" in capped[0]


def test_gather_still_stamps_a_clean_feed_ok(monkeypatch):
    """The complement, so the fix cannot be satisfied by never stamping at all."""
    monkeypatch.setitem(feeds.ADAPTERS, "fake", lambda years: [
        {"cve_id": "CVE-2026-1", "source": "fake", "source_ref": "x",
         "public_date": "2026-08-01", "product": "", "description": ""}])
    feeds.gather(["fake"], {2026})
    h = feeds.FEED_HEALTH.get("fake")
    assert h["status"] == feeds.OK and h["rows"] == 1


def test_a_cap_is_a_standing_limit_and_not_a_degraded_run():
    """Recorded so the fix above cannot drift into the class-2-as-class-1
    mistake. A configured cap fires by design on every run; folding it into
    `degraded` would put "this run is incomplete" on every page of every run,
    which is furniture rather than a warning."""
    on, _reasons = cli.degraded_state(
        failures=[], truncated=[], capped=["ghsa: hit the 40-page cap"],
        dropped=0, shrunk=[], stale=[])
    assert on is False


# --------------------------------------------------------------------------
# the CSAF fan-out has to report its own providers (found 2026-08-24)
# --------------------------------------------------------------------------

def test_csaf_reports_a_provider_it_could_not_reach(monkeypatch):
    """`feed_csaf` recorded no health at all, and it is the one adapter that fans
    out to more than a dozen third parties.

    Measured on 2026-08-24: Huawei serves provider metadata publicly at the
    well-known path and returns **401 on every advisory directory**, and Cisco
    returns 403 to a non-browser agent. Both read as a healthy feed, because
    `gather` filled in `ok, N ids` from the providers that did work.
    """
    def fake_get(url, timeout=None, retries=3, headers=None):
        raise OSError("HTTP Error 401: Unauthorized")
    monkeypatch.setattr(feeds, "_get", fake_get)
    feeds.feed_csaf({2026}, providers=("https://vendor.example/pm.json",),
                    aggregators=())
    h = feeds.FEED_HEALTH.get("csaf")
    # FAILED, because this fixture has one provider and it could not be read, so
    # the adapter returned nothing at all.
    assert h and h["status"] == feeds.FAILED, h
    assert "unreachable" in h["detail"] and "vendor.example" in h["detail"]


def test_one_unreachable_provider_among_working_ones_is_a_limit_not_a_banner(
        monkeypatch):
    """THE ONE THAT WOULD HAVE SHIPPED A PERMANENT BANNER.

    Cisco's WAF returns 403 to a non-browser agent on every single run. Recording
    that as TRUNCATED puts "This run is incomplete ... not comparable to the
    previous run" on every page of every run, for ever, which is precisely the
    furniture failure cli.degraded_state was written to avoid.

    Caught by simulating the live provider set before merging. The loss is still
    named and still published as a limitation; it is just not a degradation.
    """
    feeds.reset_health()
    feeds._record_csaf_health(providers=["a", "b", "c"],
                              unreachable=["www.cisco.com (403)"],
                              empty=[], capped_dirs=[], fell_back=[], rows=3190)
    h = feeds.FEED_HEALTH["csaf"]
    assert h["status"] == feeds.CAPPED, h
    assert "www.cisco.com" in h["detail"], "the loss is not named"
    failures, truncated, _n, capped = feeds.health_summary()
    assert capped and not truncated and not failures
    on, reasons = cli.degraded_state(failures=failures, truncated=truncated,
                                     capped=capped, dropped=0,
                                     shrunk=[], stale=[])
    assert on is False, (
        f"a standing WAF block is being reported as a degraded run: {reasons}")


def test_a_provider_that_stops_working_is_caught_by_the_shrink_guard():
    """The complement, so the decision above does not amount to ignoring an
    outage. "Worse than usual" is compare_magnitudes' job, keyed on this feed's
    own previous row count, and it IS a degradation."""
    shrunk = feeds.compare_magnitudes(
        {"csaf": {"rows": 3190, "status": feeds.CAPPED}},
        {"csaf": {"rows": 400, "status": feeds.CAPPED}})
    assert shrunk, "a 87% collapse in csaf rows was not reported"
    on, _reasons = cli.degraded_state(failures=[], truncated=[], capped=[],
                                      dropped=0,
                                      shrunk=shrunk, stale=[])
    assert on is True


def _csaf_fixture(monkeypatch, n_dirs, advisories_per_dir):
    """A provider offering `n_dirs` directories, each yielding `advisories_per_dir`
    readable advisories carrying one in-scope CVE."""
    meta = {"distributions": [
        {"directory_url": f"https://v.example/csaf/adv{n}/en"} for n in range(n_dirs)]}
    doc = {"document": {"publisher": {"name": "V Corp"}, "tracking": {"id": "V-1"}},
           "vulnerabilities": [{"cve": "CVE-2026-0001", "title": "t"}]}

    def fake_get(url, timeout=None, retries=3, headers=None):
        return (meta if url.endswith("pm.json") else doc), 200, {}

    monkeypatch.setattr(feeds, "_get", fake_get)
    monkeypatch.setattr(
        feeds, "_csaf_directory_entries",
        lambda durl, years, cap: [(f"2026-01-0{i + 1}T00:00:00Z", f"{durl}/a{i}.json")
                                  for i in range(advisories_per_dir)])


def test_csaf_reports_a_provider_whose_directories_were_capped(monkeypatch):
    """Huawei publishes 121 distributions, one directory per advisory, against a
    cap of 12. The cap is deliberate; selecting an arbitrary tenth of a top-50
    CNA's output and reporting it as a clean read is not."""
    feeds.reset_health()
    _csaf_fixture(monkeypatch, n_dirs=40, advisories_per_dir=1)
    feeds.feed_csaf({2026}, providers=("https://v.example/pm.json",), aggregators=())
    h = feeds.FEED_HEALTH.get("csaf")
    assert h and h["status"] == feeds.CAPPED, h
    assert f"{feeds.CSAF_MAX_DIRS}/40 directories" in h["detail"]


def test_a_cap_over_empty_directories_is_not_published_as_a_loss(monkeypatch):
    """The other half, and the reason the claim moved after the fetch.

    Huawei's 121 directories ALL answer 204 No Content. "capped 12/121" asserted
    that 109 directories of advisories went unread, so a reader chasing the gap
    would find nothing there, because there is nothing there. A standing warning
    naming a loss nobody can find is the furniture failure again, and it costs
    the reader the same trust as a missed one.

    Nothing readable in the directories we did consult is reported as exactly
    that, and it is not dressed up as a cap."""
    feeds.reset_health()
    _csaf_fixture(monkeypatch, n_dirs=40, advisories_per_dir=0)
    feeds.feed_csaf({2026}, providers=("https://v.example/pm.json",), aggregators=())
    h = feeds.FEED_HEALTH.get("csaf")
    assert "capped" not in h["detail"], (
        f"a cap over directories that hold nothing is not a loss: {h['detail']}")
    assert "no advisories in scope: v.example" in h["detail"]
    assert h["status"] == feeds.OK, h


def test_csaf_names_providers_that_yielded_nothing(monkeypatch):
    """FEEDS.md recorded that SUSE, Huawei and www.sick.com each returned zero
    advisories in scope, and that "the provider list has never been validated
    against what it actually yields". This is that validation, on every run,
    rather than once in a document."""
    monkeypatch.setattr(feeds, "_get",
                        lambda url, timeout=None, retries=3, headers=None: (
                            {"distributions": []}, 200, {}))
    feeds.feed_csaf({2026}, providers=("https://quiet.example/pm.json",),
                    aggregators=())
    h = feeds.FEED_HEALTH.get("csaf")
    assert h and "no advisories in scope: quiet.example" in h["detail"]
    assert h["status"] == feeds.OK, (
        "a provider with nothing to say is not an incomplete read; overstating "
        "that is how a banner becomes furniture")


def test_a_provider_whose_advisories_another_provider_already_gave_us_is_not_empty(
        monkeypatch):
    """`empty` used to be computed from rows GAINED, measured against a `seen`
    set shared across every provider in the run.

    So a provider whose advisories an earlier provider had already contributed
    scored zero and was published as "no advisories in scope". www.sick.com is
    sick.com after a 301, the same host reached twice, and the second pass was
    reported to readers as a vendor with nothing to say. Corroboration is the
    thing this site is built to measure; counting it as silence is backwards."""
    feeds.reset_health()
    meta = {"distributions": [{"directory_url": "https://v.example/csaf"}]}
    doc = {"document": {"publisher": {"name": "V Corp"}, "tracking": {"id": "V-1"}},
           "vulnerabilities": [{"cve": "CVE-2026-0001", "title": "t"}]}

    def fake_get(url, timeout=None, retries=3, headers=None):
        return (meta if url.endswith("pm.json") else doc), 200, {}

    monkeypatch.setattr(feeds, "_get", fake_get)
    monkeypatch.setattr(feeds, "_csaf_directory_entries",
                        lambda durl, years, cap: [("2026-01-01T00:00:00Z",
                                                   f"{durl}/a.json")])
    # Two hosts publishing the SAME advisory. The second gains nothing new.
    feeds.feed_csaf({2026}, aggregators=(),
                    providers=("https://first.example/pm.json",
                               "https://second.example/pm.json"))
    h = feeds.FEED_HEALTH.get("csaf")
    assert "no advisories in scope" not in h["detail"], (
        f"a corroborating provider was reported as empty: {h['detail']}")
    assert h["status"] == feeds.OK, h


# --------------------------------------------------------------------------
# a provider we can only reach by the side door (found 2026-08-26)
# --------------------------------------------------------------------------

def test_cisa_is_read_through_its_pinned_feeds_when_the_canonical_host_403s(
        monkeypatch):
    """www.cisa.gov answers 403 to the GitHub Actions runners and 200 to a
    developer laptop, same User-Agent, same code. No header change reaches it.

    Its metadata designates ROLIE feeds in CISA's own GitHub organisation, which
    the runners DO reach, so the advisories are all still readable. Recording
    CISA as unreachable while holding every one of its advisories would be a
    false claim in the more embarrassing direction."""
    feeds.reset_health()
    cisa = "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json"
    assert cisa in feeds.CSAF_METADATA_FALLBACK
    rolie = {"feed": {"entry": [{"updated": "2026-08-25T00:00:00Z",
                                 "link": [{"rel": "self",
                                           "href": "https://raw.githubusercontent.invalid/a.json"}]}]}}
    doc = {"document": {"publisher": {"name": "CISA"}, "tracking": {"id": "ICSA-26-1"}},
           "vulnerabilities": [{"cve": "CVE-2026-0001", "title": "t"}]}

    def fake_get(url, timeout=None, retries=3, headers=None):
        if url == cisa:
            raise OSError("HTTP Error 403: Forbidden")
        return (rolie if url.endswith("tlp-white.json") else doc), 200, {}

    monkeypatch.setattr(feeds, "_get", fake_get)
    rows = feeds.feed_csaf({2026}, providers=(cisa,), aggregators=())
    assert [r["cve_id"] for r in rows] == ["CVE-2026-0001"], rows

    h = feeds.FEED_HEALTH["csaf"]
    assert "unreachable" not in h["detail"], (
        f"a provider we read in full was reported as lost: {h['detail']}")
    assert "read via pinned feeds: www.cisa.gov" in h["detail"], (
        "pinned config that does not announce itself is how a stale URL rots "
        "unnoticed")
    assert h["status"] == feeds.OK, (
        "the advisories were all read; a complete read is not a degraded one")


def test_a_healthy_adapters_own_account_of_itself_survives_gather(monkeypatch):
    """FOUND BY READING THE PUBLISHED ARTEFACT OF A GREEN RUN, NOT THE LOG.

    `gather` kept an adapter's health detail only when the STATUS was bad news,
    and replaced it with "<n> ids" otherwise. `feed_csaf` records OK with a
    detail naming which of its 17 providers were read, which had nothing to say,
    and which were reached by a route other than the one in the config. On any
    run where nothing went wrong, all of that was overwritten.

    So the CISA pinned-feed disclosure reached the build log and no page. A
    disclosure that survives only when the run is also degraded is not one."""
    feeds.reset_health()
    def fake_feed(years):
        feeds.record_feed("csaf", feeds.OK,
                          "17/17 providers read; read via pinned feeds: www.cisa.gov",
                          rows=2)
        return [{"cve_id": "CVE-2026-0001", "source": "csaf", "source_ref": "a\tb\tc",
                 "public_date": "2026-01-01", "product": "", "description": ""}]

    monkeypatch.setitem(feeds.ADAPTERS, "csaf", fake_feed)
    feeds.gather(["csaf"], {2026})
    h = feeds.FEED_HEALTH["csaf"]
    assert "read via pinned feeds: www.cisa.gov" in h["detail"], (
        f"the adapter's account of itself was discarded by gather: {h['detail']}")
    assert h["rows"] == 1, "the row count still has to be the one gather counted"


def test_a_provider_with_no_pinned_fallback_is_still_reported_unreachable(
        monkeypatch):
    """The fallback must not become a blanket excuse for a 403."""
    feeds.reset_health()

    def fake_get(url, timeout=None, retries=3, headers=None):
        raise OSError("HTTP Error 403: Forbidden")

    monkeypatch.setattr(feeds, "_get", fake_get)
    feeds.feed_csaf({2026}, providers=("https://nofallback.example/pm.json",),
                    aggregators=())
    h = feeds.FEED_HEALTH["csaf"]
    assert "unreachable" in h["detail"] and "nofallback.example" in h["detail"]
    assert h["status"] == feeds.FAILED, h


def test_the_directory_count_is_taken_before_the_cap_and_the_language_filter():
    """"12 of 121" and "12" are different claims: one is a limit, the other is a
    loss. The count has to be of what the provider OFFERS."""
    meta = {"distributions": [{"directory_url": "https://v.example/a/en"},
                              {"directory_url": "https://v.example/a/zh"},
                              {"directory_url": "https://v.example/b/en"}]}
    assert feeds._csaf_directory_count(meta) == 3
    assert len(feeds._csaf_directories(meta, max_dirs=12)) == 2


# --------------------------------------------------------------------------
# Round 7 B5: seventeen CSAF providers behind one number
# --------------------------------------------------------------------------

def _csaf_meta(host, feed_url):
    return {"distributions": [{"rolie": {"feeds": [{"url": feed_url}]}}]}


def _run_csaf(monkeypatch, providers, rows_per_host, unreachable=()):
    """Drive feed_csaf over fake providers. `rows_per_host` maps host -> CVE ids."""
    def fake_get(url, timeout=90, retries=3, headers=None):
        host = url.split("/")[2]
        if host in unreachable:
            raise RuntimeError("HTTP Error 403: Forbidden")
        if url.endswith("provider-metadata.json"):
            return _csaf_meta(host, f"https://{host}/rolie.json"), 200, {}
        if url.endswith("rolie.json"):
            return {"feed": {"entry": [
                {"updated": "2026-08-01",
                 "link": [{"rel": "self", "href": f"https://{host}/a{i}.json"}]}
                for i, _ in enumerate(rows_per_host.get(host, []))]}}, 200, {}
        i = int(url.rsplit("/a", 1)[1].split(".")[0])
        cid = rows_per_host[host][i]
        return ({"document": {"publisher": {"name": host}, "title": "t",
                              "tracking": {"id": "T-1",
                                           "initial_release_date": "2026-08-01"}},
                 "vulnerabilities": [{"cve": cid, "title": "v"}]}, 200, {})

    monkeypatch.setattr(feeds, "_get", fake_get)
    monkeypatch.setattr(feeds, "_get_text",
                        lambda u, timeout=90: (_ for _ in ()).throw(RuntimeError("no dir")))
    return feeds.feed_csaf([2026], providers=providers, aggregators=(), workers=1)


def test_each_csaf_provider_records_its_own_row_count(monkeypatch):
    """Seventeen providers shared ONE `rows` number, so `compare_magnitudes`
    could not see a provider go dark.

    This is the SUSE failure's shape. SUSE dropped 14,486 in-scope advisories,
    the aggregate absorbed it, and the health line published the loss as a fact
    about SUSE. `feed_osv` has recorded per-ecosystem parts all along; this
    adapter fans out to more third parties than any other and recorded none.
    """
    providers = ("https://a.example/provider-metadata.json",
                 "https://b.example/provider-metadata.json")
    _run_csaf(monkeypatch, providers,
              {"a.example": ["CVE-2026-1", "CVE-2026-2"], "b.example": ["CVE-2026-3"]})

    assert feeds.FEED_HEALTH.get("csaf:a.example", {}).get("rows") == 2
    assert feeds.FEED_HEALTH.get("csaf:b.example", {}).get("rows") == 1
    # And they nest under the parent, so the top-level attempt count still means
    # one FEED rather than one sub-fetch.
    detail = feeds.health_detail()
    assert set(detail["csaf"]["parts"]) == {"a.example", "b.example"}
    assert "csaf:a.example" not in detail


def test_one_csaf_provider_going_dark_is_caught_while_the_aggregate_looks_normal():
    """The mutation test. With per-provider parts the collapse is reported; with
    the single aggregate record this adapter used to write, it is not.

    The numbers are csaf's real published totals: it swung 3,296 -> 3,202 ->
    3,938 -> 2,213 -> 2,695 across five runs, so a provider holding under 40% of
    the total can stop forever inside that noise.
    """
    prev = {"csaf": {"rows": 3938, "parts": {"suse.com": {"rows": 1700},
                                             "siemens.com": {"rows": 2238}}}}
    cur = {"csaf": {"rows": 3200, "parts": {"suse.com": {"rows": 0},
                                            "siemens.com": {"rows": 3200}}}}
    found = feeds.compare_magnitudes(prev, cur)
    assert any("csaf:suse.com" in f for f in found), (
        "a provider that stopped entirely was invisible: " + repr(found))

    # THE MUTATION: strip the parts, which is exactly the record this adapter
    # wrote before round 7. The aggregate moved 3,938 -> 3,200, an 19% dip, well
    # inside MAGNITUDE_DROP, so nothing fires.
    assert feeds.compare_magnitudes({"csaf": {"rows": 3938}},
                                    {"csaf": {"rows": 3200}}) == [], (
        "the fixture no longer demonstrates the blindness it exists to prove")


def test_an_unreachable_csaf_provider_never_escalates_the_parent(monkeypatch):
    """The coupling this project cannot see from either function alone.

    `health_detail` escalates a parent whose parts degraded, but ONLY when the
    parent is still OK. `_record_csaf_health` sets the parent to FAILED or CAPPED
    whenever anything was unreachable. If either side changes, an unreachable
    provider starts escalating csaf and the site wears a banner forever, because
    Cisco's edge 403s on every single run.
    """
    providers = ("https://a.example/provider-metadata.json",
                 "https://gone.example/provider-metadata.json")
    _run_csaf(monkeypatch, providers, {"a.example": ["CVE-2026-1"]},
              unreachable={"gone.example"})

    part = feeds.FEED_HEALTH["csaf:gone.example"]
    assert part["status"] == feeds.CAPPED, (
        "an unreachable provider recorded FAILED reaches health_summary's "
        "failures list, and degraded_state turns any failure into a degradation")
    detail = feeds.health_detail()
    assert detail["csaf"]["status"] == feeds.CAPPED
    assert not detail["csaf"]["ok"]


def test_a_provider_that_goes_from_healthy_to_unreachable_is_still_compared(monkeypatch):
    """The defect the coupling test found by accident.

    The unreachable branch `continue`s before the bottom of the loop, so the
    first version of the per-provider records gave no part at all to a provider
    that had gone dark. `compare_magnitudes` iterates the CURRENT parts, so a
    part that vanishes is compared against nothing: a provider going from 500
    rows to unreachable would have been invisible to the guard these records
    exist to feed. Which is the original bug, reintroduced by its own fix.
    """
    providers = ("https://a.example/provider-metadata.json",
                 "https://gone.example/provider-metadata.json")
    _run_csaf(monkeypatch, providers, {"a.example": ["CVE-2026-1"]},
              unreachable={"gone.example"})
    cur = feeds.health_detail()
    assert "gone.example" in cur["csaf"]["parts"], (
        "an unreachable provider recorded no part, so it cannot be compared")

    prev = {"csaf": {"rows": 501, "parts": {"a.example": {"rows": 1},
                                            "gone.example": {"rows": 500}}}}
    found = feeds.compare_magnitudes(prev, cur)
    assert any("gone.example" in f for f in found), found


def test_a_permanently_unreachable_csaf_provider_does_not_degrade_the_run(monkeypatch):
    """The banner argument, end to end. Cisco 403s every run; if that made the
    run degraded, `degraded` would be permanently true and a consumer could not
    branch on it at all."""
    providers = ("https://a.example/provider-metadata.json",
                 "https://gone.example/provider-metadata.json")
    _run_csaf(monkeypatch, providers, {"a.example": ["CVE-2026-1"]},
              unreachable={"gone.example"})
    failures, truncated, _attempts, capped = feeds.health_summary()
    assert failures == [], failures
    assert truncated == [], truncated
    on, reasons = cli.degraded_state(failures=failures, truncated=truncated,
                                     capped=capped, dropped=0, shrunk=[], stale=[])
    assert on is False, reasons
    # It is still published, by name, as a standing limitation.
    assert any("gone.example" in c for c in capped), capped


# --------------------------------------------------------------------------
# Round 7 B4: ids fetched is not rows published
# --------------------------------------------------------------------------

def test_a_feed_with_thousands_of_ids_and_no_published_rows_is_visible():
    """`mozilla` returned 607 ids per run and `arch` 62, on every run since they
    merged, and neither appeared in ANY of the 1,709 published rows. `/status`
    rendered them beside csaf's 2,695 with nothing to tell them apart, and csaf
    is the only source for 22 rows while those two are the only source for none.
    """
    rows = [{"sources": "ghsa-repos"}, {"sources": "ghsa-repos,osv"},
            {"sources": "csaf"}]
    detail = {"ghsa-repos": {"rows": 9861}, "osv": {"rows": 12434},
              "csaf": {"rows": 2695}, "mozilla": {"rows": 607}, "arch": {"rows": 62}}
    feeds.merge_contribution(detail, rows)

    assert detail["mozilla"]["rows_published"] == 0
    assert detail["arch"]["rows_published"] == 0
    # An explicit zero, not a missing key. A blank renders as "not measured",
    # which is the opposite claim.
    assert detail["arch"]["rows_only"] == 0
    assert "rows_published" in detail["arch"]


def test_only_source_counts_what_disappears_if_the_feed_does():
    """`touched` cannot answer it. Four distro feeds touch 196 rows between them
    and are the sole source for 132, because they mostly corroborate each other;
    ghsa-repos touches 1,188 and is the sole source for 1,015."""
    rows = [{"sources": "a"}, {"sources": "a,b"}, {"sources": "b,c"}, {"sources": "c"}]
    assert feeds.rows_by_source(rows) == {"a": (2, 1), "b": (2, 0), "c": (2, 1)}


def test_contribution_survives_a_row_with_no_sources():
    """Defensive: an empty source string must not create a feed named "".
    `classify` comma-joins a set, and a set can be empty."""
    assert feeds.rows_by_source([{"sources": ""}, {}]) == {}


def test_every_published_source_name_is_a_feed_the_run_reports_health_for():
    """The two halves of `summary.feeds` must describe the same feed set.

    A source string appearing in a published row that has no health entry means
    a row is evidenced by something the run never accounted for, and a health
    entry with no rows is B4's finding. Both are worth failing on.
    """
    rows = [{"sources": "ghsa"}, {"sources": "ghsa,osv"}]
    detail = {"ghsa": {"rows": 1}, "osv": {"rows": 1}, "arch": {"rows": 62}}
    feeds.merge_contribution(detail, rows)
    published = set(feeds.rows_by_source(rows))
    assert published <= set(detail), published - set(detail)


# --------------------------------------------------------------------------
# Round 7 B3 and H1: how far a feed reached, and how recently
# --------------------------------------------------------------------------

def test_the_ubuntu_cap_is_stated_in_days_not_pages():
    """The line this replaces read "hit the 200-page cap; rows beyond it were not
    read", which would have read identically whether the cap cost one day or
    three years. Measured live 2026-08-27: it costs all but 38 days of a
    three-year window, and reads 4,000 of 75,993 records."""
    rows = [{"public_date": "2026-07-20"}, {"public_date": "2026-08-26"}]
    line = feeds._ubuntu_reach(200, 20, 75993, rows, {2024, 2025, 2026})
    assert "4,000" in line and "75,993" in line and "5.3%" in line
    assert "2026-07-20" in line and "37-day" in line
    assert "2024-01-01" in line


def test_the_ubuntu_reach_line_survives_a_run_with_no_dated_rows():
    """It is a health string on the degraded path; it must not raise."""
    line = feeds._ubuntu_reach(200, 20, None, [{"public_date": ""}], {2024})
    assert "200-page cap" in line and "not read" in line


def test_gather_records_how_recent_each_feed_is(monkeypatch):
    """A feed frozen at a constant is invisible to `compare_magnitudes`, which
    only ever asks whether a number went DOWN.

    `mozilla` returned exactly 607 on six consecutive published snapshots, `arch`
    exactly 62, `samsung` exactly 420 on five. Had any of them stopped updating
    on day one, every guard on this site would still have been green. The row
    count cannot see it; the newest date can.
    """
    monkeypatch.setattr(feeds, "ADAPTERS", {
        "fresh": lambda years: [
            {"cve_id": "CVE-2026-1", "source": "fresh", "source_ref": "r",
             "public_date": "2026-08-26", "product": "", "description": ""},
            {"cve_id": "CVE-2026-2", "source": "fresh", "source_ref": "r",
             "public_date": "2026-01-02", "product": "", "description": ""}],
        "undated": lambda years: [
            {"cve_id": "CVE-2026-3", "source": "undated", "source_ref": "r",
             "public_date": "", "product": "", "description": ""}],
    })
    feeds.gather(["fresh", "undated"], {2026})

    assert feeds.FEED_HEALTH["fresh"]["newest"] == "2026-08-26"
    assert feeds.FEED_HEALTH["fresh"]["oldest"] == "2026-01-02"
    assert feeds.FEED_HEALTH["fresh"]["dated_rows"] == 2
    # An undated feed reports zero dated rows rather than a missing key, so
    # "cannot be checked" is distinguishable from "was not looked at". `arch`
    # publishes no dates at all and is exactly this case.
    assert feeds.FEED_HEALTH["undated"]["newest"] == ""
    assert feeds.FEED_HEALTH["undated"]["dated_rows"] == 0


# --------------------------------------------------------------------------
# Round 7 H1: a frozen feed returns a perfect row count for ever
# --------------------------------------------------------------------------

def test_a_feed_that_stopped_updating_is_caught_on_dates_not_counts():
    """The failure `compare_magnitudes` is structurally blind to.

    It only ever asks whether a number went DOWN. A feed that silently stopped
    returns the SAME number every run, for ever, which reads as perfect health.
    `mozilla` returned exactly 607 ids on six consecutive published snapshots,
    `arch` exactly 62, `samsung` exactly 420 on five.
    """
    detail = {"mozilla": {"newest": "2026-05-01", "dated_rows": 607, "rows": 607}}
    stale, unmeasurable = feeds.stale_feeds(detail, today="2026-08-27")
    assert len(stale) == 1 and "mozilla" in stale[0], stale
    assert "118 days old" in stale[0]
    assert unmeasurable == []

    # And the count is unchanged across those runs, which is the whole point:
    # the guard that reads counts sees nothing wrong.
    assert feeds.compare_magnitudes({"mozilla": {"rows": 607}},
                                    {"mozilla": {"rows": 607}}) == []


def test_the_floor_clears_every_real_feed_cadence():
    """45 days is derived from the feeds' own measured cadences, not picked.

    Newest advisory per feed over the 2026-08-27 baseline. Samsung's monthly SMR
    is the slowest genuine cadence at 26 days, and its worst legitimate case is
    about 35 just before the next bulletin. A floor that flagged any of these
    would be furniture inside a week.
    """
    measured = {"csaf": "2026-08-27", "ghsa": "2026-08-27",
                "ghsa-repos": "2026-08-27", "osv": "2026-08-27",
                "redhat": "2026-08-27", "ubuntu": "2026-08-27",
                "alas": "2026-08-26", "mozilla": "2026-08-18",
                "msrc": "2026-08-11", "samsung": "2026-08-01"}
    detail = {n: {"newest": d, "dated_rows": 10} for n, d in measured.items()}
    stale, _ = feeds.stale_feeds(detail, today="2026-08-27")
    assert stale == [], f"the floor flags a healthy feed: {stale}"

    # Samsung at its worst legitimate age still clears.
    late = {"samsung": {"newest": "2026-07-23", "dated_rows": 420}}
    assert feeds.stale_feeds(late, today="2026-08-27")[0] == []


def test_a_feed_with_no_dates_is_unmeasurable_not_fine():
    """`alpine`, `arch` and `debian` return no dates at all, so no threshold can
    check them. Silently skipping them lets "cannot be checked" read as "checked
    and fine", which is the same error as letting a page cap read as a complete
    read."""
    detail = {"debian": {"newest": "", "dated_rows": 0, "rows": 17909}}
    stale, unmeasurable = feeds.stale_feeds(detail, today="2026-08-27")
    assert stale == []
    assert len(unmeasurable) == 1 and "debian" in unmeasurable[0]


def test_staleness_degrades_the_run_and_unmeasurable_does_not():
    """A dead feed makes this run's counts a lower floor than usual and stays
    loud until fixed, which is not the same as a cap that fires by design."""
    on, reasons = cli.degraded_state(
        failures=[], truncated=[], capped=[], dropped=0, shrunk=[],
        stale=["mozilla: newest advisory is 2026-05-01, 118 days old"])
    assert on is True
    assert any("stopped returning recent advisories" in r for r in reasons), reasons

    off, _ = cli.degraded_state(failures=[], truncated=[], capped=[], dropped=0,
                                shrunk=[], stale=[])
    assert off is False


def test_a_csaf_provider_part_is_not_freshness_checked_on_its_own():
    """Parts have no dates of their own; the parent carries them. Checking a part
    would report every provider as unmeasurable on every run, which is furniture."""
    detail = {"csaf": {"newest": "2026-08-27", "dated_rows": 2992},
              "csaf:www.cisco.com": {"newest": "", "dated_rows": 0}}
    stale, unmeasurable = feeds.stale_feeds(detail, today="2026-08-27")
    assert stale == [] and unmeasurable == []


def test_osv_can_fetch_an_ecosystem_whose_name_contains_a_space(monkeypatch):
    """Five of OSV's 46 ecosystem names contain a space: "GitHub Actions",
    "Red Hat", "Rocky Linux", "Azure Linux", "BellSoft Hardened Containers".

    Unquoted, the URL raises `URL can't contain control characters` before any
    request is made, so the adapter could not fetch any of them and would record
    each as a hard FAILED. Latent because none was configured, and found by
    trying to merge them rather than by reading the code.

    It matters beyond the five: FEEDS.md's 2026-08-22 measurement that scored the
    unmerged ecosystems at +0 CNAs was a full-text probe over the archives, not
    this adapter, which is the same probe-and-adapter-disagree gap that made the
    GIT estimate wrong by its entire value.
    """
    seen = []

    def fake_url_ok(u):
        seen.append(u)
        return False        # stop before the download; the URL is the assertion

    monkeypatch.setattr(feeds, "_url_ok", fake_url_ok)
    feeds.feed_osv([2026], ecosystems=("GitHub Actions", "Red Hat"))

    assert seen, "the adapter never built a URL"
    assert all(" " not in u for u in seen), seen
    assert any("GitHub%20Actions" in u for u in seen), seen
    assert any("Red%20Hat" in u for u in seen), seen
