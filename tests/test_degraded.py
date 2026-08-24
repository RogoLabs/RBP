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
        reports_unreadable=False, shrunk=["osv: 11,000 -> 400 ids (96% fewer)"])
    assert on is True and any("fewer ids" in r for r in reasons), (
        "a magnitude drop does not reach degraded, so no banner renders")


def test_a_configured_cap_alone_does_not_degrade_the_run():
    """The banner was permanent furniture because ubuntu's page cap fires every
    run and was folded into `degraded`. A warning that is always on is not a
    warning."""
    from rbp import cli
    on, reasons = cli.degraded_state(
        failures=[], truncated=[], capped=["ubuntu: hit the 200-page cap"],
        dropped=0, reports_unreadable=False, shrunk=[])
    assert on is False and reasons == []


def test_every_other_signal_still_degrades_the_run():
    """Excluding caps must not quietly exclude anything else."""
    from rbp import cli
    for kw in ({"failures": ["debian: 500"]}, {"truncated": ["ghsa: reset"]},
               {"dropped": 12}, {"reports_unreadable": True},
               {"shrunk": ["osv: fewer"]}):
        args = {"failures": [], "truncated": [], "capped": [], "dropped": 0,
                "reports_unreadable": False, "shrunk": [], **kw}
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


def test_samsung_corroborates_google_rather_than_mirroring_it():
    """Most Samsung CVEs are Google's, applied from the Android bulletin, and
    OSV carries those too. They must count as TWO independent origins: Samsung
    shipping a fix is a separate public event from Google shipping one, unlike
    OSV re-publishing GHSA, which is one event twice."""
    from rbp.report import _indep
    assert _indep("samsung,osv") == 2
    assert _indep("osv,ghsa") == 1, "the mirror collapse must still hold"


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
        dropped=0, reports_unreadable=False, shrunk=[])
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
                              empty=[], capped_dirs=[], rows=3190)
    h = feeds.FEED_HEALTH["csaf"]
    assert h["status"] == feeds.CAPPED, h
    assert "www.cisco.com" in h["detail"], "the loss is not named"
    failures, truncated, _n, capped = feeds.health_summary()
    assert capped and not truncated and not failures
    on, reasons = cli.degraded_state(failures=failures, truncated=truncated,
                                     capped=capped, dropped=0,
                                     reports_unreadable=False, shrunk=[])
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
                                      dropped=0, reports_unreadable=False,
                                      shrunk=shrunk)
    assert on is True


def test_csaf_reports_a_provider_whose_directories_were_capped(monkeypatch):
    """Huawei publishes 121 distributions, one directory per advisory, against a
    cap of 12. The cap is deliberate; selecting an arbitrary tenth of a top-50
    CNA's output and reporting it as a clean read is not."""
    meta = {"distributions": [
        {"directory_url": f"https://v.example/csaf/adv{n}/en"} for n in range(40)]}
    monkeypatch.setattr(feeds, "_get",
                        lambda url, timeout=None, retries=3, headers=None: (meta, 200, {}))
    monkeypatch.setattr(feeds, "_csaf_directory_entries",
                        lambda durl, years, cap: [])
    feeds.feed_csaf({2026}, providers=("https://v.example/pm.json",), aggregators=())
    h = feeds.FEED_HEALTH.get("csaf")
    assert h and h["status"] == feeds.CAPPED, h
    assert f"{feeds.CSAF_MAX_DIRS}/40 directories" in h["detail"]


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


def test_the_directory_count_is_taken_before_the_cap_and_the_language_filter():
    """"12 of 121" and "12" are different claims: one is a limit, the other is a
    loss. The count has to be of what the provider OFFERS."""
    meta = {"distributions": [{"directory_url": "https://v.example/a/en"},
                              {"directory_url": "https://v.example/a/zh"},
                              {"directory_url": "https://v.example/b/en"}]}
    assert feeds._csaf_directory_count(meta) == 3
    assert len(feeds._csaf_directories(meta, max_dirs=12)) == 2
