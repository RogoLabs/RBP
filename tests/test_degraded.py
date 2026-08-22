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
    failures, truncated, attempts = feeds.health_summary()
    assert len(failures) == 1 and "debian" in failures[0]
    assert len(truncated) == 1 and "ubuntu" in truncated[0]
    assert attempts == 3


def test_a_truncated_only_run_is_still_degraded():
    """The live case. Ubuntu truncates every run, so this is the state the site is
    actually in, and `if failures:` reported it as clean."""
    feeds.record_feed("ubuntu", feeds.TRUNCATED, "hit the 200-page cap")
    failures, truncated, _ = feeds.health_summary()
    assert failures == []
    assert truncated, "a truncated run must be visible to the caller"
    assert bool(failures or truncated) is True


def test_a_fully_clean_run_is_not_degraded():
    feeds.record_feed("alpine", feeds.OK, "40 ids", rows=40)
    failures, truncated, _ = feeds.health_summary()
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
