"""FEEDS.md section 3's three guards, built 2026-09-07.

The plan said three guards had to exist before feed 10, not after feed 30, and
named the failure each one is for:

  1. a NEW feed has no shrink baseline, and if its first run is the bad one it
     has none for ever, because `was <= 0` skips it on every later run too;
  2. a failure is COUNTED where it should be WEIGHED: three feeds failing out
     of forty is a rounding error in the log and a hole in coverage;
  3. `gather` was a serial loop, and parallelising it must not disturb per-feed
     health recording, because that recording is guard 1's input.

Every test here drives the function the defect lives in. The gather tests use
a barrier rather than a timer where they can, so "concurrent" is proved by two
adapters each waiting for the other to start, which no serial loop can pass.
"""
from __future__ import annotations

import inspect
import json
import re
import threading
import time

import pandas as pd
import pytest

from rbp import cli, coverage, feeds


def _row(cid, src, date="2026-08-01", product=""):
    return {"cve_id": cid, "source": src, "source_ref": "r", "public_date": date,
            "product": product, "description": ""}


# --------------------------------------------------------------------------
# 1. the shrink baseline survives the profile change
# --------------------------------------------------------------------------

def test_a_new_feeds_first_run_is_compared_against_its_scorecard():
    """The card said 5,000 ids; the first run in the profile returned 40. Without
    the seed this is a feed with nothing to compare against, and 40 is the
    baseline from then on."""
    seeds = {"new": {"rows": 5000, "scored_at": "2026-09-01"}}
    found = feeds.compare_magnitudes({}, {"new": {"rows": 40}}, seeds=seeds)
    assert len(found) == 1 and found[0].startswith("new: 5,000 -> 40 ids"), found
    assert "scorecard" in found[0] and "2026-09-01" in found[0], found


def test_a_new_feed_matching_its_scorecard_is_not_flagged():
    seeds = {"new": {"rows": 5000, "scored_at": "2026-09-01"}}
    assert feeds.compare_magnitudes({}, {"new": {"rows": 4900}}, seeds=seeds) == []


def test_a_previous_run_outranks_the_scorecard():
    """The card is one measurement and may sit above what the profile reads:
    csaf's is 42,659 against a live 63,184, and a card scored uncapped would sit
    above every capped run. It stands in for a baseline; it is not a floor."""
    seeds = {"a": {"rows": 100000, "scored_at": "2026-09-01"}}
    assert feeds.compare_magnitudes({"a": {"rows": 100}}, {"a": {"rows": 95}},
                                    seeds=seeds) == []


def test_a_feed_that_failed_last_run_falls_back_to_its_scorecard():
    """THE EXEMPT-FOR-EVER CASE. Run one failed and recorded rows=None; run two
    returned 40 while reporting itself healthy. `was <= 0` skipped the
    comparison, and 40 became the baseline every later run was measured against."""
    seeds = {"new": {"rows": 5000, "scored_at": "2026-09-01"}}
    prev = {"new": {"rows": None, "status": "failed"}}
    found = feeds.compare_magnitudes(prev, {"new": {"rows": 40, "status": "ok"}},
                                     seeds=seeds)
    assert found and "new: 5,000 -> 40" in found[0], found


def test_without_a_seed_the_old_blindness_is_unchanged():
    """So the tests above are testing the seed and not a change to `_cmp`."""
    prev = {"new": {"rows": None}}
    assert feeds.compare_magnitudes(prev, {"new": {"rows": 40}}) == []
    assert feeds.compare_magnitudes(prev, {"new": {"rows": 40}}, seeds={}) == []


def test_scorecard_baselines_read_only_cards_that_measured_something(tmp_path):
    (tmp_path / "good.json").write_text(json.dumps(
        {"ids": 1234, "scored_at": "2026-09-06T01:00:00+00:00", "years": [2025, 2026]}))
    (tmp_path / "zero.json").write_text(json.dumps({"ids": 0}))
    (tmp_path / "broken.json").write_text("{")
    seeds = feeds.scorecard_baselines(["good", "zero", "broken", "absent"],
                                      lab=str(tmp_path))
    assert seeds == {"good": {"rows": 1234, "scored_at": "2026-09-06",
                              "years": [2025, 2026]}}


@pytest.mark.harness_artefact
def test_every_feed_in_the_running_profile_has_a_seed():
    """Otherwise a new feed's first run is exactly as blind as before. This reads
    the committed cards, so a feed added to the profile without its card, which
    FEEDS.md section 3 already forbids, fails here as well.

    Marked like `test_every_feed_in_the_running_profile_has_a_scorecard`, and
    for its reason: it compares a committed artefact to the code, and the deploy
    job deselects that class so a cron tick cannot be stopped by a card nobody
    present can rebuild. ci.yml runs it on every pull request.
    """
    profile = cli.PROFILES["weekly"].split(",")
    seeds = feeds.scorecard_baselines(profile)
    assert set(seeds) == set(profile), sorted(set(profile) - set(seeds))


def test_a_first_run_with_no_baseline_is_not_a_warning():
    assert feeds.baseline_gaps({}, {"new": {"rows": 40}}, {}) == []


def test_a_second_run_with_no_baseline_and_no_card_is_a_warning():
    prev = {"new": {"rows": None, "status": "failed"}}
    gaps = feeds.baseline_gaps(prev, {"new": {"rows": 40}}, {})
    assert len(gaps) == 1 and gaps[0].startswith("new:"), gaps
    assert "compare_magnitudes" in gaps[0]


def test_a_card_closes_the_gap():
    prev = {"new": {"rows": None}}
    assert feeds.baseline_gaps(prev, {"new": {"rows": 40}},
                               {"new": {"rows": 5000}}) == []


def test_a_previous_count_closes_the_gap():
    assert feeds.baseline_gaps({"a": {"rows": 10}}, {"a": {"rows": 40}}, {}) == []


def test_a_resolver_is_never_a_gap():
    """An entry whose rows are work done rather than ids evidenced is never
    compared by the shrink guard, so a guard that cannot see it is not a gap."""
    prev = {"res": {"rows": 0, "counts_coverage": False}}
    cur = {"res": {"rows": 0, "counts_coverage": False}}
    assert feeds.baseline_gaps(prev, cur, {}) == []


# --------------------------------------------------------------------------
# 2. a failure is weighed, not counted
# --------------------------------------------------------------------------

def _corpus(assigner_of):
    return pd.DataFrame([{"cve_id": c, "state": "PUBLISHED", "assigner": a}
                         for c, a in assigner_of.items()])


def test_the_effective_set_is_weighed_per_feed():
    """`redhat` is a roster CNA. Three of its ids seen through feed A, one of
    them also through B: A alone holds it at the floor, B holds nothing up."""
    ids = {f"CVE-2025-{i:05d}": "redhat" for i in range(3)}
    refs = {c: {"sources": {"a"}} for c in ids}
    refs["CVE-2025-00000"]["sources"].add("b")
    cov = coverage.compute(_corpus(ids), refs, recent_years=(2025,),
                           sources=("a", "b", "c"))
    assert cov["cnas_effective"] == 1
    assert cov["effective_by_feed"] == {"a": 1, "b": 0, "c": 0}


def test_a_cna_seen_through_two_feeds_is_lost_with_neither():
    ids = {f"CVE-2025-{i:05d}": "redhat" for i in range(3)}
    refs = {c: {"sources": {"a", "b"}} for c in ids}
    cov = coverage.compute(_corpus(ids), refs, recent_years=(2025,),
                           sources=("a", "b"))
    assert cov["cnas_effective"] == 1
    assert cov["effective_by_feed"] == {"a": 0, "b": 0}


def test_a_feed_with_headroom_is_not_load_bearing():
    """Four sightings, one of them through A alone. Removing A leaves three,
    which is still the floor: the weight is a recomputation, not a share."""
    ids = {f"CVE-2025-{i:05d}": "redhat" for i in range(4)}
    refs = {c: {"sources": {"a", "b"}} for c in ids}
    refs["CVE-2025-00003"]["sources"] = {"a"}
    cov = coverage.compute(_corpus(ids), refs, recent_years=(2025,),
                           sources=("a", "b"))
    assert cov["effective_by_feed"] == {"a": 0, "b": 0}


def test_a_corroborating_feed_carries_no_weight():
    """Its sightings are excluded from the gate figure, so it cannot be holding
    that figure up. The same rule `cnas_effective` applies, applied here."""
    ids = {f"CVE-2025-{i:05d}": "redhat" for i in range(3)}
    refs = {c: {"sources": {"a", "m"}} for c in ids}
    cov = coverage.compute(_corpus(ids), refs, recent_years=(2025,),
                           sources=("a", "m"), corroborating={"m"})
    assert cov["cnas_effective"] == 1
    assert cov["effective_by_feed"] == {"a": 1, "m": 0}


def test_refs_without_sources_weigh_nothing_rather_than_crashing():
    """`compute` accepts a bare set of ids, and some callers pass one."""
    ids = {f"CVE-2025-{i:05d}": "redhat" for i in range(3)}
    cov = coverage.compute(_corpus(ids), set(ids), recent_years=(2025,),
                           sources=("a",))
    assert cov["effective_by_feed"] == {"a": 0}


def test_a_failed_feed_the_figure_rested_on_is_named_with_its_weight():
    detail = {"csaf": {"status": "failed", "detail": "HTTP 503", "rows": None},
              "debian": {"status": "ok", "rows": 28000}}
    found = coverage.bearing_failures(detail, {"csaf": 41, "debian": 3})
    assert len(found) == 1 and found[0].startswith("csaf:"), found
    assert "41" in found[0]


def test_a_failed_feed_that_carried_nothing_is_not_a_finding():
    detail = {"arch": {"status": "failed", "rows": None}}
    assert coverage.bearing_failures(detail, {"arch": 0}) == []


def test_a_truncated_feed_is_not_weighed():
    """Its sightings are partly present, so the loss is bounded by nothing this
    can read; `truncated` already degrades the run."""
    detail = {"ubuntu": {"status": "truncated", "rows": 919}}
    assert coverage.bearing_failures(detail, {"ubuntu": 5}) == []


def test_the_first_run_after_the_field_exists_is_silent():
    detail = {"csaf": {"status": "failed", "rows": None}}
    assert coverage.bearing_failures(detail, {}) == []
    assert coverage.bearing_failures(detail, None) == []


def test_a_failed_provider_is_the_adapters_row_not_a_weight():
    detail = {"csaf": {"status": "ok", "rows": 60000,
                       "parts": {"www.huawei.com": {"status": "failed"}}}}
    assert coverage.bearing_failures(detail, {"csaf": 41}) == []


def test_the_status_literal_is_the_one_feeds_writes():
    assert coverage.FAILED == feeds.FAILED


def test_a_bearing_failure_is_its_own_degraded_reason():
    """One reason counts, the other weighs, and a reader must see both."""
    on, reasons = cli.degraded_state(
        failures=["csaf: HTTP 503"], truncated=[], capped=[], dropped=0,
        shrunk=[], stale=[], withdrawn=[],
        bearing=["csaf: failed this run, and 41 effective CNA(s) ..."])
    assert on is True
    assert any("carried effective CNAs" in r for r in reasons), reasons
    assert len(reasons) == 2, reasons


# --------------------------------------------------------------------------
# 3. gather runs the adapters concurrently and records exactly as before
# --------------------------------------------------------------------------

def _pair(timeout):
    """Two adapters that each wait for the other to START. Only a concurrent
    caller can get both through the barrier."""
    gate = threading.Barrier(2, timeout=timeout)

    def one(years):
        gate.wait()
        return [_row("CVE-2026-1", "one")]

    def two(years):
        gate.wait()
        return [_row("CVE-2026-2", "two")]
    return {"one": one, "two": two}


def test_gather_runs_adapters_concurrently(monkeypatch):
    monkeypatch.setattr(feeds, "ADAPTERS", _pair(timeout=5))
    refs = feeds.gather(["one", "two"], {2026})
    assert feeds.FEED_HEALTH["one"]["status"] == feeds.OK, feeds.FEED_HEALTH
    assert feeds.FEED_HEALTH["two"]["status"] == feeds.OK, feeds.FEED_HEALTH
    assert set(refs) == {"CVE-2026-1", "CVE-2026-2"}


def test_one_worker_is_the_serial_loop(monkeypatch):
    """The knob has to be a knob. At one worker the first adapter waits out the
    barrier and both are recorded FAILED, which is the serial behaviour and is
    what proves the test above measured concurrency rather than luck."""
    monkeypatch.setattr(feeds, "ADAPTERS", _pair(timeout=0.5))
    feeds.gather(["one", "two"], {2026}, workers=1)
    assert feeds.FEED_HEALTH["one"]["status"] == feeds.FAILED
    assert feeds.FEED_HEALTH["two"]["status"] == feeds.FAILED


def test_merge_order_follows_the_profile_not_the_finish_line(monkeypatch):
    """`refs` keeps the FIRST product it sees. First used to mean first in
    `sources`; it still has to, or the product published for a row two feeds
    share would depend on which download finished first."""
    def slow(years):
        time.sleep(0.3)
        return [_row("CVE-2026-1", "slow", product="from-slow")]

    def fast(years):
        return [_row("CVE-2026-1", "fast", product="from-fast")]
    monkeypatch.setattr(feeds, "ADAPTERS", {"slow": slow, "fast": fast})
    refs = feeds.gather(["slow", "fast"], {2026})
    assert refs["CVE-2026-1"]["product"] == "from-slow"
    assert refs["CVE-2026-1"]["sources"] == {"slow", "fast"}


def test_every_feed_records_how_long_it_took(monkeypatch):
    """The measurement the worker count is to be tuned from, present on a
    success and on a failure alike."""
    def quick(years):
        return [_row("CVE-2026-1", "quick")]

    def broken(years):
        raise OSError("boom")
    monkeypatch.setattr(feeds, "ADAPTERS", {"quick": quick, "broken": broken})
    feeds.gather(["quick", "broken"], {2026})
    assert isinstance(feeds.FEED_HEALTH["quick"]["seconds"], float)
    assert isinstance(feeds.FEED_HEALTH["broken"]["seconds"], float)
    assert feeds.FEED_HEALTH["broken"]["status"] == feeds.FAILED
    assert "boom" in feeds.FEED_HEALTH["broken"]["detail"]


def test_an_adapters_own_health_survives_a_concurrent_run(monkeypatch):
    """The condition FEEDS.md puts on parallelising, asserted through `gather`:
    a cap recorded on a worker thread reaches `health_detail` exactly as before,
    while another adapter is mid-run, and neither entry touches the other."""
    gate = threading.Barrier(2, timeout=5)

    def capped(years):
        feeds.record_feed("capped", feeds.CAPPED, "hit the 3-page cap")
        gate.wait()
        return [_row("CVE-2026-1", "capped")]

    def plain(years):
        gate.wait()
        return [_row("CVE-2026-2", "plain"), _row("CVE-2026-3", "plain")]
    monkeypatch.setattr(feeds, "ADAPTERS", {"capped": capped, "plain": plain})
    feeds.gather(["capped", "plain"], {2026})
    h = feeds.health_detail()
    assert set(h) == {"capped", "plain"}
    assert h["capped"]["status"] == feeds.CAPPED and h["capped"]["rows"] == 1
    assert "3-page cap" in h["capped"]["detail"]
    assert h["plain"]["status"] == feeds.OK and h["plain"]["rows"] == 2
    assert h["plain"]["months"] == {"2026-08": 2}


def test_bytes_are_counted_under_a_lock():
    feeds.reset_health()

    def hammer():
        for _ in range(20000):
            feeds._count_bytes(1)
    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert feeds.FETCH_BYTES["total"] == 8 * 20000


def test_no_fetch_helper_increments_the_counter_directly():
    """Exactly one bare increment: the body of `_count_bytes` itself."""
    src = inspect.getsource(feeds)
    assert len(re.findall(r'FETCH_BYTES\["total"\] \+=', src)) == 1
