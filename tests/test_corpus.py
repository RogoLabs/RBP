"""
Corpus freshness and incremental refresh (PLAN.md phase 2.5).

Two measured facts about the cvelistV5 release feed drive this design, and both
are asserted below so a change upstream fails loudly rather than quietly costing
half a gigabyte per run:

  * `all_CVEs_at_midnight.zip.zip` is ONE file per day. Every hourly release
    re-attaches the identical object; only the tag rotates. The original code
    keyed freshness on the tag, which re-downloaded the same 583 MB up to 24
    times a day.

  * The delta zip is cumulative from midnight, not hour-on-hour, so one fetch
    carries every change so far that day.
"""
from __future__ import annotations

import json
import os

import pandas as pd
import pytest

from rbp import cvelist

live_only = pytest.mark.skipif(
    os.environ.get("RBP_LIVE_TESTS") != "1",
    reason="hits the cvelistV5 release API; set RBP_LIVE_TESTS=1",
)

COLS = cvelist.COLUMNS


def _corpus(tmp_path, rows, corpus_date=None):
    index = tmp_path / "index"
    index.mkdir()
    pd.DataFrame(rows, columns=COLS).to_parquet(index / "corpus.parquet", index=False)
    pd.DataFrame([("widget", "acme", 3, 3, 1.0)],
                 columns=["product", "cna", "cna_cves", "total_cves", "confidence"]
                 ).to_parquet(index / "product_cna.parquet", index=False)
    if corpus_date:
        cvelist._write_state(str(index), corpus_date=corpus_date,
                             schema=cvelist.SCHEMA)
    return str(index)


# --------------------------------------------------------------------------
# asset discrimination: the bug that cost 583 MB a run
# --------------------------------------------------------------------------

def test_asset_matcher_separates_baseline_from_delta():
    """Both assets end in `.zip`, so a bare suffix test picks the baseline when
    it wants the delta. That mistake silently dropped today's delta."""
    rel = {"assets": [
        {"name": "2026-08-20_all_CVEs_at_midnight.zip.zip", "browser_download_url": "base"},
        {"name": "2026-08-20_delta_CVEs_at_2000Z.zip", "browser_download_url": "delta"},
    ]}
    base = cvelist._asset(rel, lambda n: n.endswith("all_CVEs_at_midnight.zip.zip"))
    delta = cvelist._asset(rel, lambda n: "delta_CVEs" in n and n.endswith(".zip"))
    assert base["browser_download_url"] == "base"
    assert delta["browser_download_url"] == "delta"


def test_days_between_is_inclusive():
    assert cvelist._days_between("2026-08-18", "2026-08-20") == [
        "2026-08-18", "2026-08-19", "2026-08-20"]
    assert cvelist._days_between("2026-08-20", "2026-08-20") == ["2026-08-20"]


# --------------------------------------------------------------------------
# state file
# --------------------------------------------------------------------------

def test_state_round_trips(tmp_path):
    d = str(tmp_path)
    assert cvelist._read_state(d) == {}
    cvelist._write_state(d, corpus_date="2026-08-20")
    cvelist._write_state(d, last_full="2026-08-13")
    state = cvelist._read_state(d)
    assert state == {"corpus_date": "2026-08-20", "last_full": "2026-08-13"}


def test_unreadable_state_is_not_fatal(tmp_path):
    """A truncated state file must degrade to a full rebuild, never crash the run."""
    (tmp_path / cvelist.STATE_FILE).write_text("{not json")
    assert cvelist._read_state(str(tmp_path)) == {}


# --------------------------------------------------------------------------
# delta application
# --------------------------------------------------------------------------

def test_apply_deltas_upserts_and_advances_state(tmp_path, monkeypatch):
    index = _corpus(tmp_path, [
        ("CVE-2026-1", "RESERVED", "", "", "", ""),
        ("CVE-2026-2", "PUBLISHED", "acme", "2026-08-01", "Acme", "widget"),
    ], corpus_date="2026-08-18")

    payloads = {
        "2026-08-19": [("CVE-2026-1", "PUBLISHED", "acme", "2026-08-01", "Acme", "widget")],
        "2026-08-20": [("CVE-2026-3", "PUBLISHED", "beta", "2026-08-01", "Beta", "thing")],
    }
    monkeypatch.setattr(cvelist, "_delta_rows", lambda url: payloads[url])

    corpus, applied = cvelist.apply_deltas(index, {d: d for d in payloads})
    assert applied == ["2026-08-19", "2026-08-20"]
    by_id = dict(zip(corpus["cve_id"], corpus["state"]))
    assert by_id["CVE-2026-1"] == "PUBLISHED"   # upserted, not duplicated
    assert by_id["CVE-2026-3"] == "PUBLISHED"   # appended
    assert len(corpus) == 3
    assert corpus["cve_id"].is_unique


def test_apply_deltas_orders_oldest_first(tmp_path, monkeypatch):
    """A record only moves forward, so the newest day must win. Applying out of
    order would resurrect a stale state and re-open a resolved RBP."""
    index = _corpus(tmp_path, [("CVE-2026-1", "RESERVED", "", "", "", "")])
    payloads = {
        "2026-08-20": [("CVE-2026-1", "REJECTED", "acme", "", "", "")],
        "2026-08-19": [("CVE-2026-1", "PUBLISHED", "acme", "2026-08-01", "", "")],
    }
    monkeypatch.setattr(cvelist, "_delta_rows", lambda url: payloads[url])
    corpus, applied = cvelist.apply_deltas(index, {d: d for d in payloads})
    assert applied == ["2026-08-19", "2026-08-20"]
    assert corpus.set_index("cve_id").loc["CVE-2026-1", "state"] == "REJECTED"


def test_reapplying_the_same_day_is_idempotent(tmp_path, monkeypatch):
    """Today's cumulative delta is re-fetched on every run within the day. That
    has to be a no-op, not a duplicate."""
    index = _corpus(tmp_path, [("CVE-2026-1", "RESERVED", "", "", "", "")])
    rows = [("CVE-2026-2", "PUBLISHED", "acme", "2026-08-01", "", "")]
    monkeypatch.setattr(cvelist, "_delta_rows", lambda url: rows)
    cvelist.apply_deltas(index, {"2026-08-20": "u"})
    corpus, _ = cvelist.apply_deltas(index, {"2026-08-20": "u"})
    assert len(corpus) == 2
    assert corpus["cve_id"].is_unique


def test_empty_delta_is_skipped(tmp_path, monkeypatch):
    index = _corpus(tmp_path, [("CVE-2026-1", "PUBLISHED", "acme", "2026-08-01", "", "")])
    monkeypatch.setattr(cvelist, "_delta_rows", lambda url: [])
    corpus, applied = cvelist.apply_deltas(index, {"2026-08-20": "u"})
    assert applied == []
    assert len(corpus) == 1


# --------------------------------------------------------------------------
# refresh routing: when to spend 583 MB and when not to
# --------------------------------------------------------------------------

def _route(tmp_path, monkeypatch, corpus_date, deltas, force=False, indexed=True):
    """Run refresh_corpus with the network stubbed and report which path it took."""
    index = (_corpus(tmp_path, [("CVE-2026-1", "PUBLISHED", "acme", "2026-08-01", "", "")], corpus_date)
             if indexed else str(tmp_path / "empty"))
    monkeypatch.setattr(cvelist, "survey_releases",
                        lambda: ("2026-08-20", "base-url", deltas))
    monkeypatch.setattr(cvelist, "_delta_rows", lambda url: [])
    took = {}

    def fake_full(path, url=None, date=None):
        took["baseline"] = True
        took["baseline_date"] = date
        return path

    def fake_build(zip_path, out_dir):
        took["reindex"] = True
        os.makedirs(out_dir, exist_ok=True)
        df = pd.DataFrame([("CVE-2026-1", "PUBLISHED", "acme", "2026-08-01", "", "")], columns=COLS)
        df.to_parquet(os.path.join(out_dir, "corpus.parquet"), index=False)
        prod = pd.DataFrame([], columns=["product", "cna", "cna_cves", "total_cves", "confidence"])
        prod.to_parquet(os.path.join(out_dir, "product_cna.parquet"), index=False)
        return df, prod

    monkeypatch.setattr(cvelist, "download_baseline", fake_full)
    monkeypatch.setattr(cvelist, "build_index", fake_build)
    cvelist.refresh_corpus(str(tmp_path / "base.zip"), index, force=force)
    return took, index


ALL_DELTAS = {d: f"u-{d}" for d in
              ["2026-08-14", "2026-08-15", "2026-08-16", "2026-08-17",
               "2026-08-18", "2026-08-19", "2026-08-20"]}


def test_small_gap_uses_deltas(tmp_path, monkeypatch):
    took, _ = _route(tmp_path, monkeypatch, "2026-08-18", ALL_DELTAS)
    assert "baseline" not in took, "spent 583 MB on a 2-day gap"


def test_wide_gap_rebuilds(tmp_path, monkeypatch):
    took, _ = _route(tmp_path, monkeypatch, "2026-06-01", ALL_DELTAS)
    assert took.get("baseline") and took.get("reindex")


def test_missing_delta_day_rebuilds(tmp_path, monkeypatch):
    """A hole in the chain means the corpus cannot be brought forward correctly.
    Rebuild rather than silently skipping a day of state transitions."""
    holed = {d: u for d, u in ALL_DELTAS.items() if d != "2026-08-19"}
    took, _ = _route(tmp_path, monkeypatch, "2026-08-18", holed)
    assert took.get("baseline"), "skipped a missing day instead of rebuilding"


def test_stale_schema_rebuilds(tmp_path, monkeypatch):
    """A cached index written under an older schema is missing columns the
    pipeline now depends on, so it must be rebuilt rather than used."""
    index = _corpus(tmp_path, [("CVE-2026-1", "PUBLISHED", "acme", "2026-08-01", "", "")],
                    "2026-08-20")
    cvelist._write_state(index, schema=cvelist.SCHEMA - 1)
    monkeypatch.setattr(cvelist, "survey_releases",
                        lambda: ("2026-08-20", "base-url", ALL_DELTAS))
    took = {}
    monkeypatch.setattr(cvelist, "download_baseline",
                        lambda p, url=None, date=None: took.setdefault("baseline", True))
    def fake_build(z, out):
        took["reindex"] = True
        df = pd.DataFrame([("CVE-2026-1", "PUBLISHED", "acme", "2026-08-01", "", "")],
                          columns=COLS)
        df.to_parquet(os.path.join(out, "corpus.parquet"), index=False)
        prod = pd.DataFrame(
            [], columns=["product", "cna", "cna_cves", "total_cves", "confidence"])
        prod.to_parquet(os.path.join(out, "product_cna.parquet"), index=False)
        return df, prod
    monkeypatch.setattr(cvelist, "build_index", fake_build)
    cvelist.refresh_corpus(str(tmp_path / "b.zip"), index)
    assert took.get("baseline") and took.get("reindex")
    assert cvelist._read_state(index)["schema"] == cvelist.SCHEMA


def test_cold_start_rebuilds(tmp_path, monkeypatch):
    took, _ = _route(tmp_path, monkeypatch, None, ALL_DELTAS, indexed=False)
    assert took.get("baseline") and took.get("reindex")


def test_force_rebuilds_even_when_current(tmp_path, monkeypatch):
    took, _ = _route(tmp_path, monkeypatch, "2026-08-20", ALL_DELTAS, force=True)
    assert took.get("baseline")


def test_clock_moving_backwards_rebuilds(tmp_path, monkeypatch):
    """If the cached index claims a date after the newest release, something is
    wrong with the cache. Rebuild rather than trusting it."""
    took, _ = _route(tmp_path, monkeypatch, "2026-09-01", ALL_DELTAS)
    assert took.get("baseline")


def test_refresh_advances_corpus_date(tmp_path, monkeypatch):
    _, index = _route(tmp_path, monkeypatch, "2026-08-18", ALL_DELTAS)
    assert cvelist._read_state(index)["corpus_date"] == "2026-08-20"


def test_rebuild_passes_the_date_so_the_stamp_gets_written(tmp_path, monkeypatch):
    """download_baseline only writes its freshness stamp when it knows the date.
    Callers that already surveyed the feed must pass it, or the next run
    re-downloads 583 MB it already holds."""
    took, _ = _route(tmp_path, monkeypatch, None, ALL_DELTAS, indexed=False)
    assert took["baseline_date"] == "2026-08-20"


# --------------------------------------------------------------------------
# live: the upstream facts this design rests on
# --------------------------------------------------------------------------

@live_only
def test_live_baseline_is_one_file_per_day():
    """If the baseline ever becomes per-release rather than per-day, the
    date-keyed freshness check silently goes stale."""
    date, url, _ = cvelist.survey_releases()
    assert url.rsplit("/", 1)[-1].startswith(date)
    assert "all_CVEs_at_midnight" in url


@live_only
def test_live_delta_is_available_for_today_and_recent_days():
    date, _, deltas = cvelist.survey_releases()
    assert date in deltas, "no delta for the current baseline date"
    assert len(deltas) >= 3, f"only {len(deltas)} delta day(s) visible; widen _releases()"


@live_only
def test_live_delta_is_cumulative_from_midnight():
    """The warm path fetches one delta per day. That is only correct while the
    delta is cumulative rather than hour-on-hour."""
    rels = cvelist._releases(pages=1)
    today = None
    sizes = []
    for rel in rels:
        a = cvelist._asset(rel, lambda n: "delta_CVEs" in n and n.endswith(".zip"))
        if not a:
            continue
        day = a["name"][:10]
        today = today or day
        if day == today:
            sizes.append(a["size"])
    if len(sizes) < 3:
        # Shortly after UTC midnight there is only one same-day release, so the
        # cumulative property has nothing to be evaluated against. Skipping is
        # correct: asserting here made the suite fail as a function of the time
        # of day, which trains people to ignore red builds.
        pytest.skip(f"only {len(sizes)} same-day release(s) so far; "
                    "cumulativeness is not observable yet")
    # Newest first, so sizes must be non-increasing as we walk back through the day.
    assert sizes == sorted(sizes, reverse=True), (
        f"delta sizes {sizes} are not monotonic within the day; it may no longer "
        "be cumulative, in which case the warm path is skipping changes")


# --------------------------------------------------------------------------
# feed health: a failing feed must not read as an improvement
# --------------------------------------------------------------------------

def test_archive_ceiling_refuses_to_truncate():
    """Reading a bulk archive through the in-memory cap silently truncated it
    into an invalid zip, which is how OSV npm (220 MB against a 100 MB cap) was
    dropped from every run while the build reported success. The ceiling must
    raise, never mangle."""
    from rbp import feeds
    assert feeds.MAX_ARCHIVE_BYTES > 220_000_000, (
        "ceiling is below the known size of the OSV npm archive")
    assert feeds.MAX_ARCHIVE_BYTES > feeds.MAX_BYTES


def test_feed_health_counts_feeds_not_sub_fetches(monkeypatch):
    """The unit was wrong as well as the states. OSV recorded per ecosystem AND
    gather recorded again for `osv`, so "all 20 feed fetches succeeded" described
    10 feeds, and any consumer check of the form
    `failures == [] and attempts == len(requested)` was broken on arrival."""
    from rbp import feeds
    monkeypatch.setattr(feeds, "FEED_HEALTH", {})
    feeds.record_feed("osv", feeds.OK, "8742 ids")
    feeds.record_feed("osv:npm", feeds.OK, "2321 ids")
    feeds.record_feed("osv:Hex", feeds.FAILED, "connection reset")
    feeds.record_feed("debian", feeds.OK, "17058 ids")
    failures, attempts = feeds.health_summary()
    assert attempts == 2, "osv and debian are two feeds, not four fetches"
    assert failures == ["osv:Hex: connection reset"]


def test_truncation_is_neither_success_nor_failure(monkeypatch):
    """The Ubuntu 200-page cap fires on every run, and recording it as ok made
    /method assert "all N feed fetches succeeded" every single time."""
    from rbp import feeds
    monkeypatch.setattr(feeds, "FEED_HEALTH", {})
    feeds.record_feed("ubuntu", feeds.TRUNCATED, "hit the 200-page cap")
    failures, attempts = feeds.health_summary()
    assert failures == [], "truncation is not a failure"
    detail = feeds.health_detail()
    assert detail["ubuntu"]["status"] == feeds.TRUNCATED
    assert detail["ubuntu"]["ok"] is False, "and it is not a success either"


def test_a_degraded_sub_fetch_degrades_its_parent(monkeypatch):
    """Otherwise the top-level number hides the hole: osv reads ok while one of
    its ten ecosystems failed."""
    from rbp import feeds
    monkeypatch.setattr(feeds, "FEED_HEALTH", {})
    feeds.record_feed("osv", feeds.OK, "8742 ids")
    feeds.record_feed("osv:npm", feeds.OK, "2321 ids")
    feeds.record_feed("osv:Hex", feeds.FAILED, "connection reset")
    d = feeds.health_detail()
    assert d["osv"]["status"] == feeds.FAILED
    assert d["osv"]["ok"] is False
    assert "1 of 2 parts degraded" in d["osv"]["detail"]


def test_health_is_reset_per_run(monkeypatch):
    """A module global surviving between runs in one process reports a stale
    feed as healthy."""
    from rbp import feeds
    monkeypatch.setattr(feeds, "FEED_HEALTH", {"ghost": {"status": "failed"}})
    feeds.reset_health()
    assert feeds.FEED_HEALTH == {}


def test_no_failures_reports_clean(monkeypatch):
    from rbp import feeds
    monkeypatch.setattr(feeds, "FEED_HEALTH", {})
    feeds.record_feed("debian", True, "ok")
    assert feeds.health_summary() == ([], 1)
