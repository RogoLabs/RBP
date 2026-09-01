"""The rows the Ubuntu walk cannot reach, dated by name instead.

`alpine`, `arch` and `debian` carry no dates, so a row only they saw is held
back as `undated` and never counted. Ubuntu can date those rows and mostly
cannot be walked to them: on 2026-08-27, 82 of the 151 held-back rows were
undated, 59 had an Ubuntu date, and all 59 were older than the walk's reach.
"""
import pytest

from rbp import clock, feeds, schema


@pytest.fixture(autouse=True)
def _clean_health():
    feeds.reset_health()
    yield
    feeds.reset_health()


def _serve(table, seen=None):
    """Stand in for the q= endpoint, keyed by the id in the query string."""
    def fake_get(url, timeout=90, retries=3, headers=None):
        assert "q=" in url, "the resolver must ask by name, never by offset"
        cid = url.split("q=")[1]
        if seen is not None:
            seen.append(cid)
        val = table.get(cid, [])
        if isinstance(val, Exception):
            raise val
        if val == "gone":
            return None, 404, {}
        return {"cves": val}, 200, {}
    return fake_get


def test_dates_the_ids_it_is_given(monkeypatch):
    monkeypatch.setattr(feeds, "_get", _serve({
        "CVE-2026-44235": [{"id": "CVE-2026-44235", "published": "2026-06-11T00:00:00"}],
        "CVE-2026-35332": [{"id": "CVE-2026-35332", "published": "2026-04-22T12:00:00"}],
    }))
    got = feeds.resolve_dates_ubuntu(["CVE-2026-44235", "CVE-2026-35332"])
    assert got == {"CVE-2026-44235": "2026-06-11", "CVE-2026-35332": "2026-04-22"}
    assert feeds.FEED_HEALTH["ubuntu:dates"]["status"] == feeds.OK


def test_an_id_ubuntu_does_not_carry_is_simply_absent(monkeypatch):
    monkeypatch.setattr(feeds, "_get", _serve({"CVE-2026-99999": []}))
    assert feeds.resolve_dates_ubuntu(["CVE-2026-99999"]) == {}
    # Not an error: Ubuntu answering "I have never heard of this" is a complete
    # answer, and marking it truncated would make a healthy pass read as loss.
    assert feeds.FEED_HEALTH["ubuntu:dates"]["status"] == feeds.OK


def test_q_is_a_search_so_a_row_for_another_id_is_never_attached(monkeypatch):
    """The failure this guards is silent and wrong, not loud and missing.

    `q=` matches description text as well as ids, so the endpoint can answer a
    query with somebody else's record. Taking `cves[0]` would date the row from
    it, and the row would be published with a confident, invented age.
    """
    monkeypatch.setattr(feeds, "_get", _serve({
        "CVE-2026-44235": [{"id": "CVE-2026-11111", "published": "2020-01-01T00:00:00"},
                           {"id": "CVE-2026-44235", "published": "2026-06-11T00:00:00"}],
    }))
    assert feeds.resolve_dates_ubuntu(["CVE-2026-44235"]) == {"CVE-2026-44235": "2026-06-11"}


def test_a_partial_failure_is_counted_out_loud_but_does_not_degrade_the_run(monkeypatch):
    """Measured live 2026-08-28: 82 ids, 2 lookups failed. That is an ordinary
    afternoon on this endpoint, and degrading every run for it is the furniture
    problem. It is safe to stay green ONLY because a row this pass fails to date
    stays in held_back as `undated` and is asked for again next run, so the cost
    is a day of latency on a floor rather than a silent shrink."""
    monkeypatch.setattr(feeds, "_get", _serve({
        "CVE-1": [{"id": "CVE-1", "published": "2026-06-11T00:00:00"}],
        "CVE-2": RuntimeError("HTTP 503"),
    }))
    got = feeds.resolve_dates_ubuntu(["CVE-1", "CVE-2"])
    assert got == {"CVE-1": "2026-06-11"}, "the ids that answered are kept"
    h = feeds.FEED_HEALTH["ubuntu:dates"]
    assert h["status"] == feeds.OK
    assert "1 lookup(s) failed" in h["detail"], "and it is never invisible"


def test_ubuntu_being_down_is_loud(monkeypatch):
    """The exception to the rule above, and the reason it is safe. With every
    lookup failing there is no self-healing to appeal to and the pass learned
    nothing, so `ok, dated 0` would be a silent shrink wearing that excuse."""
    monkeypatch.setattr(feeds, "_get", _serve({
        "CVE-1": RuntimeError("HTTP 503"), "CVE-2": RuntimeError("HTTP 503"),
    }))
    assert feeds.resolve_dates_ubuntu(["CVE-1", "CVE-2"]) == {}
    h = feeds.FEED_HEALTH["ubuntu:dates"]
    assert h["status"] == feeds.FAILED and h["ok"] is False


def test_a_404_is_an_error_not_an_undated_row(monkeypatch):
    """`_get` returns (None, 404, {}) instead of raising. An unknown id answers
    200 with an empty list, so a 404 is the endpoint moving, and reading it as
    'no date' would turn a retired path into a silently undated backlog."""
    monkeypatch.setattr(feeds, "_get", _serve({"CVE-1": "gone"}))
    assert feeds.resolve_dates_ubuntu(["CVE-1"]) == {}
    assert feeds.FEED_HEALTH["ubuntu:dates"]["status"] == feeds.FAILED


def test_a_spent_budget_is_capped_not_truncated(monkeypatch):
    """A configured limit belongs in `limitations`, which is the call the walk's
    own wall-clock budget already made."""
    monkeypatch.setattr(feeds, "_get", _serve({}))
    got = feeds.resolve_dates_ubuntu(["CVE-1", "CVE-2", "CVE-3"], budget_s=-1)
    assert got == {}
    h = feeds.FEED_HEALTH["ubuntu:dates"]
    assert h["status"] == feeds.CAPPED
    assert h["truncated"] is True, "a cap is still an incomplete read"
    assert "3 row(s) never asked for" in h["detail"]


def test_ids_are_deduplicated_before_the_endpoint_is_asked(monkeypatch):
    seen = []
    monkeypatch.setattr(feeds, "_get", _serve(
        {"CVE-1": [{"id": "CVE-1", "published": "2026-06-11T00:00:00"}]}, seen))
    feeds.resolve_dates_ubuntu(["CVE-1", "CVE-1", "CVE-1"])
    assert seen == ["CVE-1"]


def test_no_undated_rows_is_a_healthy_pass_that_asks_nothing(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not touch the network with nothing to date")
    monkeypatch.setattr(feeds, "_get", boom)
    assert feeds.resolve_dates_ubuntu([]) == {}
    assert feeds.FEED_HEALTH["ubuntu:dates"]["status"] == feeds.OK


def test_it_is_a_sub_entry_not_a_fourteenth_feed(monkeypatch):
    """health_summary counts an attempt per FEED. The resolver must be able to
    report loss without changing what `attempts` means."""
    monkeypatch.setattr(feeds, "_get", _serve({"CVE-1": RuntimeError("503")}))
    feeds.record_feed("ubuntu", feeds.CAPPED, "hit the 200-page cap")
    before = feeds.health_summary()[2]
    feeds.resolve_dates_ubuntu(["CVE-1"])
    failures, truncated, attempts, capped = feeds.health_summary()
    assert attempts == before, "the resolver is not an extra feed"
    assert any("ubuntu:dates" in f for f in failures), "but its loss is still visible"


def test_a_looked_up_date_starts_the_buffer_and_never_the_expectation():
    """The point of putting the date in `public_date` and nowhere else.

    Ubuntu is a tracker in clock._ORIGIN_KIND, and this endpoint's `published`
    is a tracker date whether it arrives by walk or by name. It must age the row
    so the buffer can pass it, and it must never start the 72-hour clock.
    """
    row = {"cve_id": "CVE-2026-44235", "state": "RESERVED",
           "public_date": "2026-06-11", "public_date_origin": "lookup",
           "sources": "debian", "dates": {}, "owner": None}
    clock.annotate([row], today="2026-08-28")
    assert row["clock_known"] is True
    assert row["days_public"] == 78, "the buffer can now age it"
    assert row["advisory_date"] is None, "and no advisory clock was started"
    assert row["clock_origin"] == "tracker"


def test_the_lookup_adds_no_source_and_no_corroboration():
    """A lookup only ever happens because another feed already found the row, so
    crediting ubuntu with a sighting would raise feed_count out of a sample
    chosen by which rows were already undated."""
    row = {"cve_id": "CVE-2026-44235", "sources": "debian", "feed_count": 1,
           "dates": {}, "public_date": "", "public_date_origin": "none"}
    dated = {"CVE-2026-44235": "2026-06-11"}
    # exactly what cli.py does
    d = dated.get(row["cve_id"])
    row["public_date"], row["public_date_origin"] = d, "lookup"
    assert row["sources"] == "debian" and row["feed_count"] == 1
    assert row["dates"] == {}, "and nothing entered the per-feed sighting dates"


def test_the_provenance_field_is_published_and_documented():
    assert "public_date_origin" in schema.COLUMNS
    kind, absent, meaning = schema.FIELDS["public_date_origin"]
    assert absent == "never absent", "every row must say how it was dated"
    assert "lookup" in meaning and "feed" in meaning and "none" in meaning


# --------------------------------------------------------------------------
# what this pass's row count means
#
# 2026-08-31: `ubuntu-osv` landed, carried dates for most of the held-back rows
# as ordinary feed dates, and the undated population this pass works over fell
# from 82 to 3. It dated 0 of the 3, recorded `ok` with `rows: 0`, and both
# shrink guards read that as a source going dark. The deploy stopped.
# --------------------------------------------------------------------------

def test_the_pass_records_itself_as_work_done_not_coverage(monkeypatch):
    """`rows` here counts dates resolved, not ids this source evidences, so the
    high-water comparison the shrink guards run is unsound on it in the same way
    `verify` already documents for one other transition.

    The asymmetry that makes it safe to exempt: this pass can only fail to
    IMPROVE a row, never remove one. An id it does not date stays in
    `held_back.json` as `undated`, exactly where it already was, and the next
    run asks again."""
    monkeypatch.setattr(feeds, "_get", _serve({
        "CVE-2026-44235": [{"id": "CVE-2026-44235", "published": "2026-06-11T00:00:00"}],
    }))
    feeds.resolve_dates_ubuntu(["CVE-2026-44235"])
    assert feeds.FEED_HEALTH["ubuntu:dates"]["counts_coverage"] is False


def test_a_population_drained_to_nothing_still_records_the_mark():
    """The end state, and the one that would otherwise have failed every future
    build: once `ubuntu-osv` dates every held-back row there is nothing left to
    ask for, and this returns early."""
    assert feeds.resolve_dates_ubuntu([]) == {}
    h = feeds.FEED_HEALTH["ubuntu:dates"]
    assert h["rows"] == 0 and h["status"] == feeds.OK
    assert h["counts_coverage"] is False


def test_ubuntu_being_down_is_still_loud(monkeypatch):
    """The mark turns off a comparison, not the pass's own judgement. If every
    lookup fails there is no self-healing to appeal to and the run learned
    nothing, which `verify` accounts for through the status instead."""
    monkeypatch.setattr(feeds, "_get", _serve({
        "CVE-2026-1": RuntimeError("HTTP Error 503"),
        "CVE-2026-2": RuntimeError("HTTP Error 503"),
    }))
    feeds.resolve_dates_ubuntu(["CVE-2026-1", "CVE-2026-2"])
    h = feeds.FEED_HEALTH["ubuntu:dates"]
    assert h["status"] == feeds.FAILED
    assert h["counts_coverage"] is False
