"""
The two GitHub feeds, and the coverage each one exists to close.

MEASURED 2026-08-26, and every number in these tests came from the live API on
that date rather than from an argument about it.

`feed_ghsa` read the newest 4,000 advisories in one descending scan and stopped,
which is 83 days against distro trackers observed over years. 9,512 reviewed
advisories were published in 2026 before that date, so the scan covered 42% of
the year it reported on, and it reported a roughly CONSTANT count every run,
which compare_magnitudes reads as a healthy feed rather than as a standing
truncation.

`feed_ghsa_repos` exists because raising that cap does not help at all for a
whole class of row. A repository advisory with no package ecosystem never enters
github/advisory-database, so GET /advisories cannot return it at any cap, in any
window, with any type. 150 of 150 sampled RESERVED ids sourced from the watchlist
were absent from the global endpoint; 1,018 of them were RESERVED on the day the
snapshot published without them.
"""
from __future__ import annotations

import datetime as dt
import json

import pytest

from rbp import feeds


@pytest.fixture(autouse=True)
def _clean_health():
    feeds.reset_health()
    yield
    feeds.reset_health()


@pytest.fixture(autouse=True)
def _no_token_shellout(monkeypatch):
    """`_gh_headers` falls back to `gh auth token`, which is a subprocess and an
    ambient credential. Neither belongs in a unit test."""
    monkeypatch.setattr(feeds, "_gh_headers", lambda: {"Accept": "application/json"})


def _advisory(cid="CVE-2026-0001", ghsa="GHSA-aaaa-bbbb-cccc", when="2026-08-01T00:00:00Z"):
    return {"cve_id": cid, "ghsa_id": ghsa, "published_at": when, "summary": "s"}


# --------------------------------------------------------------------------
# feed_ghsa: the shard walk
# --------------------------------------------------------------------------

def test_ghsa_asks_for_reviewed_advisories_only(monkeypatch):
    """THE TRAP IN THE FIX, and the reason this assertion is worth a test of its
    own. The endpoint's default population depends on whether `published` is
    present, which is undocumented and was measured:

        sort=published&direction=desc                    100% reviewed
        sort=published&direction=desc&published=<range>   94% unreviewed

    So the shard window that fixes the cap ALSO widens the population by itself.
    Over the 83-day window the old scan covered: 3,323 reviewed rows against
    22,571 unreviewed, a sevenfold read for advisories that cannot be RBP by
    construction, since unreviewed advisories are GitHub's imports of
    already-PUBLISHED CVE records. All 371 rows this feed contributed to the
    2026-08-20 snapshot were reviewed and none were unreviewed."""
    seen = []

    def fake_get(url, timeout=60, headers=None):
        seen.append(url)
        return [], None, {}
    monkeypatch.setattr(feeds, "_get", fake_get)

    feeds.feed_ghsa({2026}, today=dt.date(2026, 3, 15))
    assert seen, "no request was made at all"
    missing = [u for u in seen if "type=reviewed" not in u]
    assert not missing, f"{len(missing)} request(s) would have pulled unreviewed rows: {missing[:1]}"


def test_ghsa_shards_one_window_per_month_and_never_past_today(monkeypatch):
    """The cap becomes headroom only if each shard is a month. Measured reviewed
    volume per month in 2026 peaks at 1,701 (May), which is 18 pages against a
    40-page shard cap. A shard asking for a window that has not happened yet is
    the other half: the walk stops at today, not at December."""
    seen = []

    def fake_get(url, timeout=60, headers=None):
        seen.append(url)
        return [], None, {}
    monkeypatch.setattr(feeds, "_get", fake_get)

    feeds.feed_ghsa({2026}, today=dt.date(2026, 3, 15))
    windows = [u.split("published=")[1] for u in seen]
    assert windows == ["2026-01-01..2026-01-31",
                       "2026-02-01..2026-02-28",
                       "2026-03-01..2026-03-15"], windows


def test_ghsa_cap_names_every_month_it_fired_in(monkeypatch):
    """A whole-feed count cannot say WHICH window is short. The old record said
    "hit the 40-page cap" for a feed whose every run hit it; this one has to name
    the months, because a cap that fires in one month of twelve is a different
    fact from one that fires in all twelve."""
    def fake_get(url, timeout=60, headers=None):
        # Always another page, so the cap is what ends every shard.
        return [_advisory()], None, {"Link": '<https://api.github.com/next>; rel="next"'}
    monkeypatch.setattr(feeds, "_get", fake_get)

    feeds.feed_ghsa({2026}, page_cap=2, today=dt.date(2026, 3, 15))
    h = feeds.FEED_HEALTH.get("ghsa")
    assert h and h["status"] == feeds.CAPPED
    assert "2-page cap" in h["detail"]
    for month in ("2026-01", "2026-02", "2026-03"):
        assert month in h["detail"], f"{month} capped and was not named: {h['detail']}"


def test_ghsa_completing_every_shard_reports_nothing(monkeypatch):
    """The complement, so the test above cannot be satisfied by recording a cap
    unconditionally. A feed that read everything must not report itself
    incomplete: `capped` is furniture the moment it is always on."""
    def fake_get(url, timeout=60, headers=None):
        return [_advisory()], None, {}          # no next link: the data ran out
    monkeypatch.setattr(feeds, "_get", fake_get)

    feeds.feed_ghsa({2026}, today=dt.date(2026, 3, 15))
    assert "ghsa" not in feeds.FEED_HEALTH


def test_ghsa_still_finds_a_backfill_year_disclosed_later(monkeypatch):
    """A CVE-2025 id can be disclosed in 2026. The descending scan caught those
    by counting backwards from today, so a per-year shard window would have
    silently dropped exactly them on a backfill run. The walk therefore runs from
    January of the EARLIEST requested year through today, and the year filter is
    applied to the CVE ID rather than to the publication date."""
    def fake_get(url, timeout=60, headers=None):
        window = url.split("published=")[1]
        if window.startswith("2026-02"):
            return [_advisory(cid="CVE-2025-0999", when="2026-02-10T00:00:00Z")], None, {}
        return [], None, {}
    monkeypatch.setattr(feeds, "_get", fake_get)

    rows = feeds.feed_ghsa({2025}, today=dt.date(2026, 3, 15))
    assert [r["cve_id"] for r in rows] == ["CVE-2025-0999"], (
        "a 2025 id disclosed in 2026 was dropped, which is the regression the "
        "month walk had to avoid")


def test_ghsa_a_dead_shard_degrades_the_run_but_keeps_its_rows(monkeypatch):
    """A configured cap is CAPPED and expected. A shard that DIED is neither, and
    the distinction is the whole point of having four states: one is standing
    furniture disclosed on /method, the other has to turn the banner on."""
    def fake_get(url, timeout=60, headers=None):
        if "2026-02" in url:
            raise RuntimeError("boom")
        return [_advisory()], None, {}
    monkeypatch.setattr(feeds, "_get", fake_get)

    rows = feeds.feed_ghsa({2026}, today=dt.date(2026, 3, 15))
    h = feeds.FEED_HEALTH.get("ghsa")
    assert h and h["status"] == feeds.TRUNCATED
    assert "2026-02" in h["detail"]
    assert rows, "the January rows were thrown away with the February failure"


# --------------------------------------------------------------------------
# feed_ghsa_repos: the endpoint /advisories cannot substitute for
# --------------------------------------------------------------------------

def _state(tmp_path, repos):
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"schema": "ghsa-repos/1", "cursor": None, "repos": repos}))
    return str(p)


def _list(tmp_path, names):
    p = tmp_path / "repos.txt"
    p.write_text("# a comment that must be skipped\n" + "\n".join(names) + "\n")
    return str(p)


def _row(cid="CVE-2026-0005", ghsa="GHSA-aaaa-bbbb-cccc"):
    return {"cve_id": cid, "ghsa_id": ghsa, "published": "2026-07-01"}


def test_a_stopped_sweep_does_not_shrink_the_feed(monkeypatch, tmp_path):
    """THE ONE THIS FEED WOULD BE DANGEROUS WITHOUT.

    `gather` rebuilds refs from scratch every run, so a feed returning only what
    it polled THIS run reports a smaller count whenever the rate budget stops the
    sweep early. A feed shrinking quietly is the failure this project calls
    intolerable, and a budget stop is the ordinary case on a cold start, not an
    exotic one. Every stored row is returned every run; polling only decides
    which entries get refreshed."""
    monkeypatch.setattr(feeds, "_GHSA_REPO_CHUNK", 1)
    monkeypatch.setattr(feeds, "_rate_exhausted", lambda buf: True)
    state = _state(tmp_path, {
        "a/one": {"last_modified": "x", "rows": [_row("CVE-2026-0001")]},
        "b/two": {"last_modified": "x", "rows": [_row("CVE-2026-0002")]},
    })
    monkeypatch.setattr(feeds, "_get_cond",
                        lambda url, headers=None, timeout=45: (304, None, {}))

    rows = feeds.feed_ghsa_repos({2026}, list_path=_list(tmp_path, ["a/one", "b/two"]),
                                 state_path=state)
    assert sorted(r["cve_id"] for r in rows) == ["CVE-2026-0001", "CVE-2026-0002"]
    h = feeds.FEED_HEALTH.get("ghsa-repos")
    assert h["status"] == feeds.CAPPED, "a budget stop is a configured limit, not a degradation"
    assert "b/two" in h["detail"], "the resume point has to be in the record"
    assert json.load(open(state))["cursor"] == "b/two"


def test_304_keeps_rows_and_200_replaces_them(monkeypatch, tmp_path):
    """The two authoritative answers. 304 means nothing changed and costs no
    rate-limit quota (measured), so the stored rows stand. 200 is a complete
    restatement of the repo's advisory set and replaces them wholesale, which is
    how a withdrawn advisory leaves the feed."""
    state = _state(tmp_path, {
        "a/keep": {"last_modified": "x", "rows": [_row("CVE-2026-0001")]},
        "b/replace": {"last_modified": "x", "rows": [_row("CVE-2026-0002")]},
    })

    def fake(url, headers=None, timeout=45):
        if "a/keep" in url:
            return 304, None, {}
        return 200, [{"cve_id": "CVE-2026-0009", "ghsa_id": "GHSA-dddd-eeee-ffff",
                      "state": "published", "withdrawn_at": None,
                      "published_at": "2026-07-02T00:00:00Z",
                      "html_url": "https://github.com/b/replace/security/advisories/GHSA-dddd-eeee-ffff"}], {}
    monkeypatch.setattr(feeds, "_get_cond", fake)
    monkeypatch.setattr(feeds, "_rate_exhausted", lambda buf: False)

    rows = feeds.feed_ghsa_repos({2026}, list_path=_list(tmp_path, ["a/keep", "b/replace"]),
                                 state_path=state)
    assert sorted(r["cve_id"] for r in rows) == ["CVE-2026-0001", "CVE-2026-0009"]
    assert "CVE-2026-0002" not in {r["cve_id"] for r in rows}, (
        "a 200 is a full restatement, so the old row must be gone")


def test_404_clears_rows_and_an_error_keeps_them(monkeypatch, tmp_path):
    """The asymmetry that matters. 404 is authoritative-absent, the repo was
    renamed, deleted or made private, so its rows go. A transport error means
    UNKNOWN, not absent, and dropping rows on it would let one bad network minute
    shrink the published count."""
    state = _state(tmp_path, {
        "a/gone": {"last_modified": "x", "rows": [_row("CVE-2026-0001")]},
        "b/flaky": {"last_modified": "x", "rows": [_row("CVE-2026-0002")]},
    })

    def fake(url, headers=None, timeout=45):
        if "a/gone" in url:
            return 404, None, {}
        raise RuntimeError("connection reset")
    monkeypatch.setattr(feeds, "_get_cond", fake)
    monkeypatch.setattr(feeds, "_rate_exhausted", lambda buf: False)

    rows = feeds.feed_ghsa_repos({2026}, list_path=_list(tmp_path, ["a/gone", "b/flaky"]),
                                 state_path=state)
    assert [r["cve_id"] for r in rows] == ["CVE-2026-0002"]
    st = json.load(open(state))
    assert st["repos"]["a/gone"]["rows"] == []
    assert st["repos"]["a/gone"]["not_found_since"]
    assert st["repos"]["b/flaky"]["rows"], "an error dropped rows it could not know were absent"
    assert st["repos"]["b/flaky"]["consecutive_errors"] == 1


def test_an_advisory_may_not_claim_a_cve_for_another_repo(monkeypatch, tmp_path):
    """The advisory AUTHOR controls the cve_id field. Without this check a
    watchlisted repo could attach any id it liked and the site would publish the
    claim as a reserved-but-public finding against whichever CNA owns that id."""
    def fake(url, headers=None, timeout=45):
        return 200, [
            {"cve_id": "CVE-2026-0007", "ghsa_id": "GHSA-1111-2222-3333",
             "state": "published", "withdrawn_at": None,
             "published_at": "2026-07-01T00:00:00Z",
             "html_url": "https://github.com/someone/else/security/advisories/GHSA-1111-2222-3333"},
            {"cve_id": "CVE-2026-0008", "ghsa_id": "GHSA-4444-5555-6666",
             "state": "published", "withdrawn_at": None,
             "published_at": "2026-07-01T00:00:00Z",
             "html_url": "https://github.com/a/one/security/advisories/GHSA-4444-5555-6666"},
        ], {}
    monkeypatch.setattr(feeds, "_get_cond", fake)
    monkeypatch.setattr(feeds, "_rate_exhausted", lambda buf: False)

    rows = feeds.feed_ghsa_repos({2026}, list_path=_list(tmp_path, ["a/one"]),
                                 state_path=_state(tmp_path, {}))
    assert [r["cve_id"] for r in rows] == ["CVE-2026-0008"]


@pytest.mark.parametrize("bad, why", [
    ({"state": "draft"}, "a draft advisory is not public"),
    ({"withdrawn_at": "2026-07-02T00:00:00Z"}, "a withdrawn advisory is not a public claim"),
    ({"cve_id": "CVE-BOGUS"}, "the id becomes a URL and an oracle lookup"),
    ({"cve_id": None}, "no CVE id means there is nothing to be reserved"),
    ({"ghsa_id": "not-a-ghsa"}, "the ghsa id is published as the source reference"),
])
def test_only_published_well_formed_advisories_count(bad, why):
    a = {"cve_id": "CVE-2026-0008", "ghsa_id": "GHSA-4444-5555-6666",
         "state": "published", "withdrawn_at": None,
         "html_url": "https://github.com/a/one/security/advisories/GHSA-4444-5555-6666"}
    assert feeds._repo_advisory_ok(a, "a", "one"), "the clean case stopped being accepted"
    assert not feeds._repo_advisory_ok({**a, **bad}, "a", "one"), why


def test_the_conditional_header_is_not_replayed_on_page_two(monkeypatch, tmp_path):
    """If-Modified-Since belongs to the FIRST page only. Replaying it on page 2
    asks "has anything changed since?" of a URL that answered 200 a moment ago,
    and a 304 there would return half a repo's advisories as though that were the
    whole set, which is a silent shrink with no error anywhere."""
    calls = []

    def fake(url, headers=None, timeout=45):
        calls.append(dict(headers or {}))
        adv = {"cve_id": f"CVE-2026-{len(calls):04d}", "ghsa_id": "GHSA-7777-8888-9999",
               "state": "published", "withdrawn_at": None,
               "published_at": "2026-07-01T00:00:00Z",
               "html_url": "https://github.com/a/one/security/advisories/GHSA-7777-8888-9999"}
        if len(calls) == 1:
            return 200, [adv], {"link": '<https://api.github.com/p2>; rel="next"',
                                "last-modified": "Wed, 26 Aug 2026 00:00:00 GMT"}
        return 200, [adv], {}
    monkeypatch.setattr(feeds, "_get_cond", fake)
    monkeypatch.setattr(feeds, "_rate_exhausted", lambda buf: False)

    feeds.feed_ghsa_repos({2026}, list_path=_list(tmp_path, ["a/one"]),
                          state_path=_state(tmp_path, {
                              "a/one": {"last_modified": "Tue, 25 Aug 2026 00:00:00 GMT",
                                        "rows": []}}))
    assert len(calls) == 2, "the next link was not followed"
    assert "If-Modified-Since" in calls[0]
    assert "If-Modified-Since" not in calls[1], (
        "page 2 was fetched conditionally, so a 304 there would silently halve the repo")


def test_a_missing_repo_list_fails_loudly(monkeypatch, tmp_path):
    """An absent watchlist yields zero rows, and zero rows from a feed that
    returned 1,018 last run must not read as a quiet week."""
    monkeypatch.setattr(feeds, "_rate_exhausted", lambda buf: False)
    rows = feeds.feed_ghsa_repos({2026}, list_path=str(tmp_path / "nope.txt"),
                                 state_path=_state(tmp_path, {}))
    assert rows == []
    assert feeds.FEED_HEALTH["ghsa-repos"]["status"] == feeds.FAILED


def test_the_shipped_watchlist_is_readable_and_well_formed():
    """The list is vendored rather than fetched, so a typo in it is a silent loss
    of every row from that repo. `_read_repo_list` drops anything malformed, and
    that drop is invisible without this."""
    names = feeds._read_repo_list(feeds.GHSA_REPOS_LIST)
    assert len(names) > 1500, f"only {len(names)} repos survived parsing"
    assert len(names) == len(set(names)), "the shipped list has duplicates"
    assert "zephyrproject-rtos/zephyr" in names, (
        "the repo behind CVE-2026-12521, the worked example in the module comment")


def test_the_poller_state_never_reaches_the_public_branch():
    """The state file holds CVE ids by construction, and publish.suppressed_ids
    states the rule: counts, never identifiers, because committing ids to a
    public branch publishes the exact list the withhold lever exists to remove.
    Scrubbing the staged copy is not an escape, because the feed reads its rows
    back from this file and a scrubbed copy would permanently drop them on the
    next 304. So it lives under gitignored data/ and is cached, not staged."""
    from rbp import publish
    assert "ghsa_repos_state.json" not in publish.ALLOWED_ROOT
    assert feeds.GHSA_REPOS_STATE.endswith("data/ghsa_repos_state.json")
    assert "/data/" not in feeds.GHSA_REPOS_LIST, (
        "the watchlist must be COMMITTED, and data/ is gitignored wholesale")


def test_a_repo_advisory_row_links_to_the_repo_and_not_to_the_database():
    """A repository advisory is NOT at /advisories/<id>; it 404s there, which is
    the whole reason this feed exists. Without a branch of its own the row falls
    through to the cve.org last resort, and that page renders NOTHING for a
    RESERVED id, so the site would publish a row whose only evidence link
    disproved it. That exact defect already shipped once, for CSAF."""
    from rbp import report
    _pkg, _eco, _vendor, url, source_urls = report._derive_meta({
        "cve_id": "CVE-2026-12521", "sources": "ghsa-repos",
        "refs": "ghsa-repos:zephyrproject-rtos/zephyr\tGHSA-g5v9-xmfp-7gxm"})
    want = ("https://github.com/zephyrproject-rtos/zephyr"
            "/security/advisories/GHSA-g5v9-xmfp-7gxm")
    assert url == want, url
    assert source_urls == {"ghsa-repos": want}, source_urls


def test_the_repo_advisory_link_wins_over_the_database_link():
    """For a row both GitHub feeds carry, the repo's own page is the same advisory
    at the publisher's address rather than at the database's, so it takes
    precedence. Both still appear in source_urls, which is the field that answers
    "where is this showing up"."""
    from rbp import report
    _pkg, _eco, _vendor, url, source_urls = report._derive_meta({
        "cve_id": "CVE-2026-12521", "sources": "ghsa,ghsa-repos",
        "refs": ("ghsa:GHSA-g5v9-xmfp-7gxm;"
                 "ghsa-repos:zephyrproject-rtos/zephyr\tGHSA-g5v9-xmfp-7gxm")})
    assert "zephyrproject-rtos/zephyr" in url, url
    assert set(source_urls) == {"ghsa", "ghsa-repos"}


def test_a_repo_advisory_ref_without_its_repo_yields_no_link():
    """The tab-separated ref is built in one place and read in another. A ref that
    lost its repo half must produce NO url rather than a malformed github.com
    path, because the last-resort branch is then correct to fire."""
    from rbp import report
    _pkg, _eco, _vendor, url, source_urls = report._derive_meta({
        "cve_id": "CVE-2026-12521", "sources": "ghsa-repos",
        "refs": "ghsa-repos:GHSA-g5v9-xmfp-7gxm"})
    assert source_urls == {}, source_urls
    assert url == "https://www.cve.org/CVERecord?id=CVE-2026-12521"
