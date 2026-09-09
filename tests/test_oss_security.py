"""The oss-security archive, read one month index at a time.

This feed is the cheapest thing in the project and the reason to be careful with
it is exactly that: 45 requests buy a four-year window, so nothing about the cost
will ever push back on a parsing mistake. Every test here is a trap this
repository has already paid for somewhere.

  * A DAY LINK AND A MESSAGE LINK differ by one character. `href="08/"` is a day
    and `href="08/9"` is a message, and counting days as messages would attach
    every id to the wrong URL.
  * A FUTURE MONTH ANSWERS 200. `2026/12/` serves an empty calendar rather than a
    404, which is the "a 200 is still not a feed" trap FEEDS.md records being
    caught by four times.
  * AN ID IS RE-POSTED. `public_date` is a floor on how long an id has been
    public, so a later thread must never move it forward.
  * A ZERO FROM A FAILED READ AND A ZERO FROM A QUIET MONTH ARE DIFFERENT, and
    the shrink guard reads both as a number.
  * WHO IS SPEAKING is not knowable from the index, which is why this feed is a
    tracker and not an advisory.
"""
import datetime as dt
import re

from rbp import clock, feeds, report


def _msg(day, num, subject):
    return f'<li><a href="{day:02d}/{num}">{subject}</a></li>'


def _month(*messages):
    return ("<html><body><ul>"
            + "".join(f'<li><a href="{d:02d}/">{d}</a></li>' for d in (1, 2, 3))
            + "".join(messages) + "</ul></body></html>")


def _pages(mapping, missing=()):
    """Serve a canned month index, or raise for a month in `missing`."""
    def fake(url, timeout=30):
        key = url.rstrip("/").rsplit("/lists/oss-security/", 1)[1]
        if key in missing:
            raise OSError(f"boom {key}")
        return mapping.get(key, _month())
    return fake


def test_every_row_carries_a_well_formed_archive_path(monkeypatch):
    r"""The ref IS the URL, so its shape is the evidence contract.

    `report._u` builds nothing for a ref that is not `YYYY/MM/DD/N`, which is the
    right refusal and also means a malformed ref ships a row with no link rather
    than a wrong one. That failure is silent at the adapter, so it is asserted
    here instead.

    MUTATION-TESTED AND ONE SURVIVOR RECORDED, because a test that reads as
    coverage it does not have is worse than no test. Relaxing the message regex
    from `(\d+)` to `(\d*)` makes day links (`href="08/"`) match as messages and
    fails NOTHING, here or anywhere: a day anchor's text is the day number, it
    carries no CVE id, so it produces no row and the difference is unobservable.
    The `+` is defensive rather than load-bearing and this paragraph is the only
    honest thing to say about it. What IS load-bearing is the shape below, which
    is why the assertion moved here."""
    page = _month(_msg(8, 9, "XSA-512 (CVE-2026-79604) oxenstored"),
                  _msg(24, 5, "CVE-2026-78331 / CVE-2026-78332: NethServer"))
    monkeypatch.setattr(feeds, "_get_text", _pages({"2026/09": page}))
    rows = feeds.feed_oss_security({2026}, today=dt.date(2026, 9, 30))
    assert len(rows) == 3
    for r in rows:
        assert re.fullmatch(r"\d{4}/\d{2}/\d{2}/\d+", r["source_ref"]), r
        assert report._derive_meta(
            {"cve_id": r["cve_id"], "sources": "oss-security",
             "refs": f"oss-security:{r['source_ref']}"})[2].get("oss-security")


def test_the_subject_is_unescaped_and_stripped(monkeypatch):
    """Subjects carry entities and markup. An id is not affected by either, but
    the description shipped beside it on the site is, and a row whose evidence
    line reads `&lt;b&gt;` is a row a reader distrusts."""
    page = _month(_msg(3, 2, "[OSSA-2026-038] <b>Glance</b>: SSRF &amp; more "
                             "(CVE-2026-71196)"))
    monkeypatch.setattr(feeds, "_get_text", _pages({"2026/09": page}))
    rows = feeds.feed_oss_security({2026}, today=dt.date(2026, 9, 30))
    assert rows[0]["description"] == ("[OSSA-2026-038] Glance: SSRF & more "
                                      "(CVE-2026-71196)")


def test_the_earliest_posting_sets_the_date(monkeypatch):
    """`public_date` is a FLOOR on how long an id has been public. An id posted
    in March and discussed again in September is 6 months public, not 1 day, and
    a later thread winning would understate the age of the oldest evidence."""
    monkeypatch.setattr(feeds, "_get_text", _pages({
        "2026/03": _month(_msg(5, 3, "Xen Security Notice 2 (CVE-2024-35347)")),
        "2026/09": _month(_msg(8, 1, "Re: Xen Security Notice 2 (CVE-2024-35347)")),
    }))
    rows = feeds.feed_oss_security({2024, 2026}, today=dt.date(2026, 9, 30))
    assert len(rows) == 1
    assert rows[0]["public_date"] == "2026-03-05"


def test_an_id_outside_the_window_is_dropped(monkeypatch):
    page = _month(_msg(8, 1, "CVE-2019-1111 and CVE-2026-79604 in one subject"))
    monkeypatch.setattr(feeds, "_get_text", _pages({"2026/09": page}))
    rows = feeds.feed_oss_security({2026}, today=dt.date(2026, 9, 30))
    assert [r["cve_id"] for r in rows] == ["CVE-2026-79604"]


def test_one_subject_can_carry_several_ids(monkeypatch):
    """XSA-513 named two in its subject and the NethServer post named two. An
    adapter that takes the first match loses half of them, which is the ZDI
    one-cell-several-ids trap in a different document."""
    page = _month(_msg(8, 10, "XSA 513 v3 (CVE-2026-79605,CVE-2026-79606) Tapdisk"))
    monkeypatch.setattr(feeds, "_get_text", _pages({"2026/09": page}))
    rows = feeds.feed_oss_security({2026}, today=dt.date(2026, 9, 30))
    assert sorted(r["cve_id"] for r in rows) == ["CVE-2026-79605", "CVE-2026-79606"]
    assert {r["source_ref"] for r in rows} == {"2026/09/08/10"}


def test_a_future_month_is_never_requested(monkeypatch):
    """`2026/12/` answers 200 with an empty calendar rather than 404, so nothing
    in the response says the month has not happened. The loop has to know."""
    asked = []

    def fake(url, timeout=30):
        asked.append(url.rstrip("/").rsplit("/lists/oss-security/", 1)[1])
        return _month()

    monkeypatch.setattr(feeds, "_get_text", fake)
    feeds.feed_oss_security({2026}, today=dt.date(2026, 9, 9))
    assert asked == [f"2026/{m:02d}" for m in range(1, 10)]
    assert "2026/12" not in asked


def test_every_month_failing_is_recorded_as_a_failure_not_a_zero(monkeypatch):
    """`gather` records a raising adapter as FAILED and an empty one as a
    success with zero rows, and those are materially different claims. A feed
    whose host is down must not read as a feed with nothing to say."""
    feeds.reset_health()
    monkeypatch.setattr(feeds, "_get_text",
                        _pages({}, missing={f"2026/{m:02d}" for m in range(1, 10)}))
    rows = feeds.feed_oss_security({2026}, today=dt.date(2026, 9, 9))
    assert rows == []
    assert feeds.FEED_HEALTH["oss-security"]["status"] == feeds.FAILED


def test_some_months_failing_truncates_rather_than_shrinking_silently(monkeypatch):
    """A partial read returns real rows AND drops the rest, which is the state
    `TRUNCATED` exists for. Recording it as ok is how a feed shrinks silently,
    and this project has had that happen twice."""
    feeds.reset_health()
    monkeypatch.setattr(feeds, "_get_text", _pages(
        {"2026/09": _month(_msg(8, 1, "CVE-2026-79604 oxenstored"))},
        missing={"2026/07"}))
    rows = feeds.feed_oss_security({2026}, today=dt.date(2026, 9, 9))
    assert len(rows) == 1
    health = feeds.FEED_HEALTH["oss-security"]
    assert health["status"] == feeds.TRUNCATED
    assert "2026-07" in health["detail"]


def test_a_quiet_month_is_a_real_zero(monkeypatch):
    """The other half of the test above. A month that answered and held no id is
    a success, not a truncation, or every August would degrade the run."""
    feeds.reset_health()
    monkeypatch.setattr(feeds, "_get_text", _pages({}))
    rows = feeds.feed_oss_security({2026}, today=dt.date(2026, 9, 9))
    assert rows == []
    assert "oss-security" not in feeds.FEED_HEALTH


def test_a_mailing_list_post_is_a_tracker_and_says_so(monkeypatch):
    """The judgement this feed turns on. The index cannot say whether the poster
    is the owning CNA, and a forwarded advisory reads exactly like a first-party
    one, so calling it an advisory would start a 72-hour MUST clock on rows where
    the CNA may not have spoken. Mapped rather than omitted: `origin_kind`
    fail-safes to the same answer, and an unstated classification is the thing
    `tests/test_pipeline.py` refuses."""
    assert clock.origin_kind("oss-security") == "tracker"
    assert "oss-security" in clock._ORIGIN_KIND
    row = {"cve_id": "CVE-2026-79604", "dates": {"oss-security": "2026-09-08"}}
    assert clock.advisory_date(row) is None


def test_the_link_is_the_message_and_not_the_month(monkeypatch):
    """A month index lists a few hundred subjects, so linking to it would make a
    reader hunt for the id. That is the dead-chip failure F3 was about, wearing a
    200."""
    row = {"cve_id": "CVE-2026-79604", "sources": "oss-security",
           "refs": "oss-security:2026/09/08/9"}
    urls = report._derive_meta(row)[2]
    assert urls["oss-security"] == "https://www.openwall.com/lists/oss-security/2026/09/08/9"


def test_a_ref_that_is_not_an_archive_path_builds_no_link():
    """Same rule as `jvn`, `zdi` and `certcc`: the path IS the ref, so anything
    else must build nothing rather than a plausible 404."""
    for bad in ("oss-security:somepackage", "oss-security:2026/09/08",
                "oss-security:../../etc"):
        row = {"cve_id": "CVE-2026-1111", "sources": "oss-security", "refs": bad}
        assert not report._derive_meta(row)[2].get("oss-security")


def test_it_is_an_adapter_and_deliberately_not_in_the_profile():
    """The one direction the two lists are allowed to differ.

    `feedlab.fetch` refuses to score a feed that is not an adapter, because being
    scoreable and being runnable must be the same condition. So a candidate has
    to be in ADAPTERS before it has a scorecard, and it must NOT be in the
    profile until someone decides on that scorecard: `cli.PROFILES["weekly"]` is
    what the cron runs and what reaches the site.

    THIS TEST INVERTS WHEN THE FEED IS MERGED. `test_zdi_is_in_the_profile_the_
    cron_runs` is the shape it becomes, and the diff that flips it is the diff
    that adds `oss-security` to `_WEEKLY`."""
    from rbp.cli import PROFILES
    assert "oss-security" in feeds.ADAPTERS
    assert "oss-security" not in PROFILES["weekly"].split(","), (
        "oss-security is now in the profile the cron runs, so this test should "
        "have been inverted in the same diff: assert it IS there, and confirm "
        "its scorecard is in that diff too.")


def test_it_has_a_committed_scorecard():
    """FEEDS.md section 3: no feed is merged without its scorecard in the diff.
    It is also what `scorecard_baselines` reads as the stand-in shrink baseline
    for a feed with no previous count, so the card has to exist before the first
    run and not after it."""
    seeds = feeds.scorecard_baselines(["oss-security"])
    assert seeds.get("oss-security", {}).get("rows", 0) > 0, (
        "feedlab/oss-security.json is missing or records no ids")
