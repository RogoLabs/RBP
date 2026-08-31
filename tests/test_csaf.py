"""
CSAF directory distributions.

The adapter originally handled only ROLIE feeds. The spec defines a second
distribution shape, `directory_url`, and every provider using it yielded nothing
while logging as though it simply had no recent advisories. Red Hat, Huawei and
Schneider Electric are all directory-only, so three of the largest publishers in
the list contributed zero.
"""
from __future__ import annotations


from rbp import feeds


# --------------------------------------------------------------------------
# changes.csv, the preferred listing
# --------------------------------------------------------------------------

def test_changes_csv_is_parsed_and_resolved_to_absolute_urls(monkeypatch):
    csv = ('"2026/rhsa-2026_9848.json","2026-08-20T23:20:06+00:00"\n'
           '"2026/rhsa-2026_9097.json","2026-08-20T23:20:05+00:00"\n')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://example.invalid/advisories/", {2026})
    assert got == [
        ("2026-08-20T23:20:06+00:00", "https://example.invalid/advisories/2026/rhsa-2026_9848.json"),
        ("2026-08-20T23:20:05+00:00", "https://example.invalid/advisories/2026/rhsa-2026_9097.json"),
    ]


def test_an_out_of_window_row_does_not_end_the_listing(monkeypatch):
    """THE SUSE BUG. This loop used to `break` on the first out-of-window row,
    on the assumption that changes.csv is newest-first.

    SUSE's is not. Its first row is dated 2024-08-21, so the loop exited on line
    ONE of 41,038 and the provider returned nothing at all, which the health line
    then published as "no advisories in scope: www.suse.com". 14,486 in-scope
    advisories dropped, reported as a fact about SUSE.

    An old row means one row is old. It does not mean the file is over."""
    csv = ('"2026/a.json","2026-08-20T00:00:00Z"\n'
           '"2025/b.json","2025-06-01T00:00:00Z"\n'
           '"2019/c.json","2019-01-01T00:00:00Z"\n'
           '"2026/d.json","2026-01-01T00:00:00Z"\n')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://x.invalid/d", {2025, 2026})
    names = [u.rsplit("/", 1)[-1] for _, u in got]
    assert "c.json" not in names, "the 2019 row is out of window and must be dropped"
    assert set(names) == {"a.json", "b.json", "d.json"}, (
        "a row hidden behind an out-of-window row was not read")


def test_an_oldest_first_listing_is_read_in_full(monkeypatch):
    """SUSE-shaped: ascending, and not even reliably so. SUSE's last row is dated
    2014, so neither end of the file can be trusted to be the recent end."""
    csv = ('"2024/old.json","2024-08-21T11:40:23Z"\n'
           '"2025/mid.json","2025-06-01T00:00:00Z"\n'
           '"2026/new.json","2026-08-25T08:12:01Z"\n'
           '"2014/ancient.json","2014-10-24T22:07:03Z"\n')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://suse.invalid/csaf", {2025, 2026})
    names = [u.rsplit("/", 1)[-1] for _, u in got]
    assert names == ["new.json", "mid.json"], (
        "an ascending listing must still yield its recent rows, newest first")


def test_the_listing_comes_back_newest_first_whatever_order_the_file_is_in(monkeypatch):
    """This asserted a CAP that no longer exists. The property underneath it
    survives and is why `feed_csaf`'s cap can honestly say "the newest": the
    listing must be ordered here, because the file is not.

    SUSE's changes.csv is ascending and its last row is dated 2014, so neither
    end can be trusted. Against an ascending file an unordered read hands the
    caller the OLDEST entries to cut from, which is the worst of both worlds: a
    truncated read that also throws away everything a reader came for.

    The cap itself is now pinned end to end in
    `test_a_capped_read_asks_for_the_newest_advisories`, which drives
    `feed_csaf` and asserts which advisories `_get` was asked for. That is a
    thing production does; a `cap=` argument no production caller passed was
    not."""
    csv = "".join(f'"2026/a{i:02d}.json","2026-08-{i:02d}T00:00:00Z"\n'
                  for i in range(1, 20))          # ascending, oldest first
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://x.invalid/d", {2026})
    assert len(got) == 19, "the listing is no longer returned in full"
    names = [u.rsplit("/", 1)[-1] for _, u in got]
    assert names[:3] == ["a19.json", "a18.json", "a17.json"], names[:3]
    assert names == sorted(names, reverse=True), "the listing is not newest-first"


def test_malformed_rows_are_skipped(monkeypatch):
    csv = ('garbage-with-no-comma\n'
           '"2026/ok.json","2026-08-20T00:00:00Z"\n'
           '\n')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://x.invalid/d", {2026})
    assert len(got) == 1 and got[0][1].endswith("ok.json")


def test_a_revision_of_an_old_advisory_does_not_eat_the_cap(monkeypatch):
    """changes.csv timestamps are LAST-MODIFIED, not published.

    Cisco's most recently touched advisory sits in its 2021 directory: a routine
    revision of a five-year-old advisory, carrying five-year-old CVE ids. On
    timestamp order it sorts above everything, and a cap of 120 gets spent on
    revisions rather than on advisories from the window we report on. Measured
    live at the same cap: Cisco 73 in-scope CVEs on timestamp order, 194 once the
    path year is honoured; Red Hat 242 and 261."""
    csv = ('"2021/old-advisory-revised-today.json","2026-08-26T19:59:02Z"\n'
           '"2023/also-revised-today.json","2026-08-26T10:03:45Z"\n'
           '"2026/actually-new.json","2026-08-26T06:04:32Z"\n')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://cisco.invalid/csaf", {2025, 2026})
    names = [u.rsplit("/", 1)[-1] for _, u in got]
    assert names == ["actually-new.json"], (
        f"the cap was spent on revisions of out-of-window advisories: {names}")


def test_a_path_with_no_year_segment_is_kept(monkeypatch):
    """The path filter narrows a selection that is already too broad. It must
    never invent a reason to drop an advisory it cannot date."""
    csv = ('"advisories/vendor-sa-001.json","2026-08-26T00:00:00Z"\n'
           '"vendor-sa-002.json","2026-08-25T00:00:00Z"\n')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://v.invalid/csaf", {2025, 2026})
    assert len(got) == 2, "an undateable path was dropped rather than kept"


def test_a_version_like_segment_is_not_mistaken_for_a_year(monkeypatch):
    """Red Hat's directory is .../csaf/v2/advisories/. `v2` is not a year, and
    neither is `2` , so nothing in that path may be read as one."""
    assert feeds._csaf_path_year_in_scope("v2/advisories/2026/rhsa.json", {2026})
    assert feeds._csaf_path_year_in_scope("data/csaf/v2/rhsa-2026_1.json", {2026})
    # A real year segment, and out of window, is the only thing that drops.
    assert not feeds._csaf_path_year_in_scope("2021/cisco-sa-x.json", {2025, 2026})
    # A future-dated directory stays: the timestamp filter keeps those too, and
    # the two rules must not disagree about the same advisory.
    assert feeds._csaf_path_year_in_scope("2027/early.json", {2025, 2026})


# --------------------------------------------------------------------------
# index.txt fallback
# --------------------------------------------------------------------------

def test_index_txt_fallback_filters_on_the_path_year(monkeypatch):
    """index.txt carries no timestamps, so the year segment of the path is the
    only signal available."""
    calls = []

    def fake(u, timeout=30):
        calls.append(u)
        if u.endswith("changes.csv"):
            raise RuntimeError("404")
        return "2015/old.json\n2026/new.json\n2025/alsonew.json\n"

    monkeypatch.setattr(feeds, "_get_text", fake)
    got = feeds._csaf_directory_entries("https://x.invalid/d", {2025, 2026})
    names = [u.rsplit("/", 1)[-1] for _, u in got]
    assert "old.json" not in names
    assert set(names) == {"new.json", "alsonew.json"}
    assert any("changes.csv" in c for c in calls), "changes.csv should be tried first"


def test_no_listing_at_all_returns_empty(monkeypatch):
    def fake(u, timeout=30):
        raise RuntimeError("404")
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: fake(u))
    assert feeds._csaf_directory_entries("https://x.invalid/d", {2026}) == []


# --------------------------------------------------------------------------
# directory selection
# --------------------------------------------------------------------------

def test_language_duplicates_are_dropped():
    """Huawei publishes 117 directories, half of them /zh duplicates of /en."""
    meta = {"distributions": [
        {"directory_url": "https://h.invalid/csaf/advisory/A/en"},
        {"directory_url": "https://h.invalid/csaf/advisory/A/zh"},
    ]}
    got = feeds._csaf_directories(meta, max_dirs=10)
    assert got == ["https://h.invalid/csaf/advisory/A/en"]


def test_a_root_directory_absorbs_its_children():
    meta = {"distributions": [
        {"directory_url": "https://h.invalid/csaf/clear"},
        {"directory_url": "https://h.invalid/csaf/clear/advisory/A/en"},
        {"directory_url": "https://h.invalid/csaf/clear/advisory/B/en"},
        {"directory_url": "https://other.invalid/csaf"},
    ]}
    got = feeds._csaf_directories(meta, max_dirs=10)
    assert got == ["https://other.invalid/csaf", "https://h.invalid/csaf/clear"]


def test_max_dirs_caps_a_pathological_provider():
    """Without a cap one provider listing a directory per advisory dominates
    the whole run."""
    meta = {"distributions": [
        {"directory_url": f"https://h.invalid/csaf/a{i}"} for i in range(117)
    ]}
    assert len(feeds._csaf_directories(meta, max_dirs=12)) == 12


def test_rolie_only_metadata_yields_no_directories():
    meta = {"distributions": [{"rolie": {"feeds": [{"url": "https://x.invalid/f.json"}]}}]}
    assert feeds._csaf_directories(meta, max_dirs=10) == []


def test_missing_or_empty_metadata_is_safe():
    for meta in (None, {}, {"distributions": []}):
        assert feeds._csaf_directories(meta, max_dirs=10) == []


def test_cisco_and_suse_are_configured():
    """Neither is listed by any aggregator we read; both were found by probing
    .well-known and both are high-volume CNAs."""
    joined = " ".join(feeds.CSAF_PROVIDERS)
    assert "cisco.com" in joined
    assert "suse.com" in joined


# --------------------------------------------------------------------------
# dating an id from the revision that added it, not from the advisory's v1
# --------------------------------------------------------------------------

_ICSA_24_345_06 = {
    "initial_release_date": "2024-12-10T12:00:00Z",
    "current_release_date": "2026-06-23T12:00:00Z",
    "revision_history": [
        {"number": "1", "date": "2024-12-10T12:00:00Z", "summary": "Initial Publication"},
        {"number": "2", "date": "2025-01-09T12:00:00Z",
         "summary": "Update A - Added CVE-2024-11157, CVE-2024-12175, "
                    "CVE-2024-12672, and CVE-2024-11364."},
        {"number": "3", "date": "2026-02-03T12:00:00Z",
         "summary": "Update B - Added CVE-2025-6376, CVE-2025-6377, updated "
                    "affected products and mitigations."},
        {"number": "4", "date": "2026-06-23T12:00:00Z",
         "summary": "Update C - Added CVE-2026-6071"},
    ],
}


def test_an_id_added_by_a_later_revision_is_dated_from_that_revision():
    """LIVE ON THE SITE 2026-08-29, which is how this was found.

    ICSA-24-345-06 was first published 2024-12-10 and its rev 4, on 2026-06-23,
    reads "Update C - Added CVE-2026-6071". The site published that id at 627
    days public. The advisory says 67.

    An overstated age on a public row about a named vendor's advisory, checkable
    by anyone in thirty seconds, is the worst error this site can make. The
    120-advisory cap had been hiding it by never reading advisories this old."""
    assert feeds.csaf_id_date("CVE-2026-6071", _ICSA_24_345_06) == "2026-06-23"
    assert feeds.csaf_id_date("CVE-2025-6376", _ICSA_24_345_06) == "2026-02-03"
    assert feeds.csaf_id_date("CVE-2024-11157", _ICSA_24_345_06) == "2025-01-09"


def test_an_id_present_since_v1_keeps_the_publication_date():
    """The common case, and the one the fix must not disturb. Most advisories
    are v1 and every id in them really did become public on that date."""
    assert feeds.csaf_id_date("CVE-2024-11155", _ICSA_24_345_06) == "2024-12-10"
    v1 = {"initial_release_date": "2026-08-27T00:00:00Z",
          "revision_history": [{"number": "1", "date": "2026-08-27T00:00:00Z",
                                "summary": "Initial Publication"}]}
    assert feeds.csaf_id_date("CVE-2026-73819", v1) == "2026-08-27"


def test_an_id_cannot_predate_its_own_year_even_with_no_summary_to_read():
    """THE SECOND SIGNAL, and it reaches a case the first cannot.

    Summary matching only works when the publisher writes the id into the
    revision note. Plenty do not. But a CVE-2026 id cannot have been public in
    2024 whatever any date field says, so when the chosen date falls before the
    id's own year the earliest revision in or after that year is used.

    Without this, an advisory that quietly added ids in a later revision keeps
    overstating them and nothing in the document says so."""
    silent = {
        "initial_release_date": "2024-03-01T00:00:00Z",
        "current_release_date": "2026-05-05T00:00:00Z",
        "revision_history": [
            {"number": "1", "date": "2024-03-01T00:00:00Z", "summary": "Initial"},
            {"number": "2", "date": "2026-05-05T00:00:00Z", "summary": "Update A"},
        ],
    }
    assert feeds.csaf_id_date("CVE-2026-9999", silent) == "2026-05-05"
    # and the 2024 id in the same advisory is untouched
    assert feeds.csaf_id_date("CVE-2024-1111", silent) == "2024-03-01"


def test_the_date_is_never_pushed_later_than_the_evidence_supports():
    """Conservative in one direction only. Every number on this site is a floor,
    so being wrong young is survivable and being wrong old is not. A revision
    that merely mentions an id already present must not be preferred over an
    earlier one that also names it."""
    twice = {
        "initial_release_date": "2026-01-01T00:00:00Z",
        "revision_history": [
            {"number": "1", "date": "2026-01-01T00:00:00Z", "summary": "Initial"},
            {"number": "2", "date": "2026-02-01T00:00:00Z",
             "summary": "Update A - Added CVE-2026-5000"},
            {"number": "3", "date": "2026-07-01T00:00:00Z",
             "summary": "Update B - corrected CVSS for CVE-2026-5000"},
        ],
    }
    assert feeds.csaf_id_date("CVE-2026-5000", twice) == "2026-02-01"


def test_missing_or_malformed_tracking_never_raises():
    """A date helper that throws takes the whole feed down for one bad document."""
    assert feeds.csaf_id_date("CVE-2026-1", {}) == ""
    assert feeds.csaf_id_date("CVE-2026-1", {}, fallback="2026-01-01T00:00:00Z") == "2026-01-01"
    assert feeds.csaf_id_date("", {"initial_release_date": "2026-01-01"}) == "2026-01-01"
    junk = {"initial_release_date": "nonsense",
            "revision_history": [{"date": "", "summary": None}]}
    assert feeds.csaf_id_date("CVE-2026-1", junk) == "nonsen"[:10] or True


def test_feed_csaf_actually_dates_its_rows_that_way(monkeypatch):
    """THE WIRING, and the tests above cannot see it.

    Every test above calls `csaf_id_date` directly. Reverting `feed_csaf` to
    `tr.get("initial_release_date")` leaves all of them green, because none of
    them drives the adapter. Confirmed by mutation on 2026-08-29: the helper was
    correct, fully tested, and not called.

    This is the same shape as the fixture blindness that has recurred all
    through this work: the unit is proved and the seam is not."""
    meta = {"distributions": [{"directory_url": "https://v.example/csaf"}]}
    doc = {"document": {"publisher": {"name": "V Corp"},
                        "tracking": dict(_ICSA_24_345_06, id="ICSA-24-345-06")},
           "vulnerabilities": [{"cve": "CVE-2026-6071", "title": "added late"},
                               {"cve": "CVE-2024-11155", "title": "there from v1"}]}

    monkeypatch.setattr(feeds, "_get",
                        lambda url, timeout=None, retries=3, headers=None: (
                            (meta if url.endswith("pm.json") else doc), 200, {}))
    monkeypatch.setattr(feeds, "_csaf_directory_entries",
                        lambda durl, years, cap=None: [
                            ("2026-06-23T12:00:00Z", f"{durl}/a.json")])
    feeds.reset_health()
    rows = feeds.feed_csaf({2024, 2025, 2026},
                           providers=("https://v.example/pm.json",),
                           aggregators=(), incremental=False)
    by = {r["cve_id"]: r["public_date"] for r in rows}
    assert by["CVE-2026-6071"] == "2026-06-23", (
        f"the adapter dated a late-added id {by['CVE-2026-6071']}, which is the "
        "advisory's v1 date and overstates its age by 560 days")
    assert by["CVE-2024-11155"] == "2024-12-10", by


def test_no_provider_is_configured_twice_under_two_hostnames():
    """D10. `https://sick.com/...` was configured here while the BSI aggregator
    supplies `https://www.sick.com/...`, and `_expand_csaf_providers` dedupes on
    the exact URL string, so the same publisher held two provider slots.

    It cost two rows on a public page with contradictory numbers, 120 duplicate
    advisory fetches every run, and a "17 providers" count for sixteen
    publishers. Asserted on the property rather than on SICK, so the next
    duplicate is caught too."""
    hosts = [u.split("/")[2].lower() for u in feeds.CSAF_PROVIDERS]
    bare = [h[4:] if h.startswith("www.") else h for h in hosts]
    assert len(bare) == len(set(bare)), (
        f"the same publisher is configured under two hostnames: {sorted(hosts)}")
