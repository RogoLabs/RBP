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
    got = feeds._csaf_directory_entries("https://example.invalid/advisories/", {2026}, 50)
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
    got = feeds._csaf_directory_entries("https://x.invalid/d", {2025, 2026}, 50)
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
    got = feeds._csaf_directory_entries("https://suse.invalid/csaf", {2025, 2026}, 50)
    names = [u.rsplit("/", 1)[-1] for _, u in got]
    assert names == ["new.json", "mid.json"], (
        "an ascending listing must still yield its recent rows, newest first")


def test_the_cap_keeps_the_newest_whatever_order_the_file_is_in(monkeypatch):
    """The cap is a recency cap. Against an ascending file the old code would
    have kept the OLDEST rows, which is the worst of both worlds: a truncated
    read that also throws away everything a reader came for."""
    csv = "".join(f'"2026/a{i:02d}.json","2026-08-{i:02d}T00:00:00Z"\n'
                  for i in range(1, 20))          # ascending, oldest first
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://x.invalid/d", {2026}, 3)
    assert [u.rsplit("/", 1)[-1] for _, u in got] == ["a19.json", "a18.json", "a17.json"]


def test_cap_is_respected(monkeypatch):
    csv = "".join(f'"2026/a{i}.json","2026-08-{i:02d}T00:00:00Z"\n' for i in range(1, 20))
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    assert len(feeds._csaf_directory_entries("https://x.invalid/d", {2026}, 5)) == 5


def test_malformed_rows_are_skipped(monkeypatch):
    csv = ('garbage-with-no-comma\n'
           '"2026/ok.json","2026-08-20T00:00:00Z"\n'
           '\n')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://x.invalid/d", {2026}, 50)
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
    got = feeds._csaf_directory_entries("https://cisco.invalid/csaf", {2025, 2026}, 2)
    names = [u.rsplit("/", 1)[-1] for _, u in got]
    assert names == ["actually-new.json"], (
        f"the cap was spent on revisions of out-of-window advisories: {names}")


def test_a_path_with_no_year_segment_is_kept(monkeypatch):
    """The path filter narrows a selection that is already too broad. It must
    never invent a reason to drop an advisory it cannot date."""
    csv = ('"advisories/vendor-sa-001.json","2026-08-26T00:00:00Z"\n'
           '"vendor-sa-002.json","2026-08-25T00:00:00Z"\n')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://v.invalid/csaf", {2025, 2026}, 50)
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
    got = feeds._csaf_directory_entries("https://x.invalid/d", {2025, 2026}, 50)
    names = [u.rsplit("/", 1)[-1] for _, u in got]
    assert "old.json" not in names
    assert set(names) == {"new.json", "alsonew.json"}
    assert any("changes.csv" in c for c in calls), "changes.csv should be tried first"


def test_no_listing_at_all_returns_empty(monkeypatch):
    def fake(u, timeout=30):
        raise RuntimeError("404")
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: fake(u))
    assert feeds._csaf_directory_entries("https://x.invalid/d", {2026}, 50) == []


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
