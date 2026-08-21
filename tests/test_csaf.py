"""
CSAF directory distributions.

The adapter originally handled only ROLIE feeds. The spec defines a second
distribution shape, `directory_url`, and every provider using it yielded nothing
while logging as though it simply had no recent advisories. Red Hat, Huawei and
Schneider Electric are all directory-only, so three of the largest publishers in
the list contributed zero.
"""
from __future__ import annotations

import pytest

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


def test_newest_first_ordering_lets_us_stop_early(monkeypatch):
    """changes.csv is newest-first, so the first out-of-window row means every
    later row is older too. Stopping there is what keeps Red Hat's 1.5 MB
    listing cheap instead of parsing 25 years of advisories."""
    csv = ('"2026/a.json","2026-08-20T00:00:00Z"\n'
           '"2025/b.json","2025-06-01T00:00:00Z"\n'
           '"2019/c.json","2019-01-01T00:00:00Z"\n'
           '"2026/d.json","2026-01-01T00:00:00Z"\n')
    monkeypatch.setattr(feeds, "_get_text", lambda u, timeout=30: csv)
    got = feeds._csaf_directory_entries("https://x.invalid/d", {2025, 2026}, 50)
    # Stops at the 2019 row, so the trailing 2026 entry is deliberately not read.
    assert [u.rsplit("/", 1)[-1] for _, u in got] == ["a.json", "b.json"]


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
