"""JVN's English yearly RDFs, and the three traps that make this feed look
harder than it is.

FEEDS.md, "MEASURED 2026-09-05", priced this feed at 585 requests because it
recorded that JVN's CVE ids sit in HTML-escaped prose with no structured field.
That is true of `<sec:identifier>`, which carries JVNDB ids, and false of the
item as a whole: `<sec:references source="CVE" id="CVE-...">` is structured,
typed, and the field the adapter reads. Measured against `getVulnDetailInfo` on
30 sampled advisories before the calls were dropped, 30 of 30 agreeing.

Each test below is a trap already paid for somewhere in this repository:

  * a full-text regex over the same document finds seven ids the advisory does
    not publish, which is the GIT trap
  * one yearly RDF failing while the other loads halves the feed and looks
    healthy, which is the silent shrink
  * the coordinated advisories are in the ENGLISH YEARLY tree; `jvndb.rdf` is
    the iPedia mirror of NVD, 29,231 entries for 2024 alone
  * a coordinator feed credits the CNA that owns the id, never the CNA that
    publishes the advisory, which is what made this feed look worthless
"""
import pytest

from rbp import clock, feeds


def _rdf(items, year=2026):
    """A JVN yearly RDF with the namespaces the real document declares."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
        ' xmlns="http://purl.org/rss/1.0/"'
        ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
        ' xmlns:dcterms="http://purl.org/dc/terms/"'
        ' xmlns:sec="http://jvn.jp/rss/mod_sec/">\n'
        f'<channel rdf:about="x"><title>JVNDB {year}</title></channel>\n'
        + "\n".join(items) +
        "\n</rdf:RDF>\n")


def _item(vid, title, refs, issued):
    body = "".join(
        f'<sec:references source="{src}" id="{rid}">https://x/{rid}'
        f'</sec:references>' for src, rid in refs)
    return (f'<item rdf:about="https://jvndb.jvn.jp/en/contents/x/{vid}.html">'
            f'<title>{title}</title>'
            f'<description>prose mentioning CVE-1999-0001 in passing</description>'
            f'<sec:identifier>{vid}</sec:identifier>'
            f'{body}'
            f'<dcterms:issued>{issued}</dcterms:issued>'
            f'</item>')


def _serve(monkeypatch, by_year):
    """Serve one document per yearly URL; a year absent from the map raises."""
    def fake(url, timeout=60):
        for year, doc in by_year.items():
            if f"jvndb_{year}.rdf" in url:
                if isinstance(doc, Exception):
                    raise doc
                return doc
        raise AssertionError(f"adapter fetched an unexpected url: {url}")
    monkeypatch.setattr(feeds, "_get_text", fake)


def test_the_cve_id_comes_from_the_typed_attribute_not_the_prose(monkeypatch):
    """THE GIT TRAP, in the one place it is cheap to get wrong.

    Every item's `<description>` is HTML-escaped prose that names related and
    superseded CVEs. Over the three real yearly documents a full-text regex finds
    1,580 ids against the structured 1,573, and the extra seven include a
    malformed id and several the advisory only mentions. The typed attribute is
    narrower, and narrower is the direction this project wants when the number
    reaches a public page."""
    doc = _rdf([_item("JVNDB-2026-000001", "A thing",
                      [("JVN", "JVN#123"), ("CVE", "CVE-2026-1111"),
                       ("CWE", "CWE-79")],
                      "2026-01-07T14:19+09:00")])
    _serve(monkeypatch, {2026: doc})
    rows = feeds.feed_jvn({2026})
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"], (
        "the adapter read something other than sec:references[source=CVE]; "
        "CVE-1999-0001 in the description is exactly what must not appear")


def test_a_malformed_id_in_the_typed_attribute_is_still_rejected(monkeypatch):
    """The attribute is typed but not validated upstream. `CVE-2024-280016`
    really is in JVN's prose, so the shape is checked here rather than trusted
    because it arrived in the right field."""
    doc = _rdf([_item("JVNDB-2026-000001", "A thing",
                      [("CVE", "CVE-2026-22"), ("CVE", "CVE-2026-1111")],
                      "2026-01-07T14:19+09:00")])
    _serve(monkeypatch, {2026: doc})
    assert [r["cve_id"] for r in feeds.feed_jvn({2026})] == ["CVE-2026-1111"]


def test_each_cve_carries_its_own_advisory_date(monkeypatch):
    """`dcterms:issued` is the advisory's publication date. Falling back to
    today would credit this feed with disclosure lead it has not earned, which
    is the clock error a whole review item went on."""
    docs = {
        2025: _rdf([_item("JVNDB-2025-000001", "Old",
                          [("CVE", "CVE-2025-3333")],
                          "2025-01-08T12:00+09:00")], 2025),
        2026: _rdf([_item("JVNDB-2026-000002", "New",
                          [("CVE", "CVE-2026-4444")],
                          "2026-02-14T09:30+09:00")], 2026),
    }
    _serve(monkeypatch, docs)
    rows = {r["cve_id"]: r for r in feeds.feed_jvn({2025, 2026})}
    assert rows["CVE-2025-3333"]["public_date"] == "2025-01-08"
    assert rows["CVE-2026-4444"]["public_date"] == "2026-02-14"
    assert rows["CVE-2026-4444"]["source_ref"] == "JVNDB-2026-000002"


def test_one_year_failing_is_truncated_not_ok(monkeypatch):
    """THE SILENT SHRINK, and this feed's exact shape of it.

    The window is two years and each is a separate fetch, so one 503 halves the
    feed. Returning the surviving year's rows with an `ok` beside them is the
    one failure this site says it cannot tolerate: the count drops, every
    downstream check passes, and by the next run the halved value is the
    baseline."""
    docs = {
        2025: RuntimeError("HTTP 503"),
        2026: _rdf([_item("JVNDB-2026-000001", "Live",
                          [("CVE", "CVE-2026-1111")],
                          "2026-01-07T14:19+09:00")]),
    }
    _serve(monkeypatch, docs)
    rows = feeds.feed_jvn({2025, 2026})
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"]
    h = feeds.FEED_HEALTH.get("jvn")
    assert h and h["status"] == feeds.TRUNCATED, (
        "a year that did not load was recorded as a healthy fetch")
    assert "2025" in h["detail"] and h["rows"] == 1


def test_every_year_failing_is_failed_not_empty(monkeypatch):
    """A zero from a feed that could not reach its source and a zero from a
    source with nothing in it are materially different, and the shrink guards
    read them differently."""
    _serve(monkeypatch, {2025: RuntimeError("boom"), 2026: RuntimeError("boom")})
    assert feeds.feed_jvn({2025, 2026}) == []
    h = feeds.FEED_HEALTH.get("jvn")
    assert h and h["status"] == feeds.FAILED
    assert "no yearly RDF loaded" in h["detail"]


def test_the_adapter_reads_the_english_yearly_tree_and_never_jvndb_rdf(monkeypatch):
    """`jvndb.rdf` and the Japanese tree are the iPedia mirror of NVD: 29,231
    entries for 2024 alone against a few hundred coordinated advisories, ids this
    site already has from the corpus. Reading it would multiply the feed's cost
    by fifty for republication."""
    seen = []

    def fake(url, timeout=60):
        seen.append(url)
        return _rdf([])
    monkeypatch.setattr(feeds, "_get_text", fake)
    feeds.feed_jvn({2025, 2026})
    assert seen == ["https://jvndb.jvn.jp/en/rss/years/jvndb_2025.rdf",
                    "https://jvndb.jvn.jp/en/rss/years/jvndb_2026.rdf"], seen
    assert not any(u.endswith("/jvndb.rdf") or "/ja/" in u for u in seen)


def test_one_request_per_year_not_one_per_advisory(monkeypatch):
    """The measurement that removed 582 requests. Reinstating a per-advisory
    `getVulnDetailInfo` call would put 80 seconds and 585 requests back on a
    third party for a field the yearly document already hands over."""
    calls = []

    def fake(url, timeout=60):
        calls.append(url)
        return _rdf([_item(f"JVNDB-2026-{n:06d}", "T",
                           [("CVE", f"CVE-2026-{1000 + n}")],
                           "2026-01-07T14:19+09:00") for n in range(1, 51)])
    monkeypatch.setattr(feeds, "_get_text", fake)
    rows = feeds.feed_jvn({2026})
    assert len(rows) == 50
    assert len(calls) == 1, f"50 advisories cost {len(calls)} requests"


def test_the_window_filters_on_the_cve_year_not_the_advisory_year(monkeypatch):
    """A 2026 advisory routinely references a 2025 id, and 109 of the real
    2026 document's references are exactly that. The filter is on the id, which
    is how every other adapter here reads `years`."""
    doc = _rdf([_item("JVNDB-2026-000002", "Multiple",
                      [("CVE", "CVE-2025-11540"), ("CVE", "CVE-2026-1111"),
                       ("CVE", "CVE-2023-9999")],
                      "2026-01-07T14:19+09:00")])
    _serve(monkeypatch, {2026: doc})
    got = sorted(r["cve_id"] for r in feeds.feed_jvn({2025, 2026}))
    assert got == ["CVE-2025-11540", "CVE-2026-1111"], (
        "a 2023 id inside a 2026 advisory is outside the gather window")


def test_an_id_referenced_by_two_advisories_is_credited_once(monkeypatch):
    """The same id appears under several JVNDB advisories. Two rows for one id
    would double-count a sighting, and sightings are what the gate reads."""
    doc = _rdf([
        _item("JVNDB-2026-000001", "First", [("CVE", "CVE-2026-1111")],
              "2026-01-07T14:19+09:00"),
        _item("JVNDB-2026-000002", "Second", [("CVE", "CVE-2026-1111")],
              "2026-03-02T14:19+09:00"),
    ])
    _serve(monkeypatch, {2026: doc})
    rows = feeds.feed_jvn({2026})
    assert len(rows) == 1
    assert rows[0]["source_ref"] == "JVNDB-2026-000001", (
        "the first advisory to publish an id is the one that dated it")


def test_jvn_is_an_advisory_origin_not_a_tracker():
    """A JVN advisory is coordinated disclosure with its own identifier, page and
    release date, so it may start the 72-hour clock. `origin_kind` fail-safes an
    unmapped feed to `tracker`, which would silently read every row from this
    feed as never past expectation."""
    assert clock.origin_kind("jvn") == "advisory"


def test_a_jvn_row_links_to_the_advisory_a_reader_can_open():
    """F3's guard, for this feed. `report._u` dispatches on exact slug and
    `samsung` was simply absent from it, so 65 rows shipped with a dead chip and
    no evidence. The year in the JVNDB identifier is the path segment."""
    from rbp import report
    row = {"cve_id": "CVE-2026-1111", "sources": "jvn",
           "refs": "jvn:JVNDB-2026-000001"}
    _pkg, _eco, urls = report._derive_meta(row)
    assert urls["jvn"] == (
        "https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-000001.html")


def test_a_jvn_row_with_an_unusable_ref_builds_no_link_rather_than_a_broken_one():
    """A guessed URL that 404s is worse than no URL: the row's only evidence
    would disprove it, which is the csaf/RESERVED failure written up in
    `report._u`."""
    from rbp import report
    row = {"cve_id": "CVE-2026-1111", "sources": "jvn", "refs": "jvn:not-an-id"}
    assert not report._derive_meta(row)[2].get("jvn")


def test_jvn_is_in_the_profile_the_cron_runs():
    """A feed merged into ADAPTERS and left out of `weekly` contributes nothing
    to the gate, which is the mistake that had csaf and msrc on a monthly
    cadence that existed in no cron while siemens read as uncovered."""
    from rbp.cli import PROFILES
    assert "jvn" in PROFILES["weekly"].split(",")
