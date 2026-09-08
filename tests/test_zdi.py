"""ZDI's published-advisory index, and the five traps it is built to survive.

This feed is merged for DETECTION rather than for coverage, which is a first for
this repository, so the tests are weighted differently from the other per-feed
files: the ones that matter most here are the ones protecting the date and the
shape, because both of those decide whether a reserved id becomes a row and how
long the site says it has been public.

Each test below is a trap already paid for somewhere in this project, and one of
them was paid for by this adapter:

  * `/advisories/published/` serves the CURRENT YEAR ONLY, so reading it alone
    covers a quarter of the window while looking complete
  * a full-text regex over the same document finds 16 ids the index does not
    publish, which is the GIT trap and the JVN trap for a third time
  * ONE CELL CAN HOLD SEVERAL IDS, and the first version of this adapter matched
    the whole cell against the id shape and dropped 11 in-window ids silently,
    one of them a reserved id no other feed references. Found by arithmetic:
    5,472 advisories minus 328 empty cells is 5,144, and it returned 5,136
  * an id appears in up to 34 advisories with different dates, and keeping the
    wrong one understates how long it has been public
  * this is an HTML table on someone else's site: it WILL move, and a 200 with no
    rows behind it is the silent shrink this site cannot tolerate
"""
from rbp import clock, feeds


def _row(zdi_id, vendor, cve, published, updated=None, can=None):
    """One index row, with the cell wrappers the real document carries."""
    def cell(label, body):
        return (f'<td class="p-6 pb-2 align-top" data-label="{label}">'
                f'<div class="cell-content">'
                f'<span class="cell-text " style="opacity:0;">{body}</span>'
                f'<div class="cell-curtain"></div></div></td>')
    link = (f'<a href="/advisories/{zdi_id}/" class="zdi-link">{zdi_id}</a>'
            if zdi_id else "&nbsp;")
    return ("<tr>"
            + cell("ZDI ID", link)
            + cell("ZDI CAN", can or "ZDI-CAN-00000")
            + cell("Vendor / Product", vendor)
            + cell("CVE", cve or "&nbsp;")
            + cell("CVSS", '<span class="rounded">7.8</span>')
            + cell("Published", published)
            + cell("Updated", updated or published)
            + "</tr>")


def _index(rows, year=2026):
    """The page shell, including the year selector the adapter's route came from
    and a footer that mentions a CVE id in prose, which is the full-text trap."""
    return (
        "<!DOCTYPE html><html><head><title>Published Advisories</title></head>"
        "<body><select id='yearSelect'>"
        f"<option selected value='{year}'>{year}</option>"
        "</select><table><tbody>"
        + "".join(rows) +
        "</tbody></table>"
        "<footer>See also our earlier writeup of CVE-1999-0001.</footer>"
        "</body></html>")


def _serve(monkeypatch, by_year):
    """Serve one document per year URL; a year absent from the map raises."""
    def fake(url, timeout=90):
        for year, doc in by_year.items():
            if f"/published/{year}/" in url:
                if isinstance(doc, Exception):
                    raise doc
                return doc
        raise AssertionError(f"adapter fetched an unexpected url: {url}")
    monkeypatch.setattr(feeds, "_get_text", fake)
    feeds.reset_health()


# --------------------------------------------------------------------------
# what the adapter reads


def test_the_cve_id_comes_from_its_own_cell_not_from_the_page_text(monkeypatch):
    """THE GIT TRAP, for the third time in this repository.

    OSV's GIT ecosystem was scored at +18 CNAs by a full-text probe and delivered
    +0; JVN's yearly RDFs over-claim seven ids in prose. Over ZDI's four real
    year indexes a regex finds 4,441 ids against the structured 4,425, and the 16
    extras are related-advisory mentions and page furniture. The footer here is
    that furniture."""
    doc = _index([_row("ZDI-26-001", "Acme", "CVE-2026-1111", "2026-01-07")])
    _serve(monkeypatch, {2023: _index([], 2023), 2024: _index([], 2024),
                         2025: _index([], 2025), 2026: doc})
    rows = feeds.feed_zdi({2023, 2024, 2025, 2026})
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"], (
        "the adapter read page text rather than the CVE cell; CVE-1999-0001 in "
        "the footer is exactly what must not appear")


def test_a_row_carries_its_own_advisory_id_vendor_and_date(monkeypatch):
    doc = _index([_row("ZDI-26-615", "pdfforge", "CVE-2026-2222", "2026-08-31")])
    _serve(monkeypatch, {2026: doc})
    row, = feeds.feed_zdi({2026})
    assert row["source_ref"] == "ZDI-26-615"
    assert row["product"] == "pdfforge"
    assert row["public_date"] == "2026-08-31"
    assert row["source"] == "zdi"


def test_one_cell_holding_several_ids_yields_all_of_them(monkeypatch):
    """A DEFECT IN THIS ADAPTER, CAUGHT BY ARITHMETIC THAT DID NOT ADD UP.

    The first version matched the whole CVE cell against the id shape, so a cell
    holding a list failed and the row was skipped entirely. 8 of the 5,472 real
    advisories carry one -- ZDI-25-730's cell is "CVE-2019-18935, CVE-2017-11317,
    CVE-2014-2217" -- and 11 in-window ids were being dropped with nothing in the
    log, one of them (CVE-2026-19911) a reserved id no other feed references.

    It was found because 5,472 advisories minus 328 empty cells is 5,144 and the
    adapter returned 5,136. Eight rows unaccounted for, in a document whose whole
    argument is that every gap has a stated cause.

    Splitting the cell is NOT the full-text route this feed refuses: the ids were
    put in the CVE column by the publisher. The refused route is prose."""
    doc = _index([_row("ZDI-26-001", "Progress",
                       "CVE-2026-1111, CVE-2026-2222,  CVE-2026-3333",
                       "2026-01-07")])
    _serve(monkeypatch, {2026: doc})
    rows = feeds.feed_zdi({2026})
    assert sorted(r["cve_id"] for r in rows) == [
        "CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333"]
    assert {r["source_ref"] for r in rows} == {"ZDI-26-001"}, (
        "every id in the cell was published by the same advisory")
    assert {r["public_date"] for r in rows} == {"2026-01-07"}


def test_a_multi_id_cell_still_drops_ids_outside_the_window(monkeypatch):
    """The real ZDI-25-730 cell mixes a 2019 id with in-window ones. Splitting the
    cell must not smuggle the out-of-window ones in behind the valid ones."""
    doc = _index([_row("ZDI-26-001", "Progress",
                       "CVE-2019-18935, CVE-2026-1111", "2026-01-07")])
    _serve(monkeypatch, {2026: doc})
    assert [r["cve_id"] for r in feeds.feed_zdi({2026})] == ["CVE-2026-1111"]


def test_a_cell_of_only_junk_counts_as_no_cve_not_as_a_row(monkeypatch):
    """Splitting must not turn an unparseable cell into a silent success: a cell
    with nothing id-shaped in it is the same as an empty one, and if EVERY row
    looks like that the shape guard has to still fire."""
    doc = _index([_row("ZDI-26-001", "Acme", "TBD, pending", "2026-01-07")])
    _serve(monkeypatch, {2026: doc})
    assert feeds.feed_zdi({2026}) == []
    h = feeds.FEED_HEALTH.get("zdi")
    assert h and h["status"] == feeds.FAILED
    assert "none with a CVE cell" in h["detail"], h["detail"]


def test_an_advisory_with_no_cve_is_skipped_not_counted(monkeypatch):
    """328 of the 5,472 real advisories carry an empty CVE cell: ZDI published and
    no id was ever assigned. They are a genuine failure of the same system this
    site measures and they are NOT RBPs, because there is no reserved id to be
    public about. The point of the test is that they leave no row and do not read
    as a parse loss."""
    doc = _index([_row("ZDI-26-615", "pdfforge", None, "2026-08-31"),
                  _row("ZDI-26-614", "Acme", "CVE-2026-1111", "2026-08-30")])
    _serve(monkeypatch, {2026: doc})
    rows = feeds.feed_zdi({2026})
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"]
    assert feeds.FEED_HEALTH.get("zdi") is None, (
        "an advisory with no CVE is normal and must not degrade the feed")


def test_an_id_outside_the_window_is_dropped(monkeypatch):
    doc = _index([_row("ZDI-26-001", "Acme", "CVE-2019-1111", "2026-01-07"),
                  _row("ZDI-26-002", "Acme", "CVE-2026-1111", "2026-01-08")])
    _serve(monkeypatch, {2026: doc})
    assert [r["cve_id"] for r in feeds.feed_zdi({2026})] == ["CVE-2026-1111"]


def test_a_malformed_id_in_the_cve_cell_is_rejected(monkeypatch):
    """The cell is labelled but not validated upstream, so the shape is checked
    here rather than trusted because it arrived in the right column."""
    doc = _index([_row("ZDI-26-001", "Acme", "CVE-2026-22", "2026-01-07"),
                  _row("ZDI-26-002", "Acme", "CVE-2026-1111", "2026-01-08")])
    _serve(monkeypatch, {2026: doc})
    assert [r["cve_id"] for r in feeds.feed_zdi({2026})] == ["CVE-2026-1111"]


# --------------------------------------------------------------------------
# the date, which is the half that decides how long a row has been public


def test_the_earliest_advisory_dates_the_id_not_the_first_one_read(monkeypatch):
    """209 of the 4,409 real ids appear in more than one advisory and 94 carry
    more than one date, because ZDI files one advisory per sink and re-publishes
    when a patch is incomplete: CVE-2023-36804 spans thirteen advisories from
    2023-09-12 to 2023-12-15.

    Each index is ordered newest-first, so a plain `seen` set kept the LATEST
    advisory of the EARLIEST year: a date picked by two orderings nobody chose,
    understating how long the id has been public. That is the direction that
    matters, because `public_date` feeds the 7-day buffer and the expectation
    clock."""
    doc = _index([_row("ZDI-23-1792", "Microsoft", "CVE-2023-3680", "2023-12-15"),
                  _row("ZDI-23-1406", "Microsoft", "CVE-2023-3680", "2023-09-12")])
    _serve(monkeypatch, {2023: doc})
    row, = feeds.feed_zdi({2023})
    assert row["public_date"] == "2023-09-12", (
        "the newest advisory dated the row; the earliest public reference is the "
        "honest floor")
    assert row["source_ref"] == "ZDI-23-1406", (
        "the ref must be the advisory that supplied the date, or the link "
        "disproves the date beside it")


def test_the_earliest_date_wins_across_years_too(monkeypatch):
    """CVE-2022-32250 really is in both the 2023 and the 2026 index, 2023-12-20
    against 2026-03-16. The answer must not depend on the year loop's order."""
    _serve(monkeypatch, {
        2023: _index([_row("ZDI-23-1834", "Linux", "CVE-2023-9999", "2023-12-20")], 2023),
        2026: _index([_row("ZDI-26-191", "Linux", "CVE-2023-9999", "2026-03-16")], 2026)})
    row, = feeds.feed_zdi({2023, 2026})
    assert row["public_date"] == "2023-12-20"


def test_an_undated_row_is_replaced_by_a_dated_one(monkeypatch):
    """A row whose date cell is unparseable must not block a later advisory that
    has a usable one. Undated is the weakest state on this site, not a value to
    defend."""
    _serve(monkeypatch, {2026: _index([
        _row("ZDI-26-001", "Acme", "CVE-2026-1111", "not-a-date"),
        _row("ZDI-26-002", "Acme", "CVE-2026-1111", "2026-02-02")])})
    row, = feeds.feed_zdi({2026})
    assert row["public_date"] == "2026-02-02"


# --------------------------------------------------------------------------
# the shape guards, which are the reason an HTML source is acceptable at all


def test_a_year_that_loads_with_no_rows_is_a_shape_change_not_an_empty_year(monkeypatch):
    """THE ONE ERROR THIS SITE CANNOT TOLERATE. This is an HTML table on someone
    else's marketing site, so the markup will move. When it does the failure is
    200 OK, zero rows, a smaller count, and a build that reports success -- and by
    the next run the smaller number is the baseline."""
    _serve(monkeypatch, {2026: "<html><body>redesigned, no table</body></html>"})
    rows = feeds.feed_zdi({2026})
    assert rows == []
    h = feeds.FEED_HEALTH.get("zdi")
    assert h and h["status"] == feeds.FAILED, (
        f"a document that parsed to nothing was reported as {h!r}")
    assert "no advisory rows parsed" in h["detail"]


def test_rows_with_the_cve_column_renamed_is_reported_separately(monkeypatch):
    """The other way the table can move: the rows still parse, and the CVE column
    is gone. A count of zero with healthy-looking rows is indistinguishable from
    a quiet year unless the adapter says which happened."""
    doc = _index([_row("ZDI-26-001", "Acme", None, "2026-01-07"),
                  _row("ZDI-26-002", "Acme", None, "2026-01-08")])
    doc = doc.replace('data-label="CVE"', 'data-label="CVE Identifier"')
    _serve(monkeypatch, {2026: doc})
    assert feeds.feed_zdi({2026}) == []
    h = feeds.FEED_HEALTH.get("zdi")
    assert h and h["status"] == feeds.FAILED
    assert "none with a CVE cell" in h["detail"], h["detail"]


def test_one_year_failing_truncates_rather_than_silently_halving(monkeypatch):
    """The silent shrink, one year at a time. Returning the other three years'
    rows with an `ok` beside them is how a feed loses a quarter of itself and
    every downstream guard stays green."""
    _serve(monkeypatch, {
        2025: _index([_row("ZDI-25-001", "Acme", "CVE-2025-1111", "2025-01-07")], 2025),
        2026: RuntimeError("503 Service Unavailable")})
    rows = feeds.feed_zdi({2025, 2026})
    assert [r["cve_id"] for r in rows] == ["CVE-2025-1111"]
    h = feeds.FEED_HEALTH.get("zdi")
    assert h and h["status"] == feeds.TRUNCATED, (
        f"a year that never loaded was reported as {h!r}")
    assert "2025" in h["detail"] and "2026" in h["detail"]
    assert h["rows"] == 1


def test_every_year_failing_is_a_failure_not_an_empty_feed(monkeypatch):
    _serve(monkeypatch, {2026: RuntimeError("503")})
    assert feeds.feed_zdi({2026}) == []
    h = feeds.FEED_HEALTH.get("zdi")
    assert h and h["status"] == feeds.FAILED


def test_a_healthy_read_records_no_health_entry(monkeypatch):
    """`gather` records `ok` for a feed that raised nothing and set no detail. An
    adapter that marks itself healthy would overwrite the row count `gather`
    computes."""
    _serve(monkeypatch, {2026: _index(
        [_row("ZDI-26-001", "Acme", "CVE-2026-1111", "2026-01-07")])})
    assert len(feeds.feed_zdi({2026})) == 1
    assert feeds.FEED_HEALTH.get("zdi") is None


# --------------------------------------------------------------------------
# the integration points a new feed has to be wired into


def test_zdi_reads_one_index_per_year_not_just_the_current_one(monkeypatch):
    """`/advisories/published/` serves the CURRENT YEAR ONLY. A first pass read
    that page, found 541 ids and would have covered a quarter of the window while
    looking complete. The year route is what the page's own selector navigates
    to."""
    asked = []

    def fake(url, timeout=90):
        asked.append(url)
        return _index([])
    monkeypatch.setattr(feeds, "_get_text", fake)
    feeds.reset_health()
    feeds.feed_zdi({2023, 2024, 2025, 2026})
    assert len(asked) == 4, asked
    for year in (2023, 2024, 2025, 2026):
        assert any(f"/advisories/published/{year}/" in u for u in asked), asked


def test_zdi_is_an_advisory_origin_not_a_tracker():
    """A ZDI advisory has its own identifier, its own page and its own publication
    date, which is the shape 4.5.1.4 means by Publicly Disclosing. `origin_kind`
    fail-safes an unmapped feed to `tracker`, which would read every row from this
    feed as never past expectation."""
    assert clock.origin_kind("zdi") == "advisory"


def test_zdi_is_not_an_owner_feed():
    """The reasoning that excluded `ghsa`. ZDI is itself a CNA and owns some of the
    ids it publishes -- 199 of the sightings measured are its own -- but the
    advisory carries no assigner, so its presence cannot separate "zdi assigned and
    disclosed this" from "ZDI is publishing about another CNA's id". That
    ambiguity had Apple's own advisories scored as a third party's."""
    assert "zdi" not in clock.OWNER_FEEDS


def test_a_zdi_row_links_to_the_advisory_a_reader_can_open():
    """F3's guard, for this feed. `report._u` dispatches on exact slug and
    `samsung` was simply absent from it, so 65 rows shipped with a dead chip. It
    matters more here than anywhere: every row this feed produces is a RESERVED
    id, and the last-resort URL renders NOTHING for a reserved id, so the
    fallthrough would have been blank on 100% of them."""
    from rbp import report
    row = {"cve_id": "CVE-2026-1111", "sources": "zdi", "refs": "zdi:ZDI-26-615"}
    _pkg, _eco, urls = report._derive_meta(row)
    assert urls["zdi"] == "https://www.zerodayinitiative.com/advisories/ZDI-26-615/"


def test_a_zdi_row_with_an_unusable_ref_builds_no_link_rather_than_a_broken_one():
    """A guessed URL that 404s is worse than no URL: the row's only evidence would
    disprove it."""
    from rbp import report
    row = {"cve_id": "CVE-2026-1111", "sources": "zdi", "refs": "zdi:nonsense"}
    assert not report._derive_meta(row)[2].get("zdi")


def test_zdi_is_in_the_profile_the_cron_runs():
    """A feed merged into ADAPTERS and left out of `weekly` contributes nothing,
    which is the mistake that had csaf and msrc on a monthly cadence that existed
    in no cron while siemens read as uncovered."""
    from rbp.cli import PROFILES
    assert "zdi" in PROFILES["weekly"].split(",")


def test_zdi_has_a_committed_scorecard_to_seed_its_shrink_baseline():
    """FEEDS.md section 3: no feed is merged without its scorecard in the diff.
    `scorecard_baselines` reads `ids` off the card as the stand-in baseline for a
    feed with no previous count, so without it `compare_magnitudes` cannot see
    this feed at all on its first two runs."""
    seeds = feeds.scorecard_baselines(["zdi"])
    assert seeds.get("zdi", {}).get("rows", 0) > 0, (
        "feedlab/zdi.json is missing or records no ids")
