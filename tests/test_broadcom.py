"""Broadcom's support-portal advisory list, the second feed a reader found first.

VMSA-2026-0007 (CVE-2026-59346, CVE-2026-59347) was reported on 2026-10-06. Both
ids were on the site already, but only through CERT-Bund's CSAF, because
Broadcom serves no CSAF of its own. Reading the vendor's list directly found 16
more reserved ids that were in no feed.

Each test below is a trap this adapter was written against:

  * a rolling advisory dated 2025-01-08 lists twelve 2026-10-02 ids as
    "Multiple"; the ids are read from their own per-id advisories, and an id
    listed twice keeps its EARLIEST date, not the first one in the list
  * 2,833 of 4,907 advisories list no id inline, which is a floor and is said
  * one POST for the whole catalogue, so a full page back is TRUNCATED, not ok
  * a 200 that matches nothing is a shape change, not an empty catalogue
"""
import json
import pathlib

from rbp import cli, clock, feeds, report


def _adv(nid, cve, published, title="a thing", products="VMware Fusion,VMware Work..."):
    """One advisory in the real list shape, measured 2026-10-06."""
    return {"affectedCve": cve, "alertType": "S", "documentId": f"VCDSA{nid}",
            "notificationId": nid,
            "notificationUrl": feeds.BROADCOM_PAGE_URL.format(nid),
            "published": published, "severity": "HIGH", "status": "CLOSED",
            "supportProducts": products, "title": title, "totalRecords": None,
            "updated": "2026-10-06T14:50:05.177136", "workAround": ""}


def _serve(monkeypatch, advisories, success=True, raise_=None):
    seen = {}

    def fake(url, timeout=90, retries=3, headers=None, body=None):
        seen["url"], seen["body"] = url, body
        if raise_:
            raise raise_
        return ({"success": success, "data": {"list": advisories}}, 200, {})
    monkeypatch.setattr(feeds, "_get", fake)
    feeds.reset_health()
    return seen


def _rows(monkeypatch, advisories, years=(2023, 2024, 2025, 2026), **kw):
    _serve(monkeypatch, advisories, **kw)
    return {r["cve_id"]: r for r in feeds.feed_broadcom(set(years))}


# --------------------------------------------------------------------------
# the row
# --------------------------------------------------------------------------

def test_the_reported_advisory_becomes_two_rows_with_its_own_date_and_link(monkeypatch):
    got = _rows(monkeypatch, [_adv(
        38288, "CVE-2026-59346, CVE-2026-59347", "03 September 2026",
        title="VMSA-2026-0007: VMware Workstation and Fusion updates")])
    assert set(got) == {"CVE-2026-59346", "CVE-2026-59347"}
    r = got["CVE-2026-59346"]
    assert r["source"] == "broadcom"
    assert r["public_date"] == "2026-09-03"
    assert r["source_ref"] == "38288"
    assert r["description"].startswith("VMSA-2026-0007")
    # The API truncates the product list with "...", which is not a product.
    assert r["product"] == "VMware Fusion,VMware Work"


def test_the_date_parse_is_locale_independent_and_fails_closed():
    assert feeds._broadcom_date("06 October 2026") == "2026-10-06"
    assert feeds._broadcom_date("6 october 2026") == "2026-10-06"
    assert feeds._broadcom_date("31 February 2026") == ""
    assert feeds._broadcom_date("") == ""
    assert feeds._broadcom_date(None) == ""


def test_the_row_links_to_its_own_advisory_and_a_bad_ref_links_nowhere():
    _p, _e, urls = report._derive_meta(
        {"cve_id": "CVE-2026-59346", "sources": "broadcom",
         "refs": "broadcom:38288"})
    assert urls["broadcom"] == feeds.BROADCOM_PAGE_URL.format(38288)
    _p, _e, urls = report._derive_meta(
        {"cve_id": "CVE-2026-59346", "sources": "broadcom",
         "refs": "broadcom:VCDSA38288"})
    assert not urls.get("broadcom")


# --------------------------------------------------------------------------
# the rolling-advisory trap, and which date an id keeps
# --------------------------------------------------------------------------

def test_an_id_listed_twice_keeps_its_earliest_date_whatever_the_list_order(monkeypatch):
    """The list is ordered by `updated`, so a product that re-ships an old
    third-party id puts the newest advisory first. First-seen would date the id
    by the last product to ship it."""
    newer = _adv(39001, "CVE-2025-9230", "28 July 2026")
    older = _adv(37001, "CVE-2025-9230", "02 October 2025")
    for order in ([newer, older], [older, newer]):
        got = _rows(monkeypatch, order)
        assert got["CVE-2025-9230"]["public_date"] == "2025-10-02"
        assert got["CVE-2025-9230"]["source_ref"] == "37001"


def test_an_undated_advisory_never_displaces_a_dated_one(monkeypatch):
    got = _rows(monkeypatch, [_adv(1, "CVE-2026-1111", "06 October 2026"),
                              _adv(2, "CVE-2026-1111", "not a date")])
    assert got["CVE-2026-1111"]["public_date"] == "2026-10-06"


def test_the_rolling_ascg_advisory_lists_multiple_and_is_not_read(monkeypatch):
    """BSNSA24998 is dated 2025-01-08 and carries 2026-10-02 ids on its page.
    Its list row says "Multiple", so it yields nothing here, and the per-id
    advisory supplies the real date."""
    got = _rows(monkeypatch, [
        _adv(24998, "Multiple", "08 January 2025",
             title="Brocade ASCG Vulnerability Disclosures"),
        _adv(38378, "CVE-2026-85421", "02 October 2026")])
    assert got["CVE-2026-85421"]["public_date"] == "2026-10-02"
    assert got["CVE-2026-85421"]["source_ref"] == "38378"


# --------------------------------------------------------------------------
# what is and is not a row, and the floor
# --------------------------------------------------------------------------

def test_advisories_with_no_inline_id_are_counted_as_a_floor(monkeypatch):
    got = _rows(monkeypatch, [
        _adv(1, "See CVE list in advisory", "01 October 2026"),
        _adv(2, None, "01 October 2026"),
        _adv(3, "", "01 October 2026"),
        _adv(4, "N/A", "01 October 2026"),
        _adv(5, "CVE-2007-477", "01 October 2026"),   # truncated, real case
        _adv(6, "CVE-2026-2222", "01 October 2026")])
    assert set(got) == {"CVE-2026-2222"}
    h = feeds.FEED_HEALTH["broadcom"]
    assert h["status"] == feeds.OK
    assert "5 of 6 advisories list no id inline (floor)" in h["detail"]


def test_out_of_window_ids_do_not_enter(monkeypatch):
    got = _rows(monkeypatch, [_adv(1, "CVE-2019-0001, CVE-2026-0002",
                                   "01 October 2026")])
    assert set(got) == {"CVE-2026-0002"}


# --------------------------------------------------------------------------
# the request, and the ways it goes wrong
# --------------------------------------------------------------------------

def test_the_whole_catalogue_is_asked_for_in_one_post(monkeypatch):
    seen = _serve(monkeypatch, [_adv(1, "CVE-2026-0001", "01 October 2026")])
    feeds.feed_broadcom({2026})
    assert seen["url"] == feeds.BROADCOM_API
    assert seen["body"]["pageNumber"] == 0
    assert seen["body"]["pageSize"] == feeds.BROADCOM_PAGE


def test_a_full_page_back_is_truncated_not_ok(monkeypatch):
    monkeypatch.setattr(feeds, "BROADCOM_PAGE", 2)
    _rows(monkeypatch, [_adv(1, "CVE-2026-0001", "01 October 2026"),
                        _adv(2, "CVE-2026-0002", "01 October 2026")])
    assert feeds.FEED_HEALTH["broadcom"]["status"] == feeds.TRUNCATED


def test_a_catalogue_that_matches_nothing_is_failed_not_ok(monkeypatch):
    got = _rows(monkeypatch, [_adv(1, "See CVE list in advisory", "01 October 2026")])
    assert got == {}
    assert feeds.FEED_HEALTH["broadcom"]["status"] == feeds.FAILED


def test_success_false_and_a_dead_request_are_failed(monkeypatch):
    assert _rows(monkeypatch, [], success=False) == {}
    assert feeds.FEED_HEALTH["broadcom"]["status"] == feeds.FAILED
    assert _rows(monkeypatch, [], raise_=RuntimeError("reset")) == {}
    assert feeds.FEED_HEALTH["broadcom"]["status"] == feeds.FAILED


# --------------------------------------------------------------------------
# what kind of source this is, and the merge
# --------------------------------------------------------------------------

def test_a_broadcom_advisory_is_an_advisory_and_can_start_the_clock():
    assert clock.origin_kind("broadcom") == "advisory"
    assert clock.advisory_date({"dates": {"broadcom": "2026-10-02"}}) == "2026-10-02"


def test_broadcom_is_not_an_owner_feed():
    """Most ids it lists are third-party ids a Broadcom product ships, so the
    vendor is not the assigner for most rows, before the `acronis` reason even
    applies."""
    for feeds_for_owner in clock.OWNER_FEEDS.values():
        assert "broadcom" not in feeds_for_owner


def test_broadcom_is_in_the_table_and_in_the_profile_with_its_card():
    assert "broadcom" in feeds.ADAPTERS
    assert "broadcom" in cli.PROFILES["weekly"].split(",")
    card = pathlib.Path(__file__).resolve().parent.parent / "feedlab" / "broadcom.json"
    assert card.exists(), "merged with no scorecard in the diff"
    got = json.loads(card.read_text())
    assert got["verdict"].startswith("detecting"), got["verdict"]
    assert got["disclosure"]["lead_n"] > 0, "admissibility test 2"


def test_the_feed_name_is_not_a_roster_short_name():
    """`acronis` collides with a certified CNA short name and needed the publish
    guard checked both ways. `broadcom` does not: the four Broadcom CNAs are
    `vmware`, `brocade`, `ca` and `symantec`. If that changes, this feed needs
    the `acronis` guard tests."""
    roster = pathlib.Path(feeds.__file__).parent / "roster_data" / "cna_roster.json"
    names = {c.get("short_name") for c in json.loads(roster.read_text())["cnas"]}
    assert {"vmware", "brocade", "ca", "symantec"} <= names
    assert "broadcom" not in names
