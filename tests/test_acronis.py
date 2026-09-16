"""Acronis's own advisory database, the feed a reader found before a probe did.

CVE-2026-87886 was reported to the project on 2026-09-16 as a Reserved but
Public id the site could not see: reserved, no record, and carried by Acronis's
advisory SEC-10986 since the day before. It was in no feed, because Acronis
serves no CSAF and the only route to its advisories was CERT-Bund republishing
them into CSAF on a coordinator's schedule. The two Acronis ids the site already
listed arrived that way 602 and 1,032 days late.

Each test below is a trap this repository has already paid for once:

  * the human-readable line is `summary`; `description` is EMPTY on 231 of 248
    advisories, so reading the obvious field name yields a feed of blanks. That
    is the `upstream` trap in a new costume
  * a page walk that dies halfway returns a plausible number of plausible rows,
    which is the silent shrink
  * a 200 that matches nothing is a shape change, not an empty catalogue
  * the format is a vendor advisory and it starts the clock, unlike the trackers
"""
from rbp import clock, feeds, report


def _adv(sec, cve, published, summary="a thing", product="Acronis Thing",
         **over):
    """One advisory in the real API shape, measured 2026-09-16.

    `description` is present and EMPTY, which is the point of the fixture:
    231 of 248 real advisories look exactly like this.
    """
    r = {"id": sec, "cve": cve, "cwes": ["CWE-276"], "summary": summary,
         "severity": {"name": "high", "cvss": {"score": 7.8, "vector": "x"}},
         "products": [{"name": product, "patched": "1.0", "platforms": ["Linux"]}],
         "description": "", "references": None, "credits": None,
         "published": f"{published}T15:30:00Z", "updated": None}
    r.update(over)
    return r


def _serve(monkeypatch, advisories, fail_on_page=None):
    """Serve the paginated API. `fail_on_page` raises when that page is asked for."""
    def fake(url, timeout=90, retries=3, headers=None):
        page = int(url.split("page=")[1].split("&")[0])
        if fail_on_page is not None and page == fail_on_page:
            raise RuntimeError("connection reset")
        limit = int(url.split("limit=")[1].split("&")[0])
        start = (page - 1) * limit
        return ({"page": page, "limit": limit, "total": len(advisories),
                 "items": advisories[start:start + limit]}, 200, {})
    monkeypatch.setattr(feeds, "_get", fake)
    feeds.reset_health()


def _rows(monkeypatch, advisories, years=(2023, 2024, 2025, 2026), **kw):
    _serve(monkeypatch, advisories, **kw)
    return feeds.feed_acronis(set(years))


# --------------------------------------------------------------------------
# the field trap
# --------------------------------------------------------------------------

def test_the_description_comes_from_summary_not_from_description(monkeypatch):
    """`description` is empty on 231 of the 248 real advisories and `summary`
    carries the line a defender reads. An adapter that trusts the field name
    returns 147 rows with nothing in them and looks like it works.

    Reintroduce the defect by reading `description` in `feed_acronis` and this
    is the test that fails.
    """
    rows = _rows(monkeypatch, [
        _adv("SEC-10986", "CVE-2026-87886", "2026-09-15",
             summary="Local privilege escalation due to insecure file permissions"),
    ])
    assert len(rows) == 1
    assert rows[0]["description"] == (
        "Local privilege escalation due to insecure file permissions")


def test_the_advisory_id_is_kept_so_the_row_can_link_to_its_evidence(monkeypatch):
    """SEC-<n> IS the path segment of the advisory page. Losing it leaves a row
    whose only evidence a reader cannot open, which is F3's dead chip."""
    rows = _rows(monkeypatch, [_adv("SEC-10986", "CVE-2026-87886", "2026-09-15")])
    assert rows[0]["source_ref"] == "SEC-10986"
    urls = report._derive_meta({"cve_id": "CVE-2026-87886", "sources": "acronis",
                                "refs": "acronis:SEC-10986"})[2]
    assert urls["acronis"] == (
        "https://security-advisory.acronis.com/advisories/SEC-10986")


def test_the_published_date_is_the_advisorys_own(monkeypatch):
    rows = _rows(monkeypatch, [_adv("SEC-1", "CVE-2026-1111", "2026-09-15")])
    assert rows[0]["public_date"] == "2026-09-15"


# --------------------------------------------------------------------------
# what is and is not a row
# --------------------------------------------------------------------------

def test_an_advisory_with_no_cve_is_skipped_not_counted(monkeypatch):
    """33 of the 248 carry `"cve": null`. They are real advisories and they are
    not CVE sightings, so they must not inflate the id count."""
    rows = _rows(monkeypatch, [
        _adv("SEC-1", "CVE-2026-1111", "2026-01-01"),
        _adv("SEC-2", None, "2026-01-02"),
    ])
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"]


def test_out_of_window_ids_do_not_enter(monkeypatch):
    rows = _rows(monkeypatch, [
        _adv("SEC-1", "CVE-2020-1111", "2020-01-01"),
        _adv("SEC-2", "CVE-2026-2222", "2026-01-01"),
    ])
    assert [r["cve_id"] for r in rows] == ["CVE-2026-2222"]


def test_a_repeated_id_is_counted_once(monkeypatch):
    """Two advisories can carry the same CVE. The feed reports ids, not
    advisories, and the health line says both numbers."""
    rows = _rows(monkeypatch, [
        _adv("SEC-1", "CVE-2026-1111", "2026-01-01"),
        _adv("SEC-2", "CVE-2026-1111", "2026-02-01"),
    ])
    assert len(rows) == 1


def test_a_list_valued_cve_field_does_not_silently_drop(monkeypatch):
    """`cve` is a single string on all 248 today. If it ever becomes a list,
    `startswith` on a list raises or drops rather than fanning out, so the
    adapter normalises instead of assuming."""
    rows = _rows(monkeypatch, [
        _adv("SEC-1", ["CVE-2026-1111", "CVE-2026-2222"], "2026-01-01"),
    ])
    assert sorted(r["cve_id"] for r in rows) == ["CVE-2026-1111", "CVE-2026-2222"]


# --------------------------------------------------------------------------
# pagination, and the two ways it goes wrong
# --------------------------------------------------------------------------

def test_the_walk_reads_every_page(monkeypatch):
    """248 advisories at 100 a page is three requests. Stopping at the first
    would return a plausible 100 and lose the rest."""
    advs = [_adv(f"SEC-{i}", f"CVE-2026-{1000+i}", "2026-01-01")
            for i in range(250)]
    rows = _rows(monkeypatch, advs)
    assert len(rows) == 250
    assert feeds.FEED_HEALTH["acronis"]["status"] == feeds.OK


def test_a_page_that_dies_midwalk_is_truncated_not_ok(monkeypatch):
    """The silent shrink: two of three pages is a plausible number of plausible
    rows. It keeps what it read AND says the read was partial."""
    advs = [_adv(f"SEC-{i}", f"CVE-2026-{1000+i}", "2026-01-01")
            for i in range(250)]
    rows = _rows(monkeypatch, advs, fail_on_page=3)
    assert 0 < len(rows) < 250
    assert feeds.FEED_HEALTH["acronis"]["status"] == feeds.TRUNCATED


def test_a_first_page_that_dies_is_failed_not_truncated(monkeypatch):
    """Nothing read means there is no partial result to defend."""
    rows = _rows(monkeypatch, [_adv("SEC-1", "CVE-2026-1111", "2026-01-01")],
                 fail_on_page=1)
    assert rows == []
    assert feeds.FEED_HEALTH["acronis"]["status"] == feeds.FAILED


def test_a_catalogue_that_matches_nothing_is_failed_not_ok(monkeypatch):
    """A 200 carrying advisories none of which yield an id is a renamed field,
    not an empty catalogue. Reporting ok here is the silently empty feed."""
    rows = _rows(monkeypatch, [_adv("SEC-1", None, "2026-01-01")])
    assert rows == []
    h = feeds.FEED_HEALTH["acronis"]
    assert h["status"] == feeds.FAILED
    assert "shape" in h["detail"]


# --------------------------------------------------------------------------
# what kind of source this is
# --------------------------------------------------------------------------

def test_an_acronis_advisory_is_an_advisory_and_can_start_the_clock():
    """The vendor's own publication of the flaw, with its own identifier, page
    and date, which is what 4.5.1.4 and 4.5.1.6 mean by Publicly Disclosing.
    The contrast with the trackers is the point."""
    assert clock.origin_kind("acronis") == "advisory"
    assert clock.advisory_date({"dates": {"acronis": "2026-09-15"}}) == "2026-09-15"


def test_acronis_is_not_an_owner_feed():
    """Treating the vendor's advisory as the assigner's own channel would make
    these rows MUST rather than SHOULD. `owning_cna` is REDACTED for exactly the
    reserved population, so the assignment is an inference, and the site
    publishes zero MUST rows today. Acquiring the first one on an inference is
    the wrong way to acquire one."""
    for feeds_for_owner in clock.OWNER_FEEDS.values():
        assert "acronis" not in feeds_for_owner


def test_acronis_is_in_the_table_and_in_the_profile_with_its_card():
    """`feedlab.fetch` refuses a feed that is not an adapter, so a candidate has
    to be in the table to be measured, and FEEDS.md section 3 says a feed enters
    the profile with its scorecard in the same diff. This asserts all three
    together, because two of the three is the state that ships a feed the cron
    runs and nobody measured."""
    import json
    import pathlib
    from rbp import cli
    assert "acronis" in feeds.ADAPTERS
    assert "acronis" in cli.PROFILES["weekly"].split(",")
    card = pathlib.Path(__file__).resolve().parent.parent / "feedlab" / "acronis.json"
    assert card.exists(), "merged with no scorecard in the diff"
    # REDUNDANT, not corroborating: it reaches no CNA the others do not, and it
    # references ids that were unpublished at the time, so it stays in the
    # coverage numerator. The two verdicts were once the same word and five
    # feeds were briefly excluded from the numerator on a rule about neither.
    got = json.loads(card.read_text())
    assert got["verdict"].startswith("redundant"), got["verdict"]
    assert got["disclosure"]["lead_n"] > 0, "admissibility test 2"


# --------------------------------------------------------------------------
# the seam: this feed's own name is a certified CNA short name
# --------------------------------------------------------------------------

def test_a_real_acronis_row_survives_the_publish_name_guard(tmp_path):
    """`python -m rbp.publish check` refuses to stage any tree in which a
    certified CNA short name appears at all, and this vendor IS on the roster.
    So merging this feed puts its own name into `sources`, `dates`,
    `source_urls`, `product` and the `requested` feed list on every run that
    sees one of its rows, and into `feeds` health on every run that does not.

    `_NAME_OK_PATHS` already allows all of those, for `redhat` and `mozilla`
    before this. This asserts it end to end on a row shaped the way this feed
    really produces one, because the allowlist is the kind of thing that is
    right by argument and wrong by path spelling. It is the seam between the
    adapter and the publication boundary, and nothing else crosses it.
    """
    import json
    from rbp import publish

    st = tmp_path / ".state"
    (st / "snapshots" / "2026-09-16").mkdir(parents=True)
    row = {
        "cve_id": "CVE-2026-87886", "counted": True, "owner_nameable": False,
        "sources": "acronis",
        "dates": {"acronis": "2026-09-15"},
        "source_urls": {
            "acronis": "https://security-advisory.acronis.com/advisories/SEC-10986"},
        # The product string carries the vendor name because the product is
        # named after the vendor. "Describing the vulnerability is not
        # attributing it" is the allowlist's own words for exactly this.
        "product": "Acronis Backup plugin for cPanel & WHM",
        "description": "Local privilege escalation due to insecure file permissions",
        "refs": "acronis:SEC-10986",
    }
    (st / "snapshots" / "2026-09-16" / "backlog.json").write_text(json.dumps([row]))
    (st / "snapshots" / "2026-09-16" / "summary.json").write_text(json.dumps({
        "total": 1,
        "feeds": {"requested": ["acronis"],
                  "detail": {"acronis": {"status": "ok", "rows": 147}}},
    }))
    assert publish.check(str(st)) == []


def test_the_guard_still_refuses_this_vendor_as_an_owner(tmp_path):
    """The companion to the test above, and the reason it is not vacuous.

    Two things make the row above safe and only one of them is the allowlist.
    The guard matches roster names on WHOLE-VALUE equality and CASE-SENSITIVELY,
    and this vendor is on the roster as `Acronis` while the feed slug is
    `acronis`, so the slug is a different string and could never have fired.
    `"Acronis Backup plugin for cPanel & WHM"` is not equal to `"Acronis"`
    either. That is worth knowing rather than assuming, because it means a test
    that only asserted "the row passes" would pass against a guard that had been
    turned off for this name entirely.

    So this asserts the guard is live for this vendor: the roster spelling, as a
    row owner, off the allowlist, is still refused.
    """
    import json
    from rbp import publish

    assert "Acronis" in publish._roster_names(), "roster spelling"
    assert "acronis" not in publish._roster_names(), "the feed slug is not it"

    st = tmp_path / ".state"
    (st / "snapshots" / "2026-09-16").mkdir(parents=True)
    (st / "snapshots" / "2026-09-16" / "summary.json").write_text(json.dumps({
        "total": 1, "coverage": {"weight_by_feed": {"Acronis": 3}}}))
    problems = publish.check(str(st))
    assert any("Acronis" in p and "certified CNA" in p
               for p in problems), problems
