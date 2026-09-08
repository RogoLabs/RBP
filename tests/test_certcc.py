"""CERT/CC Vulnerability Notes, and the two field-level traps that make a
coordinator feed read as empty.

This is the first feed merged on the `redundant` verdict, so the test that
matters most is not about parsing at all: it is
`test_certcc_is_redundant_not_corroborating_so_it_stays_in_the_numerator`. The
two verdicts were once the same word, `cli.run` read the wrong one, and five of
the site's largest feeds were briefly excluded from its own coverage numerator on
a rule that was never about them. This feed is the one where getting that
distinction wrong would be invisible, because it really does add zero CNAs.

Each test below is a trap already paid for somewhere in this project:

  * the API answers 200 with the failure inside the document, which is the MyJVN
    trap: `/vuls/api/2026/` is a 200 carrying `{"error": ...}`
  * `uid` carries the prefixed id and `cve` carries the BARE number, so reading
    `cve` finds zero ids on every note and reports a coordinator with nothing
  * the ids are in the note's own `cveids` (162 of 162 agreement), the DATES are
    not, and dropping the per-note call over-claims lead by 7 references
  * a month with no notes is ordinary; a month that did not answer is not
"""
import json

from rbp import clock, feeds, feedlab


def _note(idnumber, name, first, cveids=None):
    return {"vuid": f"VU#{idnumber}", "idnumber": str(idnumber), "name": name,
            "datefirstpublished": f"{first}T17:40:29.755060Z",
            "publicdate": f"{first}T17:40:29.392133Z",
            "cveids": list(cveids or [])}


def _vul(cid, added, note="000000"):
    """One /vuls/ record, in the real shape: `cve` is BARE, `uid` is prefixed."""
    return {"note": note, "cve": cid.replace("CVE-", ""), "uid": cid,
            "description": "a thing", "date_added": f"{added}T15:05:58.159858Z"}


def _serve(monkeypatch, months=None, vuls=None, error_months=()):
    """Serve the month and /vuls/ endpoints.

    `months` maps "YYYY-MM" to a list of notes; anything not listed answers with
    the API's own in-body error document, which is what a real empty period does.
    """
    months = months or {}
    vuls = vuls or {}

    def fake(url, timeout=90, retries=3, headers=None):
        for key, notes in months.items():
            y, m = key.split("-")
            if f"/api/{y}/{m}/" in url:
                return notes, 200, {}
        for idnumber, rows in vuls.items():
            if f"/api/{idnumber}/vuls/" in url:
                if isinstance(rows, Exception):
                    raise rows
                return rows, 200, {}
        # THE SHAPE A MISSING PERIOD REALLY TAKES: 200, application/json, and the
        # failure in the body.
        return ({"error": "Content requested either does not exist or you do "
                          "not have permissions to view it!"}, 200, {})
    monkeypatch.setattr(feeds, "_get", fake)
    feeds.reset_health()


# --------------------------------------------------------------------------
# the two field traps


def test_the_id_comes_from_uid_not_from_the_bare_cve_field(monkeypatch):
    """`{"cve": "2026-33197", "uid": "CVE-2026-33197"}`.

    Reading `cve` and matching the CVE shape finds ZERO on every note, which is
    how this feed was first scored at 0 ids across 162 notes that all had some.
    It is the MyJVN trap one field along: the document is well-formed, the request
    succeeded, and the answer is empty for a reason nothing reports."""
    _serve(monkeypatch,
           months={"2026-01": [_note(111111, "A thing", "2026-01-07",
                                     ["CVE-2026-1111"])]},
           vuls={"111111": [_vul("CVE-2026-1111", "2026-01-07")]})
    rows = feeds.feed_certcc({2026})
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"], (
        "the adapter read `cve` (bare) rather than `uid` (prefixed)")


def test_a_200_carrying_an_error_document_is_not_a_month_of_notes(monkeypatch):
    """`/vuls/api/2026/` returns HTTP 200, `application/json`, and
    `{"error": "Content requested either does not exist ..."}`. A caller that
    checks the status code reads that as a period with no notes in it. This
    repository's own note is "read the log rather than the exit status", and this
    is the same error one layer down."""
    _serve(monkeypatch, months={})          # every month answers with the error
    assert feeds.feed_certcc({2026}) == []
    h = feeds.FEED_HEALTH.get("certcc")
    assert h and h["status"] == feeds.FAILED, (
        f"an all-error window was reported as {h!r}")
    assert "no month answered" in h["detail"]


def test_a_month_that_answers_with_no_notes_is_ordinary(monkeypatch):
    """An empty list is an ANSWER and the error document is not, and the two are
    told apart by type rather than by length. CERT/CC publishes about forty notes
    a year, so quiet months are the normal case and must not degrade the feed."""
    _serve(monkeypatch,
           months={"2026-01": [], "2026-02": [],
                   "2026-03": [_note(111111, "A thing", "2026-03-07",
                                     ["CVE-2026-1111"])]},
           vuls={"111111": [_vul("CVE-2026-1111", "2026-03-07")]})
    rows = feeds.feed_certcc({2026})
    assert len(rows) == 1
    h = feeds.FEED_HEALTH.get("certcc")
    assert h is None or h["status"] != feeds.FAILED, (
        f"quiet months were reported as a failure: {h!r}")


# --------------------------------------------------------------------------
# the date, which is why the per-note call is kept


def test_an_id_is_dated_when_it_entered_the_note_not_when_the_note_opened(monkeypatch):
    """THE REASON 162 REQUESTS ARE KEPT.

    Every note carries its own `cveids`, and over all 162 real notes it agrees
    with the `/vuls/` uids 162 times out of 162, so the ID SET does not need the
    call. `date_added` is per VULNERABILITY and a note gains CVEs after it is
    first published: 299 of 307 the same day, 2 within a week, 6 up to 30 days
    later. Scoring both ways, the note-date shortcut reports 63 lead references
    against the per-id route's 56 -- over-claiming this feed's disclosure lead by
    7, in the direction that flatters a candidate."""
    _serve(monkeypatch,
           months={"2026-01": [_note(111111, "A thing", "2026-01-07",
                                     ["CVE-2026-1111", "CVE-2026-2222"])]},
           vuls={"111111": [_vul("CVE-2026-1111", "2026-01-07"),
                            _vul("CVE-2026-2222", "2026-02-06")]})
    by = {r["cve_id"]: r["public_date"] for r in feeds.feed_certcc({2026})}
    assert by["CVE-2026-1111"] == "2026-01-07"
    assert by["CVE-2026-2222"] == "2026-02-06", (
        "an id added a month after the note opened was dated from the note, "
        "claiming it was public before it was")


def test_an_id_with_no_date_added_falls_back_to_the_note(monkeypatch):
    """`date_added` is non-null on all 307 real records, so this is a guard rather
    than a case: the fallback exists so a missing timestamp cannot produce an
    undated row, which is the weakest state on this site."""
    _serve(monkeypatch,
           months={"2026-01": [_note(111111, "A thing", "2026-01-07",
                                     ["CVE-2026-1111"])]},
           vuls={"111111": [{"uid": "CVE-2026-1111", "cve": "2026-1111",
                             "date_added": None}]})
    row, = feeds.feed_certcc({2026})
    assert row["public_date"] == "2026-01-07"


def test_no_row_is_undated(monkeypatch):
    _serve(monkeypatch,
           months={"2026-01": [_note(111111, "A", "2026-01-07", ["CVE-2026-1111"])]},
           vuls={"111111": [_vul("CVE-2026-1111", "2026-01-09")]})
    assert all(r["public_date"] for r in feeds.feed_certcc({2026}))


# --------------------------------------------------------------------------
# shape and window


def test_notes_that_yield_no_ids_at_all_is_a_shape_change(monkeypatch):
    """Every one of the 162 real notes has a non-empty `cveids`, so notes that
    parse with no ids behind them means `uid` was renamed, not that the
    coordinator had a quiet four years. A count of zero with healthy-looking
    notes is the silent shrink."""
    _serve(monkeypatch,
           months={"2026-01": [_note(111111, "A", "2026-01-07", ["CVE-2026-1111"])]},
           vuls={"111111": [{"cve": "2026-1111", "identifier": "CVE-2026-1111"}]})
    assert feeds.feed_certcc({2026}) == []
    h = feeds.FEED_HEALTH.get("certcc")
    assert h and h["status"] == feeds.FAILED
    assert "`uid` field changed" in h["detail"], h["detail"]


def test_an_unreadable_note_truncates_rather_than_vanishing(monkeypatch):
    """One note's `/vuls/` failing must not drop its ids with an `ok` beside
    them."""
    _serve(monkeypatch,
           months={"2026-01": [_note(111111, "A", "2026-01-07", ["CVE-2026-1111"]),
                               _note(222222, "B", "2026-01-08", ["CVE-2026-2222"])]},
           vuls={"111111": [_vul("CVE-2026-1111", "2026-01-07")],
                 "222222": RuntimeError("503 Service Unavailable")})
    rows = feeds.feed_certcc({2026})
    assert [r["cve_id"] for r in rows] == ["CVE-2026-1111"]
    h = feeds.FEED_HEALTH.get("certcc")
    assert h and h["status"] == feeds.TRUNCATED, (
        f"an unreadable note was reported as {h!r}")
    assert "1 notes unreadable" in h["detail"]
    assert h["rows"] == 1


def test_an_id_outside_the_window_is_dropped(monkeypatch):
    _serve(monkeypatch,
           months={"2026-01": [_note(111111, "A", "2026-01-07",
                                     ["CVE-2019-1111", "CVE-2026-1111"])]},
           vuls={"111111": [_vul("CVE-2019-1111", "2026-01-07"),
                            _vul("CVE-2026-1111", "2026-01-07")]})
    assert [r["cve_id"] for r in feeds.feed_certcc({2026})] == ["CVE-2026-1111"]


def test_a_malformed_uid_is_rejected(monkeypatch):
    _serve(monkeypatch,
           months={"2026-01": [_note(111111, "A", "2026-01-07", [])]},
           vuls={"111111": [_vul("CVE-2026-22", "2026-01-07"),
                            _vul("CVE-2026-1111", "2026-01-07")]})
    assert [r["cve_id"] for r in feeds.feed_certcc({2026})] == ["CVE-2026-1111"]


def test_the_row_carries_the_note_id_and_title(monkeypatch):
    _serve(monkeypatch,
           months={"2026-01": [_note(782720, "TCG TPM2.0 implementations "
                                     "vulnerable to memory corruption",
                                     "2026-01-07", ["CVE-2026-1111"])]},
           vuls={"782720": [_vul("CVE-2026-1111", "2026-01-07")]})
    row, = feeds.feed_certcc({2026})
    assert row["source_ref"] == "VU#782720"
    assert row["description"].startswith("TCG TPM2.0")
    assert row["source"] == "certcc"


# --------------------------------------------------------------------------
# the verdict, which is the thing this merge turns on


def test_certcc_is_redundant_not_corroborating_so_it_stays_in_the_numerator():
    """THE DISTINCTION THIS MERGE DEPENDS ON, and the one that has already been
    got wrong once at real cost.

    `redundant` fails admissibility test 1 and CLEARS test 2. `corroborating` is
    the opposite shape -- clears 1, fails 2 -- and is the only verdict that leaves
    the coverage numerator, because it is the one that says a feed cannot ever
    surface an unpublished id. Both used to be spelled `corroborating`, and
    `coverage.compute` reads the verdict string, so `mozilla`, `samsung` and
    `ubuntu` were all in the live run's published exclusion list on 2026-09-06
    with lead references apiece and not a mirror among them.

    This feed is where getting it wrong again would be hardest to see: it really
    does add zero marginal CNAs, so `corroborating` would look plausible on the
    card and would quietly drop it out of the numerator for a reason that is not
    true of it. Its 13 sole-source reserved rows are the proof it is not a
    mirror."""
    card = json.loads(open("feedlab/certcc.json", encoding="utf-8").read())
    assert card["verdict"] == "redundant", card["verdict"]
    d = card["disclosure"]
    assert (d["lead_n"] or 0) > 0 or (d["unpublished_n"] or 0) > 0, (
        "a redundant verdict requires test 2 to be CLEARED; this card clears "
        "neither, which would make it a reject")
    assert card["verdict"] != "corroborating"


def test_a_redundant_feed_is_not_in_the_corroborating_exclusion(monkeypatch):
    """The rule as `coverage.compute` actually applies it. A redundant feed's
    sightings must still count towards `cnas_effective`."""
    from rbp import coverage
    assert "certcc" not in feedlab.corroborating_feeds(
        {"certcc": {"verdict": "redundant"}}), (
        "a redundant feed was put in the exclusion set")
    assert coverage.MIN_SIGHTINGS >= 1


# --------------------------------------------------------------------------
# the integration points


def test_certcc_reads_one_request_per_month_of_the_window(monkeypatch):
    """48 month calls for a four-year window. The year endpoint is not usable:
    `/vuls/api/2026/` answers 200 with an error document, so a per-year route
    would look like a coordinator that published nothing."""
    asked = []

    def fake(url, timeout=90, retries=3, headers=None):
        asked.append(url)
        return [], 200, {}
    monkeypatch.setattr(feeds, "_get", fake)
    feeds.reset_health()
    feeds.feed_certcc({2025, 2026})
    # NOTE the filter: the month URL is `/vuls/api/<y>/<m>/` and the detail URL
    # is `/vuls/api/<n>/vuls/`, so both contain "/vuls/". Only the detail call
    # ENDS with it.
    months = [u for u in asked if not u.endswith("/vuls/")]
    assert len(months) == 24, f"{len(months)} month calls for two years"
    for y in (2025, 2026):
        for m in (1, 6, 12):
            assert any(f"/api/{y}/{m:02d}/" in u for u in months), (y, m)


def test_certcc_is_an_advisory_origin_not_a_tracker():
    """A Vulnerability Note has its own VU# identifier, its own page and its own
    date, and each id carries the date it entered the note. `origin_kind`
    fail-safes an unmapped feed to `tracker`, which would read every row here as
    never past expectation."""
    assert clock.origin_kind("certcc") == "advisory"


def test_certcc_is_not_an_owner_feed():
    """The `ghsa` reasoning, for the third time. CERT/CC is a CNA and 205 of the
    sightings measured are ids it assigned itself, but a note carries no per-id
    assigner, so its presence cannot separate "certcc assigned and disclosed
    this" from "CERT/CC coordinated someone else's id"."""
    assert "certcc" not in clock.OWNER_FEEDS


def test_a_certcc_row_links_to_the_note_a_reader_can_open():
    """The URL takes the BARE number: `/vuls/id/782720` is 200 and
    `/vuls/id/VU%23782720` is 404, both checked live, so the `VU#` comes off
    rather than being escaped."""
    from rbp import report
    row = {"cve_id": "CVE-2026-1111", "sources": "certcc",
           "refs": "certcc:VU#782720"}
    _pkg, _eco, urls = report._derive_meta(row)
    assert urls["certcc"] == "https://www.kb.cert.org/vuls/id/782720"


def test_a_certcc_row_with_an_unusable_ref_builds_no_link():
    from rbp import report
    row = {"cve_id": "CVE-2026-1111", "sources": "certcc", "refs": "certcc:nope"}
    assert not report._derive_meta(row)[2].get("certcc")


def test_certcc_is_in_the_profile_the_cron_runs():
    from rbp.cli import PROFILES
    assert "certcc" in PROFILES["weekly"].split(",")


def test_certcc_has_a_committed_scorecard_to_seed_its_shrink_baseline():
    """FEEDS.md section 3: no feed is merged without its scorecard in the diff.
    Without it `compare_magnitudes` cannot see this feed at all on its first two
    runs, and this is the smallest feed in the profile, so a shrink here is the
    easiest one to miss."""
    seeds = feeds.scorecard_baselines(["certcc"])
    assert seeds.get("certcc", {}).get("rows", 0) > 0
