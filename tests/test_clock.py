"""
The 72-hour clock and per-CNA aggregation (PLAN.md phase 3).

Two invariants here are not ordinary correctness checks, they are the project's
fairness constraints, and breaking either would discredit the site:

  * A SHOULD must never be reported as a MUST. 4.5.1.4 binds only where the CNA
    itself disclosed, which we cannot observe, so 4.5.1.6 is the default.

  * No percentage may sit beside a pass/fail verdict. RBP Policy v2.0.0 removed
    every numeric threshold, so there is no line for a CNA to be over.
"""
from __future__ import annotations

import datetime as dt
import json

import pandas as pd
import pytest

from rbp import clock

COLS = ["cve_id", "state", "assigner", "date_published", "vendor", "product"]
TODAY = "2026-08-20"


def row(cve, days, owner=None, self_disclosed=False, public=None):
    """A backlog row.

    days=None means an undated feed, so public_date is cleared too: leaving a
    usable date there would contradict the premise, since the clock derives the
    age from it.

    self_disclosed=True is expressed as a real owner plus that owner's own feed
    in `sources`, because annotate derives the flag rather than trusting it. A
    row asserting the flag directly would not exercise the real path.
    """
    return {"cve_id": cve, "days_public": days,
            "owner": owner or ("redhat" if self_disclosed else None),
            "sources": "redhat" if self_disclosed else "debian",
            "public_date": public if public is not None
            else ("2026-01-01" if days is not None else "")}


def corpus(rows):
    return pd.DataFrame(rows, columns=COLS)


# --------------------------------------------------------------------------
# the clock
# --------------------------------------------------------------------------

def test_past_expectation_is_strictly_beyond_72h():
    rows = [row("CVE-2026-1", 2), row("CVE-2026-2", 3), row("CVE-2026-3", 4)]
    clock.annotate(rows, TODAY)
    assert [r["hours_public"] for r in rows] == [48, 72, 96]
    # 72h exactly is not yet past the expectation.
    assert [r["past_expectation"] for r in rows] == [False, False, True]


def test_undated_rows_carry_no_clock_but_are_not_dropped():
    """Feeds that publish no date give no clock. Those rows must survive so the
    count can disclose them, and must never be asserted as late."""
    rows = [row("CVE-2026-1", None)]
    clock.annotate(rows, TODAY)
    assert rows[0]["clock_known"] is False
    assert rows[0]["hours_public"] is None
    assert rows[0]["past_expectation"] is False


def test_the_column_is_days_public_not_days_overdue():
    """PLAN.md 8a: the clock starts at the earliest advisory we can see, which
    is a floor. annotate must not compute a deadline-relative number."""
    rows = [row("CVE-2026-1", 519)]
    clock.annotate(rows, TODAY)
    r = rows[0]
    assert r["days_public"] == 519
    assert r["hours_public"] == 519 * 24
    assert not any("overdue" in k for k in r), "an overdue field would overclaim"


# --------------------------------------------------------------------------
# MUST vs SHOULD: the fairness constraint
# --------------------------------------------------------------------------

def test_should_is_the_default_reading():
    rows = [row("CVE-2026-1", 10)]
    clock.annotate(rows, TODAY)
    assert rows[0]["rule"] == clock.RULE_SHOULD
    assert rows[0]["rule_strength"] == "SHOULD"


def test_must_only_where_the_cna_itself_disclosed():
    rows = [row("CVE-2026-1", 10, owner="redhat", self_disclosed=True)]
    clock.annotate(rows, TODAY)
    assert rows[0]["rule"] == clock.RULE_MUST
    assert rows[0]["rule_strength"] == "MUST"


def test_every_row_carries_the_split():
    """It has to ride on the row, not be summarised away, or a downstream
    surface can render a mixed table as though it were all one rule."""
    rows = [row(f"CVE-2026-{i}", 10, owner="redhat", self_disclosed=bool(i % 2))
            for i in range(6)]
    clock.annotate(rows, TODAY)
    assert all(r["rule"] in (clock.RULE_MUST, clock.RULE_SHOULD) for r in rows)
    assert all(r["rule_strength"] in ("MUST", "SHOULD") for r in rows)


# --------------------------------------------------------------------------
# Wilson, and the small-denominator trap
# --------------------------------------------------------------------------

def test_wilson_penalises_small_denominators():
    """The R6 case. 2/5 beats 200/1000 on the point estimate and must lose on
    the lower bound, or a five-person CNA outranks Microsoft on noise."""
    assert 2 / 5 > 200 / 1000
    assert clock.wilson_lower(2, 5) < clock.wilson_lower(200, 1000)


def test_wilson_is_bounded_and_safe_on_zero():
    assert clock.wilson_lower(0, 0) == 0.0
    assert clock.wilson_lower(0, 100) == 0.0
    assert 0.0 <= clock.wilson_lower(50, 100) <= 1.0
    assert clock.wilson_lower(100, 100) < 1.0


def test_no_rate_is_published_at_any_denominator():
    """The rate is gone entirely, not merely suppressed for small CNAs.
    outstanding/published_12mo is arithmetically the quantity RBP Policy v1.0
    attached its withdrawn 5% and 50% sanction triggers to, and the v1.0 PDF is
    still mirrored and still ranks in search, which is how this project first
    picked those thresholds up. Publishing the arithmetic against named CNAs
    would hand a reader a retired threshold to apply."""
    for n_pub in (14, 100, 5000):
        rows = [row(f"CVE-2026-{i}", 10, owner="acme") for i in range(4)]
        clock.annotate(rows, TODAY)
        c = corpus([(f"CVE-2025-{i}", "PUBLISHED", "acme", "2026-01-01", "", "")
                    for i in range(n_pub)])
        out = clock.per_cna(rows, clock.ResolutionLedger("/tmp/_none.json"), c, TODAY)[0]
        for banned in ("rate", "rate_wilson_lower", "rate_suppressed"):
            assert banned not in out, f"{banned} published at denominator {n_pub}"
        assert out["outstanding"] == 4
        assert out["published_12mo"] == n_pub    # raw scale context is kept


def test_wilson_no_longer_raises_when_k_exceeds_n():
    """wilson_lower(21, 20) raised ValueError: math domain error, reachable from
    live data by any CNA holding more outstanding RBPs than it published in
    twelve months, which is the profile this site exists to surface."""
    assert clock.wilson_lower(21, 20) > 0
    assert clock.wilson_lower(30, 25) > 0
    assert clock.wilson_lower(1, 1) <= 1.0


# --------------------------------------------------------------------------
# no verdicts anywhere
# --------------------------------------------------------------------------

def test_no_threshold_or_verdict_fields_are_emitted():
    """v2.0.0 has no numeric threshold, so nothing here may imply one."""
    rows = [row("CVE-2026-1", 200, owner="big")]
    clock.annotate(rows, TODAY)
    c = corpus([(f"CVE-2025-{i}", "PUBLISHED", "big", "2026-01-01", "", "")
                for i in range(100)])
    ledger = clock.ResolutionLedger("/tmp/_none.json")
    banned = ("verdict", "pass", "fail", "violation", "compliant", "breach",
              "over_threshold", "threshold", "flag", "grade", "penalty")
    for payload in (rows[0], clock.per_cna(rows, ledger, c, TODAY)[0],
                    clock.summary(rows, [], TODAY)):
        for key in payload:
            assert not any(b in key.lower() for b in banned), f"{key} implies a verdict"


def test_cnas_are_ranked_by_count_not_rate():
    """Ranking by rate would invert the list and there is no threshold to
    justify it."""
    rows = ([row(f"CVE-2026-1{i}", 10, owner="big") for i in range(10)]
            + [row(f"CVE-2026-2{i}", 10, owner="small") for i in range(3)])
    clock.annotate(rows, TODAY)
    c = corpus([(f"CVE-2025-1{i}", "PUBLISHED", "big", "2026-01-01", "", "")
                for i in range(1000)]
               + [(f"CVE-2025-2{i}", "PUBLISHED", "small", "2026-01-01", "", "")
                  for i in range(30)])
    out = clock.per_cna(rows, clock.ResolutionLedger("/tmp/_none.json"), c, TODAY)
    assert [d["cna"] for d in out] == ["big", "small"]
    # big has far more published records, so any rate would have inverted this.
    assert out[0]["published_12mo"] > out[1]["published_12mo"]


# --------------------------------------------------------------------------
# trailing volume
# --------------------------------------------------------------------------

def test_published_volume_respects_the_12_month_window():
    c = corpus([
        ("CVE-2026-1", "PUBLISHED", "acme", "2026-08-01", "", ""),   # in
        ("CVE-2025-1", "PUBLISHED", "acme", "2025-09-01", "", ""),   # in
        ("CVE-2024-1", "PUBLISHED", "acme", "2024-01-01", "", ""),   # out
        ("CVE-2026-2", "RESERVED", "acme", "", "", ""),              # not published
        ("CVE-2026-3", "REJECTED", "acme", "2026-08-01", "", ""),    # not published
    ])
    assert clock.published_last_12mo(c, TODAY) == {"acme": 2}


# --------------------------------------------------------------------------
# resolution ledger
# --------------------------------------------------------------------------

def test_ledger_closes_rows_and_measures_time_to_publish(tmp_path):
    path = str(tmp_path / "res.json")
    led = clock.ResolutionLedger(path)
    led.track([row("CVE-2026-1", 30, owner="guess", public="2026-07-01")])
    assert len(led.state["open"]) == 1

    c = corpus([("CVE-2026-1", "PUBLISHED", "acme", "2026-07-31", "", "")])
    closed = led.reconcile(c, TODAY)
    assert len(closed) == 1
    got = closed[0]
    assert got["days_to_publish"] == 30
    # Once published the assigner is authoritative, so a resolved row never
    # rests on the earlier inference.
    assert got["owner"] == "acme"
    assert led.state["open"] == {}


def test_ledger_keeps_the_first_sighting(tmp_path):
    """Re-tracking would reset first_public and shrink every measured duration."""
    led = clock.ResolutionLedger(str(tmp_path / "r.json"))
    led.track([row("CVE-2026-1", 30, public="2026-07-01")])
    led.track([row("CVE-2026-1", 30, public="2026-08-15")])
    assert led.state["open"]["CVE-2026-1"]["first_public"] == "2026-07-01"


def test_ledger_ignores_still_unpublished_ids(tmp_path):
    led = clock.ResolutionLedger(str(tmp_path / "r.json"))
    led.track([row("CVE-2026-1", 30)])
    assert led.reconcile(corpus([("CVE-2026-1", "RESERVED", "", "", "", "")]), TODAY) == []
    assert len(led.state["open"]) == 1


def test_ledger_round_trips(tmp_path):
    path = str(tmp_path / "r.json")
    led = clock.ResolutionLedger(path)
    led.track([row("CVE-2026-1", 30, public="2026-07-01")])
    led.reconcile(corpus([("CVE-2026-1", "PUBLISHED", "acme", "2026-07-11", "", "")]), TODAY)
    led.save()
    again = clock.ResolutionLedger(path)
    assert again.by_owner() == {"acme": [10]}


def test_ledger_survives_a_corrupt_file(tmp_path):
    p = tmp_path / "r.json"
    p.write_text("{truncated")
    led = clock.ResolutionLedger(str(p))
    assert led.state == {"open": {}, "resolved": []}


def test_time_to_publish_reports_its_own_n(tmp_path):
    """A median of three must not read as a fact about a CNA."""
    led = clock.ResolutionLedger(str(tmp_path / "r.json"))
    led.track([row(f"CVE-2026-{i}", 10, public="2026-07-01") for i in range(3)])
    led.reconcile(corpus([(f"CVE-2026-{i}", "PUBLISHED", "acme", "2026-07-06", "", "")
                          for i in range(3)]), TODAY)
    rows = [row("CVE-2026-99", 10, owner="acme")]
    clock.annotate(rows, TODAY)
    c = corpus([(f"CVE-2025-{i}", "PUBLISHED", "acme", "2026-01-01", "", "")
                for i in range(50)])
    out = clock.per_cna(rows, led, c, TODAY)[0]
    assert out["resolved_n"] == 3
    assert out["median_days_to_publish"] == 5


# --------------------------------------------------------------------------
# summary
# --------------------------------------------------------------------------

def test_summary_counts_and_buckets():
    rows = [row("CVE-2026-1", 2), row("CVE-2026-2", 10), row("CVE-2026-3", 200),
            row("CVE-2026-4", None),
            row("CVE-2026-5", 40, owner="redhat", self_disclosed=True)]
    clock.annotate(rows, TODAY)
    s = clock.summary(rows, [{"cna": "acme"}], TODAY)
    assert s["total"] == 5
    assert s["clock_unknown"] == 1
    assert s["oldest_days"] == 200
    # 2 days is 48h and therefore not past the expectation; 10, 200 and 40 are.
    assert s["past_expectation"] == 3
    assert s["must_rows"] == 1 and s["should_rows"] == 4
    assert s["expectation_hours"] == 72
    assert s["age_buckets"] == {"<7d": 1, "7-30d": 1, "30-90d": 1, "180d+": 1}


def test_lowest_bucket_is_open_ended_downward():
    """The buffer is configurable, so a band labelled from it would misdescribe
    rows whenever it is lowered."""
    assert clock._buckets([1, 2, 6]) == {"<7d": 3}


def test_summary_handles_an_empty_backlog():
    s = clock.summary([], [], TODAY)
    assert s["total"] == 0 and s["oldest_days"] is None and s["median_days"] is None


def test_annotate_derives_the_age_itself(tmp_path):
    """Regression: annotate used to read days_public, which report.build sets
    later in the pipeline, so every row came out undated while the report showed
    correct ages. The clock module owns the clock."""
    rows = [{"cve_id": "CVE-2026-1", "public_date": "2026-07-01",
             "self_disclosed": False}]
    clock.annotate(rows, TODAY)
    assert rows[0]["days_public"] == 50
    assert rows[0]["clock_known"] is True
    assert rows[0]["past_expectation"] is True


def test_annotate_respects_an_age_already_set():
    rows = [{"cve_id": "CVE-2026-1", "days_public": 9, "public_date": "2026-01-01",
             "self_disclosed": False}]
    clock.annotate(rows, TODAY)
    assert rows[0]["days_public"] == 9


def test_annotate_handles_an_unusable_date():
    for bad in ("", None, "not-a-date", "2026-13-45"):
        rows = [{"cve_id": "CVE-2026-1", "public_date": bad, "self_disclosed": False}]
        clock.annotate(rows, TODAY)
        assert rows[0]["clock_known"] is False
        assert rows[0]["past_expectation"] is False


def test_summary_carries_the_undated_rows_it_could_not_age():
    """Undated rows are filtered out before the reportable set is built, so the
    count has to be passed in or the limitation disappears from the site."""
    rows = [row("CVE-2026-1", 10)]
    clock.annotate(rows, TODAY)
    s = clock.summary(rows, [], TODAY, undated_excluded=85)
    assert s["undated_excluded"] == 85
    assert s["total"] == 1


# --------------------------------------------------------------------------
# self-disclosure: what turns a SHOULD into a MUST
# --------------------------------------------------------------------------

def _r(owner, sources, dates=None):
    """A row for the disclosure-ordering tests.

    `dates` defaults to the owner's feed dated earliest, because the ordering
    rule now REQUIRES a measured ordering: the presence of the owner's feed is
    no longer sufficient on its own. Tests that want an ambiguous shape pass
    dates explicitly.
    """
    if dates is None:
        own = clock.OWNER_FEEDS.get(owner) or set()
        srcs = [s for s in sources.split(",") if s]
        dates = {}
        for s in srcs:
            dates[s] = "2026-01-01" if s in own else "2026-02-01"
    return {"cve_id": "CVE-2026-1", "owner": owner, "sources": sources,
            "dates": dates, "public_date": "2026-01-01", "days_public": 30}


def test_owners_own_feed_makes_it_a_must():
    assert clock.self_disclosed(_r("redhat", "redhat,debian")) is True
    assert clock.self_disclosed(_r("microsoft", "msrc,debian")) is True


def test_ghsa_is_not_treated_as_githubs_own_disclosure():
    """api.github.com/advisories carries NO assigner field, and GitHub's database
    curates advisories for everyone's code, so a GHSA cannot distinguish "GitHub
    assigned and disclosed this" from "another CNA's advisory is in GitHub's
    database". Every one of the site's 241 MUST rows rested on that inference and
    none survived without ghsa. Same reasoning that excludes OSV, one level up."""
    assert "GitHub_M" not in clock.OWNER_FEEDS
    assert clock.self_disclosed(_r("GitHub_M", "ghsa,alpine")) is False
    assert clock.self_disclosed(_r("GitHub_M", "ghsa")) is False


def test_must_requires_the_owners_feed_to_be_earliest():
    """4.5.1.4 turns on the CNA having disclosed. If a distro advisory predates
    the CNA's own, the CNA is reacting to a third party and 4.5.1.6 applies.
    Measured: 18 of 210 MUST rows were scored from a third party's date."""
    first = _r("redhat", "redhat,debian")
    first["dates"] = {"redhat": "2026-01-01", "debian": "2026-02-01"}
    assert clock.self_disclosed(first) is True

    reacting = _r("redhat", "redhat,debian")
    reacting["dates"] = {"redhat": "2026-02-01", "debian": "2026-01-01"}
    assert clock.self_disclosed(reacting) is False

    # No per-source dates available: fall back to presence rather than dropping
    # a legitimate MUST entirely.
    assert clock.self_disclosed(_r("redhat", "redhat")) is True


def test_third_party_feeds_alone_stay_a_should():
    assert clock.self_disclosed(_r("redhat", "debian,alas")) is False
    assert clock.self_disclosed(_r("microsoft", "alpine,debian")) is False


def test_an_aggregator_mirror_is_not_self_disclosure():
    """OSV re-publishes GHSA, so an OSV row is not evidence anyone disclosed.
    No owner feed anywhere in the map may name an aggregator."""
    aggregators = {"osv", "csaf"}
    for cna, feeds in clock.OWNER_FEEDS.items():
        assert not (feeds & aggregators), f"{cna} lists an aggregator: {feeds}"
    assert clock.self_disclosed(_r("redhat", "osv")) is False


def test_unattributed_rows_can_never_be_escalated():
    assert clock.self_disclosed(_r(None, "redhat,ghsa,msrc")) is False
    assert clock.self_disclosed(_r("", "redhat")) is False
    assert clock.self_disclosed(_r("some-unmapped-cna", "redhat")) is False


def test_annotate_computes_self_disclosure_itself():
    """Regression: self_disclosed was set inside report._gated(), which runs
    later in the pipeline AND returns copies, so annotate never saw it and every
    row in production came out as a SHOULD. 712 rows, 0 MUST."""
    rows = [_r("redhat", "redhat,debian"),
            _r("redhat", "debian", dates={"debian": "2026-01-01"})]
    clock.annotate(rows, TODAY)
    assert [r["rule_strength"] for r in rows] == ["MUST", "SHOULD"]
    assert [r["self_disclosed"] for r in rows] == [True, False]


def test_missing_sources_field_is_safe():
    for src in (None, ""):
        r = {"cve_id": "CVE-2026-1", "owner": "redhat", "sources": src,
             "public_date": "2026-01-01"}
        clock.annotate([r], TODAY)
        assert r["rule_strength"] == "SHOULD"


def test_a_must_reading_is_always_marked_a_candidate():
    """The reservation endpoint redacts owning_cna for exactly the reserved
    population, so ownership is always inferred and a MUST reading always rests
    on inference. It may be rendered as a candidate, never as an established
    breach."""
    rows = [_r("redhat", "redhat")]
    clock.annotate(rows, TODAY)
    assert rows[0]["rule_strength"] == "MUST"
    assert rows[0]["rule_certainty"] == "candidate"
    assert rows[0]["rule_basis"] == "inferred-owner"


def test_unattributed_rows_say_so_in_the_basis():
    rows = [_r(None, "debian")]
    clock.annotate(rows, TODAY)
    assert rows[0]["rule_basis"] == "unattributed"
    assert rows[0]["rule_strength"] == "SHOULD"


def test_no_row_ever_claims_an_established_breach():
    """The intent is that nothing is ever asserted as established. Both
    "candidate" and "unmeasurable" satisfy that; "unmeasurable" is the weaker
    claim of the two, so allowing it is not a loosening."""
    rows = [_r("redhat", "redhat"), _r("microsoft", "msrc"), _r(None, "debian"),
            _r("redhat", "redhat,debian", dates={})]
    clock.annotate(rows, TODAY)
    assert {r["rule_certainty"] for r in rows} <= {"candidate", "unmeasurable"}
    for r in rows:
        assert r["rule_certainty"] not in ("established", "confirmed", "proven")


def test_median_of_whole_days_stays_whole():
    """An even-length day count rendered as "42.0" on the front page, which
    reads as a precision a floor-derived clock does not have."""
    assert clock._median([40, 44]) == 42
    assert isinstance(clock._median([40, 44]), int)
    assert clock._median([1, 2, 3]) == 2
    assert clock._median([1, 2]) == 1.5   # genuinely between days, keep it
    assert clock._median([]) is None


# --------------------------------------------------------------------------
# launch epoch
# --------------------------------------------------------------------------

def test_no_epoch_counts_everything():
    rows = [row("CVE-2026-1", 500, public="2025-04-01"),
            row("CVE-2026-2", 10, public="2026-08-10")]
    counted, excluded = clock.split_epoch(rows, "")
    assert len(counted) == 2 and excluded == []


def test_epoch_holds_back_ids_public_before_launch():
    rows = [row("CVE-2026-1", 500, public="2025-04-01"),
            row("CVE-2026-2", 10, public="2026-09-10")]
    counted, excluded = clock.split_epoch(rows, "2026-09-01")
    assert [r["cve_id"] for r in counted] == ["CVE-2026-2"]
    assert [r["cve_id"] for r in excluded] == ["CVE-2026-1"]


def test_epoch_keys_on_the_advisory_date_not_first_sighting():
    """Keying on first-seen would let a newly added feed inject years-old RBPs
    into the headline count, which is the opposite of a stable measurement."""
    r = row("CVE-2026-1", 500, public="2025-04-01")
    r["first_seen"] = "2026-09-15"           # discovered after launch
    counted, excluded = clock.split_epoch([r], "2026-09-01")
    assert counted == [] and len(excluded) == 1


def test_epoch_does_not_alter_ages():
    """Excluding a row must not make it look younger. days_public derives from
    the advisory date and is unaffected."""
    rows = [row("CVE-2026-1", None, public="2025-04-01")]
    clock.annotate(rows, TODAY)
    age = rows[0]["days_public"]
    clock.split_epoch(rows, "2026-09-01")
    assert rows[0]["days_public"] == age == 506


def test_summary_discloses_the_epoch_and_what_it_held_back():
    rows = [row("CVE-2026-1", 10)]
    clock.annotate(rows, TODAY)
    s = clock.summary(rows, [], TODAY, epoch_excluded=542)
    assert s["epoch_excluded"] == 542
    assert "epoch" in s


def test_undated_rows_are_never_epoch_excluded():
    """A row with no date cannot be placed relative to the epoch, and guessing
    would silently drop it from both the count and the disclosure."""
    r = row("CVE-2026-1", None)
    assert r["public_date"] == ""
    counted, excluded = clock.split_epoch([r], "2026-09-01")
    assert len(counted) == 1 and excluded == []


def test_an_unpadded_epoch_is_refused(monkeypatch):
    """'2026-12-31' < '2026-8-20' is True, so one missing zero in a hand-typed
    repository variable would classify every row as pre-epoch, report 0, and
    exit successfully."""
    assert '2026-12-31' < '2026-8-20'
    with pytest.raises(SystemExit, match="zero-padded|not a valid ISO"):
        clock._validated_epoch("2026-8-20")
    with pytest.raises(SystemExit, match="not a valid ISO"):
        clock._validated_epoch("garbage")
    assert clock._validated_epoch("2026-09-01") == "2026-09-01"
    assert clock._validated_epoch("") == ""
    assert clock._validated_epoch(None) == ""


def test_rejection_closes_a_row_but_is_never_called_resolved():
    """Under rule 4.5.3.5 rejecting an unpublished ID is lawful and is the likely
    end state for the oldest rows. For a defender it is worse than an open RBP:
    the ID stays cited with no record ever coming."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        led = clock.ResolutionLedger(f"{d}/r.json")
        led.track([row("CVE-2026-1", 30, public="2026-07-01")])
        c = pd.DataFrame([("CVE-2026-1", "REJECTED", "acme", "2026-07-31", "", "")],
                         columns=COLS)
        closed = led.reconcile(c, TODAY)
        assert len(closed) == 1
        assert closed[0]["state"] == "REJECTED"
        assert closed[0]["days_to_publish"] is None
        assert led.by_owner() == {}      # never enters time-to-publish


def test_a_transfer_is_recorded_not_collapsed():
    """The policy's own remedy is for a Root to direct a CNA-LR to publish and
    transfer ownership (4.5.1.4, 4.5.1.5), so the published assigner is often
    not the CNA that reserved it. Collapsing them credits the wrong party."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        led = clock.ResolutionLedger(f"{d}/r.json")
        led.track([row("CVE-2026-1", 30, owner="original", public="2026-07-01")])
        c = pd.DataFrame([("CVE-2026-1", "PUBLISHED", "mitre", "2026-07-11", "", "")],
                         columns=COLS)
        closed = led.reconcile(c, TODAY)[0]
        assert closed["predicted_owner"] == "original"
        assert closed["published_assigner"] == "mitre"
        assert closed["transferred"] is True
        # charged to the tracked owner, not to whoever cleaned it up
        assert led.by_owner() == {"original": [10]}


# --------------------------------------------------------------------------
# disclosure ordering: absence of a date is not evidence (r3 item 13)
# --------------------------------------------------------------------------

def _order_row(dates, sources="redhat,debian", owner="redhat"):
    return {"cve_id": "CVE-2026-1", "owner": owner, "sources": sources,
            "dates": dates, "public_date": "2026-01-01"}


def test_every_ambiguous_ordering_abstains():
    """All four of these returned MUST, verified by execution. Three feeds in the
    scheduled weekly profile (debian, alpine, arch) emit no date at all, so they
    can never populate the third-party side, and the CNA most likely to be tested
    is the one whose own dates are least reliable. Absence of evidence was being
    read as evidence, always toward the stronger accusation."""
    ambiguous = [
        {"debian": "2026-01-01"},                              # own undated
        {"redhat": "2026-02-01"},                              # co-source undated
        {"redhat": "2026-01-01", "debian": "2026-01-01"},       # same-day tie
        {},                                                    # no dates at all
    ]
    for dates in ambiguous:
        assert clock.disclosure_order(_order_row(dates)) == "unmeasurable", dates
        assert clock.self_disclosed(_order_row(dates)) is False


def test_a_measured_ordering_is_respected_both_ways():
    assert clock.disclosure_order(
        _order_row({"redhat": "2026-01-01", "debian": "2026-02-01"})) == "own-first"
    assert clock.disclosure_order(
        _order_row({"redhat": "2026-02-01", "debian": "2026-01-01"})) == "third-party-first"


def test_the_owners_own_feed_alone_is_a_legitimate_must():
    """Nobody else disclosed it, so the CNA did. This needs no dates."""
    assert clock.disclosure_order(_order_row({}, sources="redhat")) == "own-first"
    assert clock.self_disclosed(_order_row({}, sources="redhat")) is True


def test_an_unmeasurable_ordering_is_labelled_unmeasurable_not_candidate():
    """A row where the site cannot tell which rule applies is not a candidate MUST
    downgraded to a SHOULD."""
    rows = [_order_row({}), _order_row({"redhat": "2026-01-01", "debian": "2026-02-01"})]
    clock.annotate(rows, TODAY)
    assert rows[0]["rule_certainty"] == "unmeasurable"
    assert rows[0]["rule_strength"] == "SHOULD"
    assert rows[1]["rule_certainty"] == "candidate"
    assert rows[1]["rule_strength"] == "MUST"


def test_self_disclosed_is_computed_in_exactly_one_place():
    """annotate and report._gated both computed it while only annotate derived
    `rule` from it, so a divergence could publish self_disclosed true beside rule
    4.5.1.6 on the same row."""
    import pathlib
    report_src = (pathlib.Path(__file__).parent.parent / "rbp" / "report.py").read_text()
    assert "clock.self_disclosed(" not in report_src, (
        "report.py recomputes self_disclosed; it must read what annotate set")


def test_restoring_ghsa_is_documented_as_still_unmet():
    """The old comment made restoring ghsa conditional on an ordering test that
    did not exist. It exists now, so the comment has to say which condition is
    still outstanding rather than reading as satisfied."""
    import pathlib
    src = (pathlib.Path(__file__).parent.parent / "rbp" / "clock.py").read_text()
    assert "source_code_location" in src
    assert "stays unmet" in src
