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


def test_rate_suppressed_below_the_denominator_floor():
    """OpenVPN reading 28.6% on 4 of 14 published was the motivating case."""
    rows = [row(f"CVE-2026-{i}", 10, owner="tiny") for i in range(4)]
    clock.annotate(rows, TODAY)
    c = corpus([(f"CVE-2025-{i}", "PUBLISHED", "tiny", "2026-01-01", "", "")
                for i in range(14)])
    out = clock.per_cna(rows, clock.ResolutionLedger("/tmp/_none.json"), c, TODAY)
    assert out[0]["rate"] is None
    assert out[0]["rate_suppressed"] is True
    assert out[0]["outstanding"] == 4      # the raw count is still shown


def test_rate_shown_above_the_floor():
    rows = [row(f"CVE-2026-{i}", 10, owner="big") for i in range(5)]
    clock.annotate(rows, TODAY)
    c = corpus([(f"CVE-2025-{i}", "PUBLISHED", "big", "2026-01-01", "", "")
                for i in range(100)])
    out = clock.per_cna(rows, clock.ResolutionLedger("/tmp/_none.json"), c, TODAY)
    assert out[0]["rate"] == pytest.approx(0.05)
    assert out[0]["rate_suppressed"] is False


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
    assert out[0]["rate"] < out[1]["rate"], "big has the lower rate yet ranks first"


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

def _r(owner, sources):
    return {"cve_id": "CVE-2026-1", "owner": owner, "sources": sources,
            "public_date": "2026-01-01", "days_public": 30}


def test_owners_own_feed_makes_it_a_must():
    assert clock.self_disclosed(_r("redhat", "redhat,debian")) is True
    assert clock.self_disclosed(_r("GitHub_M", "ghsa,alpine")) is True


def test_third_party_feeds_alone_stay_a_should():
    assert clock.self_disclosed(_r("redhat", "debian,alas")) is False
    assert clock.self_disclosed(_r("GitHub_M", "alpine,debian")) is False


def test_an_aggregator_mirror_is_not_self_disclosure():
    """OSV re-publishes GHSA, so an OSV row is not evidence that GitHub
    disclosed. Counting it would upgrade a SHOULD to a MUST on a mirror, which
    is the site's strongest claim resting on its weakest evidence."""
    assert "osv" not in clock.OWNER_FEEDS["GitHub_M"]
    assert clock.self_disclosed(_r("GitHub_M", "osv")) is False
    assert clock.self_disclosed(_r("GitHub_M", "osv,ghsa")) is True


def test_unattributed_rows_can_never_be_escalated():
    assert clock.self_disclosed(_r(None, "redhat,ghsa,msrc")) is False
    assert clock.self_disclosed(_r("", "redhat")) is False
    assert clock.self_disclosed(_r("some-unmapped-cna", "redhat")) is False


def test_annotate_computes_self_disclosure_itself():
    """Regression: self_disclosed was set inside report._gated(), which runs
    later in the pipeline AND returns copies, so annotate never saw it and every
    row in production came out as a SHOULD. 712 rows, 0 MUST."""
    rows = [_r("redhat", "redhat,debian"), _r("redhat", "debian")]
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
    rows = [_r("redhat", "redhat"), _r("GitHub_M", "ghsa"), _r(None, "debian")]
    clock.annotate(rows, TODAY)
    assert {r["rule_certainty"] for r in rows} == {"candidate"}
