"""
End-to-end wiring test (PLAN.md phase 2).

Exercises classify -> inference -> report against a synthetic corpus, so a
schema change in one stage can't silently break the next. No network: the
reservation oracle is stubbed, because what's under test here is the wiring,
not the endpoint (tests/test_oracle.py covers that).
"""
from __future__ import annotations

import csv
import json
import pathlib

import pandas as pd
import pytest

from rbp import classify, report
from rbp.attribution import Attributor
from rbp.inference import TIER_BLOCK, TIER_CORROBORATED, TIER_NONE, apply_to_backlog

# A synthetic 2026 block: acme owns a clean run, then the space fragments.
# CVE-2026-1004 sits inside acme's run (nameable at k=3); CVE-2026-1104 sits in
# the fragmented zone (must abstain).
ACME = list(range(1000, 1010))
FRAGMENTED = {1100: "alpha", 1101: "beta", 1102: "alpha", 1103: "gamma",
              1105: "beta", 1106: "alpha", 1107: "gamma"}

RBP_NAMEABLE = "CVE-2026-1004"
RBP_ABSTAIN = "CVE-2026-1104"


@pytest.fixture
def corpus():
    rows = [(f"CVE-2026-{n}", "PUBLISHED", "acme", "Acme", "widget")
            for n in ACME if n != 1004]
    rows += [(f"CVE-2026-{n}", "PUBLISHED", a, a, "thing") for n, a in FRAGMENTED.items()]
    return pd.DataFrame(rows, columns=["cve_id", "state", "assigner", "vendor", "product"])


@pytest.fixture
def refs():
    def entry(product, sources):
        return {"public_date": "2026-01-01", "sources": set(sources),
                "refs": {f"{s}:x" for s in sources}, "description": f"{product} flaw",
                "product": product}
    return {RBP_NAMEABLE: entry("widget", ["debian", "alas"]),
            RBP_ABSTAIN: entry("thing", ["debian", "ghsa"])}


@pytest.fixture
def backlog(corpus, refs, monkeypatch, tmp_path):
    # Stub the oracle: both IDs come back RESERVED, owner redacted, as the real
    # endpoint does for the population this project reports on.
    monkeypatch.setattr(classify, "_get",
                        lambda cid, attempts=3: {"state": "RESERVED", "assigner": "[REDACTED]"})
    bl, fresh = classify.classify(refs, corpus, Attributor(corpus),
                                  str(tmp_path / "cache.json"), workers=2, today="2026-08-20")
    return bl, fresh


def test_classify_yields_reserved_rows_with_no_owner(backlog):
    bl, fresh = backlog
    assert len(bl) == 2 and fresh == 0
    for row in bl:
        assert row["state"] == "RESERVED"
        # Naming is inference's job; classify must not pre-fill it.
        assert row["owner"] is None
        assert row["owner_method"] == "pending-inference"


def test_inference_names_inside_a_block_and_abstains_outside(backlog, corpus, tmp_path):
    bl, _ = backlog
    apply_to_backlog(bl, corpus, str(tmp_path / "precision.json"), today="2026-08-20")
    by_id = {r["cve_id"]: r for r in bl}

    named = by_id[RBP_NAMEABLE]
    assert named["owner"] == "acme"
    assert named["owner_tier"] in (TIER_BLOCK, TIER_CORROBORATED)

    abstained = by_id[RBP_ABSTAIN]
    assert abstained["owner"] is None
    assert abstained["owner_tier"] == TIER_NONE


def test_validation_block_is_returned_for_the_method_page(backlog, corpus, tmp_path):
    bl, _ = backlog
    v = apply_to_backlog(bl, corpus, str(tmp_path / "precision.json"), today="2026-08-20")
    assert v["k"] == 3
    assert v["named"][TIER_NONE] == 1
    assert v["leave_one_out"]["method"] == "leave-one-out"
    assert v["live"]["outstanding"] == 1  # the named row awaits a future grade


def test_predictions_persist_for_a_later_run_to_grade(backlog, corpus, tmp_path):
    bl, _ = backlog
    path = tmp_path / "precision.json"
    apply_to_backlog(bl, corpus, str(path), today="2026-08-20")
    saved = json.loads(path.read_text())
    assert saved["predictions"][RBP_NAMEABLE]["predicted"] == "acme"

    # Next run, the ID has published, and it was acme after all.
    later = pd.concat([corpus, pd.DataFrame(
        [(RBP_NAMEABLE, "PUBLISHED", "acme", "Acme", "widget")], columns=corpus.columns)])
    v = apply_to_backlog([], later, str(path), today="2026-09-01")
    assert v["live"]["graded"] == 1
    assert v["live"]["precision"] == 1.0
    assert v["live"]["outstanding"] == 0


def test_report_writes_a_snapshot_the_site_can_read(backlog, corpus, tmp_path):
    bl, fresh = backlog
    apply_to_backlog(bl, corpus, str(tmp_path / "precision.json"), today="2026-08-20")
    snaps = tmp_path / "snapshots"
    sdir, md, kpi = report.build(bl, fresh, str(snaps), "2026-08-20", {2026},
                                 ["debian", "alas", "ghsa"], min_age=14)

    rows = list(csv.DictReader(open(pathlib.Path(sdir) / "backlog.csv")))
    assert {r["cve_id"] for r in rows} == {RBP_NAMEABLE, RBP_ABSTAIN}
    named = next(r for r in rows if r["cve_id"] == RBP_NAMEABLE)
    abstained = next(r for r in rows if r["cve_id"] == RBP_ABSTAIN)

    assert named["owner"] == "acme" and named["owner_nameable"] == "True"
    # The abstained row still ships, it just carries no name.
    assert abstained["owner"] == "unattributed" and abstained["owner_nameable"] == "False"
    assert "RESERVED" in md and "DNE" not in md


def test_csv_never_names_a_cna_the_report_withholds(backlog, corpus, tmp_path):
    """The shareable CSV and the Markdown must gate identically, an ungated
    CSV column was a real defect in the previous engine."""
    bl, fresh = backlog
    apply_to_backlog(bl, corpus, str(tmp_path / "precision.json"), today="2026-08-20")
    sdir, md, _ = report.build(bl, fresh, str(tmp_path / "s"), "2026-08-20", {2026},
                               ["debian"], min_age=14)
    shared = json.load(open(pathlib.Path(sdir) / "backlog.json"))
    for row in shared:
        if not row["owner_nameable"]:
            assert row["owner"] == "unattributed"


def test_run_coverage_is_reported_separately_from_validation_coverage(backlog, corpus, tmp_path):
    """The method validates at ~60% coverage over published IDs but names far
    less of a live backlog, because RBPs cluster in interleaved regions. If the
    site ever shows the validation figure as the backlog's, it is lying."""
    bl, _ = backlog
    v = apply_to_backlog(bl, corpus, str(tmp_path / "p.json"), today="2026-08-20")
    assert v["run_coverage"] == 0.5           # 1 of 2 rows named
    assert v["leave_one_out"]["coverage"] != v["run_coverage"]
    assert 0.0 <= v["run_coverage"] <= 1.0


def test_published_rows_never_carry_the_ungated_product_map(backlog, corpus, tmp_path):
    """112 of 553 published rows shipped an 85%-precision CNA name on a row the
    site rendered as unattributed, because _gated spread the row with {**r} and
    overwrote only four keys. /method promises that map can never create a name."""
    bl, fresh = backlog
    apply_to_backlog(bl, corpus, str(tmp_path / "p.json"), today="2026-08-20")
    sdir, _, _ = report.build(bl, fresh, str(tmp_path / "s"), "2026-08-20", {2026},
                              ["debian"], min_age=14)
    for name in ("backlog.json",):
        for row in json.load(open(pathlib.Path(sdir) / name)):
            leaked = [k for k in row if k.startswith("product_map")]
            assert not leaked, f"{name} leaked {leaked}"
            assert "owner_contested" in row
