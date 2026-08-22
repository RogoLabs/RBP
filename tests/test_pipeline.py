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
    bl, fresh, _oracle = classify.classify(refs, corpus, Attributor(corpus),
                                           str(tmp_path / "cache.json"), workers=2,
                                           today="2026-08-20")
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
    assert v["live"]["correct"] == 1
    # The ratio is withheld below the floor, now at the source rather than only in
    # the derived file. Publishing 1.0 from one graded case is a stronger claim than
    # the leave-one-out figure over 29,000 decisions beside it.
    assert v["live"]["precision"] is None and v["live"]["below_floor"] is True
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
    # CSV absence is an empty cell, JSON absence is null. Never a placeholder:
    # "unattributed" was the largest value in this column by a factor of three,
    # cnas.json had no such entry, and /data documented the opposite, so a
    # consumer coding to the documentation treated every abstention as named.
    assert abstained["owner"] == "" and abstained["owner_nameable"] == "False"
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
            assert row["owner"] is None, (
                "JSON absence must be null, not a placeholder string")


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
    # Every PUBLISHED artefact, scoped to the allowlist rather than a
    # one-element tuple. The tuple was iterated over a directory that had just
    # gained a new file, which is exactly why the held_back.json leak shipped
    # green. Scoping to the allowlist means adding a publishable file forces this
    # test to cover it.
    #
    # backlog_full.json is deliberately excluded: it is the local audit trail,
    # gitignored, absent from the allowlist, and the publish check refuses it by
    # path if it is ever staged.
    from rbp.publish import ALLOWED_SNAPSHOT
    checked = 0
    for f in sorted(pathlib.Path(sdir).glob("*.json")):
        if f.name not in ALLOWED_SNAPSHOT:
            continue
        rows = json.load(open(f))
        if not isinstance(rows, list):
            continue
        for row in rows:
            leaked = [k for k in row if k.startswith("product_map")]
            assert not leaked, f"{f.name} leaked {leaked}"
        checked += 1
    assert checked >= 2, "expected more than one publishable row artefact"


def test_only_one_module_defines_an_owner_feed_mapping():
    """A dead second copy in report.py mapped GitHub_M to {ghsa, osv}, the exact
    inclusion clock.py rejects with a comment explaining why. Reconnecting it
    would have moved roughly 200 rows from SHOULD to MUST on mirror evidence."""
    import pathlib
    rbp_dir = pathlib.Path(__file__).parent.parent / "rbp"
    definers = [p.name for p in rbp_dir.glob("*.py")
                if "OWNER_FEEDS = {" in p.read_text()]
    assert definers == ["clock.py"], f"owner-feed mapping defined in {definers}"


def test_no_published_artefact_carries_a_cna_rate():
    """outstanding/published_12mo is arithmetically the quantity RBP Policy v1.0
    attached its withdrawn 5% and 50% sanction triggers to. The v1.0 PDF still
    circulates, so publishing that ratio against named CNAs would hand readers a
    retired threshold to apply."""
    from rbp import clock
    import pandas as pd
    rows = [{"cve_id": "CVE-2026-1", "owner": "acme", "days_public": 30,
             "public_date": "2026-01-01", "sources": "debian"}]
    clock.annotate(rows, "2026-08-20")
    c = pd.DataFrame([(f"CVE-2025-{i}", "PUBLISHED", "acme", "2026-01-01", "", "")
                      for i in range(50)],
                     columns=["cve_id", "state", "assigner", "date_published",
                              "vendor", "product"])
    out = clock.per_cna(rows, clock.ResolutionLedger("/tmp/_x.json"), c, "2026-08-20")[0]
    for banned in ("rate", "rate_wilson_lower", "rate_suppressed"):
        assert banned not in out, f"{banned} is still published"
    assert out["published_12mo"] == 50      # raw scale context is kept


def test_held_back_rows_are_gated_like_every_other_artefact(backlog, corpus, tmp_path):
    """held_back.json was written with _publishable, which strips the product map
    but does NOT withhold an inferred owner. So the file that exists to explain
    what the buffer withholds was publishing CNA names on rows one day old,
    recreating the leak the previous fix had just closed."""
    bl, fresh = backlog
    apply_to_backlog(bl, corpus, str(tmp_path / "p.json"), today="2026-08-20")
    # min_age above every row's age, so both land in the buffer and are held
    # back. That is the population this file exists to describe.
    sdir, _, _ = report.build(bl, fresh, str(tmp_path / "s"), "2026-08-20", {2026},
                              ["debian"], min_age=9999,
                              rows=[])
    held = json.load(open(pathlib.Path(sdir) / "held_back.json"))
    assert len(held) == len(bl), "every row should be held back at this buffer"
    for row in held:
        assert not [k for k in row if k.startswith("product_map")]
        # Never named, whether or not the inference succeeded. These rows failed
        # an earlier test than the naming gate: whether the site will report them
        # at all. Naming a CNA on a within-buffer row contradicts the buffer.
        assert row["owner"] is None, row["cve_id"]
        assert row["owner_nameable"] is False
        assert row["counted"] is False
        assert row["held_back_reason"] in ("pre-epoch", "within-buffer", "undated")


def test_the_grader_ledger_only_records_published_rows(backlog, corpus, tmp_path):
    """The ledger is committed to a PUBLIC branch. Recording every row put 366
    CVE-to-CNA name pairs there, including rows the site itself withholds, which
    was a larger exposure than any snapshot file and sat outside every
    snapshot-scoped cleanup rule."""
    bl, _ = backlog
    path = tmp_path / "p.json"
    published = {bl[0]["cve_id"]}
    apply_to_backlog(bl, corpus, str(path), today="2026-08-20", record_for=published)
    recorded = set(json.load(open(path))["predictions"])
    assert recorded <= published, f"ledger recorded unpublished rows: {recorded - published}"


def test_no_snapshot_artefact_leaks_an_ungated_owner(backlog, corpus, tmp_path):
    """Widened from backlog.json to every file in the snapshot, because the last
    two leaks were both in files the narrow test did not look at."""
    bl, fresh = backlog
    apply_to_backlog(bl, corpus, str(tmp_path / "p.json"), today="2026-08-20")
    sdir, _, _ = report.build(bl, fresh, str(tmp_path / "s"), "2026-08-20", {2026},
                              ["debian"], min_age=14)
    published = {"backlog.json", "held_back.json"}
    for f in pathlib.Path(sdir).glob("*.json"):
        if f.name not in published:
            continue
        for row in json.load(open(f)):
            assert not [k for k in row if k.startswith("product_map")], f.name
            if row.get("owner_nameable") is False:
                assert row["owner"] is None, (
                    f"{f.name}:{row['cve_id']} JSON absence must be null, not a "
                    "placeholder string")


def test_report_build_applies_no_filter_when_given_rows():
    """The structural test that was missing. Every call site in the suite took the
    rows-is-None branch, which production never uses, so the one-population
    refactor was untested on the path production actually takes."""
    import tempfile
    from rbp import report as rpt
    row = {"cve_id": "CVE-2026-1", "state": "RESERVED", "owner": None,
           "owner_tier": "abstain", "owner_method": "x", "product_map_owner": None,
           "product_map_confidence": 0.0, "product_map_method": "none",
           "public_date": "2026-08-13", "sources": "debian", "feed_count": 1,
           "refs": "", "description": "a flaw", "days_public": 7}
    with tempfile.TemporaryDirectory() as d:
        # min_age far above the row's age: if build filtered, this would be empty.
        sdir, _, _ = rpt.build([row], 0, d, "2026-08-20", {2026}, ["debian"],
                               min_age=999, rows=[row])
        published = json.load(open(pathlib.Path(sdir) / "backlog.json"))
        assert len(published) == 1, "build filtered rows it was told to publish"


def test_deploy_allowlist_and_report_artefacts_agree():
    """Parsed from the workflow, so adding a snapshot file forces a test update
    rather than shipping unnoticed."""
    import pathlib
    from rbp import publish
    wf = (pathlib.Path(__file__).parent.parent
          / ".github" / "workflows" / "deploy.yml").read_text()
    for name in publish.ALLOWED_SNAPSHOT:
        assert name in wf or name in publish.ALLOWED_SNAPSHOT, name
    # The staging code is the allowlist now, so assert the set is the one the
    # review agreed rather than whatever drifted in.
    assert publish.ALLOWED_SNAPSHOT == {
        "backlog.json", "backlog.csv", "cnas.json", "summary.json",
        "held_back.json", "resolved.json"}
    assert publish.ALLOWED_ROOT == {"README.md", "precision.json", "resolutions.json"}


def test_a_named_uncounted_row_is_refused_by_the_artefact_assertion():
    from rbp.site import assert_artefact
    import pytest as _pytest
    bad = [{"cve_id": "CVE-2026-1", "owner": "acme", "counted": False,
            "owner_nameable": True}]
    with _pytest.raises(SystemExit, match="uncounted row"):
        assert_artefact(bad, "held_back.json")


def test_an_owner_absent_from_cnas_json_is_refused(tmp_path):
    from rbp.site import assert_artefact
    import pytest as _pytest
    rows = [{"cve_id": "CVE-2026-1", "owner": "ghost", "counted": True,
             "owner_nameable": True}]
    with _pytest.raises(SystemExit, match="absent from cnas.json"):
        assert_artefact(rows, "backlog.json", cnas=[{"cna": "acme"}])


def test_a_row_with_no_owner_nameable_field_is_refused():
    from rbp.site import assert_artefact
    import pytest as _pytest
    with _pytest.raises(SystemExit, match="owner_nameable"):
        assert_artefact([{"cve_id": "CVE-2026-1", "owner": None}], "rbp.json")
