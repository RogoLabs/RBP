"""
The precision claim, stratified and floored (review item 21, Part 2 condition 6).

Two defects, one of them live on the data branch.

THE TWO-ANSWERS BUG. The floor lived only in site.py, applied while building the
derived file, so Grader.summary published the raw value straight into summary.json.
Two files from the same run said different things about the site's own accuracy:
`inference.live.precision: 1.0` at graded 1 beside `precision: null,
below_floor: true`. A consumer reading the first got "100% accurate" from a single
graded case, a stronger claim than the leave-one-out figure over 29,000 decisions.

AND AN UNSTRATIFIED CLAIM. The out-of-sample warrant was 100% on n=224 with 213 of
those 224 a single CNA, so eleven cases informed every other CNA in the Program and
both known-wrong rows were outside the 213.
"""
from __future__ import annotations


import pandas as pd

from rbp import inference, site


def _state(n_correct, n_wrong=0, cna="acme"):
    graded = ([{"cve_id": f"CVE-2026-{i}", "tier": "block", "correct": True,
                "scored": True, "actual": cna} for i in range(n_correct)]
              + [{"cve_id": f"CVE-2026-9{i}", "tier": "block", "correct": False,
                  "scored": True, "actual": cna} for i in range(n_wrong)])
    return {"graded": graded, "predictions": {}}


# --------------------------------------------------------------------------
# one answer, floored at the source
# --------------------------------------------------------------------------

def test_the_floor_is_applied_where_the_number_is_computed():
    r = inference.summarise_state(_state(1))
    assert r["graded"] == 1 and r["correct"] == 1
    assert r["precision"] is None, "a ratio from n=1 must not leave the grader"
    assert r["below_floor"] is True
    assert r["floor"] == inference.MIN_GRADED


def test_a_zero_precision_is_withheld_too():
    """0.0 from one graded case is as unpublishable as 1.0 from one, and the old
    code published either."""
    r = inference.summarise_state(_state(0, n_wrong=1))
    assert r["correct"] == 0 and r["precision"] is None


def test_above_the_floor_the_figure_appears():
    r = inference.summarise_state(_state(inference.MIN_GRADED))
    assert r["precision"] == 1.0 and r["below_floor"] is False


def test_site_does_not_recompute_the_floor():
    """One implementation. Two implementations produced two published answers."""
    import inspect
    src = inspect.getsource(site.load)
    assert "summarise_state" in src
    # Was `assert "GRADER_MIN_N" not in src`, naming an alias that site.py
    # exported for this test and nothing else and that has now been deleted.
    #
    # The property is not that the floor's NAME is absent from load(): load hands
    # it to the templates as `precision_floor`, so a page can say why a figure is
    # withheld, and that is a use rather than a second implementation. What must
    # not happen is load COMPARING against it, which is what produced two
    # published answers to one question. Parsed rather than grepped, because
    # "MIN_GRADED" appearing is the wrong question.
    import ast
    tree = ast.parse(inspect.getsource(site.load).lstrip())
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            assert "MIN_GRADED" not in names, (
                "site.load compares against the precision floor; the floor is "
                "applied in summarise_state and nowhere else")


def test_the_grader_and_the_site_cannot_disagree(tmp_path):
    """The specific live contradiction: summary.json said 1.0, precision.json said
    null, same run, both published."""
    g = inference.Grader(str(tmp_path / "p.json"))
    st = _state(1)
    g.state = st
    from_grader = g.summary()
    from_site = inference.summarise_state(st)
    assert from_grader["precision"] == from_site["precision"]
    assert from_grader["below_floor"] == from_site["below_floor"]


# --------------------------------------------------------------------------
# stratification
# --------------------------------------------------------------------------

def test_a_cna_below_the_floor_does_not_inherit_the_global_figure():
    """Which is what one shared number silently does."""
    st = _state(inference.MIN_GRADED, cna="big")
    st["graded"].append({"cve_id": "CVE-2026-777", "tier": "block", "correct": True,
                         "scored": True, "actual": "tiny"})
    r = inference.summarise_state(st)
    assert r["precision"] is not None, "the global figure is measurable here"
    assert r["by_cna"]["tiny"]["precision"] is None
    assert r["by_cna"]["tiny"]["below_floor"] is True
    assert r["by_cna"]["big"]["precision"] == 1.0


def test_strata_are_counted():
    st = _state(3, cna="a")
    st["graded"] += _state(2, cna="b")["graded"]
    r = inference.summarise_state(st)
    assert r["strata"] == 2


def test_leave_one_out_is_stratified_and_reports_its_composition():
    """The composition is the part that makes the global figure readable. It used to
    sit twelve lines away in PLAN.md and nowhere on the site."""
    rows = [(f"CVE-2026-{n}", "PUBLISHED", "big") for n in range(1000, 1100)]
    rows += [(f"CVE-2026-{n}", "PUBLISHED", "small") for n in range(2000, 2030)]
    df = pd.DataFrame(rows, columns=["cve_id", "state", "assigner"])
    loo = inference.BlockInferencer(df, k=3).validate_loo(year="2026", k=3)
    assert loo["strata"] == 2
    assert loo["largest_stratum"] == "big"
    assert 0 < loo["largest_stratum_share"] <= 1
    assert "tail" in loo and loo["tail"]["decided"] > 0
    assert "big" in loo["by_cna"] and "small" in loo["by_cna"]


def test_the_tail_is_reported_separately_from_the_whole():
    """The number to read if you are a CNA that is not the largest one, and the
    check a global figure cannot give you."""
    rows = [(f"CVE-2026-{n}", "PUBLISHED", "big") for n in range(1000, 1200)]
    rows += [(f"CVE-2026-{n}", "PUBLISHED", "mid") for n in range(3000, 3060)]
    df = pd.DataFrame(rows, columns=["cve_id", "state", "assigner"])
    loo = inference.BlockInferencer(df, k=3).validate_loo(year="2026", k=3)
    assert loo["tail"]["decided"] < loo["decided"]
    assert loo["tail"]["decided"] == loo["by_cna"]["mid"]["decided"]


# --------------------------------------------------------------------------
# run length, which cannot be backfilled
# --------------------------------------------------------------------------

def test_run_length_discriminates_a_wide_block_from_a_narrow_one():
    """Without it there is no way to separate "the method is accurate" from "the
    method is accurate on wide blocks and has never been tested on narrow ones",
    and the whole precision warrant is dominated by one CNA with very wide blocks."""
    rows = [(f"CVE-2026-{n}", "PUBLISHED", "acme") for n in range(1000, 1060)]
    rows += [(f"CVE-2026-{n}", "PUBLISHED", a) for n, a in
             {1100: "alpha", 1101: "beta", 1102: "alpha", 1103: "gamma"}.items()]
    bi = inference.BlockInferencer(pd.DataFrame(rows, columns=["cve_id", "state", "assigner"]))
    assert bi.run_length("CVE-2026-1030") > 40, "a wide block reads as wide"
    assert bi.run_length("CVE-2026-1104") == 0, "a fragmented zone reads as zero"


def test_a_recorded_prediction_carries_its_run_length(tmp_path):
    """Recorded NOW because it is a property of the corpus at prediction time and
    the corpus moves."""
    g = inference.Grader(str(tmp_path / "p.json"))
    g.record("CVE-2026-1", "acme", "block", 3, "2026-08-22", run_length=17)
    assert g.state["predictions"]["CVE-2026-1"]["run_length"] == 17


def test_apply_to_backlog_records_the_run_length(tmp_path):
    """The call site has to pass it, or the field is always null."""
    import inspect
    src = inspect.getsource(inference.apply_to_backlog)
    assert "run_length=inferencer.run_length" in src
