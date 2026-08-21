"""
Acceptance tests for block inference and live grading (PLAN.md phase 2).

Both harnesses run offline against a frozen 2026-07-14 corpus slice, so the
precision figures the site publishes are reproducible by anyone who clones the
repo. That reproducibility is the point, the site names CNAs, so its method
has to be auditable rather than merely described.
"""
from __future__ import annotations

import bisect
import gzip
import json
import pathlib

import pandas as pd
import pytest

from rbp.inference import (
    DEFAULT_K,
    TIER_BLOCK,
    TIER_CORROBORATED,
    TIER_NONE,
    BlockInferencer,
    Grader,
)

FIX = pathlib.Path(__file__).parent / "fixtures"

# Published (num -> assigner) for 2025-2026 as of the 2026-07-14 baseline.
# Predates every ground-truth publication below, so predictions made from it
# are genuinely out-of-sample.
CORPUS_FIX = json.loads(gzip.open(FIX / "corpus_2026-07-14_pub.json.gz", "rt").read())
PROBE = json.loads((FIX / "probe_2026-08-20.json").read_text())

# Ground truth: IDs reserved on 2026-07-19 that had published by 2026-08-20,
# at which point the reservation endpoint finally revealed the assigner.
TRUTH = {c: r["owning_cna"] for c, r in PROBE["results"].items()
         if r["state"] == "PUBLISHED"}


def _corpus_df():
    rows = [(f"CVE-{y}-{num}", "PUBLISHED", a, "", "")
            for y, m in CORPUS_FIX["years"].items() for num, a in m.items()]
    return pd.DataFrame(rows, columns=["cve_id", "state", "assigner", "vendor", "product"])


@pytest.fixture(scope="module")
def corpus():
    return _corpus_df()


@pytest.fixture(scope="module")
def inf(corpus):
    return BlockInferencer(corpus)


# --------------------------------------------------------------------------
# out-of-sample, the headline number
# --------------------------------------------------------------------------

def _out_of_sample(inf, k):
    correct = wrong = abstain = 0
    for cve, actual in TRUTH.items():
        pred = inf.infer(cve, k=k)
        if pred is None:
            abstain += 1
        elif pred.lower().replace("_", "") == actual.lower().replace("_", ""):
            correct += 1
        else:
            wrong += 1
    decided = correct + wrong
    return decided / len(TRUTH), (correct / decided if decided else None), decided


def test_ground_truth_population(inf):
    assert len(TRUTH) == 224


def test_out_of_sample_k3_is_the_documented_result(inf):
    """PLAN.md F5: k=3 -> 59.8% coverage at 100% precision on the real RBP set."""
    coverage, precision, decided = _out_of_sample(inf, 3)
    assert decided == 134
    assert precision == 1.0
    assert coverage == pytest.approx(0.598, abs=0.001)


@pytest.mark.parametrize("k,exp_decided,exp_precision", [
    (1, 193, 0.9948),
    (2, 146, 0.9932),
    (3, 134, 1.0),
    (5, 114, 1.0),
])
def test_out_of_sample_precision_curve(inf, k, exp_decided, exp_precision):
    _, precision, decided = _out_of_sample(inf, k)
    assert decided == exp_decided
    assert precision == pytest.approx(exp_precision, abs=0.001)


def test_precision_is_monotone_in_k(inf):
    """The gate has to actually trade coverage for precision, or it isn't a gate."""
    results = [_out_of_sample(inf, k) for k in (1, 2, 3, 5)]
    coverages = [c for c, _, _ in results]
    assert coverages == sorted(coverages, reverse=True)
    assert all(p >= 0.99 for _, p, _ in results)


def test_shipped_gate_clears_the_kill_threshold(inf):
    """PLAN.md section 8: below ~97% out-of-sample, the owner column comes down."""
    _, precision, _ = _out_of_sample(inf, DEFAULT_K)
    assert precision >= 0.97


# --------------------------------------------------------------------------
# leave-one-out: corroborates on 20x the sample
# --------------------------------------------------------------------------

def test_leave_one_out_2026(inf):
    """PLAN.md F5: k=3 -> ~60.8% coverage at ~99.35% precision over 31,815 IDs."""
    r = inf.validate_loo(year="2026", k=3)
    assert r["decided"] + r["abstained"] == 31815
    assert r["coverage"] == pytest.approx(0.608, abs=0.005)
    assert r["precision"] == pytest.approx(0.9935, abs=0.002)


def test_neighbour_window_excludes_the_target(inf):
    """A record must never be a neighbour of itself. If it were, every
    published ID would trivially predict its own assigner and the harness
    would report a precision it hasn't earned."""
    ids, owners = inf.index["2026"]

    # An ID that IS in the corpus: the window must skip over it.
    present = ids[500]
    i = ids.index(present)
    left, right = inf._neighbours(f"CVE-2026-{present}", 3)
    assert left == [owners[x] for x in ids[i - 3:i]]
    assert right == [owners[x] for x in ids[i + 1:i + 4]]
    assert len(left) == len(right) == 3

    # An ID that is NOT in the corpus (the real RBP case): the window is the
    # three published IDs either side, with nothing skipped.
    gap = next(n for n in range(ids[500], ids[-1]) if n not in owners)
    j = bisect.bisect_left(ids, gap)
    left, right = inf._neighbours(f"CVE-2026-{gap}", 3)
    assert left == [owners[x] for x in ids[j - 3:j]]
    assert right == [owners[x] for x in ids[j:j + 3]]


def test_loo_and_out_of_sample_agree_at_k3(inf):
    """Two independent harnesses on different populations. If they diverge
    sharply, one of them is measuring the wrong thing."""
    loo = inf.validate_loo(year="2026", k=3)
    _, oos_precision, _ = _out_of_sample(inf, 3)
    assert abs(loo["precision"] - oos_precision) < 0.01


# --------------------------------------------------------------------------
# gate behaviour
# --------------------------------------------------------------------------

def test_abstains_rather_than_guesses(inf):
    """Unanimity: a split neighbourhood must produce no name at all."""
    abstained = [c for c in TRUTH if inf.infer(c) is None]
    assert len(abstained) == len(TRUTH) - 134
    for cve in abstained[:10]:
        owner, tier, method = inf.attribute(cve)
        assert owner is None
        assert tier == TIER_NONE
        assert "abstain" in method


def test_product_map_corroboration_never_creates_a_name(inf):
    """The product map can only confirm a block inference, never supply one.
    Measured at 85% precision as a standalone fallback, under the floor."""
    abstained = next(c for c in TRUTH if inf.infer(c) is None)
    owner, tier, _ = inf.attribute(abstained, product_map_owner="redhat")
    assert owner is None and tier == TIER_NONE


def test_corroborated_tier_requires_agreement(inf):
    named = next(c for c in TRUTH if inf.infer(c) is not None)
    actual = inf.infer(named)
    assert inf.attribute(named, product_map_owner=actual)[1] == TIER_CORROBORATED
    assert inf.attribute(named, product_map_owner="definitely-not-this-cna")[1] == TIER_BLOCK
    assert inf.attribute(named)[1] == TIER_BLOCK


def test_unknown_year_and_malformed_ids_abstain(inf):
    for bad in ("CVE-1998-0001", "CVE-2030-1234", "NOT-A-CVE", "CVE-2026-notanumber"):
        assert inf.infer(bad) is None


# --------------------------------------------------------------------------
# grader
# --------------------------------------------------------------------------

def test_grader_marks_predictions_against_published_truth(tmp_path, inf, corpus):
    g = Grader(str(tmp_path / "precision.json"))
    for cve in list(TRUTH)[:60]:
        pred = inf.infer(cve)
        if pred:
            g.record(cve, pred, TIER_BLOCK, DEFAULT_K, "2026-07-19")

    # Truth arrives as those IDs land in a later corpus.
    later = pd.concat([corpus, pd.DataFrame(
        [(c, "PUBLISHED", TRUTH[c], "", "") for c in list(TRUTH)[:60]],
        columns=corpus.columns)])
    newly, summary = g.grade(later, today="2026-08-20")

    assert newly, "nothing graded"
    assert summary["graded"] == len(newly)
    assert summary["outstanding"] == 0
    assert summary["precision"] == 1.0
    assert summary["by_tier"][TIER_BLOCK]["graded"] == len(newly)


def test_grader_keeps_the_first_prediction(tmp_path):
    """Re-recording would let a late correction bury an early miss."""
    g = Grader(str(tmp_path / "p.json"))
    g.record("CVE-2026-1", "alpha", TIER_BLOCK, 3, "2026-01-01")
    g.record("CVE-2026-1", "beta", TIER_BLOCK, 3, "2026-02-01")
    assert g.state["predictions"]["CVE-2026-1"]["predicted"] == "alpha"


def test_grader_counts_a_miss(tmp_path, corpus):
    g = Grader(str(tmp_path / "p.json"))
    g.record("CVE-2026-999001", "wrong-cna", TIER_BLOCK, 3, "2026-01-01")
    later = pd.concat([corpus, pd.DataFrame(
        [("CVE-2026-999001", "PUBLISHED", "actual-cna", "", "")], columns=corpus.columns)])
    newly, summary = g.grade(later, today="2026-08-20")
    assert len(newly) == 1 and newly[0]["correct"] is False
    assert summary["precision"] == 0.0
    assert summary["misses"][0]["cve_id"] == "CVE-2026-999001"


def test_grader_round_trips(tmp_path, inf):
    p = str(tmp_path / "precision.json")
    g = Grader(p)
    g.record("CVE-2026-2574", "redhat", TIER_BLOCK, 3, "2026-08-20")
    g.save()
    assert Grader(p).state["predictions"]["CVE-2026-2574"]["predicted"] == "redhat"


def test_name_normalisation_across_sources():
    """CNA short names vary in punctuation between the corpus and the API."""
    from rbp.inference import _same
    assert _same("GitHub_M", "github-m")
    assert _same("Red Hat", "redhat")
    assert not _same("redhat", "GitHub_M")


# --------------------------------------------------------------------------
# the product-map veto (REVIEW.md part 1 item 2)
# --------------------------------------------------------------------------

def test_a_confident_contradicting_product_map_withholds_the_name(inf):
    """The two worst rows in the deployed build were CVE-2026-16566 named WPScan
    on an Ansible flaw and CVE-2026-9238 named Wordfence on a QEMU flaw. Both had
    a product map verdict of redhat at 0.85 and 0.9 sitting right there, and both
    carried three independent sources so a corroboration threshold would not have
    caught either."""
    named = next(c for c in TRUTH if inf.infer(c) is not None)
    owner, tier, method = inf.attribute(named, product_map_owner="definitely-not-this",
                                        product_map_confidence=0.9)
    assert owner is None
    assert tier == TIER_NONE
    assert "vetoed" in method


def test_a_low_confidence_contradiction_does_not_veto(inf):
    """A weak corpus plurality must not override a k=3 block agreement."""
    named = next(c for c in TRUTH if inf.infer(c) is not None)
    owner, tier, _ = inf.attribute(named, product_map_owner="something-else",
                                   product_map_confidence=0.5)
    assert owner is not None and tier == TIER_BLOCK


def test_agreement_still_promotes_to_corroborated(inf):
    named = next(c for c in TRUTH if inf.infer(c) is not None)
    actual = inf.infer(named)
    assert inf.attribute(named, product_map_owner=actual,
                         product_map_confidence=0.9)[1] == TIER_CORROBORATED


def test_silence_from_the_product_map_leaves_the_block_standing(inf):
    named = next(c for c in TRUTH if inf.infer(c) is not None)
    assert inf.attribute(named, product_map_owner=None, product_map_confidence=0.0)[1] == TIER_BLOCK


def test_veto_threshold_is_explicit():
    from rbp.inference import VETO_CONFIDENCE
    assert VETO_CONFIDENCE == 0.85
