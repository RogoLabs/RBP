"""
Reconstruct the redacted owning CNA of a reserved CVE ID, and grade the
reconstruction in public.

The CVE Services reservation endpoint serves `owning_cna` for PUBLISHED and
REJECTED records and returns "[REDACTED]" for RESERVED ones, precisely the
population the RBP policy governs (PLAN.md F4). So the owner of an RBP row has
to be inferred from public data.

Method: block inference. CVE IDs are handed to CNAs in runs, so an ID whose
published neighbours all share one assigner is very likely assigned to that CNA
too. Require `k` published IDs on *each* side, all naming the same assigner;
abstain otherwise. Unanimity is the whole point, a majority-with-margin rule
buys coverage at a precision cost this project cannot afford.

Measured on the real RBP population (n=224 IDs that were reserved on
2026-07-19 and had published by 2026-08-20, predicted from the pre-publication
corpus, so genuinely out-of-sample):

    k=1   coverage 86.2%   precision  99.48%
    k=2   coverage 65.2%   precision  99.32%
    k=3   coverage 59.8%   precision 100.00%   <- shipped
    k=5   coverage 50.9%   precision 100.00%

Leave-one-out over all 31,815 published 2026 IDs corroborates: k=3 gives 60.8%
coverage at 99.35% precision.

COVERAGE IS POPULATION-DEPENDENT, PRECISION IS NOT. The figures above are
coverage over *published* IDs, which are spread evenly through the ID space. A
live RBP set is not: a measured run over the alas+alpine feeds named only 24% of
reportable rows, because those RBPs sit in interleaved regions where no single
CNA owns the neighbourhood. Loosening the gate barely helps, on that same run
k=2 named one extra row for a 0.25pt precision cost, and k=1 named five more but
dropped leave-one-out precision to 97.75%, brushing the kill floor. The binding
constraint is the shape of the ID space, not the threshold.

So the site must publish the *actual* naming coverage of each run alongside the
*validated* precision of the method, and never present the validation coverage
as though it described the backlog. `apply_to_backlog` returns both.

Two things deliberately NOT done:

  * REJECTED records are not used as neighbours. Tested; they are too rare
    (452 in 2026) to move coverage: k=3 shifts 60.8% -> 60.9%. Not worth the
    extra state to explain.

  * The product->CNA map (attribution.py) is never used to name a CNA. Tested
    as a fallback where block inference abstains: it adds 20 decisions at 85%
    precision, far under the ~97% floor in PLAN.md section 8. It is used only
    as corroboration: where both methods fire they agreed 14/14, which earns
    a row the highest confidence tier but never creates a name on its own.

Everything here is arithmetic over the public corpus. No network.
"""
from __future__ import annotations

import bisect
import collections
import datetime as dt
import json
import os

DEFAULT_K = 3

# Confidence tiers. These are labels for the site, not probabilities, the
# honest probability is the measured precision, published alongside.
TIER_CORROBORATED = "block-corroborated"   # block inference + product map agree
TIER_BLOCK = "block"                       # block inference alone
TIER_NONE = "abstain"                      # not named

# A product map verdict at or above this confidence, disagreeing with the block
# inference, withholds the name. Set at the level where the map is a curated or
# strong-majority signal rather than a weak corpus plurality.
VETO_CONFIDENCE = 0.85

# A CNA must be sighted at least this many times before this site will name it.
# One incidental reference is not evidence that we read that CNA's output, and a
# gate keyed on a single sighting reopens on any stray row with no code change.
MIN_SIGHTINGS = 3


class BlockInferencer:
    """Infer the assigner of an ID from its published neighbours in ID space."""

    def __init__(self, corpus_df, k=DEFAULT_K):
        self.k = k
        # year -> (sorted [num], {num: assigner}) over PUBLISHED records only
        by_year = collections.defaultdict(dict)
        pub = corpus_df[corpus_df["state"] == "PUBLISHED"]
        for cid, assigner in zip(pub["cve_id"], pub["assigner"]):
            if not assigner:
                continue
            try:
                _, year, num = cid.split("-")
                by_year[year][int(num)] = assigner
            except ValueError:
                continue
        self.index = {y: (sorted(d), d) for y, d in by_year.items()}

    def _neighbours(self, cve_id, k):
        try:
            _, year, num = cve_id.split("-")
            num = int(num)
        except ValueError:
            return None, None
        if year not in self.index:
            return None, None
        ids, owners = self.index[year]
        i = bisect.bisect_left(ids, num)
        left = ids[max(0, i - k):i]
        # bisect_left puts an existing num at i, so drop it explicitly, this
        # is what makes leave-one-out honest rather than self-confirming.
        right = [x for x in ids[i:i + k + 1] if x != num][:k]
        if len(left) < k or len(right) < k:
            return None, None
        return [owners[x] for x in left], [owners[x] for x in right]

    def infer(self, cve_id, k=None):
        """Return the unanimous assigner of the k neighbours each side, or None."""
        k = self.k if k is None else k
        left, right = self._neighbours(cve_id, k)
        if left is None:
            return None
        candidates = set(left) | set(right)
        return candidates.pop() if len(candidates) == 1 else None

    def attribute(self, cve_id, product_map_owner=None, product_map_confidence=0.0,
                  covered=None, sightings=None, bulk_reporters=frozenset()):
        """Full attribution for one RBP row.

        Returns (owner, tier, method). `owner` is None when the gate does not
        pass, the site renders those rows with an empty owner column and links
        to the method page, rather than guessing.

        Four outcomes, not two. The product map can VETO a name, and the covered
        set can withhold one.

        The veto exists because of the two worst rows this project produced. Both
        named a WordPress-ecosystem CNA on a Linux distribution vulnerability,
        both had a high-confidence contradicting product map verdict already
        computed and ignored, and both carried three independent sources, so a
        corroboration threshold would not have caught either. Their identifiers
        are deliberately not written here: this function's job is to stop those
        attributions being published, and repeating a withdrawn attribution in
        tracked code republishes it into git history and code search, where no
        later correction reaches it.

        Agreement promotes to corroborated. Confident disagreement withholds the
        name. Silence leaves the block inference standing, but is recorded as
        silence rather than as agreement. Measured on the live snapshot the veto
        fires on 11 of 287 named rows, which is a cheap price for not misnaming a
        third party.

        The covered-set gate is the stronger guarantee, because it needs no
        product string at all: it refuses to name a CNA whose advisories this
        site does not read. That matters most for the CSAF population, which is
        every ICS and enterprise vendor row and where the product field is empty,
        so the product map has no opinion to contribute either way.
        """
        owner = self.infer(cve_id)
        if owner is None:
            return None, TIER_NONE, f"block-k{self.k}-abstain"

        corroborated = bool(product_map_owner and _same(product_map_owner, owner))

        # Confident disagreement withholds the name.
        if (product_map_owner and product_map_confidence >= VETO_CONFIDENCE
                and not corroborated):
            return None, TIER_NONE, f"block-k{self.k}-vetoed-by-product-map"

        # The covered-set gate: never name a CNA whose advisories this site does
        # not actually read. This holds with no product string, no description
        # matching and no hard-coded exclusion list, and it is the gate that also
        # covers the entire CSAF population where the product field is empty.
        if covered is not None:
            seen = (sightings or {}).get(owner, 0)
            if owner not in covered:
                return None, TIER_NONE, "uncorroborated-cna-not-reached"
            if seen < MIN_SIGHTINGS:
                return None, TIER_NONE, f"uncorroborated-cna-sighted-{seen}x"

        # A bulk reporter is by definition rarely the canonical owner of a
        # distro-shipped component, which is why the product map excludes them.
        # Block inference was naming them anyway, so they need a second signal.
        if owner in bulk_reporters and not corroborated:
            return None, TIER_NONE, "bulk-reporter-needs-second-signal"

        if corroborated:
            return owner, TIER_CORROBORATED, f"block-k{self.k}+product-map"
        return owner, TIER_BLOCK, f"block-k{self.k}"

    # -- self-validation ---------------------------------------------------

    def validate_loo(self, year=None, k=None):
        """Leave-one-out over published records: hide each ID, predict it from
        its neighbours, compare. Runs every build so the precision the site
        displays is this build's, not a number from a README."""
        k = self.k if k is None else k
        years = [year] if year else list(self.index)
        correct = wrong = abstain = 0
        for y in years:
            ids, owners = self.index.get(y, ([], {}))
            for idx, num in enumerate(ids):
                left = ids[max(0, idx - k):idx]
                right = ids[idx + 1:idx + 1 + k]
                if len(left) < k or len(right) < k:
                    abstain += 1
                    continue
                cands = {owners[x] for x in left} | {owners[x] for x in right}
                if len(cands) != 1:
                    abstain += 1
                    continue
                pred = cands.pop()
                if pred == owners[num]:
                    correct += 1
                else:
                    wrong += 1
        return _score(correct, wrong, abstain, k, "leave-one-out")


def _same(a, b):
    """CNA short names vary in punctuation across sources (GitHub_M vs GitHub-M)."""
    def norm(s):
        return (s or "").lower().replace("_", "").replace("-", "").replace(" ", "")
    return norm(a) == norm(b)


def _score(correct, wrong, abstain, k, method):
    decided = correct + wrong
    total = decided + abstain
    return {
        "method": method, "k": k,
        "decided": decided, "abstained": abstain, "total": total,
        "correct": correct, "wrong": wrong,
        "coverage": round(decided / total, 4) if total else 0.0,
        "precision": round(correct / decided, 4) if decided else None,
    }


# --------------------------------------------------------------------------
# live grading, the claim the site makes about itself
# --------------------------------------------------------------------------

class Grader:
    """Score past predictions against records that have since published.

    Every RBP eventually resolves one way or another, and when it publishes the
    CVE List finally reveals its true assigner. That makes the inference
    self-marking: each run grades the predictions it made on earlier runs, so
    the precision shown on the site is earned continuously rather than asserted
    once. Nobody has to trust the method, they can watch it being graded.
    """

    def __init__(self, path):
        self.path = path
        self.state = {"predictions": {}, "graded": [], "history": []}
        if os.path.exists(path):
            try:
                loaded = json.load(open(path))
                if isinstance(loaded, dict):
                    self.state.update(loaded)
            except Exception:  # noqa: BLE001
                pass

    def record(self, cve_id, predicted_owner, tier, k, today):
        """Log a prediction so a future run can mark it. First prediction for
        an ID wins: re-recording would let a late correction hide an early miss."""
        if predicted_owner and cve_id not in self.state["predictions"]:
            self.state["predictions"][cve_id] = {
                "predicted": predicted_owner, "tier": tier, "k": k, "on": today,
            }

    def withdraw(self, keep_ids):
        """Drop open predictions for rows the site no longer publishes.

        A name can be withdrawn after it was recorded: the contradiction veto
        starts firing on it, the buffer is raised, an epoch is set, or a CNA
        disputes it. Without this the ledger keeps asserting a name the site has
        already retracted, on a public branch, and no correction on the site can
        reach it. Graded verdicts are never withdrawn: those rest on an
        authoritative assigner from the published record, not on inference.
        """
        gone = [c for c in self.state["predictions"] if c not in keep_ids]
        for c in gone:
            del self.state["predictions"][c]
        return gone

    def grade(self, corpus_df, today=None):
        """Mark every outstanding prediction whose ID now appears PUBLISHED in
        the corpus, and fold the result into the running score."""
        today = today or dt.date.today().isoformat()
        # REJECTED closes a prediction too. Filtering on PUBLISHED only meant a
        # prediction on an ID later rejected could never be graded, sat in the
        # public ledger forever, and biased the precision figure onto IDs that
        # published, which is the opposite of where block inference is weakest.
        terminal = corpus_df[corpus_df["state"].isin(["PUBLISHED", "REJECTED"])]
        truth = dict(zip(terminal["cve_id"], zip(terminal["assigner"], terminal["state"])))

        newly = []
        for cve_id, p in list(self.state["predictions"].items()):
            hit = truth.get(cve_id)
            if not hit:
                continue
            actual, state = hit
            # Outcome, not just correct/wrong. A transfer is the policy's own
            # remedy (4.5.1.5), so a correct inference on a transferred row used
            # to publish as a named method miss in the /method misses table.
            if not actual:
                outcome = "unattributed-on-publish"
            elif _same(p["predicted"], actual):
                outcome = "correct"
            else:
                outcome = "wrong"
            newly.append({
                "cve_id": cve_id, "predicted": p["predicted"], "actual": actual,
                "state": state, "outcome": outcome,
                # Only a genuine mismatch on a PUBLISHED record counts against
                # precision. A rejection reveals no assigner to have been right
                # or wrong about.
                "correct": outcome == "correct",
                "scored": state == "PUBLISHED" and outcome in ("correct", "wrong"),
                "tier": p["tier"], "k": p["k"],
                "predicted_on": p["on"], "graded_on": today,
            })
            del self.state["predictions"][cve_id]

        self.state["graded"].extend(newly)
        summary = self.summary()
        if newly:
            self.state["history"].append({
                "date": today, "newly_graded": len(newly),
                "newly_correct": sum(1 for g in newly if g["correct"]),
                "cumulative_precision": summary["precision"],
            })
        return newly, summary

    def summary(self):
        # Precision is computed over SCORED verdicts only. A rejection closes a
        # prediction without revealing an assigner, so counting it as a miss
        # would penalise the method for an outcome it never predicted.
        graded = [g for g in self.state["graded"] if g.get("scored", True)]
        correct = sum(1 for g in graded if g["correct"])
        n = len(graded)
        by_tier = collections.defaultdict(lambda: [0, 0])
        for g in graded:
            by_tier[g["tier"]][0] += 1
            by_tier[g["tier"]][1] += int(g["correct"])
        return {
            "graded": n, "correct": correct,
            "precision": round(correct / n, 4) if n else None,
            "outstanding": len(self.state["predictions"]),
            "closed_unscored": sum(1 for g in self.state["graded"]
                                   if not g.get("scored", True)),
            "by_tier": {t: {"graded": a, "correct": b,
                            "precision": round(b / a, 4) if a else None}
                        for t, (a, b) in by_tier.items()},
            "misses": [g for g in graded if not g["correct"]][-25:],
        }

    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        json.dump(self.state, open(self.path, "w"), indent=1)


# --------------------------------------------------------------------------
# pipeline entry point
# --------------------------------------------------------------------------

def apply_to_backlog(backlog, corpus_df, precision_path, today=None, k=DEFAULT_K,
                     record_for=None, covered=None, sightings=None,
                     bulk_reporters=frozenset()):
    """Name what can be named, grade what can be graded, and report both.

    Mutates each backlog row in place with `owner` / `owner_tier` /
    `owner_method`, then returns the validation block the site renders on its
    method page. Rows below the gate keep `owner = None`, the site shows an
    empty owner column there and links to the method, rather than guessing.
    """
    today = today or dt.date.today().isoformat()
    inferencer = BlockInferencer(corpus_df, k=k)
    grader = Grader(precision_path)

    # Grade first: predictions made on earlier runs whose IDs have since
    # published are now markable against the corpus. The score is re-read after
    # this run's predictions are recorded, so `outstanding` reflects reality
    # rather than the state before we added to it.
    newly_graded, _ = grader.grade(corpus_df, today=today)

    named = collections.Counter()
    vetoed = 0
    for row in backlog:
        owner, tier, method = inferencer.attribute(
            row["cve_id"],
            product_map_owner=row.get("product_map_owner"),
            product_map_confidence=row.get("product_map_confidence") or 0.0,
            covered=covered, sightings=sightings, bulk_reporters=bulk_reporters)
        # Silence from the product map must be distinguishable from agreement.
        # owner_contested shipped false on every row as though it were measured.
        row["veto_evaluated"] = bool(row.get("product_map_owner"))
        row["owner"], row["owner_tier"], row["owner_method"] = owner, tier, method
        named[tier] += 1
        if "vetoed" in method:
            vetoed += 1
        if record_for is None or row["cve_id"] in record_for:
            grader.record(row["cve_id"], owner, tier, k, today)

    # A retraction has to reach the ledger, not just the site.
    withdrawn = grader.withdraw(record_for) if record_for is not None else []
    if withdrawn:
        print(f"  withdrew {len(withdrawn)} prediction(s) for rows no longer published")

    grader.save()
    live_score = grader.summary()
    loo = inferencer.validate_loo(year=today[:4], k=k)

    total = len(backlog) or 1
    run_coverage = round((total - named[TIER_NONE]) / total, 4) if backlog else 0.0
    print(f"  attribution: {named[TIER_CORROBORATED]} corroborated + "
          f"{named[TIER_BLOCK]} block = "
          f"{named[TIER_CORROBORATED] + named[TIER_BLOCK]}/{len(backlog)} named "
          f"({100 * (total - named[TIER_NONE]) / total:.1f}%), "
          f"{named[TIER_NONE]} abstained"
          + (f", {vetoed} name(s) vetoed by a contradicting product map" if vetoed else ""))
    print(f"  method precision (leave-one-out, {today[:4]}): {_pct(loo['precision'])} "
          f"[validation coverage {_pct(loo['coverage'])} over published IDs, "
          f"NOT this run's {_pct(run_coverage)}]")
    if live_score["graded"]:
        print(f"  live grading: {live_score['correct']}/{live_score['graded']} correct "
              f"({_pct(live_score['precision'])}), {len(newly_graded)} newly marked, "
              f"{live_score['outstanding']} outstanding")
    else:
        print(f"  live grading: no predictions resolved yet "
              f"({live_score['outstanding']} outstanding)")

    return {
        "date": today, "k": k,
        "named": {t: named[t] for t in (TIER_CORROBORATED, TIER_BLOCK, TIER_NONE)},
        # How much of THIS backlog got a name. This is the number the site shows
        # next to the table; it is not the validation coverage and the two must
        # never be conflated.
        "run_coverage": run_coverage,
        # How accurate the method is, measured on published IDs where truth is
        # known. `leave_one_out["coverage"]` describes that validation set only.
        "leave_one_out": loo,
        "live": live_score,
        "newly_graded": newly_graded,
        "withdrawn": len(withdrawn),
    }


def _pct(x):
    return "n/a" if x is None else f"{100 * x:.2f}%"
