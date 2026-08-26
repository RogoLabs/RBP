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

# Minimum graded verdicts before a precision figure is published at all, globally
# or per stratum. At n=1 the site rendered "100.00%" in a headline tile, which is a
# stronger claim than the leave-one-out figure over 29,000 decisions beside it.
#
# Owned here rather than in site.py, because whoever computes the number has to be
# the one that floors it. Split across two modules, the raw value reached
# summary.json while the floored one reached precision.json, and both published.
MIN_GRADED = 20


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

    def run_length(self, cve_id, cap=60):
        """How many contiguous published neighbours agree on one assigner.

        Recorded per prediction because it CANNOT be backfilled: it is a property
        of the corpus at prediction time and the corpus moves. Without it there is
        no way to separate "the method is accurate" from "the method is accurate on
        wide blocks and has never been tested on narrow ones", which matters because
        the entire precision warrant is dominated by one CNA whose blocks are very
        wide.

        Counts outward from the ID in both directions while the assigner holds, so a
        prediction resting on 3 neighbours either side is distinguishable from one
        resting on 40. Capped, because walking a 10,000-ID block per row would cost
        more than the signal is worth.
        """
        try:
            _, year, num = cve_id.split("-")
            num = int(num)
        except ValueError:
            return None
        if year not in self.index:
            return None
        ids, owners = self.index[year]
        i = bisect.bisect_left(ids, num)
        left = [x for x in ids[max(0, i - cap):i]]
        right = [x for x in ids[i:i + cap + 1] if x != num]
        if not left or not right:
            return 0
        who = owners[left[-1]]
        if owners[right[0]] != who:
            return 0
        n = 0
        for x in reversed(left):
            if owners[x] != who:
                break
            n += 1
        for x in right:
            if owners[x] != who:
                break
            n += 1
        return n

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
        # STRATIFIED BY TRUE OWNER, which is the point.
        #
        # The out-of-sample warrant was 100% on n=224 and 213 of those 224 were one
        # CNA, so eleven cases informed every other CNA in the Program. A global
        # figure can clear a 97% floor while the tail error rate is 2 in 3, and both
        # known-wrong rows were in the tail. A single number cannot express that; a
        # distribution can.
        per = collections.defaultdict(lambda: [0, 0, 0])   # [correct, wrong, abstain]
        for y in years:
            ids, owners = self.index.get(y, ([], {}))
            for idx, num in enumerate(ids):
                truth = owners[num]
                left = ids[max(0, idx - k):idx]
                right = ids[idx + 1:idx + 1 + k]
                if len(left) < k or len(right) < k:
                    abstain += 1
                    per[truth][2] += 1
                    continue
                cands = {owners[x] for x in left} | {owners[x] for x in right}
                if len(cands) != 1:
                    abstain += 1
                    per[truth][2] += 1
                    continue
                pred = cands.pop()
                if pred == truth:
                    correct += 1
                    per[truth][0] += 1
                else:
                    wrong += 1
                    per[truth][1] += 1

        out = _score(correct, wrong, abstain, k, "leave-one-out")
        # Per-CNA, floored. Below the floor a CNA reads "not separately measurable"
        # rather than inheriting the global figure, which is what a single shared
        # number silently does.
        strata = {}
        for cna, (c, w, a) in per.items():
            decided = c + w
            strata[cna] = {
                "decided": decided, "correct": c, "wrong": w, "abstained": a,
                "precision": round(c / decided, 4) if decided >= MIN_GRADED else None,
                "below_floor": decided < MIN_GRADED,
                "coverage": round(decided / (decided + a), 4) if (decided + a) else None,
            }
        ranked = sorted(strata.items(), key=lambda kv: -kv[1]["decided"])
        out["by_cna"] = dict(ranked[:40])
        out["strata"] = len(strata)
        out["measurable_strata"] = sum(1 for v in strata.values() if not v["below_floor"])
        # THE COMPOSITION, published beside the figure rather than twelve lines
        # away. This is the number that makes the global precision readable.
        top = ranked[0] if ranked else None
        out["largest_stratum"] = top[0] if top else None
        out["largest_stratum_share"] = (
            round(top[1]["decided"] / max(correct + wrong, 1), 4) if top else None)
        # The tail: every stratum outside the largest, taken together.
        tail_c = sum(v["correct"] for c_, v in ranked[1:])
        tail_w = sum(v["wrong"] for c_, v in ranked[1:])
        out["tail"] = {
            "decided": tail_c + tail_w, "correct": tail_c, "wrong": tail_w,
            "precision": (round(tail_c / (tail_c + tail_w), 4)
                          if (tail_c + tail_w) >= MIN_GRADED else None),
            "below_floor": (tail_c + tail_w) < MIN_GRADED,
        }
        return out


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

    def record(self, cve_id, predicted_owner, tier, k, today, run_length=None):
        """Log a prediction so a future run can mark it. First prediction for
        an ID wins: re-recording would let a late correction hide an early miss.

        `run_length` is how many contiguous published IDs on either side agreed,
        recorded NOW because it cannot be backfilled: it is a property of the
        corpus at prediction time, and the corpus moves. Density bands are the only
        way to tell "the method is accurate" from "the method is accurate on wide
        blocks and untested on narrow ones", and the whole precision warrant is
        dominated by one CNA with very wide blocks.
        """
        if predicted_owner and cve_id not in self.state["predictions"]:
            self.state["predictions"][cve_id] = {
                "predicted": predicted_owner, "tier": tier, "k": k, "on": today,
                "run_length": run_length,
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

        newly, ungradable = [], []
        for cve_id, p in list(self.state["predictions"].items()):
            hit = truth.get(cve_id)
            if not hit:
                continue
            # A PREDICTION WITH NO NAME CANNOT BE GRADED.
            #
            # publish.denamed_ledger strips `predicted` from precision.json
            # before it reaches the public data branch, and its docstring says
            # so plainly: "an open prediction with no name cannot be graded when
            # the row publishes, so live precision restarts." What it did not
            # say is that the ledger is READ BACK from that branch on the next
            # run, so the de-named shape is the shape this loop actually meets.
            # It read p["predicted"] unguarded and raised KeyError, which killed
            # three consecutive scheduled builds and left the site 19 hours
            # stale. All 251 open predictions on origin/data are {tier, k, on}.
            #
            # Dropped rather than skipped, because a prediction that can never
            # be graded is not outstanding, it is closed with no verdict; left
            # in place it would be retried on every run for ever. COUNTED and
            # returned, because "could not be measured" and "nothing to measure"
            # are different facts and this project does not let them read the
            # same way.
            if not p.get("predicted"):
                ungradable.append(cve_id)
                del self.state["predictions"][cve_id]
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
        # A running total, so the loss is visible on /method rather than being
        # inferred from a number that quietly stopped growing.
        if ungradable:
            self.state["ungradable"] = (self.state.get("ungradable") or 0) + len(ungradable)
            print(f"  grader: {len(ungradable)} prediction(s) closed with no verdict; "
                  "the ledger no longer records what was predicted "
                  f"({self.state['ungradable']} cumulative)")
        summary = self.summary()
        if newly:
            self.state["history"].append({
                "date": today, "newly_graded": len(newly),
                "newly_correct": sum(1 for g in newly if g["correct"]),
                "cumulative_precision": summary["precision"],
            })
        return newly, summary

    def summary(self):
        """The live accuracy record for this grader's state."""
        return summarise_state(self.state)

    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        json.dump(self.state, open(self.path, "w"), indent=1)


def summarise_state(state):
    """The live accuracy record, FLOORED here and nowhere else.

    The floor used to live only in site.py, applied while building the derived
    file, so Grader.summary published the raw value straight into summary.json.
    Two files from the same run then said different things about the site's own
    accuracy: summary.json carried `precision: 1.0` on a single graded case while
    precision.json carried `precision: null, below_floor: true`. A consumer reading
    the first got "100% accurate" from n=1, a stronger claim than the leave-one-out
    figure over 29,000 decisions sitting beside it.

    A module-level function over raw state, so the site can floor a ledger it loaded
    from disk without either recomputing the rule or depending on a summary block
    that may be absent. One implementation, two callers.

    Precision is over SCORED verdicts only. A rejection closes a prediction without
    revealing an assigner, so counting it as a miss would penalise the method for an
    outcome it never predicted.
    """
    graded = [g for g in (state.get("graded") or []) if g.get("scored", True)]
    correct = sum(1 for g in graded if g.get("correct"))
    n = len(graded)

    by_tier = collections.defaultdict(lambda: [0, 0])
    # Per-CNA strata. The out-of-sample warrant was 100% on n=224 and 213 of those
    # 224 were one CNA, so eleven cases informed every other CNA in the Program. A
    # global figure that clears a floor while the tail error rate is 2 in 3 is not
    # a measurement of the tail, and the tail is where both known-wrong rows were.
    by_cna = collections.defaultdict(lambda: [0, 0])
    for g in graded:
        by_tier[g.get("tier", "?")][0] += 1
        by_tier[g.get("tier", "?")][1] += int(bool(g.get("correct")))
        who = g.get("actual") or g.get("predicted") or "unknown"
        by_cna[who][0] += 1
        by_cna[who][1] += int(bool(g.get("correct")))

    def floored(a, b):
        """(precision, below_floor). The floor applies per stratum, not just
        globally: a CNA below it reads "not separately measurable" rather than
        inheriting the global figure, which is what one shared number silently
        does."""
        if a < MIN_GRADED:
            return None, True
        return round(b / a, 4), False

    prec, below = floored(n, correct)
    return {
        "graded": n,
        "correct": correct,
        "precision": prec,
        "below_floor": below,
        "floor": MIN_GRADED,
        "outstanding": len(state.get("predictions") or {}),
        "closed_unscored": sum(1 for g in (state.get("graded") or [])
                               if not g.get("scored", True)),
        "by_tier": {t: {"graded": a, "correct": b,
                        "precision": floored(a, b)[0],
                        "below_floor": floored(a, b)[1]}
                    for t, (a, b) in sorted(by_tier.items())},
        "by_cna": {c: {"graded": a, "correct": b,
                       "precision": floored(a, b)[0],
                       "below_floor": floored(a, b)[1]}
                   for c, (a, b) in sorted(by_cna.items(), key=lambda kv: -kv[1][0])},
        "strata": len(by_cna),
        "misses": [g for g in graded if not g.get("correct")][-25:],
    }



# --------------------------------------------------------------------------
# pipeline entry point
# --------------------------------------------------------------------------

def apply_to_backlog(backlog, corpus_df, precision_path, today=None, k=DEFAULT_K,
                     record_for=None, covered=None, sightings=None,
                     bulk_reporters=frozenset(), suppressed=()):
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
    n_suppressed = 0
    for row in backlog:
        # Checked FIRST, before inference runs on the row at all.
        #
        # This must not be only in report._gated. The grader ledger is a published
        # artefact on the data branch, so gating display alone would withhold the
        # row from the site while writing the inferred CNA name into
        # precision.json: a row withheld because someone reported it as under
        # embargo would be named in public anyway. That is the exact
        # one-stage-writes-another-reads shape that has already bitten
        # days_public, self_disclosed, feed health, the epoch and PAGES-at-import.
        #
        # The row keeps no owner fields at all rather than an unattributed
        # placeholder, so no artefact can carry a name for it even by accident.
        if row["cve_id"] in suppressed:
            row["suppressed"] = True
            row["owner"], row["owner_tier"] = None, "suppressed"
            row["owner_method"] = "suppressed-on-report"
            row["veto_evaluated"] = False
            n_suppressed += 1
            continue
        owner, tier, method = inferencer.attribute(
            row["cve_id"],
            product_map_owner=row.get("product_map_owner"),
            product_map_confidence=row.get("product_map_confidence") or 0.0,
            covered=covered, sightings=sightings, bulk_reporters=bulk_reporters)
        # Silence from the product map must be distinguishable from agreement.
        # owner_contested shipped false on every row as though it were measured.
        row["veto_evaluated"] = bool(row.get("product_map_owner"))
        row["owner"], row["owner_tier"], row["owner_method"] = owner, tier, method
        row["suppressed"] = False
        named[tier] += 1
        if "vetoed" in method:
            vetoed += 1
        if record_for is None or row["cve_id"] in record_for:
            grader.record(row["cve_id"], owner, tier, k, today,
                          run_length=inferencer.run_length(row["cve_id"]))

    # A retraction has to reach the ledger, not just the site.
    withdrawn = grader.withdraw(record_for) if record_for is not None else []
    if withdrawn:
        print(f"  withdrew {len(withdrawn)} prediction(s) for rows no longer published")

    grader.save()
    live_score = grader.summary()
    loo = inferencer.validate_loo(year=today[:4], k=k)

    # Suppressed rows are out of both halves of this ratio. Leaving them in the
    # denominator would make a withhold look like an abstention and quietly drag
    # the published naming rate down; leaving them in the numerator would be worse.
    total = (len(backlog) - n_suppressed) or 1
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
        # Counted so the lever cannot be used quietly. Never the ids.
        "suppressed": n_suppressed,
    }


def _pct(x):
    return "n/a" if x is None else f"{100 * x:.2f}%"


def unattributed_validation(k=DEFAULT_K, today=None):
    """The validation block for a run that did not infer anything.

    Shaped exactly like apply_to_backlog's return so no consumer needs a branch,
    and filled with the honest values rather than zeros pretending to be
    measurements: precision is None, which summarise_state and the site already
    render as "not measurable", and NOT 0.0, which reads as "measured, and
    wrong".

    The distinction is the same one this repository keeps having to relearn:
    `feeds.record_feed` draws it between a failed feed and an empty one,
    `summarise_state` draws it with the precision floor, and the feed scorecard
    had to grow an `unmeasurable` verdict for it. A run that did not attempt to
    name anything has not scored 0% at naming.
    """
    today = today or dt.date.today().isoformat()
    empty = {"method": "not-run", "k": k, "decided": 0, "abstained": 0,
             "total": 0, "correct": 0, "wrong": 0, "coverage": 0.0,
             "precision": None, "below_floor": True, "not_run": True}
    return {
        "date": today, "k": k,
        "named": {TIER_CORROBORATED: 0, TIER_BLOCK: 0, TIER_NONE: 0},
        "run_coverage": 0.0,
        "leave_one_out": dict(empty),
        "live": {**empty, "graded": 0, "outstanding": 0},
        "newly_graded": 0,
        "withdrawn": 0,
        "suppressed": 0,
        # So a reader of summary.json can tell "this site does not attribute"
        # from "this site attributes and got nothing this run".
        "not_run": True,
        "not_run_reason": "v1 publishes no attribution; inference is not run",
    }
