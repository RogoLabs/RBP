"""
Static site build (PLAN.md phase 4).

Reads the newest snapshot plus both ledgers and renders rbptracker.org. No
network, no runtime API calls: every page is a file, and the data the tables
sort and filter is embedded as JSON so the browser never fetches anything.

EDITORIAL STANCE, rewritten 2026-08-26 with the pivot it had stopped describing.

The site is A LIST. "Here are the CVE IDs that are reserved and public, and where
they are showing up." The front door is the rows, a command bar over them, and a
slide-over carrying everything that used to be a separate page.

It previously led with the COUNT, as an instrument panel: a 104px number and
around 650 words before the first CVE, over a seven-column table that answered
the first half of the question and none of the second. Four pages are rendered
now, and this docstring described the eight-page version for the whole time it
was wrong, which is the argument for it being here rather than in PLAN.md.

What has not changed, and is the part that binds:

  - no verdict, because RBP Policy v2.0.0 has no threshold for a CNA to be over;
  - no attribution at all under v1, see NAMING_ENABLED, so there is no per-CNA
    page and no CNA is named on any row;
  - the `owning_cna` redaction is the reason the count had to be assembled from
    outside, and it is answered in the panel rather than assumed;
  - a count that is a lower floor than usual says so where the count is. The
    explanation lives on /status; the disclosure does not move off the page
    carrying the number.
"""
from __future__ import annotations

import csv
import datetime as dt
import glob
import collections
import hashlib
import io
import json
import os
import re
import shutil

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import clock
from . import schema as _schema

# Pre-launch posture. The dashboard is built and reachable either way, because
# the repo is public and the data files are served regardless; the gate is on
# what the front door presents, not on hiding anything.
#
#   not launched: / is the holding page, the dashboard lives at /overview.html
#                 and every dashboard page is noindex, so search engines do not
#                 index a count that is still built on partial CNA coverage.
#   launched:     / IS the dashboard.
#
# Flip with RBP_LAUNCHED=1, wired to a repository variable so it is a settings
# change rather than a commit. The gate itself is GATE_TOP_N_PCT below; do not
# restate the number here, because the two said different things for four days.
# Minimum coverage before the front door may become the dashboard, measured on
# cnas_effective: CNAs seen at least MIN_SIGHTINGS times, which is the same floor
# inference uses before it will attach a name to a row.
#
# This was briefly gated on cnas_own_channel instead, reasoning that it was the
# stricter figure. It is stricter, but it is bounded by the number of
# hand-written owner-feed parsers, which is three, so the ceiling was 3/434 =
# 0.7% against a 50% gate: the gate could never clear. A launch would have
# produced a red check forever, with nothing to distinguish a threshold that was
# merely distant from one that was unreachable. That was found by reading a
# summary artefact, not by a test, so test_gate_threshold_is_reachable now
# asserts the gate figure can in principle reach GATE_TOP_N_PCT.
#
# The objection that motivated own-channel still stands and is answered instead
# by the floor: a single stray sighting no longer credits a CNA as covered.
# THE GATE, re-derived 2026-08-23. Read this before changing the number.
#
# The old gate was `cnas_effective` >= 50% of the pinned 539-CNA roster. It was
# unreachable, and not by a little. Two ceilings, both measured:
#
#   28.2%  every CNA the nine feeds sight even once, promoted to the 3-sighting
#          floor. The ceiling on the CURRENT feed set. Tuning cannot pass 50%.
#   68.8%  roster CNAs that have published 3 CVEs in the window at all. Only 371
#          of 539 qualify; 128 published nothing. The ceiling on ANY feed set,
#          so 100% of the roster is arithmetically impossible and 80% would be
#          a stricter version of the same mistake.
#
# 50.0 was set when the gate figure was `cnas_sighted` over a corpus-derived
# denominator. The numerator later moved to `cnas_effective` and the denominator
# to the pinned roster, and nobody re-derived the threshold. It was a leftover
# from two metric changes that each made it harder to clear.
#
# The replacement asks a question that has an answer: of the 50 CNAs that issue
# the most CVEs, how many can this site actually see, on the same 3-sighting
# floor `cnas_effective` uses. Measured live at 31 of 50; the CSAF/MSRC
# promotion and the OSV ecosystem expansion together take it to 40 of 50.
#
# Deliberately NOT paired with a roster-share floor. That was offered and
# declined: the top-50 condition alone is the gate. The cost of that choice is
# that it clears at exactly 40/50 with no margin, so `_gate_status` reports the
# margin explicitly rather than letting a bare pass read as a comfortable one.
GATE_TOP_N_PCT = 80.0


def _validated_launched(raw):
    """Parse RBP_LAUNCHED strictly, the way the epoch is parsed.

    A bare truthiness test silently read `on`, `y` and `enabled` as
    not-launched, so a deliberate launch could look like a no-op and be
    debugged as a build problem.
    """
    raw = (raw or "").strip().lower()
    if raw in ("", "0", "false", "no"):
        return False
    if raw in ("1", "true", "yes"):
        return True
    raise SystemExit(
        f"RBP_LAUNCHED={raw!r} is not a recognised boolean. Use 1 or 0. "
        "Refusing to guess: a misread flag either publishes a site that should "
        "be held or holds one that should be published.")


LAUNCHED = _validated_launched(os.environ.get("RBP_LAUNCHED"))

# Build the LAUNCHED posture even below the coverage gate, for rehearsal only.
#
# Deliberately a second variable rather than a mode of RBP_LAUNCHED: bypassing the
# gate should take two explicit levers, so no single setting can both request a
# launch and waive the check on it. The workflow sets this only on a dry run, where
# the deploy job is skipped and the artefact is discarded.
REHEARSE = (os.environ.get("RBP_REHEARSE") or "").strip() in ("1", "true", "yes")

# THE PRECISION FLOOR, and the one implementation of the rule.
#
# Moved here from rbp.inference on 2026-08-26. It is a PUBLISHING rule rather than
# a block-inference one: it decides whether a ratio is fit to print, and it was
# the last thing keeping the publish path importing 699 lines that no longer run.
# `inference` imports it back, so there is still exactly one implementation.
#
# Why one implementation matters here specifically: split across two modules, the
# raw value reached summary.json while the floored one reached precision.json, so
# two files from the same run published different figures for this site's own
# accuracy.
#
# (Three overlapping comment blocks stood here after the move, two of them saying
# the floor lived in inference and one saying it was "owned here rather than in
# site.py", inside site.py. Left as a note because the move is exactly when this
# happens.)
MIN_GRADED = 20


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


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TEMPLATES = os.path.join(ROOT, "templates")
STATIC = os.path.join(ROOT, "static")


def slug(name):
    """Filesystem-safe CNA name for /cna/<slug>.html."""
    return re.sub(r"[^a-z0-9]+", "-", (name or "unknown").lower()).strip("-") or "unknown"


def _snapshots(snap_root):
    return sorted(d for d in glob.glob(os.path.join(snap_root, "*")) if os.path.isdir(d))


def _read(path, default):
    """Tolerant read. Only for the two ledgers, where absence is a valid
    first-run state."""
    try:
        return json.load(open(path))
    except FileNotFoundError:
        return default
    except Exception as e:
        raise SystemExit(f"{path} exists but is unreadable: {e}. Refusing to "
                         "publish from a corrupt ledger.") from e


def _read_strict(path):
    """A snapshot artefact the pages assert numbers from.

    Previously these were tolerant, so a truncated backlog.json beside a good
    summary.json published a front page reading 553 above an empty table, an
    empty rbp.json, a header-only CSV, and per-CNA pages asserting rows above
    none of them. The step exited 0, so the artifact uploaded, the deploy ran,
    and the truncated snapshot became the next run's diff baseline.
    """
    try:
        return json.load(open(path))
    except Exception as e:
        raise SystemExit(f"cannot read {path}: {e}") from e


# The legacy placeholder. `owner` is now a CNA short name or None (schema v1), but
# snapshots written before that carry the string "unattributed" in the same field,
# and CI restores prior snapshots from the data branch for the week-over-week diff.
#
# Coerced on read rather than tolerated in the invariant. _assert_consistent
# deliberately no longer special-cases the string, so without this a stale snapshot
# reads as a row naming a CNA called "unattributed" that is absent from cnas.json,
# which is exactly what it said when this change first built. Version skew on a
# published artefact is an operational fact, not a bug to crash on; publishing the
# placeholder as though it were a CNA name is the bug.
_LEGACY_OWNER = "unattributed"

# v1 PUBLISHES NO NAMES. Read this before flipping it.
#
# The site's argument is about a redacted field and a withdrawn Program metric.
# It is not about which CNA is worst, and it never needed to be: the count, the
# clock, the sources, the age distribution and the coverage table carry the whole
# case. Naming was carrying nine of the eighteen launch blockers on its own.
#
# What was actually true when this flipped, on 2026-08-23: production graded n
# was 1; 96.4% of named rows sat on one CNA whose own advisory channel the
# pipeline does not read; two of the five named CNAs held exactly one inferred,
# single-origin, unmeasurable-ordering row apiece; and the correction channel a
# named party would have to use was unreachable by anyone without repository
# permissions. A published accuracy figure on n=1 is not a measurement.
#
# Inference still RUNS. The grader still records and still grades, so a v2
# naming release starts from real n instead of from one. What changes is only
# that no name crosses the publication boundary.
#
# Flipping this back to True is not sufficient to restore naming. assert_artefact
# inverts with it, and the conditions in PLAN.md 8d that naming depends on
# (2, 4, 5) must be genuinely met first, not declared.
NAMING_ENABLED = False

# Every field that carries or qualifies a name. Stripped as a set, so adding a
# new owner_* field cannot leak by being forgotten here: schema.COLUMNS is
# asserted against this list in tests.
#
# ONE DEFINITION, in schema.py since 2026-08-26. There were four overlapping
# lists across three modules and two of them were byte-identical duplicates, on a
# rule whose entire value is that a new field cannot be forgotten. Re-exported
# under the local name so the call sites below read the same as they did.
NAME_FIELDS = _schema.ROW_NAME_FIELDS


def _denamed(rows, source="artefact"):
    """Strip every name-bearing field from rows about to be published.

    The publication boundary, not the pipeline. Rows arrive here with whatever
    inference decided; they leave with `owner_nameable` False and no name of any
    kind. Applied on READ so it covers prior snapshots and the dated archive too,
    which is where the previous withhold lever leaked: a row scrubbed from the
    current run was still published verbatim inside /data/archive/<yesterday>.

    Idempotent, so running it over an already-clean snapshot is a no-op.

    NON-MUTATING, deliberately. An in-place version is the obvious implementation
    and it is wrong here: `reportable`, `backlog` and `held` share row objects, so
    stripping one artefact on the way out silently stripped the rows that the
    per-CNA aggregation had not consumed yet. Callers use the return value.
    """
    if NAMING_ENABLED:
        return rows
    out, stripped = [], 0
    for r in rows:
        if not isinstance(r, dict):
            out.append(r)
            continue
        if any(k in r for k in NAME_FIELDS):
            stripped += 1
        clean = {k: v for k, v in r.items() if k not in NAME_FIELDS}
        # Kept, and forced. Consumers branch on this field rather than on the
        # emptiness of `owner`, and v1's answer to "is this nameable" is no.
        clean["owner_nameable"] = False
        out.append(clean)
    if stripped:
        print(f"  note: {source}: stripped names from {stripped} row(s); "
              f"v1 publishes no attribution")
    return out


def _normalise_legacy(rows, source="snapshot"):
    """Bring a snapshot written under an older schema up to the current contract.

    Two coercions, both idempotent, so applying them to a current snapshot is a
    no-op and applying them to an old one makes it readable.
    """
    from . import classify
    owners = descs = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        if r.get("owner") == _LEGACY_OWNER:
            r["owner"] = None
            r.setdefault("owner_nameable", False)
            owners += 1
        # Descriptions written before the sanitiser existed still carry URLs and
        # tracker annotations, which assert_artefact refuses. Cleaning on read is
        # correct rather than lenient: the sanitiser is idempotent, so this cannot
        # weaken a current snapshot, and the alternative is a build that cannot
        # read its own history.
        d = r.get("description")
        if d:
            cleaned = classify.display_description(d)
            if cleaned != d:
                r["description"] = cleaned or (r.get("package") or "")
                descs += 1
    if owners:
        print(f"  note: {source}: coerced {owners} legacy {_LEGACY_OWNER!r} owner "
              "value(s) to null (predates schema v1)")
    if descs:
        # Naming the source matters. "sanitised 170 legacy description(s)" on a run
        # whose own snapshot is clean reads as the pipeline failing to sanitise;
        # every one of the 170 was in YESTERDAY's snapshot, read for the diff.
        print(f"  note: {source}: sanitised {descs} legacy description(s) on read "
              "(predates the description sanitiser)")
    # Fields a previous schema published and this one does not. Dropped here for
    # the same reason the names are: this is the one read path, so it is the only
    # place that can promise an OLD snapshot is republished under the CURRENT
    # contract. rbp.csv is projected through COLUMNS and would have dropped these
    # on its own; rbp.json rows and the dated archive are not, and would not.
    retired = 0
    for r in rows:
        if isinstance(r, dict) and any(k in r for k in _schema.RETIRED_ROW_FIELDS):
            retired += 1
            for k in _schema.RETIRED_ROW_FIELDS:
                r.pop(k, None)
    if retired:
        print(f"  note: {source}: dropped retired field(s) "
              f"{', '.join(_schema.RETIRED_ROW_FIELDS)} from {retired} row(s); "
              f"schema v{_schema.SCHEMA_VERSION} does not publish them")

    # LAST, and unconditionally. Every read path into the site build goes through
    # here, including prior snapshots and the dated archive, so this is the one
    # place that can guarantee no name reaches a published artefact regardless of
    # what the snapshot on disk says.
    return _denamed(rows, source)


def _gate_status(summary):
    """Is the launch gate cleared, on the effective coverage figure?

    Reported whether or not the flag is set, so /method can state the position
    truthfully at any time rather than only when someone tries to launch. All
    three coverage figures are returned, because a reader asking "can this site
    see my CNA" and a reader asking "could this site ever call my CNA a 4.5.1.4
    breach" are asking different questions with different answers.
    """
    cov = summary.get("coverage") or {}
    total = cov.get("total_cnas") or 0
    eff = cov.get("cnas_effective")
    sighted = cov.get("cnas_sighted", cov.get("covered_cnas"))
    top_n = cov.get("top_n") or 0
    top_eff = cov.get("top_covered_effective")
    floor = cov.get("min_sightings")

    # The gate reads top_covered_effective, NOT top_covered. A run produced
    # before that field existed must fail closed rather than fall back to the
    # one-sighting figure, which would clear the gate on a weaker measure than
    # the one it names.
    if not top_n or top_eff is None:
        return {"cleared": False, "pct": None, "required": GATE_TOP_N_PCT,
                "basis": f"top-{top_n or '?'}-by-volume at the {floor or '?'}-sighting floor",
                "reason": ("this snapshot does not report top-N coverage on the "
                           "sighting floor, so the gate cannot be evaluated")}

    pct = round(100 * top_eff / top_n, 1)
    needed = -(-int(GATE_TOP_N_PCT * top_n) // 100)      # ceil, in whole CNAs
    # CLEARED IS DERIVED FROM THE MARGIN, not from the rounded percentage.
    #
    # It was `pct >= GATE_TOP_N_PCT`, and `pct` is rounded to one decimal, so the
    # two could disagree: any figure in [79.95, 80.0) rounds to 80.0 and clears
    # while `needed` is still one CNA above `top_eff`, publishing
    # `cleared: true, margin: -1`. At top_n = 50 the granularity is 2% and it
    # cannot happen; `top_n` is a parameter, and a gate that is only correct at
    # one value of its own input is correct by accident.
    #
    # One comparison, in whole CNAs, which is also the unit the gate is argued in
    # everywhere else: "40 of 50", not "80.0%".
    margin = top_eff - needed
    cleared = margin >= 0
    return {
        "cleared": cleared,
        "pct": pct,
        "required": GATE_TOP_N_PCT,
        "basis": f"top-{top_n}-by-volume at the {floor or '?'}-sighting floor",
        "top_n": top_n,
        "top_effective": top_eff,
        "needed": needed,
        # Published because the gate was deliberately left without a second
        # condition, so it can clear by exactly one CNA. A bare "cleared: true"
        # would hide that; a margin of 0 says it out loud.
        "margin": margin,
        "top_missed": cov.get("top_missed_effective") or [],
        # Carried so the roster-share figures stay visible and quotable even
        # though they no longer gate anything. Removing them would make the
        # weaker number harder to find, not the site more honest.
        "roster_pct_effective": round(100 * eff / total, 1) if total and eff is not None else None,
        "effective": eff,
        "sighted": sighted,
        "total": total,
        "min_sightings": floor,
        "own_channel": cov.get("cnas_own_channel"),
        "profile": cov.get("profile"),
        "reason": (
            f"{top_eff} of the top {top_n} CNAs by volume are seen at least "
            f"{floor if floor is not None else '?'} times ({pct}%), "
            + (f"clearing the {GATE_TOP_N_PCT}% gate by {margin} CNA(s)" if cleared
               else f"below the {GATE_TOP_N_PCT}% gate, which needs {needed}")),
    }


def _assert_consistent(rows, summary, cnas):
    """One invariant, raised in one place, covering three separate defects:
    the epoch applied to some writers and not others, a truncated artefact, and
    an owner link pointing at a CNA page that was never generated."""
    total = summary.get("total")
    if total is not None and len(rows) != total:
        raise SystemExit(
            f"snapshot is inconsistent: backlog.json has {len(rows)} rows but "
            f"summary.json reports total={total}. The published population must "
            "be computed once. Refusing to publish contradictory numbers.")
    known = {c["cna"] for c in cnas}
    # No placeholder special-case. `owner` is a CNA short name or None, so this is
    # a plain truthiness test; the previous version only passed because it knew
    # about a magic string that the published field dictionary denied existed.
    named = [r for r in rows if r.get("owner")]
    if not NAMING_ENABLED:
        # v1 publishes no attribution, so the only invariant left on this axis is
        # that there is nothing to check. The three arms below all describe
        # relationships between named rows and per-CNA pages that no longer
        # exist; keeping them would be keeping three ways to fail an assertion
        # whose subject was removed.
        if named:
            raise SystemExit(
                f"{len(named)} row(s) still carry an owner after the de-naming "
                "boundary. _denamed did not run on this path. Refusing to publish.")
        return

    orphans = sorted({r["owner"] for r in named} - known)
    if orphans:
        raise SystemExit(
            f"rows name CNAs absent from cnas.json: {orphans}. Every owner link "
            "would 404. Refusing to publish.")
    # No published artefact may name a CNA outside the covered set for the run
    # that named it. Before this, coverage.top_missed said "we do not read this
    # CNA" while a row said "this CNA owns this vulnerability".
    covered = set((summary.get("coverage") or {}).get("covered") or [])
    if covered:
        outside = sorted({r["owner"] for r in named if r["owner"] not in covered})
        if outside:
            raise SystemExit(
                f"rows name CNAs outside the covered set: {outside}. The site "
                "would simultaneously claim not to read these CNAs and to know "
                "what they own. Refusing to publish.")

    counted = sum(c.get("outstanding", 0) for c in cnas)
    if counted != len(named):
        raise SystemExit(
            f"per-CNA outstanding sums to {counted} but {len(named)} rows are "
            "named. The per-CNA cards would contradict their own tables.")


# A URL, by scheme. Deliberately not the bare substring "http": protocol names
# appear legitimately inside software identifiers (NIOHTTPRequestDecompressor,
# HTTPDecoder) and inside prose about a protocol ("unauthenticated HTTP endpoint").
_URL_IN_TEXT = re.compile(r"\b(?:https?|ftp|git)://|\bwww\.\w", re.I)


def assert_artefact(rows, label, cnas=None, covered=None):
    """Invariants every published artefact must satisfy, not just backlog.json.

    The one assertion that existed iterated a single-element tuple over a
    directory that had just gained a new file, which is exactly why the
    held_back.json leak shipped green. held_back's named owners included CNAs
    absent from cnas.json, so it published precisely the values the existing
    assertion refused.

    UNDER v1 THIS INVARIANT IS INVERTED, and the inversion is the point. The old
    rule was "a name must be inside the covered set", which is a set-membership
    question with four ways to be subtly wrong, and it was: `publish.check`'s
    ledger arm compared id sets and could not see a name at all, so 121 rows on
    the public data branch named CNAs the site itself refused to name. The new
    rule is "no row carries a name", which has one way to be wrong and is
    checkable by grep. Keeping the old arms as well would be keeping four ways to
    fail an assertion that is now trivially true.
    """
    known = {c["cna"] for c in (cnas or [])}
    problems = []
    for r in rows:
        if not isinstance(r, dict):
            problems.append(f"{label}: non-object row")
            continue
        cid = r.get("cve_id", "?")
        owner = r.get("owner")
        is_named = owner not in (None, "", "unattributed")

        if not NAMING_ENABLED:
            # ONE arm replaces four. The old rule was "a name must be inside the
            # covered set", a set-membership question with four ways to be
            # subtly wrong, and it was wrong: publish.check's ledger arm compared
            # id sets and could not see a name at all.
            # On the VALUE, not on the key. `owner: null` carries no name, and
            # refusing it would fail every legitimately abstaining row while
            # catching nothing: the harm is a name being published, not a key
            # being present. _denamed drops the keys entirely, so the strip stays
            # stricter than the assertion, which is the safe direction.
            present = sorted(k for k in NAME_FIELDS if r.get(k) is not None)
            if present:
                problems.append(
                    f"{label}:{cid} carries name-bearing field(s) {present} while "
                    "the site publishes no attribution")
            if r.get("owner_nameable") is not False:
                problems.append(
                    f"{label}:{cid} has owner_nameable={r.get('owner_nameable')!r}; "
                    "v1 publishes no attribution, so it must be False")
        else:
            if "owner_nameable" not in r:
                problems.append(f"{label}:{cid} has no owner_nameable field")
            if is_named and r.get("counted") is False:
                problems.append(f"{label}:{cid} names {owner} on an uncounted row")
            if is_named and known and owner not in known:
                problems.append(f"{label}:{cid} names {owner}, absent from cnas.json")
            if is_named and covered and owner not in covered:
                problems.append(f"{label}:{cid} names {owner}, outside the covered set")
            if any(k.startswith("product_map") for k in r):
                problems.append(f"{label}:{cid} carries an ungated product-map field")

        # Review item 4. A suppressed row is withheld because someone reported it
        # as wrong or under embargo, so its presence in ANY published artefact
        # defeats the lever. Class 1: publishing it is a false statement about, or
        # a disclosure concerning, a named third party. Blocks.
        if r.get("suppressed"):
            problems.append(
                f"{label}:{cid} is suppressed and must not appear in a published "
                "artefact at all")

        # Review item 18. A backstop, not a policy gate, and the distinction
        # matters under PLAN 8b. Cleaning happens deterministically upstream in
        # classify.display_description, so this can only fire if that sanitiser
        # has a bug or a new feed bypasses it. When it does fire the failure is a
        # disclosure harm (a pointer to vulnerable code on an unpublished CVE),
        # not an ugly string, so blocking is the correct direction. Contrast the
        # NOTE: guard this replaced, which blocked on cosmetics and froze a
        # publication over six harmless rows.
        # Match a URL SCHEME, not the substring "http". The first version of this
        # check was `"http" in desc.lower()`, which flagged 16 rows on
        # NIOHTTPRequestDecompressor, HTTPDecoder and "unauthenticated HTTP
        # tools/call" against 7 genuine URLs, and blocked the build on all 23. A
        # blocking guard with a sloppy pattern is the same class-1-on-class-2
        # mistake as the NOTE: guard, so a guard that CAN stop a publication has to
        # be precise about what it matches.
        desc = r.get("description") or ""
        if _URL_IN_TEXT.search(desc):
            problems.append(
                f"{label}:{cid} publishes a URL in its description: {desc[:80]!r}")
        if re.search(r"\bNOTE\s*:|\bDEBIANBUG", desc, re.I):
            problems.append(
                f"{label}:{cid} publishes a tracker annotation: {desc[:80]!r}")
        # Deliberately NOT asserted here: a low-quality description is bad
        # display text, not a false statement about a third party. Refusing to
        # publish over it would fail dark on data that is merely ugly, which is
        # the opposite of the rule these invariants exist to serve. It is cleaned
        # at the publishable boundary in report._publishable instead.
    if problems:
        raise SystemExit("refusing to publish:\n  " + "\n  ".join(problems[:25]))
    return len(rows)


def cadence(data_dir, today=None, days=7):
    """What the run ledger can evidence about the publish cadence: three numbers.

    The site tells readers it updates every six hours. Before the ledger existed
    there was no evidence for that anywhere, and the claim was false at least
    twice: the 2026-08-21 06:00Z and 18:00Z scheduled ticks both produced
    nothing, with zero pushes in the window, so nothing could have been queued or
    evicted. Nobody could have known.

    THE FIRST VERSION OF THIS FUNCTION COULD NOT HAVE KNOWN EITHER, and that is
    why it now returns three figures instead of one.

    It answered the six-hour claim with `delivered / (days * 4)`, where the
    numerator counted EVERY successful publish and the denominator counted only
    the cron schedule. Merging to `main` also publishes, so a week carrying 29
    pushes scored 47 against 28 and /status published "46 of 28 scheduled runs
    published in the last 7 days (164.3%)". A ratio over 100% is the visible half
    of the defect and the harmless half.

    The other half: a push-triggered publish CANNOT evidence a scheduled tick, so
    a week in which every single cron tick was evicted or failed still read green
    as long as somebody was merging. The one failure this ledger exists to catch
    was the one failure it was arithmetically unable to report. Measured on the
    live ledger on 2026-09-01: 15 of 28 scheduled ticks delivered, reported as
    164.3%.

    So the scheduled claim is counted from scheduled runs only, and the two
    figures that stop that number being MISread as staleness are published beside
    it rather than dropped:

      scheduled / expected   the cadence claim, cron ticks only
      publishes              every successful publish, any trigger
      longest_gap_hours      the longest the site went without publishing at all

    A low `scheduled` next to a healthy `publishes` and a small gap is a site
    that is fresh and whose cron ticks are being evicted by its own pushes. That
    is a real thing, worth seeing, and not the same as a stale site. Reporting
    the first number alone would trade a figure that was too flattering for one
    that is too alarming, which is not an improvement.

    An entry with no `event` is not credited as a scheduled tick. Every line the
    deploy job has written carries one, so this only governs a torn or
    hand-edited ledger, and it errs toward reporting LESS delivery than happened:
    this figure exists to raise an alarm, not to reassure.

    Returns None when the ledger is absent, and the template then says the
    cadence is not yet evidenced rather than printing a confident zero. A fresh
    repository and a broken pipeline must not look the same.
    """
    path = os.path.join(data_dir, "runs.jsonl")
    if not os.path.exists(path):
        return None
    try:
        now = (dt.datetime.fromisoformat(today) if today
               else dt.datetime.now(dt.timezone.utc))
    except ValueError:
        now = dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    cutoff = now - dt.timedelta(days=days)

    scheduled, publishes, last = 0, 0, None
    published_at = []
    try:
        for line in open(path):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            try:
                at = dt.datetime.fromisoformat(rec.get("at", ""))
            except ValueError:
                continue
            if at.tzinfo is None:
                at = at.replace(tzinfo=dt.timezone.utc)
            if last is None or at > last:
                last = at
            if rec.get("conclusion") != "success":
                continue
            # Kept for the gap, INCLUDING entries older than the cutoff: a gap
            # that opens before the window and closes inside it is exactly the
            # gap a reader cares about, and slicing before measuring hides it.
            published_at.append(at)
            if at < cutoff:
                continue
            publishes += 1
            if rec.get("event") == "schedule":
                scheduled += 1
    except OSError:
        return None

    published_at.sort()
    longest = None
    for earlier, later in zip(published_at, published_at[1:]):
        if later < cutoff:
            continue
        hours = (later - earlier).total_seconds() / 3600
        if longest is None or hours > longest:
            longest = hours

    # 4 a day is the schedule. Expressed as a fraction of expected rather than a
    # bare count, because "23" means nothing without "of 28".
    expected = days * 4
    return {"days": days, "scheduled": scheduled, "expected": expected,
            "pct": round(100 * scheduled / expected, 1) if expected else None,
            "publishes": publishes,
            "longest_gap_hours": round(longest, 1) if longest is not None else None,
            "last": last.isoformat(timespec="seconds") if last else None}


def _publish_keep():
    """The retention window, read from publish rather than restated.

    A second copy of this number in a template is how /data came to describe
    "the current snapshot, the previous one, and one per month" while the
    constant said something else.
    """
    try:
        from .publish import KEEP_SNAPSHOTS
        return KEEP_SNAPSHOTS
    except Exception:
        return None


def _drop_withheld(rows, withheld, label):
    """Remove withheld ids from a row set. Idempotent, and loud when it fires."""
    if not withheld:
        return rows
    keep = [r for r in rows
            if not (isinstance(r, dict)
                    and (r.get("cve_id") or "").strip().upper() in withheld)]
    if len(keep) != len(rows):
        print(f"  note: {label}: withheld {len(rows) - len(keep)} row(s) at the "
              "site boundary")
    return keep


def withheld_ids(data_dir):
    """Ids this build must not publish. Delegates; see publish.suppressed_ids.

    THE SITE READS THIS ITSELF rather than relying on the workflow having
    scrubbed the tree first, and the distinction is the whole of review item 4.

    `publish.stage` was the only code that scrubbed withheld ids, and it runs
    AFTER the site is built (deploy.yml: Run pipeline, Build site, upload, then
    Stage durable state). It scrubs `.state`, which is the data branch. The
    runner's own `snapshots/` tree, which `site.build` reads, was never touched,
    so on the run where a withhold first fired the site published the withheld id
    twice: in /data/archive/<yesterday>/rbp.json and as plain text under "no
    longer listed". For an embargo the id IS the sensitive fact, so that defeats
    the lever for a full six-hour cycle.

    Doing it here rather than adding a scrub step ahead of the build is
    deliberate. A workflow ordering constraint is invisible to anyone reading the
    Python, holds only in CI, and breaks silently the first time someone reorders
    a step. This holds in a local build too.

    DELEGATED since 2026-08-26. This used to be a second implementation of the
    same read against the same file: same path, same empty-on-error contract,
    same intent, maintained twice. One of them normalising ids and the other not
    would be a withhold that worked on the data branch and not on the page.
    """
    from .publish import suppressed_ids
    return suppressed_ids(data_dir)


def load(snap_root, data_dir):
    """Assemble the render context from the newest snapshot and the ledgers."""
    snaps = _snapshots(snap_root)
    if not snaps:
        raise SystemExit(f"no snapshots in {snap_root}; run the pipeline first")
    latest, prev = snaps[-1], (snaps[-2] if len(snaps) > 1 else None)

    withheld = withheld_ids(data_dir)
    rows = _normalise_legacy(_read_strict(os.path.join(latest, "backlog.json")),
                             source=f"{os.path.basename(latest)}/backlog.json")
    n_before = len(rows)
    rows = _drop_withheld(rows, withheld, "backlog.json")
    withheld_here = n_before - len(rows)
    summary = _read_strict(os.path.join(latest, "summary.json"))
    if withheld_here:
        # The snapshot's own total was computed before the withhold, so leaving
        # it alone makes _assert_consistent refuse the build: a withhold would
        # take the site down rather than remove a row. Adjusted here, and the
        # count is published rather than absorbed, because "counts, never
        # identifiers" is the promise and a silently shrinking total is the one
        # thing a suppression lever must not be.
        summary = dict(summary)
        if isinstance(summary.get("total"), int):
            summary["total"] = max(0, summary["total"] - withheld_here)
        sup = dict(summary.get("suppression") or {})
        sup["withheld_at_site"] = withheld_here
        summary["suppression"] = sup
    cnas = _read_strict(os.path.join(latest, "cnas.json"))
    # Tolerant: a snapshot written before held_back.json existed is a valid input,
    # and an absent archive must not stop a publication.
    held_back = _normalise_legacy(_read(os.path.join(latest, "held_back.json"), []),
                                  source=f"{os.path.basename(latest)}/held_back.json")
    held_back = _drop_withheld(held_back, withheld, "held_back.json")
    _assert_consistent(rows, summary, cnas)

    # The launch gate, enforced here but deliberately NOT by refusing to build.
    # A SystemExit in this function lands in the Build site step, and deploy is
    # `needs: build` with no `if:`, so the whole deploy job would be skipped and
    # Pages would serve the previous artefact indefinitely with no notification.
    # Worse, after a launch cleared on a manual `deep` run, every scheduled
    # `weekly` run would trip the refusal and the site would freeze permanently
    # four times a day while still serving a count and a six-hour cadence claim.
    #
    # So: fail CLOSED on the flag (ignore RBP_LAUNCHED and keep serving the
    # pre-launch page), and let a separate workflow step fail loud in CI. Never
    # fail dark on the publication itself.
    launched = LAUNCHED
    gate = _gate_status(summary)
    if launched and not gate["cleared"]:
        # REHEARSAL ESCAPE, and only that.
        #
        # The demotion is correct for a real run: a launch below coverage must serve
        # the pre-launch page rather than the dashboard. But it also made the launch
        # rehearsal impossible, which the first rehearsal proved by building the
        # holding page while every other lever said LAUNCHED. So the one thing
        # condition 9 exists to prevent, launch day being the first execution of the
        # launched code path, survived a green rehearsal.
        #
        # RBP_REHEARSE=1 skips the demotion. The workflow sets it only on a dry run,
        # where `deploy` is skipped, so the artefact is built and discarded. It is a
        # separate variable from RBP_LAUNCHED on purpose: someone who sets
        # RBP_LAUNCHED alone still gets the demotion, and bypassing the gate takes
        # two deliberate levers rather than one.
        if REHEARSE:
            print(f"REHEARSAL: {gate['reason']}, but RBP_REHEARSE=1, so the "
                  "LAUNCHED posture is being built anyway. This artefact must not "
                  "be published; the workflow only sets this on a dry run.")
        else:
            print(f"REFUSING TO LAUNCH: {gate['reason']}. "
                  "Serving the pre-launch page instead.")
            launched = False
    grader = _read(os.path.join(data_dir, "precision.json"),
                   {"graded": [], "predictions": {}, "history": []})
    resolutions = _read(os.path.join(data_dir, "resolutions.json"),
                        {"resolved": [], "open": {}})

    changes = _changes(rows, prev, latest, withheld)
    for c in cnas:
        c["slug"] = slug(c["cna"])

    _closures = resolutions.get("resolved", [])

    def _by_days_desc(rows):
        """Sort here, never in Jinja.

        The first attempt at this split left the sort in the template, and it
        crashed again in CI: filtering to PUBLISHED is not enough, because a
        published closure still carries days_to_publish None whenever the date
        arithmetic failed on an unparseable feed date. Jinja's sort calls
        sorted() with no key fallback and do_sort has no `default` parameter, so
        any None in the column is a build-killing TypeError. Sorting in Python
        with an explicit sentinel is the only version that cannot raise.
        """
        return sorted(rows,
                      key=lambda r: (r.get("days_to_publish") is None,
                                     -(r.get("days_to_publish") or 0)))

    _published_closures = _by_days_desc(
        [r for r in _closures if r.get("state", "PUBLISHED") == "PUBLISHED"])[:200]
    _rejected_closures = [r for r in _closures if r.get("state") == "REJECTED"][-200:]

    # item 13: freshness measured, not asserted. The site claimed "Updated every
    # six hours" as static copy while nothing anywhere computed staleness, and a
    # scheduled workflow can stop silently (GitHub disables cron after 60 days of
    # repository inactivity, and cron is best-effort regardless).
    age_hours = None
    stamped = summary.get("generated_at")
    if stamped:
        try:
            then = dt.datetime.fromisoformat(stamped)
            if then.tzinfo is None:
                then = then.replace(tzinfo=dt.timezone.utc)
            age_hours = round((dt.datetime.now(dt.timezone.utc) - then).total_seconds() / 3600, 1)
        except ValueError:
            age_hours = None

    return {
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "snapshot_date": os.path.basename(latest),
        "snap_root": snap_root,
        # Rendered on /data so the retention promise is a number a reader can
        # check against the archive index, not an adjective.
        "keep_snapshots": _publish_keep(),
        # Evidence for the cadence the site claims. None when the ledger has not
        # been written yet, which the template distinguishes from zero.
        "cadence": cadence(data_dir),
        # Carried so _write_data can apply it to the dated archive, which is
        # rebuilt from prior snapshots on every run and is therefore a writer in
        # its own right. Runner-local; never rendered, never published.
        "withheld": sorted(withheld),
        "archive": None,          # filled by _write_data, read by /data
        "rows": rows,
        "summary": summary,
        "cnas": cnas,
        "changes": changes,
        # _gate_status' own docstring said "reported whether or not the flag is
        # set, so /method can state the position truthfully at any time", and then
        # it was never passed to a template, so no page could state it at all.
        # Same shape as days_public, self_disclosed, feed health, the epoch and
        # PAGES-at-import: computed in one stage, read in none.
        "gate": gate,
        # Review Part 2's nine conditions. Published, not just recorded, because
        # the panel's ask was that the commitment be "checkable from outside".
        # Coverage is condition 1 of 9, so `gate` and `launch` answer different
        # questions and the templates must not present either as the other.
        # `launch` IS NOT IN THE CONTEXT ANY MORE, removed 2026-08-27 with the
        # /method section that was its only reader.
        #
        # This project has shipped the same shape as a defect once already:
        # `site._changes`
        # was computed on every run, put in the render context, and rendered by
        # nothing, with five tests guarding an output no reader could reach. A
        # structure computed for a template that no longer exists is exactly that,
        # so it goes with the template rather than being left to be found.
        #
        # `rbp/launch.py` and tests/test_launch.py are UNTOUCHED and now have no
        # production caller. That is a deliberate loose end rather than an
        # oversight: the eight conditions are the design record, and deleting the
        # module is a separate decision from unpublishing the section.
        # The published contract, rendered on /data rather than described there.
        # The rows the epoch removes. Read from the snapshot rather than recomputed,
        # so the page shows exactly what the pipeline held back. Never carries an
        # owner: these rows are outside the reportable set, so they are outside the
        # set this site is willing to attribute.
        "held_back": held_back,
        "held_back_oldest": max((r.get("days_public") or 0 for r in held_back),
                                default=0),
        "schema_version": _schema.SCHEMA_VERSION,
        "columns": _schema.COLUMNS,
        "fields": _schema.FIELDS,
        # Split at the render boundary, not in the templates. Both states used
        # to share one list that the templates sorted on days_to_publish, which
        # is None for a rejection, and Jinja's sort filter calls sorted(), so one
        # published plus one rejected closure raised TypeError and killed the
        # whole build. The page rendering it was in PAGES, so that killed the
        # pre-launch build too, the artefact never uploaded, deploy was skipped,
        # and the
        # next run re-derived the same rejection and failed identically. A
        # self-sustaining outage, latent only because resolved is currently 0.
        #
        # Below the crash threshold the render was worse than the crash: a lone
        # rejection printed under a "Resolved" heading with the prose "RBPs
        # attributed here that have since published" and a cell reading None. A
        # rule 4.5.3.5 rejection is the CNA complying with the rules.
        # The talk deck's own figures. Computed HERE rather than in the
        # template, and from the FULL resolution ledger rather than from
        # `resolutions_published` beside it, which is capped at the 200
        # slowest closures and whose median is nine days worse than the
        # ledger's as a result. See rbp/slides.py.
        #
        # `None` when it could not be computed, and the deck is then not
        # rendered at all. See `_deck` for why that is not the same shape as
        # swallowing the error.
        "deck": _deck(rows, summary, resolutions, snaps,
                      len(_published_closures)),
        "resolutions_published": _published_closures,
        "resolutions_rejected": _rejected_closures,
        # Counted from the same lists that render, not from an untruncated
        # original, or the two diverge silently past the truncation point.
        "resolutions_n": len(_published_closures),
        "resolutions_rejected_n": len(_rejected_closures),
        "resolutions_tracked": len(resolutions.get("open", {})),
        # Read from the run's own accuracy block, NOT recomputed here.
        #
        # This block used to recompute precision with the floor applied, while
        # Grader.summary published the unfloored value into summary.json. Two files
        # from the same run then disagreed about the site's own accuracy:
        # summary.json said precision 1.0 at graded 1, precision.json said null with
        # below_floor true, and both were live. The floor now lives in
        # Grader.summary, and this reads what it produced.
        # Floored by inference.summarise_state, the one implementation of the rule.
        #
        # This block used to recompute precision with the floor applied while
        # Grader.summary published the unfloored value into summary.json. Two files
        # from the same run then disagreed about the site's own accuracy:
        # summary.json said precision 1.0 at graded 1, precision.json said null with
        # below_floor true, and both were live on the data branch.
        "grader": {
            **summarise_state(grader),
            "history": grader.get("history", [])[-30:],
        },
        "expectation_hours": clock.EXPECTATION_HOURS,
        "min_denominator": clock.MIN_DENOMINATOR,
        "rule_must": clock.RULE_MUST,
        "rule_should": clock.RULE_SHOULD,
        "owner_feeds": {k: sorted(v) for k, v in clock.OWNER_FEEDS.items()},
        "asset_v": _asset_versions(),
        "age_hours": age_hours,
        "stale": age_hours is not None and age_hours > 12,
        "very_stale": age_hours is not None and age_hours > 24,
        # The floor, for templates that explain why a figure is withheld. Sourced
        # from inference so there is exactly one definition of it.
        "precision_floor": MIN_GRADED,
        "launched": launched,
        # `gate` is set once, above, with the reasoning. It was in this dict
        # twice with the same value; harmless, and the kind of duplicate a merge
        # leaves behind on a dict whose whole job is to be the one context.
        # Where the dashboard actually lives, so the nav and the logo point at
        # it in both postures.
        "home": "index.html" if launched else "overview.html",
    }


def _deck(rows, summary, resolutions, snaps, published_n):
    """The talk deck's figures, or None if they could not be computed.

    THE HALF THE try/except IN `build` DID NOT COVER, and the review round that
    found it was right that the gap made the comment there a false claim. That
    block wraps the RENDER. This is the COMPUTE, it ran here in `load`, and a
    raise in it propagated straight out of `site.build`.

    Demonstrated rather than assumed: making `slides.deck` raise and running a
    build produced ZERO pages. Not a degraded deck, not a missing slide, the
    whole site. `deploy` is `needs: build` with no `if:`, so that is the deploy
    skipped and Pages serving the previous artefact four times a day for a page
    nobody can reach from anywhere on the site.

    Returning None rather than swallowing: the message is printed, CI fails on
    tests/test_slides.py long before this, and `build` renders no deck at all
    when the figures are absent, so there is no half-built page carrying blank
    cells that read as measured zeroes.

    The import is local for the same reason. At module scope a syntax error in
    rbp/slides.py made `import rbp.site` fail, which is the same outage by a
    shorter route and one this function could not have caught.
    """
    try:
        from . import slides as _slides
        return _slides.deck(rows, summary, resolutions, snaps, published_n)
    except Exception as e:                  # noqa: BLE001 - see the docstring
        import traceback
        print(f"SLIDES: the deck figures did not compute ({type(e).__name__}: "
              f"{e}). /slides.html will not be written; every other page is "
              "unaffected. This should have been caught in CI:")
        traceback.print_exc()
        return None


def _changes(rows, prev_dir, latest_dir, withheld=frozenset()):
    """Movement against the previous snapshot, in three buckets that are never
    merged.

    A set difference over two backlogs is NOT a publication event. A row leaves
    the set for at least six other reasons: a transient oracle error, a failed
    or truncated feed, a feed-profile change (one `deep` dispatch followed by the
    next `weekly` cron drops every CSAF-only row), a raised buffer, a revised
    `public_date`, and rejection. Labelling that difference "Published, and
    therefore resolved" asserted a fact about a CNA that the site had not
    checked, and the honest answer was already being computed and thrown away.

      published      verified PUBLISHED in the corpus, from the ledger.
      rejected       state REJECTED. Lawful under rule 4.5.3.5, and worse for a
                     defender than an open RBP, so it is never called resolved.
      no_longer_listed  unverified. The word "published" must not appear near it.

    Two snapshots taken under different feed profiles or buffers are not
    comparable at all, and saying so is better than showing a difference that
    means nothing.
    """
    empty = {"published": [], "rejected": [], "no_longer_listed": [], "new": [],
             "still_open": 0, "have_previous": False, "comparable": True,
             "incomparable_reason": None, "epoch_started": False,
             "dropped_by_epoch": 0}
    if not prev_dir:
        return empty

    # STRICT on the previous backlog when its directory exists. The tolerant read
    # turned a missing or corrupt previous backlog into an empty set, which makes
    # every current row "new" and every previous row "no longer listed" while
    # `comparable` stays True. A diff computed against nothing is the one output
    # that must never be published as a diff.
    prev_backlog = os.path.join(prev_dir, "backlog.json")
    prev_rows = (_normalise_legacy(_read_strict(prev_backlog),
                                   source=f"{os.path.basename(prev_dir)}/backlog.json "
                                          "(previous, for the diff)")
                 if os.path.exists(prev_backlog) else None)
    if prev_rows is None:
        return {**empty, "have_previous": True, "comparable": False,
                "previous_date": os.path.basename(prev_dir),
                "incomparable_reason":
                    "the previous snapshot has no backlog.json, so there is nothing "
                    "to diff against. Showing no movement rather than reporting "
                    "every row as new."}
    prev_sum = _read(os.path.join(prev_dir, "summary.json"), {})
    now_sum = _read(os.path.join(latest_dir, "summary.json"), {})

    # Refuse to diff snapshots that disagree on how they were produced.
    #
    # Keyed on PRESENCE, not truthiness. `epoch` is emitted as `EPOCH or None`, so
    # the None-to-date transition short-circuited `is not None` and the pair was
    # declared comparable on exactly the run where it is least comparable: launch
    # day, when every row moves. Reproduced by execution before this fix:
    # comparable True, no_longer_listed 150 of 150, which at live scale is ~500 CVE
    # IDs rendered as a comma-joined mono dump under "No longer listed, cause
    # unverified" on the first day anyone reads the site.
    #
    # The guard caught the harmless direction (unsetting the epoch) and missed the
    # one that will actually happen. Same hole a third time, after `min_age_days`
    # and the feed set.
    for key, label in (("min_age_days", "buffer"), ("epoch", "epoch")):
        in_prev, in_now = key in prev_sum, key in now_sum
        if in_prev and in_now and prev_sum.get(key) != now_sum.get(key):
            return {**empty, "have_previous": True, "comparable": False,
                    "previous_date": os.path.basename(prev_dir),
                    "epoch_started": (key == "epoch" and not prev_sum.get(key)
                                      and bool(now_sum.get(key))),
                    "incomparable_reason":
                        f"the {label} changed from {prev_sum.get(key)!r} to "
                        f"{now_sum.get(key)!r} between these snapshots"}
    a = set((prev_sum.get("feeds") or {}).get("requested") or [])
    b = set((now_sum.get("feeds") or {}).get("requested") or [])
    # Presence again, not truthiness: `if a and b` skipped the check whenever
    # either side was empty, which is precisely a run where every feed was dropped.
    if "feeds" in prev_sum and "feeds" in now_sum and a != b:
        return {**empty, "have_previous": True, "comparable": False,
                "previous_date": os.path.basename(prev_dir),
                "incomparable_reason":
                    "the feed set changed between these snapshots "
                    f"(added {sorted(b - a)}, dropped {sorted(a - b)})"}

    # `gone` is computed against the previous snapshot RESTRICTED to rows that are
    # still epoch-eligible, so an epoch change moves rows into the archive rather
    # than through the diff. Better than a comparability flag: the flag tells a
    # reader the diff is meaningless, this stops the meaningless diff existing.
    # Withheld ids leave BOTH sides of the diff.
    #
    # Dropping them only from `rows` would move each one into `gone`, and `gone`
    # minus the authoritative closures is `no_longer_listed`, which /status
    # renders as a plain list of CVE IDs (it was /changes until 2026-08-26; the
    # page moved and the hazard did not). So the lever that exists to remove an
    # id from the site would have published it, in a list captioned as rows that
    # stopped being listed. That is worse than not withholding at all: it is a
    # short, high-signal list of exactly the ids someone asked to have removed.
    if withheld:
        prev_rows = [r for r in prev_rows
                     if (r.get("cve_id") or "").strip().upper() not in withheld]
    now_epoch = now_sum.get("epoch")
    before = {r["cve_id"] for r in prev_rows
              if not (now_epoch and (r.get("public_date") or "") < now_epoch)}
    dropped_by_epoch = len(prev_rows) - len(before)
    now = {r["cve_id"] for r in rows}
    by_id = {r["cve_id"]: r for r in rows}
    gone = before - now

    # The authoritative closures, written by the pipeline from the corpus.
    resolved = {r["cve_id"]: r for r in _read(os.path.join(latest_dir, "resolved.json"), [])}
    published = [resolved[c] for c in sorted(gone) if resolved.get(c, {}).get("state") == "PUBLISHED"]
    rejected = [resolved[c] for c in sorted(gone) if resolved.get(c, {}).get("state") == "REJECTED"]
    accounted = {r["cve_id"] for r in published + rejected}
    return {
        "new": [by_id[c] for c in sorted(now - before)],
        "published": published,
        "rejected": rejected,
        "no_longer_listed": sorted(gone - accounted),
        "still_open": len(now & before),
        "have_previous": True,
        "comparable": True,
        "incomparable_reason": None,
        "epoch_started": False,
        "dropped_by_epoch": dropped_by_epoch,
        "previous_date": os.path.basename(prev_dir),
    }


# --------------------------------------------------------------------------
# render
# --------------------------------------------------------------------------

def _asset_versions():
    """Short content hashes for the stylesheets, appended to their URLs.

    Without this a returning visitor keeps a cached stylesheet after a design
    change, which is exactly what happened during development: a dark-mode fix
    appeared to have no effect because the browser held the old file.
    """
    out = {}
    css = os.path.join(STATIC, "css")
    if os.path.isdir(css):
        for name in sorted(os.listdir(css)):
            if name.endswith(".css"):
                data = open(os.path.join(css, name), "rb").read()
                out[name] = hashlib.sha256(data).hexdigest()[:10]
    # The social card too, and for a harsher reason than the stylesheets. Slack,
    # Teams and X cache an og:image against its URL for a long time and do not
    # revalidate, so replacing the file at a fixed path leaves every previously
    # unfurled link showing the old card indefinitely. The hash in the query is
    # the only way to make a new card reach a channel that has already seen one.
    card = os.path.join(STATIC, "img", "og-card.png")
    if os.path.isfile(card):
        out["og-card.png"] = hashlib.sha256(
            open(card, "rb").read()).hexdigest()[:10]
    return out


def _env():
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["commafy"] = lambda n: f"{n:,}" if isinstance(n, (int, float)) else n
    # One decimal, not two. Two decimals on a 223-row base implies a precision of
    # one part in ten thousand from a measurement that cannot support one part in
    # a hundred. The raw ratio stays in the JSON for anyone who wants it.
    env.filters["pct"] = lambda x: "n/a" if x is None else f"{100 * x:.1f}%"
    env.filters["slug"] = slug

    def sortnum(rows, attribute, reverse=True):
        """Sort on a possibly-null numeric attribute without raising.

        Jinja's built-in sort calls sorted() with no key fallback, and do_sort
        has no `default` parameter, so a single None in the column raises
        TypeError inside the Build site step. That took the whole site down twice
        during this review: once on days_to_publish for a rejected closure, and
        it was latent on days_public for an undated row. Nulls sort last in both
        directions, because a missing value is not a small value.
        """
        return sorted(
            rows,
            key=lambda r: (r.get(attribute) is None,
                           -(r.get(attribute) or 0) if reverse else (r.get(attribute) or 0)),
        )

    env.filters["sortnum"] = sortnum
    return env


# Columns for the public CSV. Deliberately the gated view: an ungated owner
# column in a shareable file was a real defect in the previous engine.
# `rule_strength` never travels without `rule_certainty`. clock.py states the
# rule that the qualifier must accompany the strength wherever it appears, and it
# was in no template and no CSV, so a consumer could not reconstruct it at all.
# The published column contract lives in rbp/schema.py, once. This was a 25-field
# list here and a 26-field list in a different order in report.build, under a
# comment claiming the two CSVs were identical. Imported at the top of the module
# with the others since 2026-08-26, because NAME_FIELDS is now defined from it and
# a module-level constant cannot read an import that happens 800 lines later.

CSV_COLS = _schema.COLUMNS


# Per-CNA breakdowns inside a summary block. Keyed BY CNA, so a de-namer that
# reads field names cannot see them: `by_cna` was a 40-CNA table of decided,
# precision and coverage, published live for four days.
_PER_CNA_KEYS = _schema.PER_CNA_KEYS
_LEDGER_NAMES = _schema.LEDGER_NAME_FIELDS


def _strip_keys(obj, keys):
    if isinstance(obj, dict):
        return {k: _strip_keys(v, keys) for k, v in obj.items() if k not in keys}
    if isinstance(obj, list):
        return [_strip_keys(v, keys) for v in obj]
    return obj


def _unattributed_summary(summary):
    """A published summary with every per-CNA breakdown removed.

    The aggregate figures stay: leave-one-out precision over 29,614 decisions is
    the strongest claim the site makes and it is name-free. What goes is which
    CNA each decision was about.
    """
    if NAMING_ENABLED or not isinstance(summary, dict):
        return summary
    out = dict(summary)
    if isinstance(out.get("inference"), dict):
        out["inference"] = _strip_keys(out["inference"], _PER_CNA_KEYS)
    return out


def _denamed_grader(grader):
    """The ledger, with every naming field AND every per-CNA breakdown dropped.

    Both, because the ledger carries both shapes: `predicted`/`actual` name a CNA
    in a field, and `by_cna` names forty of them in KEYS. Stripping only the
    first left `$.by_cna.GitHub_M` in the published precision.json, which is what
    a rebuild from the pre-cleanup snapshots produced on the first attempt.
    """
    return _strip_keys(grader, set(_LEDGER_NAMES) | set(_PER_CNA_KEYS))


def _write_data(out, ctx):
    launched = ctx["launched"]
    withheld = set(ctx.get("withheld") or ())
    # Every published row set, not only the one the old test looked at.
    covered = set((ctx["summary"].get("coverage") or {}).get("covered") or [])
    assert_artefact(ctx["rows"], "rbp.json", ctx["cnas"], covered)
    d = os.path.join(out, "data")
    os.makedirs(d, exist_ok=True)

    # Wrapped, not bare. `rbp.json` was json.dump(rows): an array with no schema
    # version, no generation time, no epoch, no buffer, no coverage and no floor
    # flag, so every caveat that makes the count safe to use lived in HTML a tool
    # has no reason to fetch.
    env = _schema.envelope(ctx["rows"], ctx["summary"], launched=launched,
                           snapshot_date=ctx["snapshot_date"])
    # DE-NAMED AT THE WRITER, not upstream of it.
    #
    # This is the mechanism by which /data/cnas.json served seven ranked CNAs on
    # the live site. These four lines copy whatever the RESTORED SNAPSHOT holds
    # straight into the published tree, and the data branch keeps 90 days of
    # snapshots plus one per month for ever. Fixing the pipeline that WRITES a
    # snapshot does nothing for the four already on the branch, and the archive
    # rebuild reads them every run.
    #
    # So the guarantee is made here, where publication actually happens, and it
    # holds no matter how old or how dirty the input snapshot is.
    _schema.write_json(os.path.join(d, "rbp.json"), env)
    _schema.write_json(os.path.join(d, "summary.json"),
                       _unattributed_summary(ctx["summary"]))
    _schema.write_json(os.path.join(d, "cnas.json"), ctx["cnas"] if NAMING_ENABLED else [])
    _schema.write_json(
        os.path.join(d, "precision.json"),
        ctx["grader"] if NAMING_ENABLED else _denamed_grader(ctx["grader"]))

    # The closure record. resolved.json and held_back.json were computed, rendered
    # and then withheld from consumers entirely: neither reached the data branch or
    # site/data. The resolved rows are the only public evidence the pipeline closes,
    # and the held-back count is the filter that removes the oldest and strongest
    # rows, so withholding both left a consumer unable to check either.
    # The archive, published rather than computed and withheld. The oldest row is
    # this project's single strongest piece of evidence and the epoch would have
    # deleted it from the site with no home anywhere.
    assert_artefact(ctx["held_back"], "held-back.json", ctx["cnas"], covered)
    _schema.write_json(
        os.path.join(d, "held-back.json"),
        _schema.envelope(ctx["held_back"], ctx["summary"], launched=launched,
                         snapshot_date=ctx["snapshot_date"], kind="held-back"))

    # `published_assigner` joined to first_public / published / days_to_publish
    # is a dated per-CNA lateness table. 46 of 47 rows carried one, live, and the
    # assigner is authoritative rather than inferred.
    _schema.write_json(
        os.path.join(d, "resolved.json"),
        _schema.envelope(
            _strip_keys(ctx["resolutions_published"], set(_LEDGER_NAMES))
            if not NAMING_ENABLED else ctx["resolutions_published"],
            ctx["summary"], launched=launched,
            snapshot_date=ctx["snapshot_date"], kind="resolved"))

    # A CSV sidecar, so the column contract is machine-readable beside the file
    # rather than only prose on /data.
    _schema.write_json(
        os.path.join(d, "rbp.csv.meta.json"),
        {"schema_version": _schema.SCHEMA_VERSION,
         "columns": _schema.COLUMNS,
         # HOW A NON-STRING TYPE IS SPELLED IN A CELL. Declaring a column's type
         # as `object` without saying how an object is written is the gap that
         # let a Python `repr` sit in that column unnoticed: the declared type
         # was right and the encoding was unstated, so nothing contradicted
         # anything.
         "csv_encoding": {
             "object": "JSON, keys sorted. json.loads() on the cell.",
             "array": "JSON, keys sorted. json.loads() on the cell.",
             "bool": "the strings true and false, lowercase.",
             "null": "the empty cell.",
         },
         "fields": {k: {"type": t, "absent": a, "meaning": m}
                    for k, (t, a, m) in _schema.FIELDS.items()}})

    # Encoded through the one definition in schema.csv_cell, which
    # report.build's snapshot CSV also uses. See the note there.
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLS, extrasaction="ignore")
    w.writeheader()
    w.writerows(_schema.csv_row(r) for r in ctx["rows"])
    _schema.write_text(os.path.join(d, "rbp.csv"), buf.getvalue())

    # THE DATED ARCHIVE (Part 2 condition 7).
    #
    # /data/rbp.json is the only target a citation could use, and it changes every
    # six hours. After the epoch flip its numbers change entirely, so anything cited
    # before launch resolves afterwards to a file that no longer says what was cited.
    #
    # Every retained snapshot is now also published at a dated path, so a citation
    # can point at /data/2026-08-22/rbp.json and keep meaning what it meant. Written
    # from the snapshot on disk rather than from the current context, so a dated file
    # is that day's numbers and not today's wearing that day's name.
    #
    # HONESTY ABOUT "IMMUTABLE": it is not. A withhold request removes a row from
    # every published artefact including these, which is the whole point of the
    # suppression lever. So the archive is STABLE rather than immutable: a figure can
    # go down if someone asks for a row to be withheld, and /data says so rather than
    # promising permanence this project deliberately does not offer.
    arch_root = os.path.join(d, "archive")
    archive = []
    for snap in _snapshots(ctx["snap_root"]):
        date = os.path.basename(snap)
        rows_path = os.path.join(snap, "backlog.json")
        sum_path = os.path.join(snap, "summary.json")
        if not (os.path.exists(rows_path) and os.path.exists(sum_path)):
            continue
        try:
            snap_rows = _drop_withheld(
                _normalise_legacy(json.load(open(rows_path)),
                                  source=f"archive/{date}"),
                withheld, f"archive/{date}")
            snap_sum = json.load(open(sum_path))
        except Exception:
            continue
        # Validated against ITS OWN covered set and cnas.json, not today's.
        #
        # The first version passed the current snapshot's, which fails the moment a
        # CNA named in an older snapshot is absent from today's cnas.json, or falls
        # outside today's covered set because a feed moved. Reproduced immediately in
        # CI: the archive refused to publish a historical row that was correct when
        # it was written.
        #
        # A historical artefact has to be judged by the rules that applied when it
        # was produced, and the site published its own covered set alongside it for
        # exactly that reason. Checking it against today's is a category error, and
        # the version that fails closed on correct history is still failing.
        try:
            snap_cnas = json.load(open(os.path.join(snap, "cnas.json")))
        except Exception:
            snap_cnas = []
        snap_covered = set((snap_sum.get("coverage") or {}).get("covered") or [])
        assert_artefact(snap_rows, f"archive/{date}/rbp.json", snap_cnas, snap_covered)
        dd = os.path.join(arch_root, date)
        os.makedirs(dd, exist_ok=True)
        _schema.write_json(
            os.path.join(dd, "rbp.json"),
            _schema.envelope(snap_rows, snap_sum, launched=launched,
                             snapshot_date=date, kind="backlog"))
        archive.append({
            "date": date,
            "url": f"data/archive/{date}/rbp.json",
            "rows": len(snap_rows),
            "epoch": snap_sum.get("epoch"),
            "min_age_days": snap_sum.get("min_age_days"),
        })
    archive_index = sorted(archive, key=lambda a: a["date"], reverse=True)
    _schema.write_json(
        os.path.join(d, "archive.json"),
        {"schema_version": _schema.SCHEMA_VERSION,
         "stable_not_immutable": True,
         "note": ("A request to remove a row removes it from every published "
                  "artefact including these, so a figure can go down. This "
                  "archive is stable, not immutable."),
         "snapshots": archive_index})
    _archive_index = archive_index

    # One file per CNA, so anyone can pull just their own rows. NOT WRITTEN under
    # v1: a file keyed by CNA short name, containing that CNA's rows, is an
    # attribution whatever the rows inside it say. This writer sat outside
    # assert_artefact, so the de-naming invariant did not reach it and it kept
    # emitting named endpoints after every other surface had stopped; the test
    # that now checks both postures is what caught it.
    if NAMING_ENABLED:
        per = os.path.join(d, "cna")
        if launched:
            os.makedirs(per, exist_ok=True)
        for c in (ctx["cnas"] if launched else []):
            mine = [r for r in ctx["rows"] if r.get("owner") == c["cna"]]
            _schema.write_json(os.path.join(per, f"{c['slug']}.json"),
                               {"cna": c["cna"], "summary": c, "rows": mine})

    # Returned so /data can render the citable routes. The pages render AFTER the
    # data files for exactly this reason.
    return _archive_index


# Page targets depend on the EFFECTIVE posture, which is not the same as the
# environment flag: the launch gate can demote a requested launch. Computing this
# at import time meant the demotion never reached the page targets, so a launch
# attempted below gate still wrote the dashboard to index.html. That is precisely
# the outcome the gate exists to prevent.
_PAGE_TEMPLATES = [
    # ONE ROUTE. `list.html` is the front door and the list: the command bar, the
    # rows, and a slide-over carrying what used to be four other pages.
    #
    # The old index.html dashboard opened with a 104px number and ~650 words
    # before the first CVE, and its stat tiles were instrument readings about
    # this site's own machinery rather than about the CVEs. It is not rendered.
    ("list.html", None),
    # Kept as its own URL, deliberately. The panel answers quickly; these two
    # have to stay citable at a stable address for the same reason the filters
    # are linkable, and quotations that people rely on should not live inside a
    # modal.
    ("method.html", "method.html"),
    ("policy.html", "policy.html"),
    # The run's own health, moved off the front page on 2026-08-26. The degraded
    # banner rendered above the count on every page; it was correct and it was in
    # the wrong place, because a reader who came for the list met a paragraph
    # about feed truncation first. The front page keeps one line and a link; the
    # explanation, the per-feed table and the cadence evidence are here.
    ("status.html", "status.html"),
    # cnas.html and cna.html are NOT here. Both pages existed only to attribute
    # rows to named CNAs, and v1 publishes no attribution. They are not rendered
    # empty, because an empty per-CNA page is an invitation to fill it before the
    # conditions naming depends on are met. See NAMING_ENABLED.
    # A permanent home for the rows the epoch removes. Published whether or not an
    # epoch is set, so the archive exists BEFORE the day it is needed rather than
    # being designed on launch day, which is the sequencing item 6 insists on:
    # design the zero state, publish the archive, then set the epoch.
]


def pages_for(launched):
    """Template to output filename, for the given effective posture."""
    return [(t, ("index.html" if launched else "overview.html") if o is None else o)
            for t, o in _PAGE_TEMPLATES]


def build(out, snap_root, data_dir):
    ctx = load(snap_root, data_dir)
    env = _env()
    os.makedirs(out, exist_ok=True)

    if os.path.isdir(STATIC):
        shutil.copytree(STATIC, os.path.join(out, "static"), dirs_exist_ok=True)
        # /favicon.ico AT THE ROOT, on top of the copy under static/.
        #
        # Browsers request /favicon.ico on their own, before and regardless of any
        # <link rel="icon"> the page carries, so linking the SVG does not stop the
        # request and without this file every first visit takes a 404. It is the
        # one asset whose location is decided by the browser rather than by us.
        _ico = os.path.join(STATIC, "favicon.ico")
        if os.path.isfile(_ico):
            shutil.copyfile(_ico, os.path.join(out, "favicon.ico"))

    launched = ctx["launched"]
    # The archive index is built by _write_data, which runs after the pages. /data
    # needs it while rendering, so the data files are written first and the list is
    # put back into the context before the templates run.
    ctx["archive"] = _write_data(out, ctx)
    pages = pages_for(launched)
    for template, target in pages:
        # `page_file` is the page's own path, for a per-page og:url and canonical.
        # A single hard-coded root og:url on every page meant every paste
        # unfurled as the front page regardless of what was actually shared.
        html = env.get_template(template).render(
            **ctx, page=target,
            page_file="" if target == "index.html" else target)
        _schema.write_text(os.path.join(out, target), html)

    # THE TALK DECK, rendered outside the loop above and behind a catch.
    #
    # /slides.html is an unlinked page for a working-group session. It is the
    # least important thing this site serves and it renders on the same publish
    # path as the count, so a template error in it would raise inside the Build
    # site step, and `deploy` is `needs: build` with no `if:`: the whole deploy
    # is skipped and Pages serves the previous artefact indefinitely, four times
    # a day, with nothing saying why. That is the exact failure the launch gate
    # is written to avoid, and a slide is not worth it.
    #
    # So the split is: CI FAILS LOUD, PUBLISH DEGRADES. tests/test_slides.py
    # renders this page and asserts its figures, and that job gates the commit
    # path, so a broken deck cannot reach main. If one reaches the publish path
    # anyway, the message below goes to the build log and every other page still
    # ships. The failure is never silent and it is never fatal.
    #
    # BOTH HALVES, and for a while only this one. `ctx["deck"]` is None when the
    # FIGURES failed, which this block never saw because that happened up in
    # `load`; the guard is in `_deck` now and this skips the page rather than
    # rendering a deck of blank cells. A blank cell reads as a measured zero.
    if ctx.get("deck") is None:
        print("SLIDES: no deck figures, so /slides.html was not written. Every "
              "other page is unaffected.")
    else:
        try:
            _schema.write_text(
                os.path.join(out, "slides.html"),
                env.get_template("slides.html").render(
                    **ctx, page="slides.html", page_file="slides.html"))
        except Exception as e:          # noqa: BLE001 - see the note above
            import traceback
            print(f"SLIDES: /slides.html did not render ({type(e).__name__}: "
                  f"{e}). Every other page is unaffected and the site is "
                  "publishing normally. This should have been caught in CI:")
            traceback.print_exc()

    if not launched:
        # GitHub Pages cannot set X-Robots-Tag, and a meta tag cannot cover the
        # JSON and CSV under data/. robots.txt is the only lever that reaches them.
        _schema.write_text(
            os.path.join(out, "robots.txt"),
            "# Pre-launch. The count is built on partial CNA coverage and is not\n"
            "# ready to be indexed or cited. See PLAN.md launch gate.\n"
            "User-agent: *\nDisallow: /\n")
    # /.well-known/security.txt (RFC 9116). The site names organisations and
    # invites embargo reports, so the one machine-readable place a security team
    # looks for a contact route must not be empty. Expires is required by the RFC.
    wk = os.path.join(out, ".well-known")
    os.makedirs(wk, exist_ok=True)
    _expires = (dt.datetime.now(dt.timezone.utc)
                + dt.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # REWRITTEN 2026-08-27. This described a removal channel and led with a
    # mailto:, and the removal promise is retired: a row is listed only once the
    # reservation endpoint confirms the ID is reserved and unpublished, and every
    # row is already referenced in a public advisory.
    #
    # The file stays and stays VALID. RFC 9116 requires at least one Contact, and
    # the GitHub private-advisory URL is one; it is now the only one, and it is
    # for vulnerabilities in this site's own code rather than for the data.
    # Saying which, in the comment block, matters more here than anywhere else on
    # the site: security.txt is the file someone reads when they have found
    # something and are deciding whether this is the right door.
    _schema.write_text(
        os.path.join(wk, "security.txt"),
        "# rbptracker.org\n"
        "# This site lists CVE IDs that are in the Reserved state and are\n"
        "# referenced in public advisories. Every row is an identifier that is\n"
        "# already public, confirmed unpublished against the CVE Services\n"
        "# reservation endpoint, and held for a buffer before it is listed.\n"
        "#\n"
        "# The contact below is for a vulnerability in THIS SITE'S OWN CODE.\n"
        "# This site does not operate a removal channel for listed CVE IDs.\n"
        "Contact: https://github.com/RogoLabs/RBP/security/advisories/new\n"
        f"Expires: {_expires}\n"
        "Preferred-Languages: en\n"
        "Canonical: https://rbptracker.org/.well-known/security.txt\n"
        "Policy: https://rbptracker.org/method.html\n")

    # The holding page, always written, at a permanent route.
    #
    # It used to be copied over index.html only in the `not launched` branch, so
    # flipping RBP_LAUNCHED would have DELETED it, and with it the three paragraphs
    # that do the site's framing work: the glossary provenance ("That is not our
    # term. It is the CVE Program's own"), the full 4.5.1.7 quotation, and the
    # narrow ask with its own safety reasoning. A grep of the built dashboard
    # returned zero occurrences of "unblind" and zero of "glossary"; the only
    # surviving ask was one line of footer small print. Launch day would have
    # quietly destroyed the most careful copy on the site.
    #
    # So it lives at /about-this-count.html in both postures, and pre-launch it is
    # ALSO the front door.
    #
    # ONE COPY, TWO SHELLS since 2026-08-26. This used to be a standalone
    # placeholder.html at the repo root, copied byte-for-byte to both routes. That
    # made /about-this-count a page with no header, no nav, no footer and no theme
    # toggle, in a palette nothing else on the site uses, reachable from the nav as
    # "About" and offering no way back. It read as a different website.
    #
    # The reason it was standalone is real and it survives: pre-launch the front
    # door must not link into the dashboard, because linking to it effectively
    # launches it, and base.html's nav does exactly that. So the words live in
    # templates/_about-copy.html and two shells wrap them:
    #
    #   about.html    extends base.html, full chrome   -> /about-this-count.html
    #   holding.html  standalone, links nowhere inside -> /index.html, pre-launch
    #
    # Rendered rather than copied, so `asset_v` cache-busting and the og:url both
    # work on the About page, which a static copy could not have.
    _schema.write_text(
        os.path.join(out, "about-this-count.html"),
        env.get_template("about.html").render(
            **ctx, page="about", page_file="about-this-count.html"))

    # /404.html, IN BOTH POSTURES.
    #
    # GitHub Pages serves this file for any unmatched path, which is the only way
    # to get a branded error page out of a static host. Without it every mistyped,
    # truncated or stale link landed on GitHub's own "Page not found - GitHub
    # Pages", with GitHub's branding and no route back here.
    #
    # Rendered rather than copied, so it carries the real nav, the real footer and
    # the cache-busted stylesheet URLs. `page="404"` is read by base.html, which
    # makes every link on the page root-absolute: this file answers for a path at
    # ANY depth, so relative URLs would resolve against a directory that does not
    # exist and the page would arrive unstyled and unnavigable.
    #
    # NOT in _PAGE_TEMPLATES: that list is what the nav and the link checker walk,
    # and 404.html is neither a destination nor something any page should link to.
    _schema.write_text(
        os.path.join(out, "404.html"),
        env.get_template("notfound.html").render(
            **ctx, page="404", page_file="404.html"))
    if not launched:
        _schema.write_text(
            os.path.join(out, "index.html"),
            env.get_template("holding.html").render(**ctx))

    # PER-CNA DETAIL PAGES ARE GONE, not merely switched off.
    #
    # They existed to be the page a CNA lands on when someone sends them the
    # link, carrying the full row list attributed to that CNA. v1 publishes no
    # attribution, so there is no such page to write, and writing an empty one
    # would leave a URL shaped like an accusation waiting for content.
    #
    # This used to be `if NAMING_ENABLED:` around a loop rendering cna.html, kept
    # under a comment saying the reasoning "still applies if NAMING_ENABLED is
    # ever flipped". It did not apply, because templates/cna.html was deleted
    # with the rest of the attribution surface and flipping the flag raised
    # TemplateNotFound on the first build. A branch that cannot execute is not a
    # preserved behaviour; it is a claim that a future maintainer would have
    # discovered was false at the worst moment. Removed 2026-08-26, with the
    # reasoning kept because the reasoning is the part worth having:
    #
    #   the pages were withheld until launch, because report.py states this
    #   project's rule that a named CNA gets a private preview before any row
    #   naming it circulates, and a six-hourly public deploy breaks that rule on
    #   every run. noindex was not sufficient, since the pages remained fetchable
    #   and linkable.
    #
    # Restoring naming means writing that template again, deliberately, against
    # the conditions in PLAN.md 8d. See NAMING_ENABLED.

    posture = "LAUNCHED, / is the dashboard" if launched else \
              "pre-launch, / is the holding page and the dashboard is /overview.html"
    # Report what was written, not what was available. Printing the available
    # count while withholding the pages is the same class of untruth the review
    # found elsewhere on this site.
    print(f"site: {len(pages)} pages -> {out}"
          + ("" if NAMING_ENABLED else " (v1 publishes no attribution)"))
    print(f"      {posture}")
    return ctx
