"""
Feed scoring: one command, one candidate, one verdict.

FEEDS.md section 3. Thirty new adapters written by hand and merged on judgement
is how this project acquires thirty silent failure modes, and the feed count is
going up roughly fourfold. So no feed is merged without a scorecard in the diff.

WHAT THIS EXISTS TO STOP, which is not a hypothesis. Two estimates in FEEDS.md
have already been cancelled by measurement, in opposite directions. The Android
bulletin parser was the top candidate in the plan, worth an estimated 4 to 6 new
CNAs, and it was cancelled because OSV's Android ecosystem already carried every
name but one for a single line of config. Then OSV's GIT ecosystem was banked at
31,366 ids and +18 CNAs from a full-text regex over the archive, and the adapter
that would actually read it returns 450 rows and +0, because `feed_osv` reads CVE
aliases and GIT records carry their references elsewhere. **Only the adapter's
number can be banked**, so this module scores the adapter, never a probe.

THE TWO ADMISSIBILITY TESTS, from FEEDS.md section 2, and the reason both are
here rather than only the first:

  1. **Marginal CNA yield >= 1.** At least one roster CNA crosses the sighting
     floor that no already-merged feed crosses. Measured against the baseline,
     not argued from volume.
  2. **Disclosure lead > 0.** At least one referenced ID was, at the time of
     reference, not yet published. A feed that has only ever referenced already
     published CVEs is a publication mirror: it raises coverage and is
     structurally incapable of surfacing a single RBP, which is the thing this
     site exists to publish.

A feed that clears (1) and fails (2) is still mergeable and is tagged
`corroborating`. It can strengthen a row it did not find. It cannot credit a CNA
as observable. That distinction is currently unmeasured anywhere in the codebase,
and `mozilla` and `arch` are the standing proof that the two properties come
apart: both are in the profile the gate is measured on, and between them they
have produced zero RBP rows.

HOW DISCLOSURE LEAD IS MEASURED, and its honest limit. The corpus carries
`date_published` per CVE. The adapters carry the advisory's own date. So the lead
is `date_published - advisory_date`, per referenced ID, computed offline against
the corpus this repository already holds. Positive means the feed named the ID
before the CVE Program published it, which is exactly the RBP condition.

The limit, stated because a scorecard that hides its own weakness is worse than
no scorecard: this is a BACKTEST against today's corpus, not a record of what was
knowable at the time. An ID referenced while reserved and published an hour later
scores a lead of 0 days and reads as a mirror. It therefore UNDERSTATES lead,
which is the safe direction: it can refuse a good feed, and it cannot admit a
mirror.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import sys
import time

from . import feeds, roster as roster_mod
from .coverage import MIN_SIGHTINGS

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# TWO DIRECTORIES, and the split is not tidiness.
#
# FEEDS.md section 3 says the harness "writes `data/feedlab/<name>.json`, and the
# merge commit includes it. No feed is merged without its scorecard in the diff."
# The first half of that was impossible: `.gitignore` line 3 is `data/`, because
# the 583 MB corpus lives there, so a scorecard written under `data/` can never
# appear in any diff and the rule it exists to enforce would have been unenforced
# from the day it was written.
#
#   feedlab/         COMMITTED. The scorecards, the probe results and the
#                    baseline's summary. Small, reviewable, and the artefact the
#                    merge commit carries.
#   data/feedlab/    IGNORED. The baseline's working state, which holds every
#                    referenced id from every merged feed and is several MB of
#                    derived data that would be regenerated rather than read.
LAB = os.path.join(ROOT, "feedlab")
STATE = os.path.join(ROOT, "data", "feedlab")
BASELINE = os.path.join(STATE, "_baseline.json")

# --------------------------------------------------------------------------
# the live run's own profile, pinned
# --------------------------------------------------------------------------
#
# THE HARNESS AND THE PIPELINE DISAGREED ABOUT WHAT THE MERGED SET IS, and the
# harness was the permissive half.
#
# Measured 2026-09-06. A baseline rebuilt on the same commit, over the same
# window, read the same fifteen feeds as the live run and fourteen returned the
# same row count to the id. `csaf` returned 42,659 against the live run's 62,800,
# and that one feed was the whole difference between 247 effective roster CNAs
# here and 263 there.
#
# Neither half was broken. `deploy.yml` caches `data/csaf_state.json` and a
# provider emits everything it has ever seen, so the live state is as deep as
# every run before it and a local state is as deep as the runs that happened
# locally. The consequence is one-directional: a candidate scored against a cold
# baseline LOOKS BETTER THAN IT IS, because the CNAs `csaf` already covers are
# missing from the set it is supposed to be marginal to.
#
# The fix is not to drain the backlog locally, which is 125,588 advisories behind
# at three providers and would make every baseline only as good as its last
# drain. The live run already publishes the answer four times a day, at a public
# URL, in the artefact the site serves: `coverage.sightings` is per-CNA counts
# over the merged set the site actually has, and `feeds.detail.<name>.rows` is
# how deep each feed read. So it is PINNED, the way the roster is pinned in
# `roster_data/cna_roster.json`: fetched deliberately, committed with a visible
# diff, and drift-tested rather than polled.
LIVE = os.path.join(LAB, "_live.json")

# The published summary of the newest live run. Not an API to poll: one fetch,
# recorded, and refreshed when a scorecard is about to be believed.
LIVE_URL = "https://rbptracker.org/data/summary.json"

# How stale a pin may be before the drift test complains. The site rebuilds four
# times a day and feeds are merged in batches, so a fortnight is "nobody has
# refreshed this in a release cycle" rather than "this moved yesterday".
LIVE_MAX_AGE_DAYS = 14

# FEEDS FROM WHICH THE LIVE SITE HAS NOT YET PUBLISHED A RUN.
#
# The pin is taken from `rbptracker.org/data/summary.json`, so it can only ever
# name feeds the site has already run. A commit that ADDS a feed therefore lands
# with the profile one name ahead of the pin, and merging to main is what makes
# the site run it -- the pin cannot be brought into step before the merge it is
# supposed to be checking.
#
# `zdi` is the first feed merged since the pin test was written (#33), so it is
# the first to hit this, and the honest fix is a declaration rather than a
# loosened assertion. `certcc` followed within the hour and is the second. A test that accepted any profile/pin difference would stop
# noticing the case it exists for: a feed REMOVED from the live run while the
# repo still scores against it, which is the same-direction error as a cold
# baseline and makes a candidate look better than it is.
#
# It is self-clearing, and that is the property that keeps it from becoming
# furniture. `test_no_feed_is_declared_pending_once_the_live_run_has_it` fails
# the moment a name here appears in the pin, so the first re-pin after the deploy
# forces the name out. `test_the_pinned_live_run_is_not_stale` already bounds that
# to a fortnight.
#
# Anything in here is scored against a pin that does not contain it, which is the
# `live.upper_bound` case every card already records: the candidate looks better
# than it is, by at most `live.rows_short`.
PENDING_FIRST_RUN = frozenset({"zdi", "certcc"})

# Advisory dates more than this far before the CVE's publication are treated as
# a data error rather than as evidence of lead. Feeds carry wrong dates: a
# changelog entry dated by the package release rather than the advisory, or a
# 1970 epoch from a failed parse, would otherwise read as three decades of
# prescience and admit a mirror on one bad row.
MAX_PLAUSIBLE_LEAD_DAYS = 3650


def _days_between(earlier, later):
    """Whole days from `earlier` to `later`, or None if either is unusable."""
    try:
        a = dt.date.fromisoformat((earlier or "")[:10])
        b = dt.date.fromisoformat((later or "")[:10])
    except (TypeError, ValueError):
        return None
    return (b - a).days


def fetch(name, years):
    """Run ONE adapter, instrumented. Returns (rows, stats).

    Through `feeds.ADAPTERS` rather than by importing the function directly, so a
    candidate that is not wired into the adapter table cannot be scored. Being
    scoreable and being runnable must be the same condition, or the scorecard in
    the merge diff describes something the pipeline will not execute.
    """
    if name not in feeds.ADAPTERS:
        raise SystemExit(f"unknown feed {name!r}; known: {sorted(feeds.ADAPTERS)}")
    feeds.reset_health()
    t0 = time.time()
    rows = feeds.ADAPTERS[name](years)
    wall = time.time() - t0
    return rows, {
        "wall_seconds": round(wall, 1),
        "bytes": feeds.FETCH_BYTES["total"],
        "health": dict(feeds.FEED_HEALTH.get(name, {})),
    }


def _corpus_maps(corpus_df):
    """(assigner by id, state by id, publication date by id) for the whole corpus."""
    ids = list(corpus_df["cve_id"])
    assigner = dict(zip(ids, corpus_df["assigner"]))
    state = dict(zip(ids, corpus_df["state"]))
    if "date_published" in getattr(corpus_df, "columns", []):
        published = dict(zip(ids, corpus_df["date_published"]))
    else:
        # Refuse to score rather than score a feed's disclosure lead as zero.
        # A missing column would make every candidate a publication mirror and
        # the harness would reject the entire expansion with a straight face.
        raise SystemExit(
            "the corpus index carries no date_published column, so disclosure "
            "lead cannot be measured; rebuild the index (cli run --reindex)")
    return assigner, state, published


# The window, from the one place that defines it.
#
# This used to compute `(y - 2, y - 1, y)` itself, with a comment explaining that
# it was WIDER than the feed-gather window because `cli.run` gathered two years
# and measured coverage over three. That gap is closed: both now read
# coverage.WINDOW_YEARS, so a scorecard's "marginal CNA" is marginal to exactly
# the denominator the gate uses and to exactly the years the feeds read.
def coverage_years(today=None):
    from . import coverage as _coverage
    return _coverage.window(int((today or dt.date.today().isoformat())[:4]))


def _cve_year(cid):
    try:
        return int(str(cid).split("-")[1])
    except (IndexError, ValueError, AttributeError):
        return None


def _corpus_newest(corpus_df):
    """The newest publication date the corpus knows, as its own freshness mark.

    A feed row can only credit a CNA if the corpus has the record it names, so a
    baseline is measured against TWO moving things and only recorded one of them.
    """
    try:
        v = corpus_df["date_published"].max()
    except KeyError:
        return None
    return str(v)[:10] or None


def eligible_published(corpus_df, recent_years):
    """Published CVEs inside the coverage window, exactly as coverage.compute
    selects them.

    Computed here rather than approximated, because the whole value of this
    harness is that its number and the gate's number are the same kind of thing.
    A scorecard measured on a different denominator would be one more estimate.
    """
    pub = corpus_df[corpus_df["state"] == "PUBLISHED"]
    return {c for c in pub["cve_id"] if _cve_year(c) in set(recent_years)}


def sightings_by_cna(ids, assigner, roster_index, eligible=None):
    """Roster CNAs, and how many of their published CVEs these ids reached.

    `eligible` is the published-in-window set. Passing None counts any id with a
    known assigner, which is looser than the gate and is used only by tests that
    supply their own corpus.
    """
    out = {}
    for cid in ids:
        if eligible is not None and cid not in eligible:
            continue
        a = assigner.get(cid)
        if not a:
            continue
        key = roster_index.get(roster_mod.normalise(a))
        if key:
            out[key] = out.get(key, 0) + 1
    return out


def effective(sight, floor=MIN_SIGHTINGS):
    return {c for c, n in sight.items() if n >= floor}


def disclosure_lead(rows, published, state):
    """Admissibility test 2, per referenced ID.

    Three populations, kept apart because they answer different questions:

      lead        the CVE is published AND the advisory predates its publication.
                  Positive evidence, and the only kind that can be banked.
      unpublished the referenced ID has no published record in the corpus at all,
                  or is RESERVED. This is an RBP candidate right now, which is
                  stronger evidence than a historical lead, and it is counted
                  separately rather than folded in, because an id absent from the
                  corpus can also mean a stale index.
      mirror      the advisory is dated on or after publication. No lead.
    """
    lead, unpublished, mirror, undated = [], [], 0, 0
    for r in rows:
        cid = r.get("cve_id")
        adv = (r.get("public_date") or "")[:10]
        st = state.get(cid)
        if st is None or st == "RESERVED":
            unpublished.append(cid)
            continue
        if not adv:
            undated += 1
            continue
        d = _days_between(adv, (published.get(cid) or "")[:10])
        if d is None:
            undated += 1
        elif 0 < d <= MAX_PLAUSIBLE_LEAD_DAYS:
            lead.append((cid, d))
        else:
            mirror += 1
    dated = len(lead) + mirror
    return {
        # PUBLISHED SEPARATELY, because it is the denominator that decides
        # whether the other numbers mean anything. `arch` returns 62 references
        # and dates none of them, so its lead is 0 out of 0: unmeasured, not
        # measured as zero. Every distro tracker is the same shape.
        "dated_n": dated,
        "lead_n": len(lead),
        "lead_pct": round(100 * len(lead) / dated, 2) if dated else 0.0,
        "lead_median_days": (sorted(d for _c, d in lead)[len(lead) // 2]
                             if lead else None),
        "lead_max_days": max((d for _c, d in lead), default=None),
        "lead_examples": [c for c, _d in sorted(lead, key=lambda x: -x[1])[:5]],
        "unpublished_n": len(unpublished),
        "unpublished_examples": sorted(unpublished)[:5],
        "mirror_n": mirror,
        "undated_n": undated,
    }


def classify(marginal_cnas, lead):
    """detecting | redundant | corroborating | unmeasurable | reject, with the
    reason in words.

    `corroborating` is not a soft rejection. It means the feed may be merged and
    must be excluded from the coverage numerator, because crediting a CNA as
    observable on a feed that cannot surface an unpublished ID is how a launch
    gate clears while the site's actual claim gets weaker.

    `redundant` was split out of `corroborating` on 2026-09-06, because ONE WORD
    WAS DOING TWO JOBS AND THE PIPELINE READ THE WRONG ONE.

    FEEDS.md section 2 defines the exclusion on one combination and one only: "A
    feed that clears (1) and fails (2) ... is then tagged `corroborating` and
    excluded from the coverage numerator." Clears the marginal test, FAILS the
    disclosure test. A publication mirror. This function also returned that word
    for the opposite shape, a feed that fails (1) and CLEARS (2), and
    `corroborating_feeds` fed both to `coverage.compute`.

    The same document had already written down what should happen to the second
    shape, about the only feed then in it: "`mozilla` is corroborating rather
    than mirroring ... it clears admissibility test 2, SO IT STAYS IN THE
    NUMERATOR." It did not stay in the numerator. `mozilla`, `samsung` and
    `ubuntu` are all in the live run's published `corroborating_feeds`, all three
    on this branch, none of them a mirror.

    It cost nothing while the marginal figures were inflated, because a feed with
    a wrongly-marginal CNA never reached this branch. Fixing the combine to a
    union of ids put `alas`, `debian`, `ghsa`, `alpine` and `ubuntu-osv` on it,
    which would have dropped five of the site's largest feeds out of its own
    coverage numerator on a rule that was never about them.

    Measured, the correction moves the published figure by zero CNAs today: the
    exclusion set becomes empty, and `cnas_effective` computed with and without
    it is 263 either way. That is the same answer FEEDS.md recorded on
    2026-08-24 ("the split would exclude nothing ... no merged feed is a proven
    publication mirror") and the same one `coverage.compute` measured for
    `mozilla` alone. The number does not move; what changes is that the rule now
    fires on the case it describes.

    `unmeasurable` was added on 2026-08-24, when the first real audit made this
    function commit exactly the error the rest of this repository is built to
    avoid. `arch` returns 62 references and dates none of them, so its historical
    lead is 0 out of 0. The classifier read that as "no disclosure lead" and
    returned `reject`, which is a claim about a feed that the data cannot
    support: "cannot measure" and "measured zero" are the same value and must not
    be the same outcome, which is the distinction `feeds.record_feed` already
    draws between a failed feed and an empty one and the one
    `inference.summarise_state` draws with "not separately measurable".

    It matters beyond tidiness. FEEDS.md's rule excludes PUBLICATION MIRRORS from
    the coverage numerator, and a feed nobody has measured is not a proven
    mirror. Excluding it would silently lower a launch gate on the strength of a
    missing date field.
    """
    detects = lead["lead_n"] > 0 or lead["unpublished_n"] > 0
    # The test could not run at all: nothing dated to compare, and nothing
    # currently unpublished to point at.
    evaluable = lead.get("dated_n", 0) > 0 or lead["unpublished_n"] > 0
    if not evaluable:
        return "unmeasurable", (
            f"every one of its {lead.get('undated_n', 0)} references is undated and "
            "none is currently unpublished, so admissibility test 2 could not "
            "be run. Not a mirror; not measured. It must not be excluded from "
            "the coverage numerator on this evidence")
    if marginal_cnas < 1 and not detects:
        return "reject", ("no marginal CNA and no disclosure lead: it raises "
                          "neither coverage nor detection")
    if marginal_cnas < 1:
        return "redundant", ("no marginal CNA, but it references ids that were "
                             "unpublished at the time, so it clears "
                             "admissibility test 2 and STAYS IN THE NUMERATOR: "
                             "redundant on coverage, not a publication mirror")
    if not detects:
        return "corroborating", ("it crosses the sighting floor for "
                                 f"{marginal_cnas} new CNA(s) but has never "
                                 "referenced an unpublished id: a publication "
                                 "mirror, excluded from the coverage numerator")
    return "detecting", (f"{marginal_cnas} marginal CNA(s) and "
                         f"{lead['lead_n']} lead / {lead['unpublished_n']} "
                         "unpublished references")


def live_marginal(name, ids, base_ids, assigner, roster_index, eligible,
                  base=None, live=None):
    """What this feed would add to the merged set THE SITE ACTUALLY HAS.

    The local baseline is the set this machine could reach. The pinned live
    profile is the set the published run reached, which is deeper by every id
    every previous run banked, and the gap is not small: 20,141 `csaf` ids on
    2026-09-06, worth 13 roster CNAs that sit below the floor here and are
    already effective there, and three more this baseline has not sighted at all.
    A card scored only against the local baseline can credit a candidate for
    making one of those sixteen observable when the site has been reading it for
    weeks.

    THREE STATES, AND THEY ARE DIFFERENT STATEMENTS:

      no pin              `pinned` false, figures None. Score against the local
                          baseline and say so; do not report a live number
                          nobody measured.
      already merged      the feed is in the live profile. It cannot be marginal
                          to a set that already contains it, so the figure is
                          None with a reason rather than a meaningless 0. This
                          is every card `audit` produces.
      a real candidate    the figure, with `upper_bound` set when the baseline is
                          colder than live.

    WHY IT IS STILL AN UPPER BOUND. Only counts are published, not ids, so the
    candidate's own overlap with the live set cannot be removed exactly. What CAN
    be removed exactly is its overlap with the local baseline, and that is done
    here: only ids this baseline has never seen are allowed to add a sighting.
    The residue is a candidate id that the live run has and this baseline does
    not, which is bounded by `rows_short` and shrinks to nothing as the local
    state drains. It is the same direction as before and a far smaller number.
    """
    # `live` is the pinned profile or None. Resolving the pin is the caller's
    # job, so "no pin on disk" and "do not use the pin" arrive here as one state
    # and this function has one behaviour for it.
    if not live:
        return {
            "pinned": False,
            "cnas_new_effective": None,
            "cnas_new_effective_names": None,
            "reason": ("no pinned live profile; run `python -m rbp.feedlab "
                       "pin-live`. This card is marginal to the local baseline "
                       "only, which is the permissive direction."),
        }
    live_sight = live.get("sightings") or {}
    live_eff = effective(live_sight)
    short = {k: v for k, v in depth_shortfall(base, live).items() if v > 0}
    common = {
        "pinned": True,
        "fetched": live.get("fetched"),
        "generated_at": live.get("generated_at"),
        "source_commit": live.get("source_commit"),
        "effective_n": len(live_eff),
        "rows_short": short,
        "ids_short": sum(short.values()),
    }
    if name in (live.get("sources") or ()):
        return {**common,
                "already_merged": True,
                "cnas_new_effective": None,
                "cnas_new_effective_names": None,
                "upper_bound": None,
                "reason": ("already in the live profile, so it cannot be "
                           "marginal to a set that contains it; the figure "
                           "above is the leave-one-out one, against this "
                           "machine's baseline"
                           + (", and is an upper bound while that baseline is "
                              f"{sum(short.values()):,} rows colder than the "
                              "live run" if short else ""))}
    unseen = [c for c in ids if c not in base_ids]
    add = sightings_by_cna(unseen, assigner, roster_index, eligible)
    combined = dict(live_sight)
    for c, n in add.items():
        combined[c] = combined.get(c, 0) + n
    names = sorted(effective(combined) - live_eff)
    return {**common,
            "already_merged": False,
            "ids_not_in_baseline": len(unseen),
            "cnas_new_effective": len(names),
            "cnas_new_effective_names": names,
            "upper_bound": bool(short),
            "reason": (("an upper bound: this baseline is "
                        f"{sum(short.values()):,} rows colder than the live run "
                        f"at {', '.join(sorted(short))}")
                       if short else
                       "measured against a baseline no colder than the live run")}


# `live=PINNED` means "read the committed pin". Passing `live=None` means "there
# is no live run to compare against" and is a different statement, which is why
# this is a sentinel rather than a None default: a test scoring a synthetic feed
# against a synthetic corpus must be able to say the second without the committed
# pin leaking into it, and `audit` must be able to read the pin once rather than
# fifteen times.
PINNED = object()


def scorecard(name, years, corpus_df, base=None, rows=None, stats=None,
              live=PINNED):
    """The whole verdict for one candidate, as the dict written to disk."""
    assigner, state, published = _corpus_maps(corpus_df)
    roster_index = roster_mod.index(roster_mod.load())
    eligible = eligible_published(corpus_df, coverage_years())
    if rows is None:
        rows, stats = fetch(name, years)
    stats = stats or {}

    ids = sorted({r["cve_id"] for r in rows if r.get("cve_id")})
    sight = sightings_by_cna(ids, assigner, roster_index, eligible)
    mine = effective(sight)

    base = base if base is not None else load_baseline()
    base_effective = set((base or {}).get("effective") or ())
    base_sight = (base or {}).get("sightings") or {}
    base_ids = set((base or {}).get("ids") or ())

    # THE NUMBER THAT JUSTIFIES THE MERGE. Not "CNAs this feed reaches", which
    # counts the 53 that every distro feed already covers, and not "CNAs it
    # reaches alone", which misses the CNA that this feed pushes over the floor.
    # Recomputed on the COMBINED set, because a CNA at 2 sightings in the
    # baseline and 1 here is a CNA this feed makes observable.
    #
    # COMBINED BY THE UNION OF IDS, NOT BY SUMMING SIGHTINGS, and the difference
    # is not academic. A sighting is a PUBLISHED CVE THIS SITE SAW: `coverage.
    # compute` counts distinct ids (`surfaced_ids`), so two feeds referencing the
    # same CVE are one sighting there and were two here. Adding the counts
    # credited a feed for re-referencing what the merged set already had, which
    # is precisely the mirror that admissibility test 1 exists to refuse.
    #
    # Measured on the 2026-09-06 baseline, summing against union: `alas` 2 -> 0,
    # `debian` 4 -> 0, `ubuntu-osv` 4 -> 0, `ghsa` 3 -> 0, `alpine` 1 -> 0,
    # `osv` 5 -> 1, `redhat` 6 -> 3, `csaf` 84 -> 80. Ten of the fifteen
    # committed cards carried marginal CNAs that no id in the feed had earned,
    # and every one of them was in the permissive direction.
    if base_ids or not base_sight:
        combine = "union"
        combined = sightings_by_cna(sorted(base_ids | set(ids)), assigner,
                                    roster_index, eligible)
    else:
        # A baseline that recorded counts but not ids cannot be combined this
        # way. Recorded on the card rather than silently scored, because the two
        # methods disagree and the reader is entitled to know which one ran.
        combine = "sum"
        combined = dict(base_sight)
        for c, n in sight.items():
            combined[c] = combined.get(c, 0) + n
    new_effective = sorted(effective(combined) - base_effective)

    live_block = live_marginal(name, ids, base_ids, assigner, roster_index,
                               eligible, base=base,
                               live=load_live() if live is PINNED else live)

    lead = disclosure_lead(rows, published, state)
    # THE LIVE FIGURE DECIDES WHEN THERE IS ONE. The verdict is a claim about
    # what merging this feed would do to the site, and the site is the live run,
    # not a local baseline that is 20,141 `csaf` ids behind it.
    marginal = (live_block["cnas_new_effective"]
                if live_block.get("cnas_new_effective") is not None
                else len(new_effective))
    verdict, why = classify(marginal, lead)

    return {
        "feed": name,
        "years": sorted(years),
        "scored_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "baseline": {
            "feeds": (base or {}).get("feeds"),
            "scored_at": (base or {}).get("scored_at"),
            "effective_n": len(base_effective),
        },
        "ids": len(ids),
        "ids_new": len(set(ids) - base_ids) if base_ids else None,
        "cnas_reached": len(sight),
        "cnas_effective_alone": len(mine),
        "cnas_new_effective": len(new_effective),
        "cnas_new_effective_names": new_effective,
        "combine": combine,
        # What the same question answers against the set the SITE has. Null-safe:
        # `pinned` false means no pin was available and every figure under it is
        # None, which is a different statement from zero.
        "live": live_block,
        "disclosure": lead,
        "verdict": verdict,
        "verdict_reason": why,
        "wall_seconds": stats.get("wall_seconds"),
        "bytes": stats.get("bytes"),
        "health": stats.get("health"),
        # Filled in over repeated runs by `stability`, never in one run: a feed
        # whose own count swings 40% between fetches has no usable shrink
        # baseline, and that cannot be observed by fetching it once.
        "stability": None,
    }


# --------------------------------------------------------------------------
# the baseline: the merged set, as it stands
# --------------------------------------------------------------------------

def build_baseline(sources, years, corpus_df):
    """Fetch every merged feed, PER FEED rather than through `gather`.

    `gather` merges as it goes, which is right for the pipeline and useless here:
    the question this harness exists to answer is what each feed contributes that
    the others do not, and a merged id set has already thrown that away. Keeping
    the rows per feed also makes `audit` an offline operation, so re-scoring
    against a changed corpus or a changed floor costs nothing and does not put
    twelve more fetches on twelve third parties.
    """
    assigner, _state, _published = _corpus_maps(corpus_df)
    roster_index = roster_mod.index(roster_mod.load())
    eligible = eligible_published(corpus_df, coverage_years())
    per_feed, failed = {}, {}
    t0 = time.time()
    for name in sources:
        try:
            rows, stats = fetch(name, years)
        except Exception as e:
            # Recorded, not skipped. A baseline missing a feed because it threw
            # is a baseline that makes every later candidate look better than it
            # is, and the whole point of a marginal number is what it is marginal
            # TO.
            failed[name] = str(e)[:160]
            print(f"  [{name}] FAILED: {e}", file=sys.stderr)
            continue
        # STABILITY ACCRUES HERE, at the only place a REAL fetch happens.
        #
        # `stability` was null on all twelve committed scorecards, because only
        # `score` called `record_fetch` and every merged feed had been scored by
        # `audit`, which is offline by design. So the field this harness's own
        # README calls out as "how a scorecard field becomes decoration" was
        # decoration on every feed in the profile.
        #
        # It must NOT be recorded in `audit`. Audit replays one baseline's stored
        # rows, so every audit run would append an identical id count and
        # `stability` would report a 0% swing over N "fetches" that were one
        # fetch. A fabricated 100%-stable reading is worse than null: null says
        # "not measured", and 0% says "measured, and perfect".
        #
        # A baseline rebuild is a real fetch of every feed, so each one
        # contributes one honest observation and the field fills in over
        # successive rebuilds rather than being asserted.
        record_fetch(name, {r["cve_id"] for r in rows if r.get("cve_id")}, years)
        per_feed[name] = {
            "rows": [{"cve_id": r["cve_id"], "public_date": r.get("public_date") or ""}
                     for r in rows if r.get("cve_id")],
            "stats": stats,
        }
        print(f"  [{name}] {len(rows)} rows, {stats['wall_seconds']}s, "
              f"{stats['bytes'] / 1e6:.0f} MB", file=sys.stderr)
    wall = time.time() - t0
    ids = sorted({r["cve_id"] for f in per_feed.values() for r in f["rows"]})
    sight = sightings_by_cna(ids, assigner, roster_index, eligible)
    return {
        "feeds": sorted(per_feed),
        "failed": failed,
        "coverage_years": list(coverage_years()),
        "years": sorted(years),
        # WHICH CORPUS THIS WAS MEASURED AGAINST, because a sighting is a feed
        # row meeting a corpus record and the corpus half was invisible. Built
        # 2026-09-06 against an index ten days old, this baseline reached 247
        # effective CNAs where the live run of the same fifteen feeds over the
        # same window reached 263: 3,696 of the 77,219 referenced ids, 4.8%, were
        # not in the index at all, so they credited nobody. `twcert` was 15 live
        # and 0 here for exactly that reason and nothing on either side said why.
        "corpus_newest": _corpus_newest(corpus_df),
        "scored_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "ids": ids,
        "per_feed": per_feed,
        "sightings": sight,
        "effective": sorted(effective(sight)),
        "wall_seconds": round(wall, 1),
        "bytes": sum(f["stats"].get("bytes") or 0 for f in per_feed.values()),
        "health": {k: dict(v["stats"].get("health") or {}) for k, v in per_feed.items()},
        # HOW COLD THE CSAF HALF WAS, as counts. The health record says "3 still
        # catching up" in a sentence, which no test can read and no card can
        # subtract. This is the same fact as numbers, recorded beside the rows it
        # explains: a baseline whose `csaf` is 20,141 ids short of the live run's
        # is not a baseline a candidate can be honestly marginal to, and until
        # this field existed nothing in the artefact said so.
        "csaf_state": csaf_depth(),
    }


def rescore_baseline(corpus_df, base=None):
    """Recompute a recorded baseline's derived fields against the CURRENT corpus,
    from the rows it already stored.

    Same reasoning as `audit` being offline: "re-scoring against a changed corpus
    or a changed floor must not cost twelve more fetches at twelve third
    parties." A corpus refresh changes which referenced ids are PUBLISHED and who
    they belong to, which changes `sightings` and `effective`, and none of that
    is a reason to pull seven gigabytes off fifteen third parties a second time.

    It records no fetch, for the same reason `audit` does not: nothing was
    fetched, and a fabricated observation is worse than none. `scored_at` stays
    the time the ROWS were read, because that is what it means and what
    `test_the_recorded_baseline_describes_the_profile_that_actually_runs` reads.
    """
    base = base if base is not None else load_baseline()
    if base is None or not base.get("per_feed"):
        raise SystemExit(
            "no recorded baseline with per-feed rows to re-score. Run "
            "`python -m rbp.feedlab baseline` first; there is nothing offline "
            "to recompute from.")
    assigner, _state, _published = _corpus_maps(corpus_df)
    roster_index = roster_mod.index(roster_mod.load())
    eligible = eligible_published(corpus_df, coverage_years())
    ids = sorted({r["cve_id"] for f in base["per_feed"].values() for r in f["rows"]})
    sight = sightings_by_cna(ids, assigner, roster_index, eligible)
    return {**base,
            "ids": ids,
            "sightings": sight,
            "effective": sorted(effective(sight)),
            "coverage_years": list(coverage_years()),
            "corpus_newest": _corpus_newest(corpus_df),
            # Re-read here as well as at fetch time, so a baseline recorded
            # before this field existed gains it for the cost of an offline
            # rescore rather than a 26-minute refetch. It describes the read
            # marks AS OF THE RESCORE. That is the same state the rows came
            # from, only ever deeper: `feed_csaf` never forgets a reference, so
            # this can overstate how cold the baseline was and cannot understate
            # it.
            "csaf_state": csaf_depth(),
            "rescored_at": dt.datetime.now(dt.timezone.utc)
                             .isoformat(timespec="seconds")}


def extend_baseline(names, years, corpus_df, base=None):
    """Fetch ONLY `names` and splice them into the recorded baseline.

    A baseline that can only be built all-at-once costs sixteen fetches to learn
    about one new feed, and this module already refuses that trade twice in
    exactly these words: "re-scoring against a changed corpus or a changed floor
    must not cost twelve more fetches at twelve third parties." Adding a feed is
    the same trade and had no path, so the merge of `zdi` on 2026-09-08 rebuilt
    all sixteen (32 minutes, 6.8 GB) and the merge of `certcc` an hour later would
    have rebuilt all seventeen again.

    It bit twice in one day in a second way worth recording: `zdi`'s adapter was
    fixed AFTER that rebuild, so the committed baseline row is 11 ids short of
    what the adapter returns, and the choice was between a wrong number and a
    second full refetch. With this, it is neither.

    THE OTHER FEEDS' ROWS ARE REUSED, NOT RE-READ, and the derived half is
    recomputed from the union exactly as `rescore_baseline` does it, so a spliced
    baseline and a rebuilt one differ only in WHEN each feed's rows were read.
    That is recorded per feed rather than glossed: `per_feed[name]["stats"]`
    already carries its own timing, and `extended_at` says the splice happened.

    `scored_at` is deliberately NOT moved. It means "when these rows were read",
    it is what `test_the_recorded_baseline_describes_the_profile_that_actually_runs`
    and every card's `baseline.scored_at` report, and advancing it for feeds that
    were not re-read would be the same fabrication `rescore_baseline` and `audit`
    both refuse when they decline to record a fetch.
    """
    base = base if base is not None else load_baseline()
    if base is None or not base.get("per_feed"):
        raise SystemExit(
            "no recorded baseline to extend. Run `python -m rbp.feedlab "
            "baseline` first; there is nothing to splice into.")
    per_feed = dict(base["per_feed"])
    failed = dict(base.get("failed") or {})
    for name in names:
        try:
            rows, stats = fetch(name, years)
        except Exception as e:
            failed[name] = str(e)[:160]
            print(f"  [{name}] FAILED: {e}", file=sys.stderr)
            continue
        # A REAL FETCH, so it contributes a real stability observation, on the
        # same reasoning as `build_baseline` and unlike `audit` or a rescore.
        record_fetch(name, {r["cve_id"] for r in rows if r.get("cve_id")}, years)
        failed.pop(name, None)
        per_feed[name] = {
            "rows": [{"cve_id": r["cve_id"], "public_date": r.get("public_date") or ""}
                     for r in rows if r.get("cve_id")],
            "stats": stats,
        }
        print(f"  [{name}] {len(rows)} rows, {stats['wall_seconds']}s, "
              f"{stats['bytes'] / 1e6:.0f} MB", file=sys.stderr)
    merged = {**base, "per_feed": per_feed, "feeds": sorted(per_feed),
              "failed": failed,
              "extended_at": dt.datetime.now(dt.timezone.utc)
                               .isoformat(timespec="seconds"),
              "extended": sorted(set(names))}
    # The derived half, from the union of the spliced rows. Same function the
    # offline rescore uses, so there is one definition of what these fields mean.
    out = rescore_baseline(corpus_df, base=merged)
    out.pop("rescored_at", None)      # this was a fetch, not a rescore
    # RECOMPUTED FROM THE PER-FEED STATS, not inherited. `build_baseline` times a
    # sequential loop, so its `wall_seconds` and `bytes` ARE the per-feed sums;
    # carrying the old values through a splice would report the original build's
    # 1,938 seconds for an operation that took 30, which is the kind of number
    # that gets quoted later as the cost of adding a feed.
    out["bytes"] = sum(f["stats"].get("bytes") or 0 for f in per_feed.values())
    out["wall_seconds"] = round(
        sum(f["stats"].get("wall_seconds") or 0 for f in per_feed.values()), 1)
    out["health"] = {k: dict(v["stats"].get("health") or {})
                     for k, v in per_feed.items()}
    return out


def baseline_summary(base):
    """The committed half: everything except the 32,000-id list.

    A reviewer needs to know which feeds the baseline was built from, when, how
    long it took and how many CNAs it reaches. They do not need every id, and a
    diff containing every id is a diff nobody reads.
    """
    return {k: v for k, v in base.items() if k not in ("ids", "per_feed")} | {
        "ids_n": len(base.get("ids") or []),
        "per_feed_rows": {k: len(v["rows"]) for k, v in
                          (base.get("per_feed") or {}).items()},
    }


def load_baseline(path=BASELINE):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")
    return path


# --------------------------------------------------------------------------
# the pinned live profile: what the site's own run can see
# --------------------------------------------------------------------------

def _roster_sightings(raw, roster_index):
    """Published per-CNA sighting counts, keyed the way this harness keys them.

    The live artefact counts by the CORPUS ASSIGNER STRING and this harness
    counts by ROSTER SHORT NAME, and the two are not the same alphabet:
    `Hitachi Energy` upstream is `Hitachi_Energy` on the roster, `JFROG` is
    `JFrog`, `SICK AG` is `SICK_AG`. Comparing them raw reports eight CNAs as
    "effective here, missing live" that are the same eight CNAs spelled twice.

    So every key goes through `roster.normalise` and the pinned index, exactly as
    `sightings_by_cna` does, and counts that collapse onto one roster entry are
    summed. Off-roster assigners are dropped for the same reason they are dropped
    there: the roster is the denominator, and something not on it cannot be
    marginal to it.
    """
    out = {}
    for name, n in (raw or {}).items():
        key = roster_index.get(roster_mod.normalise(name))
        if key:
            out[key] = out.get(key, 0) + int(n or 0)
    return out


def _live_feed_rows(feeds_block):
    """Rows per feed from a published summary's health block.

    `feeds.detail.<name>.rows` is the parent count for a fan-out adapter too, so
    `csaf` reads 62,800 rather than the 121,827 its provider rows sum to: a
    provider row counts ids in ITS scope and the same id is in several.
    """
    detail = (feeds_block or {}).get("detail") or {}
    return {k: int(v.get("rows") or 0) for k, v in detail.items()
            if isinstance(v, dict)}


def pin_live(url=None):
    """Fetch the live run's published summary and pin the half this harness scores
    against.

    NOT THE WHOLE ARTEFACT. What is recorded is the per-CNA sightings, the rows
    each feed returned, the provider rows behind `csaf`, and enough provenance to
    tell whether the pin still describes the running site. The rest of the
    summary is the site's business and would make the diff unreadable.

    The site publishes these names on purpose: `coverage.covered`, `sightings`,
    `near_floor` and `top_missed_effective` are allowlisted in `publish.check`
    "so the naming gate is inspectable", and they are aggregate coverage rather
    than attribution of a row to an owner. No row, no id and no owner is read
    here.
    """
    url = url or LIVE_URL
    body, code, _hdrs = feeds._get(url, timeout=60)
    if not isinstance(body, dict):
        raise SystemExit(f"{url} returned {code} and no JSON object; nothing to pin")
    cov = body.get("coverage") or {}
    if not cov.get("sightings"):
        raise SystemExit(
            f"{url} carries no coverage.sightings, so there is nothing for a "
            "candidate to be marginal to. The published summary's shape "
            "changed; fix the reader rather than pinning an empty set.")
    roster_index = roster_mod.index(roster_mod.load())
    sight = _roster_sightings(cov.get("sightings"), roster_index)
    csaf = ((body.get("feeds") or {}).get("detail") or {}).get("csaf") or {}
    return {
        "source_url": url,
        "fetched": dt.date.today().isoformat(),
        # The run's own marks, so a pin can be told from the run it describes.
        "generated_at": body.get("generated_at"),
        "source_commit": body.get("source_commit"),
        "source_dirty": body.get("source_dirty"),
        "date": body.get("date"),
        "years": sorted(cov.get("recent_years") or []),
        "sources": sorted(cov.get("sources") or []),
        "corroborating_feeds": sorted(cov.get("corroborating_feeds") or []),
        "min_sightings": cov.get("min_sightings"),
        "feed_rows": _live_feed_rows(body.get("feeds")),
        "csaf_provider_rows": {k: int((v or {}).get("rows") or 0)
                               for k, v in (csaf.get("parts") or {}).items()},
        "sightings": sight,
        "effective": sorted(effective(sight)),
        # The site's own count, kept beside ours because they are two different
        # questions and a reader will otherwise assume one is a typo. TWO
        # DIFFERENCES, both deliberate. Theirs applies the corroborating
        # exclusion and ours does not, so ours can never be the smaller; see
        # `coverage.compute`, "applied to effective ONLY". And theirs applies the
        # floor to the raw assigner counts and maps the survivors onto the
        # roster, where ours maps first and then counts, which is what
        # `sightings_by_cna` does for the baseline: two assigner strings that
        # collapse onto one roster entry are one CNA here and two there. Ours is
        # the one comparable to the baseline, which is the whole point of the
        # pin. On 2026-09-06 both are 263, which is the measurement that says the
        # exclusion costs nothing today.
        "published_cnas_effective": cov.get("cnas_effective"),
        "published_cnas_sighted": cov.get("cnas_sighted"),
    }


def load_live(path=LIVE):
    """The pinned live profile, or None.

    None is a state, not an error. A candidate can still be scored against the
    local baseline alone; what it cannot do is claim the resulting figure is what
    the site would see, and `scorecard` says so on the card rather than here.
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            live = json.load(fh)
    except (OSError, ValueError):
        return None
    return live if isinstance(live, dict) and live.get("sightings") else None


def live_age_days(live, today=None):
    """Days since the pin was fetched, or None if it does not say."""
    if not live:
        return None
    if today is None:
        today = dt.date.today()
    return _days_between(live.get("fetched"),
                         today if isinstance(today, str) else today.isoformat())


def depth_shortfall(base, live):
    """Per feed, how many rows the live run read that this baseline did not.

    THE NUMBER THIS WHOLE SECTION EXISTS FOR. A feed list that matches the
    pipeline says nothing about the state behind one of those feeds, which is
    exactly where the 20,141-id `csaf` gap was hiding: `test_the_recorded_
    baseline_describes_the_profile_that_actually_runs` passed while the harness
    was reading two thirds of one feed.

    Positive means the baseline is COLDER than the live run, which is the
    permissive direction and the one worth failing on. Negative means the
    baseline read more than the live run did, which happens while a feed is
    draining and is not a defect.
    """
    if not base or not live:
        return {}
    rows = base.get("per_feed_rows") or {
        k: len(v.get("rows") or ()) for k, v in (base.get("per_feed") or {}).items()}
    out = {}
    for name, live_n in (live.get("feed_rows") or {}).items():
        if name in rows:
            out[name] = int(live_n) - int(rows[name])
    return out


def csaf_depth(path=None):
    """How deep the LOCAL csaf read marks are, as counts rather than as prose.

    `_record_csaf_health` already said "3 stopped on time budget; 3 still
    catching up" in a health string, which is a sentence a reader can see and no
    test can read. The same facts are recorded here as numbers so the baseline
    can carry them and a card can subtract them.

    `ids` is the UNIQUE reference count across providers, which is the figure
    comparable to the live run's `csaf` rows; the per-provider sum is larger
    because providers reference the same id.
    """
    path = path or feeds.CSAF_STATE
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return None
    provs = {k: v for k, v in state.items()
             if not k.startswith("_") and isinstance(v, dict)}
    ids = set()
    for v in provs.values():
        ids |= set(v.get("refs") or ())
    behind = {k: int(v.get("behind") or 0) for k, v in provs.items()}
    return {
        "providers": len(provs),
        "ids": len(ids),
        "behind": sum(behind.values()),
        "providers_behind": sorted(k for k, n in behind.items() if n > 0),
        "listed": sum(int(v.get("listed") or 0) for v in provs.values()),
        "oldest_read": min((str(v.get("oldest_read") or "") for v in provs.values()
                            if v.get("oldest_read")), default=None),
    }


# --------------------------------------------------------------------------
# stability, which accrues across runs and cannot be faked in one
# --------------------------------------------------------------------------

# FEEDS.md asks for "ids on 3 fetches 24h apart" and `stability` enforced only
# "more than one". Two fetches in one session are one observation of a feed, so
# the interval the document asks for is applied when the history is READ, not
# when it is written: the file keeps every fetch, and the swing is computed over
# the spaced subset.
MIN_FETCH_INTERVAL_H = 24


def record_fetch(name, ids, years=None, path=None):
    """Append one fetch's id count AND the window it was fetched over.

    FEEDS.md asks for "ids on 3 fetches 24h apart". A single invocation cannot
    produce that number, and returning one anyway is how a scorecard field
    becomes decoration. So each run appends, and `stability` reports None until
    there are at least two comparable ones.

    THE WINDOW IS PART OF THE OBSERVATION. This file used to record `{at, ids}`
    with nowhere to say which config produced the count, so widening
    `coverage.WINDOW_YEARS` from 2 to 4 put counts from two different windows in
    one list and every feed's swing became the width of the window rather than
    the movement of the feed. `csaf` had already shown the shape one level down,
    at the provider set: its 29.3% is sixteen providers against eighteen.
    """
    # Working state, not a scorecard: it is one line per fetch and it
    # accrues, so it belongs beside the baseline rather than in the diff.
    path = path or os.path.join(STATE, f"{name}.fetches.json")
    hist = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            hist = json.load(fh)
    entry = {"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "ids": len(ids)}
    if years:
        entry["years"] = sorted(years)
    hist.append(entry)
    write(hist, path)
    return hist


def _read_fetches(name, path=None):
    """The recorded fetch history for one feed, without appending to it."""
    path = path or os.path.join(STATE, f"{name}.fetches.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return []


def _fetch_window(entry):
    """The window one recorded fetch was taken over, or None for a fetch
    recorded before the field existed."""
    y = entry.get("years")
    return tuple(y) if isinstance(y, list) else None


def _spaced(hist, hours=MIN_FETCH_INTERVAL_H):
    """The fetches at least `hours` apart, oldest first, keeping the earliest of
    each cluster. An entry with no readable timestamp is always kept."""
    kept, last = [], None
    for h in hist:
        try:
            at = dt.datetime.fromisoformat(h["at"])
        except (KeyError, TypeError, ValueError):
            kept.append(h)
            continue
        if last is not None and at - last < dt.timedelta(hours=hours):
            continue
        kept.append(h)
        last = at
    return kept


def stability(hist):
    """Widest swing between comparable recorded fetches, as a fraction of the
    largest. Two fetches are comparable when they read the SAME WINDOW and are
    at least `MIN_FETCH_INTERVAL_H` apart.

    Both filters exist because the field lied in both directions on committed
    cards. `jvn` was fetched twice thirty minutes apart, in one session, and the
    next audit would have written `swing_pct: 0.0` -- measured, and perfect,
    over a feed nobody had watched for a day. Ten of the fifteen cards carried a
    0.0% from a pair four hours apart. And the moment the gather window went from
    two years to four, every feed's next reading would have been a 20-50% swing
    that is the window moving, not the feed.

    Null when fewer than two survive. Null says "not measured"; a number says
    "measured", and the whole reason this field exists is that a feed which
    swings on its own has no usable shrink baseline.
    """
    hist = [h for h in (hist or []) if isinstance(h.get("ids"), int)]
    if not hist:
        return None
    # The newest window, because that is the one the pipeline reads now. A swing
    # measured over a window the site no longer gathers is not the number a
    # shrink baseline needs, however many observations went into it.
    #
    # It is the LAST fetch's window, not `coverage_years()`, so this stays a pure
    # function of the history a card was written from. The cost is that a
    # deliberate `--years` experiment reads as a new window and returns null
    # until the next real fetch, which is the safe direction: null says not
    # measured. What it must never do is average a one-year probe into the
    # four-year readings and call the difference volatility.
    win = _fetch_window(hist[-1])
    counts = [h["ids"] for h in _spaced([h for h in hist
                                         if _fetch_window(h) == win])]
    if len(counts) < 2:
        return None
    hi, lo = max(counts), min(counts)
    return {"fetches": len(counts), "min": lo, "max": hi,
            "swing_pct": round(100 * (hi - lo) / hi, 1) if hi else 0.0,
            "years": list(win) if win else None}


# --------------------------------------------------------------------------
# the CSAF provider sweep
# --------------------------------------------------------------------------
#
# FEEDS.md section 4, Tier 2: "the highest-leverage item here and it is not one
# feed. It is a probe that runs `.well-known/csaf/provider-metadata.json` against
# every roster CNA's known domain, keeps what answers, and turns each hit into a
# config line rather than a parser."
#
# That last clause is why this is worth doing before anything in Tier 3.
# `feed_csaf` already handles ROLIE and directory distributions, so a discovered
# provider costs one tuple entry in CSAF_PROVIDERS and no new parsing code, and
# every new parser is a separately breaking dependency on someone else's CMS.
#
# WHAT THIS PROBE WILL NOT DO. Dell answered 403 when sampled, and some vendors
# serve CSAF behind a WAF that refuses a non-browser agent. FEEDS.md is explicit
# that "this plan does not authorise working around that", so the project's own
# User-Agent is sent unchanged and a 403 is recorded as a refusal rather than
# retried differently. A refusal is a finding: it says the vendor publishes CSAF
# and has chosen not to serve it to automated clients.

# RFC 9110 well-known location for a CSAF provider. One path, not a search: a
# probe that guesses paths is a scanner, and this is not one.
CSAF_WELL_KNOWN = "/.well-known/csaf/provider-metadata.json"


def _hosts_for(entry):
    """Candidate hosts for one upstream roster entry, most specific first.

    Drawn from the URLs the CNA itself published to the Program: its advisory
    pages, then its security contact page, then its disclosure policy. Nothing
    is guessed from the organisation name, because "Dell Technologies" to
    dell.com is a guess that is right often enough to feel safe and wrong in
    exactly the cases that matter.
    """
    from urllib.parse import urlparse
    urls = []
    sa = entry.get("securityAdvisories") or {}
    for key in ("advisories", "alerts"):
        urls += [d.get("url") for d in (sa.get(key) or []) if d.get("url")]
    for c in entry.get("contact") or []:
        urls += [d.get("url") for d in (c.get("contact") or []) if d.get("url")]
    for d in entry.get("disclosurePolicy") or []:
        if d.get("url"):
            urls.append(d["url"])
    out = []
    for u in urls:
        try:
            host = urlparse(u).hostname
        except ValueError:
            continue
        if not host or host in out:
            continue
        # Skip the shared platforms. A CSAF document at hackerone.com or
        # github.com is not this CNA's channel, and probing them once per CNA
        # would be several hundred requests at one host.
        if any(host.endswith(d) for d in
               ("github.com", "githubusercontent.com", "hackerone.com",
                "bugcrowd.com", "gitlab.com", "google.com", "cve.org",
                "mitre.org", "twitter.com", "x.com", "linkedin.com")):
            continue
        out.append(host)
    return out


def probe_csaf(shortnames=None, roster_url=None, per_cna_hosts=2, sleep=0.3):
    """Probe .well-known/csaf for each named CNA. Returns a list of results.

    One request per host, at most `per_cna_hosts` hosts per CNA, with a pause
    between. The point is a config line, not a crawl.
    """
    roster_url = roster_url or roster_mod.SOURCE_URL
    upstream, _st, _h = feeds._get(roster_url, timeout=60)
    by_name = {e.get("shortName"): e for e in (upstream or [])}
    names = list(shortnames) if shortnames else sorted(by_name)
    out = []
    for name in names:
        entry = by_name.get(name)
        if entry is None:
            out.append({"cna": name, "status": "not-on-roster", "hosts": []})
            continue
        hosts = _hosts_for(entry)[:per_cna_hosts]
        if not hosts:
            out.append({"cna": name, "status": "no-published-url", "hosts": []})
            continue
        tried = []
        hit = None
        for host in hosts:
            url = f"https://{host}{CSAF_WELL_KNOWN}"
            try:
                meta, code, _hdrs = feeds._get(url, timeout=20, retries=1)
            except Exception as e:
                tried.append({"host": host, "result": _short(e)})
                time.sleep(sleep)
                continue
            if code == 404 or meta is None:
                tried.append({"host": host, "result": "404"})
            elif isinstance(meta, dict) and meta.get("distributions"):
                tried.append({"host": host, "result": "200 provider-metadata"})
                hit = {"host": host, "url": url,
                       "publisher": (meta.get("publisher") or {}).get("name"),
                       "distributions": len(meta.get("distributions") or [])}
                time.sleep(sleep)
                break
            else:
                tried.append({"host": host, "result": "200 but not a CSAF provider"})
            time.sleep(sleep)
        out.append({"cna": name, "hosts": tried,
                    "status": "provider" if hit else "none",
                    "provider": hit})
    return out


def _short(e):
    """An exception as one readable line. A 403 must stay legible as a refusal
    rather than becoming a stack trace in a report."""
    import urllib.error
    if isinstance(e, urllib.error.HTTPError):
        return f"{e.code}"
    return type(e).__name__ + ": " + str(e)[:60]


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _corpus(index_dir):
    import pandas as pd
    path = os.path.join(index_dir, "corpus.parquet")
    if not os.path.exists(path):
        raise SystemExit(f"no corpus index at {path}; run `python -m rbp.cli run` first")
    return pd.read_parquet(path)


def _years(s):
    return {int(y) for y in str(s).split(",") if y.strip()}


def _default_years():
    """The gather window the pipeline actually reads, as the CLI's default.

    This was the literal "2025,2026" in three subcommands, and it stayed that way
    when `coverage.WINDOW_YEARS` became 4 and `a6332c0` unified the gather and
    coverage windows. So the harness fetched two years, `cli.run` fetched four,
    and every scorecard's `cnas_new_effective` was marginal to a merged set
    smaller than the live one: `jvn` scored 1,117 ids here against 1,968 in the
    first live run of its merge.

    An argparse default is a second definition of the window and nothing was
    reading the first one. Overriding it is still allowed, because measuring what
    a wider window costs a feed is how WINDOW_YEARS was chosen, but a baseline
    recorded off-window fails
    `test_the_baseline_gathers_the_years_the_pipeline_gathers` rather than
    quietly becoming what later candidates are marginal to.
    """
    return ",".join(str(y) for y in coverage_years())


def _render_live(card):
    """The live half of the card, as the two or three lines a reader needs.

    Printed under the baseline figure rather than beside it, because they are not
    two estimates of one number: the first is marginal to what this machine
    reached and the second to what the site reached, and when they disagree the
    second is the one that decides.
    """
    live = card.get("live") or {}
    if not live.get("pinned"):
        return [f"  vs the live run        not pinned ({live.get('reason', '')})"]
    short = live.get("rows_short") or {}
    head = (f"  vs the live run        {live.get('effective_n')} effective, "
            f"pinned {live.get('fetched')} @ {live.get('source_commit')}"
            + (f"; this baseline is {live.get('ids_short'):,} rows colder at "
               f"{', '.join(sorted(short))}" if short else
               "; no feed is colder here"))
    if live.get("cnas_new_effective") is None:
        return [head, f"    {live.get('reason')}"]
    return [head,
            f"  cnas_new_effective     {live['cnas_new_effective']}"
            f"   <- the number that justifies the merge"
            + ("  (upper bound)" if live.get("upper_bound") else ""),
            f"    {', '.join(live['cnas_new_effective_names']) or '(none)'}",
            f"    {live.get('reason')}"]


def _render(card):
    d = card["disclosure"]
    L = [f"\n{card['feed']}  ({', '.join(str(y) for y in card['years'])})",
         f"  ids                    {card['ids']:,}"
         + (f"  ({card['ids_new']:,} not already seen)"
            if card["ids_new"] is not None else ""),
         f"  cnas reached           {card['cnas_reached']}",
         f"  cnas_new_effective     {card['cnas_new_effective']}"
         f"   <- vs this machine's baseline",
         f"    {', '.join(card['cnas_new_effective_names']) or '(none)'}",
         *_render_live(card),
         f"  disclosure lead        {d['lead_n']} of {d['dated_n']} dated "
         f"references ({d['lead_pct']}%), median {d['lead_median_days']}d, "
         f"max {d['lead_max_days']}d",
         f"  unpublished now        {d['unpublished_n']}"
         f"   e.g. {', '.join(d['unpublished_examples']) or '(none)'}",
         f"  mirror / undated       {d['mirror_n']} / {d['undated_n']}",
         f"  wall / bytes           {card['wall_seconds']}s / "
         f"{(card['bytes'] or 0) / 1e6:.1f} MB",
         f"  stability              {card['stability'] or 'needs a second fetch'}",
         f"  VERDICT                {card['verdict'].upper()}: {card['verdict_reason']}",
         ""]
    return "\n".join(L)


def corroborating_feeds(path=None):
    """Feed names whose committed scorecard says they cannot detect.

    Read by `cli.run` so `coverage.compute` can enforce FEEDS.md section 2's rule
    that a corroborating feed does not credit a CNA as observable. The verdicts
    live in `feedlab/_audit.json`, which is committed precisely so the pipeline
    does not have to re-derive them from twelve live fetches every six hours.

    RETURNS EMPTY ON ANY PROBLEM, which is the permissive direction, and the
    caller publishes the result so an empty exclusion is visible rather than
    assumed. Failing closed here would mean an unreadable JSON file stops a
    publication, and this is a refinement to one figure, not a correctness
    guarantee. `test_every_feed_in_the_running_profile_has_a_scorecard` is what
    actually keeps the verdicts present.

    Only `corroborating` is excluded, and that word now means one thing. TWO
    verdicts are deliberately NOT excluded, for the same reason in both cases:
    the exclusion is evidence a feed CANNOT surface an unpublished id, and
    neither of them is that evidence.

    `unmeasurable` means the feed published nothing datable to score, which is an
    absence of evidence rather than evidence of absence, and treating the two the
    same would quietly demote any new feed whose first scorecard was thin.

    `redundant` means the feed clears admissibility test 2 and adds no marginal
    CNA. It used to be spelled `corroborating` and was therefore excluded, which
    is how `mozilla`, `samsung` and `ubuntu` came to be in the live run's
    published exclusion list on 2026-09-06 while FEEDS.md said in as many words
    that `mozilla` "clears admissibility test 2, so it stays in the numerator".
    See `classify`.
    """
    path = path or os.path.join(LAB, "_audit.json")
    try:
        with open(path, encoding="utf-8") as fh:
            feeds_ = (json.load(fh).get("feeds") or {})
    except Exception:
        return set()
    return {n for n, v in feeds_.items()
            if isinstance(v, dict) and v.get("verdict") == "corroborating"}


def _near_floor_report(args):
    """Which CNAs are one or two sightings from counting, and which are not.

    ROUND 7 H3. `top_missed_effective` and `top_missed` were both published and
    the difference between the two lists is exactly the near-floor set, so the
    cheapest headroom on the board was derivable and never derived. On
    2026-08-27 the eight top-50 misses split three to five: `dell`, `TR-CERT`
    and `sap` at one sighting each against a floor of three, and five at zero.
    Two more sightings apiece takes the gate from 42 of 50 to 45.

    Offline, out of the run's own summary.json. It fetches nothing, because the
    numbers it needs were already published and nobody was reading them.
    """
    path = args.summary
    if not path:
        snaps = sorted(glob.glob(os.path.join(ROOT, "snapshots", "*",
                                              "summary.json")))
        if not snaps:
            raise SystemExit(
                "no snapshot to read. Pass --summary <path>, or run the "
                "pipeline once so there is a coverage block to report on.")
        path = snaps[-1]
    with open(path, encoding="utf-8") as fh:
        cov = (json.load(fh).get("coverage") or {})
    near = cov.get("near_floor")
    if near is None:
        raise SystemExit(
            f"{path} predates the near_floor measurement. Re-run the pipeline, "
            "or point --summary at a snapshot written after 2026-08-27.")
    missed = set(cov.get("top_missed_effective") or [])
    floor = cov.get("min_sightings")
    rows = [r for r in near if not args.top_only or r["cna"] in missed]

    print(f"{path}: floor is {floor} sightings, {len(near)} roster CNA(s) "
          f"sighted and short of it\n")
    for r in rows:
        flag = "  <- top-50 miss" if r["cna"] in missed else ""
        print(f"  {r['cna']:<24} {r['sightings']} sighting(s), "
              f"short by {r['short_by']}{flag}")
    in_top = [r for r in near if r["cna"] in missed]
    print(f"\n{len(in_top)} of the {len(missed)} top-50 misses are within "
          f"{max((r['short_by'] for r in in_top), default=0)} sighting(s) of the "
          f"floor: {', '.join(r['cna'] for r in in_top) or '-'}")
    print("The rest are a parser apiece. FEEDS.md section 4 sequences the tail "
          "by VOLUME, not by this;\nthe two orderings disagree and which one "
          "wins is a decision, not a measurement.")
    return 0


def _build_parser():
    """The parser, separated from the dispatch so a test can read a default
    without running a fetch. `--years` defaulting to a stale literal is the one
    defect this module has shipped twice; the assertion that catches it has to be
    cheaper than half an hour of third-party fetches."""
    ap = argparse.ArgumentParser(
        prog="python -m rbp.feedlab",
        description="Score one candidate feed against the corpus and the merged set.")
    ap.add_argument("--index", default=os.path.join(ROOT, "data", "index"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="record the merged set, once, before scoring")
    b.add_argument("--sources", default="", help="comma-separated; default is the weekly profile")
    b.add_argument("--rescore", action="store_true",
                   help="recompute the recorded baseline against the current "
                        "corpus, from the rows it already stored; no fetch")
    b.add_argument("--add", default="",
                   help="comma-separated; fetch ONLY these feeds and splice them "
                        "into the recorded baseline, reusing the other feeds' "
                        "stored rows. Adding a feed should not cost a fetch of "
                        "every other one")
    b.add_argument("--years", default=_default_years(),
                   help="comma-separated; default is the window the pipeline "
                        "gathers, %(default)s")

    s = sub.add_parser("score", help="score one candidate against the baseline")
    s.add_argument("name")
    s.add_argument("--years", default=_default_years(),
                   help="comma-separated; default is the window the pipeline "
                        "gathers, %(default)s")
    s.add_argument("--no-write", action="store_true")

    # `audit` takes no --years. It replays the baseline's stored rows and scores
    # them over `base["years"]`, so the argument it used to accept reached
    # nothing: passing it changed no output. Deleted rather than derived.
    sub.add_parser("audit",
                   help="score every merged feed against all the others, "
                        "offline, from the recorded baseline")

    p = sub.add_parser("pin-live",
                       help="pin the live run's published profile, so a "
                            "candidate is marginal to the set the site has "
                            "rather than to the set this machine reached")
    p.add_argument("--url", default=LIVE_URL,
                   help="the published summary to pin, %(default)s")

    n = sub.add_parser("near-floor",
                       help="roster CNAs sighted but short of the sighting "
                            "floor; the cheapest coverage on the board")
    n.add_argument("--summary", default="",
                   help="a summary.json to read; default is the newest snapshot")
    n.add_argument("--top-only", action="store_true",
                   help="only CNAs that are also a top-50 miss")

    c = sub.add_parser("probe-csaf",
                       help="probe .well-known/csaf for named CNAs; a hit is one "
                            "CSAF_PROVIDERS line, not a new parser")
    c.add_argument("--cnas", default="",
                   help="comma-separated roster short names; default is every "
                        "top-50 CNA the last run could not see")
    c.add_argument("--missed-from", default="",
                   help="a summary.json whose coverage.top_missed_effective "
                        "supplies the list")

    return ap


def main(argv=None):
    args = _build_parser().parse_args(argv)
    if args.cmd == "probe-csaf":
        names = [x for x in args.cnas.split(",") if x.strip()]
        if not names and args.missed_from:
            with open(args.missed_from, encoding="utf-8") as fh:
                names = ((json.load(fh).get("coverage") or {})
                         .get("top_missed_effective") or [])
        if not names:
            raise SystemExit(
                "no CNAs to probe. Pass --cnas, or --missed-from "
                "snapshots/<date>/summary.json so the list is the run's own "
                "top_missed_effective rather than one typed by hand.")
        res = probe_csaf(names)
        write({"probed_at": dt.datetime.now(dt.timezone.utc)
                            .isoformat(timespec="seconds"),
               "results": res},
              os.path.join(LAB, "_csaf_probe.json"))
        hits = [r for r in res if r["status"] == "provider"]
        for r in res:
            detail = "; ".join(f"{h['host']} {h['result']}" for h in r["hosts"])
            print(f"  {r['cna']:<18} {r['status']:<16} {detail or '-'}")
        print(f"\n{len(hits)} of {len(res)} serve CSAF at the well-known path.")
        for h in hits:
            print(f'    "{h["provider"]["url"]}",  # {h["cna"]}'
                  f' ({h["provider"]["publisher"]})')
        if hits:
            print("\nEach line above is one CSAF_PROVIDERS entry in rbp/feeds.py. "
                  "None of them is merged until it has a scorecard: "
                  "`python -m rbp.feedlab score csaf` after adding it, against "
                  "the baseline recorded before.")
        return 0

    if args.cmd == "pin-live":
        live = pin_live(args.url)
        write(live, LIVE)
        print(f"pinned {args.url}")
        print(f"  run           {live.get('generated_at')} @ "
              f"{live.get('source_commit')}"
              + ("  (DIRTY TREE)" if live.get("source_dirty") else ""))
        print(f"  feeds         {len(live.get('sources') or [])}: "
              f"{', '.join(live.get('sources') or [])}")
        print(f"  effective     {len(live.get('effective') or [])} roster CNAs "
              f"at floor {MIN_SIGHTINGS} "
              f"(the site publishes {live.get('published_cnas_effective')}, "
              "which applies the corroborating exclusion and this does not)")
        base = load_baseline()
        short = {k: v for k, v in depth_shortfall(base, live).items() if v > 0}
        if short:
            # THE POINT OF THE PIN, printed at the moment it is measurable.
            print(f"  COLDER HERE   this baseline is {sum(short.values()):,} "
                  "rows short of the live run:")
            for k, v in sorted(short.items(), key=lambda kv: -kv[1]):
                print(f"      {k:12} {v:+,} rows")
            print("    Every marginal figure scored against it is an upper "
                  "bound by that much.")
        elif base:
            print("  depth         no feed is colder here than the live run")
        return 0

    if args.cmd == "near-floor":
        return _near_floor_report(args)

    corpus = _corpus(args.index)

    if args.cmd == "baseline":
        from .cli import PROFILES
        years = _years(args.years)
        srcs = [x for x in (args.sources or PROFILES["weekly"]).split(",") if x]
        if args.add and (args.rescore or args.sources):
            raise SystemExit("--add is exclusive with --rescore and --sources: "
                             "one splices a fetch in, the others replace or "
                             "recompute the whole set")
        if args.add:
            base = extend_baseline([x for x in args.add.split(",") if x],
                                   years, corpus)
        elif args.rescore:
            base = rescore_baseline(corpus)
        else:
            base = build_baseline(srcs, years, corpus)
        write(base, BASELINE)
        write(baseline_summary(base), os.path.join(LAB, "_baseline.json"))
        print(f"baseline: {len(base['ids']):,} ids, {len(base['effective'])} "
              f"effective roster CNAs, {base['wall_seconds']}s, "
              f"{base['bytes'] / 1e6:.1f} MB")
        # The corpus half of a sighting, printed because it was invisible: a feed
        # row can only credit a CNA if the corpus holds the record it names, so a
        # baseline is measured against two moving things and used to record one.
        # RULED OUT AS THE GAP, and recorded so nobody re-measures it: refreshing
        # a ten-day-old index on 2026-09-06 moved 3,696 referenced ids into the
        # corpus and changed the effective count by nothing. The 247 against the
        # live run's 263 was the other half, below.
        print(f"  corpus newest {base.get('corpus_newest')}"
              + ("  (re-scored, no fetch)" if args.rescore else ""))
        depth = base.get("csaf_state") or {}
        if depth.get("behind"):
            print(f"  csaf depth    {depth['ids']:,} ids from "
                  f"{depth['providers']} providers, {depth['behind']:,} "
                  f"advisories still unread at "
                  f"{len(depth['providers_behind'])} of them")
        live = load_live()
        short = {k: v for k, v in depth_shortfall(base, live).items() if v > 0}
        if short:
            print(f"  COLDER THAN THE LIVE RUN by {sum(short.values()):,} rows "
                  f"at {', '.join(sorted(short))}. Every marginal figure scored "
                  "against this baseline is an upper bound by that much.")
        elif live:
            print("  depth         no feed is colder here than the live run "
                  f"pinned {live.get('fetched')}")
        else:
            print("  depth         NO PINNED LIVE RUN to compare against. Run "
                  "`python -m rbp.feedlab pin-live`; a baseline nobody has "
                  "compared to the site is a baseline that can be quietly cold.")
        print(f"  working state -> {BASELINE} (gitignored)")
        print(f"  summary       -> {os.path.join(LAB, '_baseline.json')} (committed)")
        if base["failed"]:
            print(f"  {len(base['failed'])} feed(s) FAILED and are not in this "
                  f"baseline: {', '.join(sorted(base['failed']))}")
        return 0

    if args.cmd == "score":
        base = load_baseline()
        if base is None:
            raise SystemExit(
                "no baseline recorded, so 'marginal' has nothing to be marginal "
                "to. Run `python -m rbp.feedlab baseline` first.")
        years = _years(args.years)
        rows, stats = fetch(args.name, years)
        card = scorecard(args.name, years, corpus, base=base, rows=rows, stats=stats)
        card["stability"] = stability(record_fetch(
            args.name, {r["cve_id"] for r in rows if r.get("cve_id")}, years))
        if not args.no_write:
            write(card, os.path.join(LAB, f"{args.name}.json"))
        print(_render(card))
        return 0

    if args.cmd == "audit":
        # THE QUESTION FEEDS.md SECTION 2 ASKS AND NOTHING HAS EVER ANSWERED.
        #
        # "`mozilla` and `arch` are in the profile the gate is measured on. They
        # contribute to coverage and have produced no RBP row." Each merged feed
        # is scored against ALL THE OTHERS, so a feed that only ever repeats what
        # the others already carry scores zero marginal CNAs, and a feed that has
        # never referenced an unpublished id is named as a publication mirror.
        #
        # Offline, from the baseline's per-feed rows. Re-scoring against a
        # changed corpus or a changed floor must not cost twelve more fetches at
        # twelve third parties.
        base = load_baseline()
        if base is None or not base.get("per_feed"):
            raise SystemExit(
                "no baseline with per-feed rows. Run `python -m rbp.feedlab "
                "baseline` first; a baseline recorded before this command "
                "existed stored only the merged id set.")
        assigner, _state, _published = _corpus_maps(corpus)
        roster_index = roster_mod.index(roster_mod.load())
        eligible = eligible_published(corpus, coverage_years())
        per_feed = base["per_feed"]
        # Read once, for fifteen cards. Also the one place a missing pin is worth
        # saying out loud, because every card below will otherwise say it.
        live = load_live()
        if live is None:
            print("  no pinned live profile: these verdicts are marginal to "
                  "this machine's baseline only. `python -m rbp.feedlab "
                  "pin-live`.", file=sys.stderr)
        cards = []
        for name, payload in sorted(per_feed.items()):
            other_ids = sorted({r["cve_id"] for n, p in per_feed.items()
                                if n != name for r in p["rows"]})
            other_sight = sightings_by_cna(other_ids, assigner, roster_index,
                                           eligible)
            others = {"feeds": [n for n in per_feed if n != name],
                      "scored_at": base.get("scored_at"), "ids": other_ids,
                      "sightings": other_sight,
                      "effective": sorted(effective(other_sight)),
                      # The WHOLE baseline's rows, not the leave-one-out set's.
                      # How cold this machine is against the live run is a
                      # property of the machine, and a card that omits it while
                      # omitting one feed would read as though the missing feed
                      # were the gap.
                      "per_feed_rows": {n: len(p["rows"])
                                        for n, p in per_feed.items()}}
            card = scorecard(name, set(base["years"]), corpus, base=others,
                             rows=payload["rows"], stats=payload["stats"],
                             live=live)
            # READ the history, never append to it. See build_baseline: audit
            # replays stored rows, so appending here would manufacture a perfect
            # stability reading out of a single fetch.
            card["stability"] = stability(_read_fetches(name))
            cards.append(card)
            write(card, os.path.join(LAB, f"{name}.json"))
            print(_render(card))
        write({"scored_at": dt.datetime.now(dt.timezone.utc)
                             .isoformat(timespec="seconds"),
               "baseline_scored_at": base.get("scored_at"),
               "note": ("each feed scored against ALL THE OTHERS, so these "
                        "marginal figures do not sum: two feeds that both "
                        "uniquely cover the same CNA each score 0"),
               # HOW COLD THIS MACHINE WAS WHEN THE VERDICTS WERE STRUCK, at the
               # top of the file that carries them. `corroborating_feeds` reads
               # this artefact on every pipeline run, so the one place a stale
               # verdict has consequences is the one place its provenance has to
               # be legible.
               "live": {k: (cards[0].get("live") or {}).get(k)
                        for k in ("pinned", "fetched", "generated_at",
                                  "source_commit", "effective_n", "rows_short",
                                  "ids_short")} if cards else None,
               "feeds": {c["feed"]: {"verdict": c["verdict"],
                                     "cnas_new_effective": c["cnas_new_effective"],
                                     "cnas_new_effective_names":
                                         c["cnas_new_effective_names"],
                                     "combine": c.get("combine"),
                                     "lead_n": c["disclosure"]["lead_n"],
                                     "unpublished_n": c["disclosure"]["unpublished_n"],
                                     "wall_seconds": c["wall_seconds"]}
                         for c in cards}},
              os.path.join(LAB, "_audit.json"))
        by_verdict = {}
        for c in cards:
            by_verdict.setdefault(c["verdict"], []).append(c["feed"])
        for v in ("detecting", "redundant", "corroborating", "unmeasurable",
                  "reject"):
            names = by_verdict.get(v) or []
            print(f"{v:14}{len(names)}: {', '.join(names) or '-'}")
        print("only `corroborating` leaves the coverage numerator: it is the "
              "one verdict that says a feed cannot surface an unpublished id")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
