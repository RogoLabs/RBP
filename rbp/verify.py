"""Does the artefact we are about to serve actually hold up?

WHY THIS EXISTS, and it is not a hypothetical. On 2026-08-29 and 2026-08-30 this
project shipped three separate regressions to the live site, each one a variant
of "state that claims to know something it does not":

  1. the CSAF read cursor cached the read POSITION and not the RESULT, so a
     caught-up provider returned nothing and its rows left the site;
  2. adding `refs` changed the state's shape without migrating it, so restored
     marks said "caught up" beside a `refs` that did not exist;
  3. the migration guard asked whether `refs` existed, and the damaged run had
     already SAVED a `refs` that existed and was nearly empty.

The offline suite passed on all three. Every one was obvious in the published
artefact within seconds. Two of them ran on the live site with CISA showing 3
rows instead of 13 while cisagov/CSAF#466 was open and linking to those rows.

THE GAP WAS NOT DETECTION. `feeds.compare_magnitudes` fired on the first one and
printed "DEGRADED: a feed returned far fewer ids than last run". Nothing acted on
it: no step failed, the site published, and by the next run the shrunken value
was the baseline the guard compared against, so it went quiet. A guard whose
finding reaches only stdout is a guard nobody is reading.

So this module asserts INVARIANTS on the built artefact and exits non-zero. It
publishes nothing and blocks nothing: the deploy step that runs it sits AFTER the
upload, on the same reasoning the launch gate uses, "fail LOUD, separately from
the publication", because failing dark on the publication itself is worse than
serving a bad count with a red build beside it.

WHAT IT DELIBERATELY DOES NOT ASSERT: today's numbers. An earlier version of this
check, written by hand, asserted `== 67` days on one CVE and `== 5` publishers and
`== 8` CISA rows. All three produced false alarms within a day, twice because the
site had IMPROVED. Counts that only grow get floors; anything derived from a date
is computed, never written down. That lesson cost three false alarms before it
stuck, and it is the same one NEXT.md records about documents.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

# How far the published row count may fall between two runs before it is a
# finding rather than weather.
#
# Rows leave the list legitimately: a CNA publishes the record and the row
# resolves, which is the outcome this site exists to encourage. Across the runs
# of 2026-08-27 to 08-30 that churn was single-digit percentages. The three
# regressions above were 30%, 84% and 84%.
#
# 25% sits above the churn and below every real failure observed. It is a floor
# on ALARM, not on truth: a legitimate mass publication would trip it, and the
# right response to that is to read the diff, not to widen the threshold.
MAX_ROW_DROP = 0.25

# ... and a ratio alone is not enough on a small source.
#
# THE FIRST REAL RUN OF THIS CHECK FAILED THE BUILD ON NOISE, which is the way a
# guard earns the reputation that gets it ignored. It reported
# `csaf.data.security.nozominetworks.com` at 62 -> 35 and `psirt.kunbus.com` at
# 26 -> 15: 44% and 42%, and 27 and 11 ids. The site was correct.
#
# Two causes, both worth stating. These are small providers where tens of ids is
# ordinary movement. And `rows` for a provider CHANGED MEANING in the commit
# before this one, from "CVE rows fetched this run", which double-counts an id
# appearing in several advisories, to "distinct ids this provider knows".
# Comparing a high-water mark straight across a semantic change is unsound for
# exactly one transition, and this was it.
#
# So a proportional drop is a finding only when the absolute loss is also
# material. A source going to ZERO stays a finding at any size, because that is
# how all three of the regressions this module exists for presented.
#
# 100 from the data: the regressions lost 21,510 ids and two went to zero
# outright; the false positives lost 27 and 11.
MIN_ABSOLUTE_LOSS = 100

# A feed that contributed rows and now contributes none.
#
# Separate from the row-count check because it is the sharper signal: the whole
# list can look healthy while one source silently stops. All three regressions
# showed here first, as providers reporting "0 ids in scope" beside marks that
# said they were caught up.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# THE STATUSES THAT EXPLAIN A SHORTFALL, and the one that does not.
#
# The shortfall check below has always said, in its own comment, "without failing
# or truncating". It never read a status, so it did not mean it: on 2026-08-31
# Ubuntu's API returned 503 and 504 at the fifth page on two consecutive runs,
# the feed correctly recorded TRUNCATED with the HTTP error in its detail, and
# this module failed the build anyway. `deploy` is `needs: build`, so the site
# published nothing for either run. One of thirteen feeds having a bad afternoon
# froze the whole site, which is the outcome the comment on the verify step in
# deploy.yml says the ordering was chosen to avoid.
#
# A shortfall the run has already accounted for is not the silent shrink this
# module exists to catch. It is weather, it is disclosed, and the right response
# is to publish it with `degraded: true` beside it rather than to publish
# nothing. What still fails the build is a shortfall with NOTHING behind it,
# because that is the signature of all three 2026-08 regressions: a feed that
# returned almost nothing while reporting itself perfectly healthy.
#
# CAPPED IS DELIBERATELY NOT HERE. A configured page cap fires on every single
# run by design -- ubuntu's and ghsa's both do -- so the high-water mark this
# check compares against was itself recorded with the cap firing. Letting a cap
# excuse a shortfall would excuse every shortfall on those two feeds forever.
# `cli.degraded_state` draws the same line for the same reason.
#
# The literals are checked against `feeds.OK` and friends in tests/test_verify.py
# rather than imported: this module is a deploy step and imports nothing that
# opens a socket.
EXPLAINS_A_SHORTFALL = ("failed", "truncated")


def _rows(site_dir):
    """The rows as published, read from the artefact rather than from memory."""
    p = os.path.join(site_dir, "data", "rbp.json")
    with open(p, encoding="utf-8") as fh:
        d = json.load(fh)
    return d.get("rows", d) if isinstance(d, dict) else d


def _summary(snap_dir):
    with open(os.path.join(snap_dir, "summary.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _feed_rows(summary):
    """{feed or provider: ids returned}, parts flattened alongside parents."""
    out = {}
    for name, h in ((summary.get("feeds") or {}).get("detail") or {}).items():
        if isinstance(h, dict):
            out[name] = h.get("rows")
            for child, c in (h.get("parts") or {}).items():
                if isinstance(c, dict):
                    out[f"{name}:{child}"] = c.get("rows")
    return out


def _feed_status(summary):
    """{feed or provider: (status, detail)}, flattened the same way as _feed_rows.

    A provider INHERITS its parent's status when it records none of its own. A
    csaf provider that returned nothing because the csaf fetch as a whole failed
    is explained by that failure, and asking only the child would call it a
    silent shrink.
    """
    out = {}
    for name, h in ((summary.get("feeds") or {}).get("detail") or {}).items():
        if not isinstance(h, dict):
            continue
        parent = (h.get("status"), h.get("detail"))
        out[name] = parent
        for child, c in (h.get("parts") or {}).items():
            if isinstance(c, dict):
                out[f"{name}:{child}"] = (c.get("status") or parent[0],
                                          c.get("detail") or parent[1])
    return out


def _artefact(site_dir):
    """The published rbp.json as a dict, or {} if it is a bare list of rows."""
    p = os.path.join(site_dir, "data", "rbp.json")
    with open(p, encoding="utf-8") as fh:
        d = json.load(fh)
    return d if isinstance(d, dict) else {}


def check(site_dir, snapshots_dir=None):
    """The findings that should FAIL THE BUILD. Empty means clean.

    Kept as the narrow question because it is the one the exit code answers.
    `review()` is the same pass with the disclosed shortfalls returned as well.
    """
    return review(site_dir, snapshots_dir)[0]


def review(site_dir, snapshots_dir=None):
    """`(problems, notes)`.

    `problems` fail the build. `notes` are shortfalls this run has already
    accounted for: real, worth printing, and not a reason to publish nothing.
    See EXPLAINS_A_SHORTFALL.
    """
    problems, notes = [], []
    rows = _rows(site_dir)

    # 1. IT PUBLISHED SOMETHING. A zero-row artefact is a legitimate state only
    #    immediately after an epoch reset, which this site is not doing.
    if not rows:
        return ["the published artefact holds no rows at all"], notes

    # 2. EVERY ROW'S EVIDENCE OPENS. `cve.org/CVERecord` renders NOTHING for a
    #    reserved id, so a row whose only link points there disproves itself.
    #    Asserted as a RATIO that must not get worse rather than as zero: 63 of
    #    1,870 rows are samsung-only and have no per-id page today, which is a
    #    known gap with its own review item. This catches the gap SPREADING.
    # `advisory_url` is gone with D1; `source_urls` is the evidence now, and a
    # row with none of it is a row a reader cannot check. That is the property
    # this was really asserting: the cve.org fallback was only ever the SHAPE
    # the absence took.
    dead = [r for r in rows if not (r.get("source_urls") or {})]
    # A RATIO WITH A SMALL FLOOR. Absolute counts do not travel: an artefact of
    # 50 rows and one of 50,000 need the same rule. The floor only keeps a
    # three-row test fixture from tripping it.
    if len(dead) > 10 and len(dead) > len(rows) * 0.10:
        problems.append(
            f"{len(dead)} of {len(rows)} rows carry no advisory link at all, so "
            "a reader cannot check them")

    # 3. IDS LOOK LIKE IDS.
    malformed = [r.get("cve_id") for r in rows if not _CVE_RE.match(r.get("cve_id") or "")]
    if malformed:
        problems.append(f"{len(malformed)} malformed CVE ids, first {malformed[0]!r}")

    if not snapshots_dir:
        return problems, notes

    snaps = sorted(d for d in glob.glob(os.path.join(snapshots_dir, "*"))
                   if os.path.isdir(d) and os.path.exists(os.path.join(d, "summary.json")))
    if len(snaps) < 2:
        return problems, notes

    now, prev = _summary(snaps[-1]), _summary(snaps[-2])

    # 4. THE COUNT DID NOT COLLAPSE. Compared against the previous PUBLISHED
    #    artefact, which is the number a reader saw last.
    was = (prev.get("summary") or prev).get("total") or prev.get("total")
    is_ = (now.get("summary") or now).get("total") or now.get("total")
    if isinstance(was, int) and isinstance(is_, int) and was > 0:
        if is_ < was * (1 - MAX_ROW_DROP):
            problems.append(
                f"the published count fell {was:,} -> {is_:,} "
                f"({round(100 * (was - is_) / was)}%), past the "
                f"{round(MAX_ROW_DROP * 100)}% alarm threshold")

    # 5. NO SOURCE WENT DARK. A feed or provider that returned ids last run and
    #    returns none now, without failing or truncating, is the silent-shrink
    #    signature and is exactly how all three 2026-08 regressions presented.
    #
    #    Against the PREVIOUS RUN and against the BEST run recorded, because a
    #    shrink that persists becomes its own baseline and the previous-run
    #    comparison goes quiet on the second occurrence. That is not theoretical:
    #    it is why the second of the three regressions produced no warning at all.
    now_f = _feed_rows(now)
    # Seeded empty on purpose: the loop below covers every snapshot except the
    # current one, which includes the previous. Seeding it with the previous run
    # as well was dead code, and a mutation that emptied the seed changed
    # nothing, which is how it was found.
    best = {}
    for snap in snaps[:-1]:
        try:
            for k, v in _feed_rows(_summary(snap)).items():
                if isinstance(v, int) and v > (best.get(k) or 0):
                    best[k] = v
        except (OSError, ValueError):
            continue
    now_status = _feed_status(now)
    accounted = []
    for name, high in sorted(best.items()):
        cur = now_f.get(name)
        if not isinstance(high, int) or high <= 0:
            continue
        if cur == 0:
            finding = (f"{name} returned {high:,} ids at its best and 0 now; a source "
                       "that goes dark takes every row it alone evidenced with it")
        elif (isinstance(cur, int) and cur < high * (1 - MAX_ROW_DROP)
              and high - cur >= MIN_ABSOLUTE_LOSS):
            finding = (f"{name} returned {high:,} ids at its best and {cur:,} now "
                       f"({round(100 * (high - cur) / high)}% down)")
        else:
            continue
        # DID THE RUN ALREADY SAY WHY? A shortfall behind a recorded failure or
        # truncation is weather the run has accounted for; one behind a status of
        # `ok` is the silent shrink, and that still fails.
        status, why = now_status.get(name) or (None, None)
        if status in EXPLAINS_A_SHORTFALL:
            accounted.append(name)
            notes.append(f"{finding} -- {status}: {why or 'no detail recorded'}")
        else:
            problems.append(finding)

    # ...AND THE ARTEFACT HAS TO SAY SO. This is the half that replaces the build
    # failure, and without it the change would be a straight loss: a shortfall
    # would publish with nothing on the site or in the JSON to mark the run as
    # worse than usual, which is precisely the state `degraded` exists to name.
    #
    # `cli.degraded_state` already sets it from the same failed/truncated lists,
    # so this asserts the two agree rather than recomputing the verdict. If they
    # ever stop agreeing, the artefact is the one that is wrong.
    if accounted and not _artefact(site_dir).get("degraded"):
        problems.append(
            f"{len(accounted)} source(s) fell short behind a recorded failure "
            f"({', '.join(sorted(accounted))}) and the artefact still publishes "
            "degraded=false, so a reader is given a short count with nothing "
            "saying the run was worse than usual")
    return problems, notes


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Assert invariants on the built site. Exits non-zero on any "
                    "finding. Publishes nothing and blocks nothing.")
    ap.add_argument("--site", default="site")
    ap.add_argument("--snapshots", default="snapshots")
    args = ap.parse_args(argv)

    problems, notes = review(args.site, args.snapshots)
    # Printed whether or not anything failed: a shortfall the run accounted for
    # is still a shortfall, and the build log is where it is read.
    for n in notes:
        print(f"verify: accounted-for shortfall, published as degraded: {n}")
    if not problems:
        print(f"verify: {len(_rows(args.site)):,} rows, no findings")
        return 0
    print("VERIFY FAILED, the artefact that was just published does not hold up:")
    for p in problems:
        print(f"  - {p}")
    # WHAT ACTUALLY HAPPENS NEXT, which this line used to get wrong. It read "The
    # site is already serving this", on the reasoning that verify runs after the
    # upload. It does, but `deploy` is `needs: build` with no `if:`, so failing
    # here fails the build and the deploy is SKIPPED: Pages keeps serving the
    # previous good artefact and nothing new reaches a reader. An operator who
    # believed this line went looking for bad data on a site that had not
    # changed, and did not know publication had stopped.
    print("\nThe deploy is skipped, so the site keeps serving the previous "
          "artefact and stops getting fresher. Read the diff before the next run.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
