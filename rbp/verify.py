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

# A feed that contributed rows and now contributes none.
#
# Separate from the row-count check because it is the sharper signal: the whole
# list can look healthy while one source silently stops. All three regressions
# showed here first, as providers reporting "0 ids in scope" beside marks that
# said they were caught up.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


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


def check(site_dir, snapshots_dir=None):
    """Every reason this artefact should raise an alarm. Empty means clean."""
    problems = []
    rows = _rows(site_dir)

    # 1. IT PUBLISHED SOMETHING. A zero-row artefact is a legitimate state only
    #    immediately after an epoch reset, which this site is not doing.
    if not rows:
        return ["the published artefact holds no rows at all"]

    # 2. EVERY ROW'S EVIDENCE OPENS. `cve.org/CVERecord` renders NOTHING for a
    #    reserved id, so a row whose only link points there disproves itself.
    #    Asserted as a RATIO that must not get worse rather than as zero: 63 of
    #    1,870 rows are samsung-only and have no per-id page today, which is a
    #    known gap with its own review item. This catches the gap SPREADING.
    dead = [r for r in rows if "cve.org/CVERecord" in (r.get("advisory_url") or "")]
    # A RATIO WITH A SMALL FLOOR. Absolute counts do not travel: an artefact of
    # 50 rows and one of 50,000 need the same rule. The floor only keeps a
    # three-row test fixture from tripping it.
    if len(dead) > 10 and len(dead) > len(rows) * 0.10:
        problems.append(
            f"{len(dead)} of {len(rows)} rows link only to cve.org, which renders "
            "nothing for a reserved id; the row's own evidence disproves it")

    # 3. IDS LOOK LIKE IDS.
    malformed = [r.get("cve_id") for r in rows if not _CVE_RE.match(r.get("cve_id") or "")]
    if malformed:
        problems.append(f"{len(malformed)} malformed CVE ids, first {malformed[0]!r}")

    if not snapshots_dir:
        return problems

    snaps = sorted(d for d in glob.glob(os.path.join(snapshots_dir, "*"))
                   if os.path.isdir(d) and os.path.exists(os.path.join(d, "summary.json")))
    if len(snaps) < 2:
        return problems

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
    for name, high in sorted(best.items()):
        cur = now_f.get(name)
        if not isinstance(high, int) or high <= 0:
            continue
        if cur == 0:
            problems.append(
                f"{name} returned {high:,} ids at its best and 0 now; a source "
                "that goes dark takes every row it alone evidenced with it")
        elif isinstance(cur, int) and cur < high * (1 - MAX_ROW_DROP):
            problems.append(
                f"{name} returned {high:,} ids at its best and {cur:,} now "
                f"({round(100 * (high - cur) / high)}% down)")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Assert invariants on the built site. Exits non-zero on any "
                    "finding. Publishes nothing and blocks nothing.")
    ap.add_argument("--site", default="site")
    ap.add_argument("--snapshots", default="snapshots")
    args = ap.parse_args(argv)

    problems = check(args.site, args.snapshots)
    if not problems:
        print(f"verify: {len(_rows(args.site)):,} rows, no findings")
        return 0
    print("VERIFY FAILED, the artefact that was just published does not hold up:")
    for p in problems:
        print(f"  - {p}")
    print("\nThe site is already serving this. Read the diff before the next run.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
