"""
The figures behind /slides.html, computed here rather than in the template.

WHY THIS IS A MODULE AND NOT A BLOCK OF JINJA. Every aggregate on the deck is a
sort, a percentile or a group-by over the same rows the site already publishes,
and this project has taken the site down twice by leaving exactly that work in a
template: Jinja's `sort` calls `sorted()` with no key fallback, so one null in a
numeric column raises TypeError inside the Build site step and the deploy that
`needs: build` is skipped. A deck is the least important page on this site and it
renders on the publish path, so it gets the same treatment as the pages that
matter.

WHY THE DECK RECOMPUTES ALMOST NOTHING. `total`, `median_days`, `oldest_days`,
`age_buckets`, `past_expectation` and every coverage figure are read straight off
`summary.json`. The one failure this project keeps meeting is two surfaces from
one run disagreeing about the same number, so the deck is a READER of the
summary wherever the summary already has the figure, and only computes what
genuinely is not there: the per-feed split, the sole-source split, the closure
distribution and the run-over-run series.

THE ONE FIGURE THAT MUST NOT COME FROM THE PUBLISHED FILE. `site.load` caps
`resolutions_published` at the 200 SLOWEST closures, sorted by `days_to_publish`
descending. Read that list as a sample and every statistic off it is biased
upward by construction: on the 2026-09-02 ledger its minimum is 7 days against a
true minimum of 2, and its median is 41 days against a true 34. So `closures()`
takes the WHOLE ledger and says how many rows the published file drops, because
a deck that quotes a truncated median to a room of data consumers is the exact
error this site exists to complain about.
"""
from __future__ import annotations

import json
import os
import statistics


def _pct(n, d):
    return round(100.0 * n / d, 1) if d else None


def _tidy(x):
    """A whole-numbered median as an int.

    `statistics.median` returns a float whenever the sample is even, so a median
    of exactly 41 days rendered as "41.0" beside a median of 34 that rendered as
    "34". Two figures the slide invites the reader to compare should not be
    formatted differently by an accident of sample parity. A genuinely fractional
    median, like the site's own 60.5, keeps its half.
    """
    return int(x) if isinstance(x, float) and x.is_integer() else x


def feed_split(rows, requested=()):
    """Rows by the feed that evidenced them, and rows evidenced by one feed only.

    A row carries every feed that referenced the ID, so the first list overlaps
    and does not sum to the total. The second does not overlap and is the figure
    a consumer actually needs: it is the count of rows that disappear entirely if
    you are not reading that one source.

    TWO FEED COUNTS, AND THEY ARE NOT THE SAME NUMBER. `configured` is how many
    feeds the run asked for; `evidencing` is how many of them put a row in the
    published set. On the 2026-09-02 run those were 14 and 12, because two feeds
    answered fully and referenced nothing that was still reserved. The deck says
    "the count is bounded by N feeds" and the honest N there is the CONFIGURED
    one: a feed that found nothing this run is still part of the reach, and
    quoting the smaller number understates the floor's base.
    """
    total = len(rows)
    seen, sole = {}, {}
    for r in rows:
        names = [s for s in (r.get("sources") or "").split(",") if s]
        for s in names:
            seen[s] = seen.get(s, 0) + 1
        if len(names) == 1:
            sole[names[0]] = sole.get(names[0], 0) + 1
    by_feed = sorted(({"feed": k, "rows": v, "pct": _pct(v, total),
                       "sole": sole.get(k, 0)} for k, v in seen.items()),
                     key=lambda d: -d["rows"])
    # Sorted descending so the template never has to, and keyed on a name that
    # cannot be null, so there is no sentinel to get wrong.
    return {
        "by_feed": by_feed,
        # Sorted on the sole count rather than reusing `by_feed`'s order, which is
        # total rows and put a 63-row sole source below two 1-row ones.
        "sole_list": sorted(({"feed": k, "sole": v,
                              "pct": _pct(v, sum(sole.values()))}
                             for k, v in sole.items()),
                            key=lambda d: -d["sole"]),
        "total": total,
        "sole_total": sum(sole.values()),
        "sole_pct": _pct(sum(sole.values()), total),
        "configured": len(requested) or len(seen),
        "evidencing": len(seen),
    }


def clock_basis(rows):
    """How the site dates a row, split by what it is willing to claim.

    `past_expectation` is asserted only where the clock came from a DATED
    ADVISORY. A row sighted in a distribution tracker with no advisory date is
    not claimed as past the 72-hour expectation however old it is, and on the
    2026-09-02 run 79 rows sat in that bucket with a median age well past two
    years. That refusal is the most quotable thing about the method and it is
    invisible in every published figure, because the summary reports the
    numerator and not the reason.
    """
    out = {"advisory": 0, "tracker": 0, "other": 0, "oldest_unclaimed": 0}
    for r in rows:
        origin = r.get("clock_origin")
        key = origin if origin in ("advisory", "tracker") else "other"
        out[key] += 1
        if not r.get("past_expectation"):
            out["oldest_unclaimed"] = max(out["oldest_unclaimed"],
                                          r.get("days_public") or 0)
    out["unclaimed"] = out["tracker"] + out["other"]
    return out


def closures(resolutions, published_n):
    """The closure distribution, over the WHOLE ledger. See the module docstring.

    `published_n` is the length of the capped list the site actually publishes,
    carried so the deck can state the gap rather than leave a reader to find that
    /data/resolved.json and this slide disagree.
    """
    rows = [r for r in (resolutions or {}).get("resolved", [])
            if r.get("state", "PUBLISHED") == "PUBLISHED"]
    days = sorted(r["days_to_publish"] for r in rows
                  if isinstance(r.get("days_to_publish"), int))
    if not days:
        return {"n": len(rows), "measured": 0, "undated": len(rows),
                "open": len((resolutions or {}).get("open", {})),
                "published_n": published_n, "withheld_by_cap": 0,
                "withheld_measured": 0, "withheld_undated": 0,
                "published_median": None, "buckets": []}
    edges = [(0, 3), (3, 7), (7, 14), (14, 30), (30, 60), (60, 90), (90, None)]
    buckets = []
    for lo, hi in edges:
        n = sum(1 for d in days if d >= lo and (hi is None or d < hi))
        buckets.append({
            "label": f"{lo}-{hi}d" if hi else f"{lo}d+",
            "n": n, "pct": _pct(n, len(days)),
            # The first bucket is the one the expectation is written against, so
            # it is marked rather than left for a reader to count edges.
            "within_expectation": hi == 3,
        })
    # WHAT THE CAP ACTUALLY DROPS, split rather than summed.
    #
    # The deck said "capped at the 200 slowest, which drops 29 of the fastest".
    # 29 is right and "of the fastest" is not: on the 2026-09-02 ledger 19 of them
    # are the fastest closures and the other 10 are rows whose duration could not
    # be measured at all, which `site.load`'s sort puts last precisely so they
    # fall off the end. Overstating how many FAST rows the cap eats overstates the
    # bias it introduces, and a reader who downloads the file can count both.
    #
    # Derived from the three totals rather than by re-sorting, so this cannot
    # drift from `site.load`'s ordering by being a second implementation of it.
    # Nulls sort last there, so the cap fills from the measured rows first.
    kept_measured = min(published_n, len(days))
    withheld_measured = len(days) - kept_measured
    withheld_total = max(0, len(rows) - published_n)
    # THE MEDIAN A READER GETS IF THEY RECOMPUTE FROM THE PUBLISHED FILE. Stated
    # beside the true one, because "the cap moves the median" is an assertion and
    # two numbers are a fact the reader can check against the file in front of
    # them. `days` is ascending and the cap keeps the SLOWEST, so the kept set is
    # its tail.
    kept = days[len(days) - kept_measured:] if kept_measured else []
    return {
        "n": len(rows),
        "measured": len(days),
        "undated": len(rows) - len(days),
        "open": len((resolutions or {}).get("open", {})),
        "published_n": published_n,
        "withheld_by_cap": withheld_total,
        "withheld_measured": withheld_measured,
        "withheld_undated": max(0, withheld_total - withheld_measured),
        "published_median": _tidy(statistics.median(kept)) if kept else None,
        "min": days[0],
        "median": _tidy(statistics.median(days)),
        "mean": round(statistics.mean(days), 1),
        "p90": days[int(0.9 * (len(days) - 1))],
        "max": days[-1],
        "buckets": buckets,
    }


def series(snaps, keep=14):
    """One row per dated snapshot: the count, and how many feeds produced it.

    THE FEED COUNT IS NOT DECORATION. The published total went from 522 to 2,044
    across twelve days on this ledger and almost none of that is the world
    changing: five feeds were added over the same twelve days. A count that is
    explicitly a floor moves when the floor moves, so a series of the count with
    no series of the instrument beside it is a chart that argues something the
    data does not support. The deck renders both columns or neither.
    """
    out = []
    for d in list(snaps)[-keep:]:
        p = os.path.join(d, "summary.json")
        try:
            with open(p, encoding="utf-8") as fh:
                s = json.load(fh)
        except (OSError, ValueError):
            # A snapshot with no readable summary is skipped rather than
            # rendered as a zero. A gap in a line is honest; a zero is a claim.
            continue
        total = s.get("total")
        if not isinstance(total, int):
            continue
        out.append({
            "date": os.path.basename(d),
            "total": total,
            "feeds": ((s.get("feeds") or {}).get("attempts")),
            "degraded": bool(s.get("degraded")),
        })
    peak = max((r["total"] for r in out), default=0)
    for r in out:
        r["height"] = round(100.0 * r["total"] / peak, 1) if peak else 0
    return out


def deck(rows, summary, resolutions, snaps, published_n):
    """Everything /slides.html renders that is not already in `summary`."""
    requested = ((summary or {}).get("feeds") or {}).get("requested") or ()
    return {
        "feeds": feed_split(rows, requested),
        "clock": clock_basis(rows),
        "closures": closures(resolutions, published_n),
        "series": series(snaps),
    }
