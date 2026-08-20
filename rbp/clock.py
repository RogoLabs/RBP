"""
The 72-hour clock, and per-CNA aggregation that carries no verdict.

RBP Policy v2.0.0 (CVE Board approved 2026-08-13) sets one expectation:

    A CVE Record should be published within 72 hours of either (a) disclosure
    by the CNA or (b) the CNA becoming aware of a third-party disclosure.

and aligns itself to two CNA Operational Rules v4.1.0 sections that are NOT
interchangeable:

    4.5.1.4  MUST publish within 72 hours of *the CNA itself* disclosing.
    4.5.1.6  SHOULD publish within 72 hours of becoming aware a *third party*
             disclosed. This is the ordinary distro case.

We cannot observe who disclosed first, so 4.5.1.6 is the default reading and
4.5.1.4 is claimed only where the owning CNA's own feed carried the advisory.
Reporting a SHOULD as a MUST would be the single most damaging error this
project could make, so the distinction is carried on every row rather than
being summarised away.

Two limits on the clock, stated on every surface that shows it:

  * It starts at the earliest downstream advisory we can see, which is a FLOOR
    on how long an ID has been public. The rule's clock starts when the CNA
    became aware, which is unobservable from outside. So a row reads "N days
    public", never "N days overdue".

  * Feeds that publish no date give no clock at all. Those rows are counted and
    disclosed but are never reportable at any buffer.

On aggregation: v2.0.0 removed every numeric threshold that v1.0 had, so there
is nothing for a CNA to be over. Per-CNA output here is descriptive only. It
carries counts, ages and a distribution, plus a normalised rate for scale
context so a CNA with 8,000 published records is not compared naively against
one with fourteen. That rate is this site's own statistic and never a verdict.
Nothing in this module emits a pass, a fail, or a threshold flag.
"""
from __future__ import annotations

import collections
import datetime as dt
import json
import math
import os

EXPECTATION_HOURS = 72

RULE_MUST = "4.5.1.4"      # the CNA itself disclosed
RULE_SHOULD = "4.5.1.6"    # a third party disclosed

# Below this many published records in the trailing 12 months, a rate is noise:
# four RBPs against fourteen published reads as 28.6% and would top any
# leaderboard above Microsoft. Show the raw count instead.
MIN_DENOMINATOR = 20


def annotate(rows, today=None):
    """Add clock and rule fields to each backlog row, in place.

        days_public       floor on days since the earliest advisory we can see
        hours_public      the same, in the rule's unit
        past_expectation  bool, past the 72h expectation
        rule              "4.5.1.4" or "4.5.1.6"
        rule_strength     "MUST" or "SHOULD"
        clock_known       False for rows from undated feeds

    This module owns the clock, so it derives `days_public` itself rather than
    depending on another stage having run first. It previously read a value that
    report.build sets, and since annotate runs earlier in the pipeline every row
    came out undated while the report showed correct ages.
    """
    today = today or dt.date.today().isoformat()
    for r in rows:
        days = r.get("days_public")
        if not isinstance(days, int):
            days = age_days(r.get("public_date"), today)
            r["days_public"] = days
        known = isinstance(days, int)
        r["clock_known"] = known
        r["hours_public"] = days * 24 if known else None
        r["past_expectation"] = bool(known and days * 24 > EXPECTATION_HOURS)
        # Self-disclosure is what makes 4.5.1.4 apply. We can only assert it
        # where the owning CNA's own feed carried the advisory; absent that,
        # the weaker rule is the honest reading.
        must = bool(r.get("self_disclosed"))
        r["rule"] = RULE_MUST if must else RULE_SHOULD
        r["rule_strength"] = "MUST" if must else "SHOULD"
    return rows


def age_days(public_date, today):
    """Days from the earliest advisory we can see to today, or None if the feed
    gave no usable date."""
    try:
        return (dt.date.fromisoformat(today) - dt.date.fromisoformat(public_date)).days
    except Exception:  # noqa: BLE001
        return None


def wilson_lower(k, n, z=1.96):
    """Lower bound of the Wilson score interval for k/n.

    Used instead of the raw proportion wherever CNAs are ordered by rate, so a
    small denominator cannot outrank a large one on noise alone. 2/5 beats
    200/1000 on the point estimate and loses on this.
    """
    if not n:
        return 0.0
    p = k / n
    d = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - margin) / d)


def published_last_12mo(corpus_df, today=None):
    """Published records per CNA in the trailing 12 months, for scale context."""
    today = today or dt.date.today().isoformat()
    cutoff = (dt.date.fromisoformat(today) - dt.timedelta(days=365)).isoformat()
    pub = corpus_df[corpus_df["state"] == "PUBLISHED"]
    counts = collections.Counter()
    for assigner, when in zip(pub["assigner"], pub["date_published"]):
        if assigner and when and when >= cutoff:
            counts[assigner] += 1
    return counts


# --------------------------------------------------------------------------
# resolution ledger: how long RBPs actually take to publish
# --------------------------------------------------------------------------

class ResolutionLedger:
    """Records each RBP that later published, and how long it took.

    Time-to-publish cannot be computed from the corpus alone: the corpus knows
    when a record published, but only a prior snapshot knows when the ID first
    appeared publicly downstream. So this accumulates forward from the first run
    rather than being backfillable, and the distribution is thin until it has
    run for a while. It is reported with its own n so nobody reads a median of
    three as a fact about a CNA.
    """

    def __init__(self, path):
        self.path = path
        self.state = {"open": {}, "resolved": []}
        if os.path.exists(path):
            try:
                loaded = json.load(open(path))
                if isinstance(loaded, dict):
                    self.state.update(loaded)
            except Exception:  # noqa: BLE001
                pass

    def track(self, rows):
        """Remember when each currently-open RBP was first seen public."""
        for r in rows:
            cid = r["cve_id"]
            if cid not in self.state["open"]:
                self.state["open"][cid] = {
                    "first_public": r.get("public_date"),
                    "owner": r.get("owner"),
                }

    def reconcile(self, corpus_df, today=None):
        """Close out every tracked ID that now has a published record."""
        today = today or dt.date.today().isoformat()
        pub = corpus_df[corpus_df["state"] == "PUBLISHED"]
        published = dict(zip(pub["cve_id"], zip(pub["assigner"], pub["date_published"])))

        closed = []
        for cid, rec in list(self.state["open"].items()):
            hit = published.get(cid)
            if not hit:
                continue
            assigner, when = hit
            days = _days_between(rec.get("first_public"), when or today)
            closed.append({
                "cve_id": cid,
                # The assigner is authoritative once published, so a resolved
                # row never relies on inference.
                "owner": assigner or rec.get("owner"),
                "first_public": rec.get("first_public"),
                "published": when or today,
                "days_to_publish": days,
                "closed_on": today,
            })
            del self.state["open"][cid]
        self.state["resolved"].extend(closed)
        return closed

    def by_owner(self):
        out = collections.defaultdict(list)
        for r in self.state["resolved"]:
            if r["owner"] and isinstance(r["days_to_publish"], int):
                out[r["owner"]].append(r["days_to_publish"])
        return out

    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        json.dump(self.state, open(self.path, "w"), indent=1)


def _days_between(a, b):
    try:
        return (dt.date.fromisoformat(b) - dt.date.fromisoformat(a)).days
    except Exception:  # noqa: BLE001
        return None


def _median(xs):
    if not xs:
        return None
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


# --------------------------------------------------------------------------
# per-CNA view
# --------------------------------------------------------------------------

def per_cna(rows, ledger, corpus_df, today=None):
    """Descriptive per-CNA rows. No thresholds, no verdicts, no flags.

    Only rows whose owner passed the inference gate can be attributed, so these
    counts are a floor on a floor: they miss both unattributed RBPs and RBPs in
    feeds we do not read. Ordered by outstanding count, never by rate.
    """
    today = today or dt.date.today().isoformat()
    volume = published_last_12mo(corpus_df, today)
    ttp = ledger.by_owner()

    grouped = collections.defaultdict(list)
    for r in rows:
        if r.get("owner"):
            grouped[r["owner"]].append(r)

    out = []
    for owner, group in grouped.items():
        ages = [r["days_public"] for r in group if isinstance(r.get("days_public"), int)]
        denom = volume.get(owner, 0)
        n = len(group)
        resolved = ttp.get(owner, [])
        rate_shown = denom >= MIN_DENOMINATOR
        out.append({
            "cna": owner,
            "outstanding": n,
            "oldest_days": max(ages) if ages else None,
            "median_days_public": _median(ages),
            "past_expectation": sum(1 for r in group if r.get("past_expectation")),
            "must_rows": sum(1 for r in group if r.get("rule") == RULE_MUST),
            "should_rows": sum(1 for r in group if r.get("rule") == RULE_SHOULD),
            "published_12mo": denom,
            # Scale context only. None below the denominator floor, so a tiny
            # CNA never shows a percentage at all.
            "rate": round(n / denom, 4) if rate_shown else None,
            "rate_wilson_lower": round(wilson_lower(n, denom), 4) if rate_shown else None,
            "rate_suppressed": not rate_shown,
            "resolved_n": len(resolved),
            "median_days_to_publish": _median(resolved),
        })
    # Absolute count, never rate. Ranking by rate would put a five-person CNA
    # above Microsoft, and there is no threshold that would justify it.
    out.sort(key=lambda d: (-d["outstanding"], d["cna"]))
    return out


def summary(rows, cnas, today=None, undated_excluded=0):
    """The numbers the front page leads with.

    `undated_excluded` carries the rows dropped before this point for having no
    usable date. They cannot be aged at any buffer, so they are a permanent
    floor on coverage and belong in the summary rather than being lost when the
    reportable set is filtered.
    """
    today = today or dt.date.today().isoformat()
    dated = [r for r in rows if r.get("clock_known")]
    ages = [r["days_public"] for r in dated]
    return {
        "date": today,
        "expectation_hours": EXPECTATION_HOURS,
        "total": len(rows),
        "past_expectation": sum(1 for r in rows if r.get("past_expectation")),
        "clock_unknown": len(rows) - len(dated),
        "undated_excluded": undated_excluded,
        "oldest_days": max(ages) if ages else None,
        "median_days": _median(ages),
        "named_cnas": len(cnas),
        "must_rows": sum(1 for r in rows if r.get("rule") == RULE_MUST),
        "should_rows": sum(1 for r in rows if r.get("rule") == RULE_SHOULD),
        "age_buckets": _buckets(ages),
    }


def _buckets(ages):
    """Age bands. The lowest is open-ended downward rather than starting at the
    buffer, because the buffer is configurable: labelling it "7-30d" would
    misdescribe every row if the buffer is ever lowered."""
    b = collections.Counter()
    for d in ages:
        b["<7d" if d < 7 else "7-30d" if d < 30 else "30-90d" if d < 90
          else "90-180d" if d < 180 else "180d+"] += 1
    return dict(b)
