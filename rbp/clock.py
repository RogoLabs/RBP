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

# Launch epoch. Rows first observed before this date are excluded from the
# reportable set, so the published count starts from launch rather than carrying
# the backlog accumulated while feed coverage was still changing underneath it.
#
# What this does NOT do, and must not be described as doing: it does not make
# those RBPs younger or less real. `days_public` derives from the advisory date,
# so an ID that went public 519 days ago is 519 days old whether or not this site
# counts it. The excluded rows stay in the raw data files and their count is
# disclosed, because a filter that removes the oldest and strongest evidence has
# to be visible rather than quietly applied.
#
# Empty means no epoch, which is the state before launch.
def _validated_epoch(raw):
    """Parse RBP_EPOCH strictly, or refuse to run.

    The comparison in `before_epoch` is lexicographic on ISO strings, which is
    correct only for zero-padded dates. A single missing zero in a hand-typed
    repository variable is silently catastrophic: '2026-12-31' < '2026-8-20' is
    True, so every row classifies as pre-epoch, the site reports 0, and the run
    exits successfully.
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        parsed = dt.date.fromisoformat(raw)
    except ValueError as e:
        raise SystemExit(
            f"RBP_EPOCH={raw!r} is not a valid ISO date (YYYY-MM-DD): {e}. "
            "Refusing to run: an unparseable epoch would silently zero the count."
        ) from e
    if parsed.isoformat() != raw:
        raise SystemExit(
            f"RBP_EPOCH={raw!r} must be zero-padded ISO (got {parsed.isoformat()!r}). "
            "Lexicographic comparison on an unpadded date silently zeroes the count."
        )
    return raw


EPOCH = _validated_epoch(os.environ.get("RBP_EPOCH"))


def before_epoch(row, epoch=None):
    """Did this ID go public before the launch epoch?

    Keyed on the advisory date, NOT on when this site first saw the row. That
    choice matters while feed coverage is still expanding: keying on first-seen
    would let a newly added feed inject hundreds of years-old RBPs straight into
    the headline count, which is the opposite of a stable measurement. Keyed on
    the advisory date, the count means "RBPs that went public since launch and
    are still unpublished", and adding a feed cannot inflate it retroactively.
    """
    epoch = EPOCH if epoch is None else epoch
    if not epoch:
        return False
    when = row.get("public_date") or ""
    return bool(when and when < epoch)


def split_epoch(rows, epoch=None):
    """(counted, excluded) against the launch epoch."""
    epoch = EPOCH if epoch is None else epoch
    if not epoch:
        return list(rows), []
    counted, excluded = [], []
    for r in rows:
        (excluded if before_epoch(r, epoch) else counted).append(r)
    return counted, excluded

# A CNA's OWN publication channel. Presence of the owner's own advisory is what
# turns 4.5.1.6 (SHOULD) into 4.5.1.4 (MUST), because it shows the CNA itself
# disclosed rather than a third party.
#
# Aggregators are deliberately excluded even where they carry the CNA's data.
# OSV re-publishes GHSA, so an OSV row is not evidence that GitHub disclosed;
# only `ghsa` is. Getting this wrong would upgrade a SHOULD to a MUST on a
# mirror, which is the strongest claim the site makes resting on the weakest
# evidence available.
OWNER_FEEDS = {
    "redhat": {"redhat"},
    "microsoft": {"msrc"},
    "mozilla": {"mozilla"},
    # GitHub_M is deliberately ABSENT, and removing it dropped the site's MUST
    # count from 241 to 0.
    #
    # `ghsa` was here on the theory that a GitHub Security Advisory is GitHub's
    # own publication. It is not, or rather it is not only that:
    # api.github.com/advisories carries NO assigner field (verified), and GitHub's
    # database curates advisories for everyone's code, so the presence of a GHSA
    # cannot distinguish "GitHub_M assigned and disclosed this" from "some other
    # CNA's advisory is in GitHub's database". The site's own export proved it in
    # both directions: apple/swift-nio repository advisories arrive through `ghsa`
    # and were scored SHOULD, which is Apple's own channel being read as a third
    # party's.
    #
    # This is exactly the reasoning applied one level down to exclude OSV. Every
    # one of the 241 MUST rows carried `ghsa`, none survived without it, and
    # ~195 were `ghsa` plus its own OSV mirror, so a single unauthenticated feed
    # with an 83-day rolling window was carrying the strongest claim on the site.
    #
    # Restoring it needs BOTH of: feed_ghsa retaining `source_code_location` so
    # a GHSA can be attributed to an org rather than to GitHub-the-database, and
    # a measurable disclosure ordering for the row. The second condition now
    # exists (see disclosure_order), the first does not, so this stays unmet.
}


def _same_name(a, b):
    """CNA short names vary in punctuation across sources (GitHub_M vs GitHub-M)."""
    def norm(s):
        return (s or "").lower().replace("_", "").replace("-", "").replace(" ", "")
    return norm(a) == norm(b)


def disclosure_order(row):
    """Who published first, as three states rather than a boolean.

    Returns "own-first", "third-party-first" or "unmeasurable".

    The previous version defaulted to MUST on every ambiguous shape, verified by
    execution on all four: own feed undated against a dated third party, own feed
    dated against undated co-sources, a same-day tie, and no dates at all. All
    four claimed the CNA disclosed first.

    That mattered because three feeds in the scheduled weekly profile (debian,
    alpine, arch) emit no date at all, so they can never populate the
    third-party side, and the CNA most likely to be tested is the one whose own
    dates are least reliable. The effect was systematic, not marginal: absence of
    evidence was being read as evidence, always in the direction of the stronger
    accusation.

    One rule now. MUST requires either the owner's own feed to be the only
    source, or at least one dated own-feed entry AND at least one dated
    third-party entry with the owner's strictly earlier. A same-day tie does not
    establish who was first, so it abstains. Absence of a date is never evidence
    in either direction.
    """
    own = OWNER_FEEDS.get(row.get("owner"))
    if not own:
        return "unmeasurable"
    sources = {s for s in (row.get("sources") or "").split(",") if s}
    if not (own & sources):
        return "third-party-first"
    others = sources - own
    if not others:
        # The CNA's own channel is the only place this appeared. Nobody else
        # disclosed it, so the CNA did.
        return "own-first"

    dates = row.get("dates") or {}
    mine = sorted(d for s, d in dates.items() if s in own and d)
    theirs = sorted(d for s, d in dates.items() if s in others and d)
    if not mine or not theirs:
        return "unmeasurable"
    if mine[0] < theirs[0]:
        return "own-first"
    if mine[0] > theirs[0]:
        return "third-party-first"
    return "unmeasurable"        # same-day tie establishes nothing


def self_disclosed(row):
    """True only where the ordering is measured AND the owner was first."""
    return disclosure_order(row) == "own-first"


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
        # Self-disclosure is what makes 4.5.1.4 apply. Computed here rather
        # than read off the row: it used to be set inside report._gated(), which
        # runs later in the pipeline AND returns copies, so annotate never saw
        # it and every row in production came out as a SHOULD.
        # Computed ONCE, here. report._gated used to recompute self_disclosed
        # while only annotate derived `rule` from it, so a divergence could
        # publish a row reading self_disclosed true beside rule 4.5.1.6.
        order = disclosure_order(r)
        must = order == "own-first"
        r["disclosure_order"] = order
        r["self_disclosed"] = must
        r["rule"] = RULE_MUST if must else RULE_SHOULD
        r["rule_strength"] = "MUST" if must else "SHOULD"
        # Ownership is ALWAYS inferred for a reserved ID, because the
        # reservation endpoint redacts owning_cna for exactly that population.
        # So a MUST reading rests on inference and must be rendered as a
        # candidate, never as an established breach. The site is required to
        # carry this qualifier wherever it shows rule_strength.
        r["rule_basis"] = "inferred-owner" if r.get("owner") else "unattributed"
        # An unmeasurable ordering is not a candidate MUST downgraded to a
        # SHOULD; it is a row where the site cannot tell which rule applies, and
        # saying so is the honest reading.
        r["rule_certainty"] = "candidate" if order != "unmeasurable" else "unmeasurable"
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

    Valid only where k is genuinely a subset of n, so it is used on the grader's
    correct/graded and nowhere else. It was previously applied to
    outstanding_rbp / published_last_12mo, which are disjoint populations: an RBP
    is by definition not a published record, so that ratio is not a proportion
    and an interval over it means nothing. See per_cna.

    Clamped because it is public and used to raise: wilson_lower(21, 20) gave
    ValueError: math domain error, and k > n was reachable from live data by any
    CNA holding more outstanding RBPs than it published in twelve months, which
    is exactly the profile this site exists to surface.
    """
    if not n:
        return 0.0
    p = min(k / n, 1.0)
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

    def track(self, rows, suppressed=()):
        """Remember when each currently-open RBP was first seen public.

        `suppressed` both stops new entries and REMOVES existing ones. This ledger
        is published at the root of the data branch, so a withheld id sitting in
        `open` keeps it listed after every other artefact has dropped it. Found by
        checking the branch rather than the site after the first live withhold: the
        row was gone from rbp.json, rbp.csv, summary.json, cnas.json and
        precision.json, and still in resolutions.json.

        No CNA name was attached there, so this was never a misattribution. But for
        an embargo the id IS the sensitive fact, which is the whole reason the row
        leaves rather than merely losing its owner.
        """
        # MEMBERSHIP ONLY, never iteration. `suppressed` is usually a
        # suppress.Suppressions, whose committed half holds keyed hashes rather
        # than CVE IDs precisely so it CANNOT be enumerated. Iterating it raised
        # `TypeError: 'Suppressions' object is not iterable` in production while
        # the test passed, because the test handed in a plain set. Test with the
        # type the caller actually passes.
        sup = suppressed if suppressed is not None else ()
        drop = {cid for cid in list(self.state["open"]) if cid in sup}
        for cid in drop:
            del self.state["open"][cid]
        for r in rows:
            cid = r["cve_id"]
            if cid in sup or r.get("suppressed"):
                continue
            if cid not in self.state["open"]:
                self.state["open"][cid] = {
                    "first_public": r.get("public_date"),
                    "owner": r.get("owner"),
                }
        return len(drop)

    def reconcile(self, corpus_df, today=None):
        """Close out every tracked ID that now has a published record."""
        today = today or dt.date.today().isoformat()
        # REJECTED closes a row too, and it is a different outcome. Under rule
        # 4.5.3.5 rejecting an unused or unpublished ID is lawful, it is the
        # likely end state for the oldest rows, and for a defender it is WORSE
        # than an open RBP: the ID stays cited in advisories with no record ever
        # coming. It must never be reported as resolved.
        terminal = corpus_df[corpus_df["state"].isin(["PUBLISHED", "REJECTED"])]
        published = dict(zip(terminal["cve_id"],
                             zip(terminal["assigner"], terminal["date_published"],
                                 terminal["state"])))

        closed = []
        for cid, rec in list(self.state["open"].items()):
            hit = published.get(cid)
            if not hit:
                continue
            assigner, when, state = hit
            days = _days_between(rec.get("first_public"), when or today)
            closed.append({
                "cve_id": cid,
                "state": state,
                # Kept as two fields, never collapsed. The policy's own remedy
                # for an overdue record is for a Root to direct a CNA-LR to
                # publish it and transfer ownership (4.5.1.4, 4.5.1.5), so the
                # assigner on the published record is often NOT the CNA that
                # reserved it. Collapsing them would credit the resolution to
                # the wrong party and score a correct inference as a miss.
                "predicted_owner": rec.get("owner"),
                "published_assigner": assigner,
                "transferred": bool(assigner and rec.get("owner")
                                    and not _same_name(assigner, rec.get("owner"))),
                "owner": assigner or rec.get("owner"),
                "first_public": rec.get("first_public"),
                "published": when or today,
                "days_to_publish": days if state == "PUBLISHED" else None,
                "closed_on": today,
            })
            del self.state["open"][cid]
        self.state["resolved"].extend(closed)
        return closed

    def by_owner(self):
        """Time-to-publish per owner. Keyed on the TRACKED owner, not the
        post-transfer assigner: a row transferred to a CNA-LR under 4.5.1.5
        would otherwise be charged to whoever cleaned it up. Rejections carry no
        publish time and are excluded."""
        out = collections.defaultdict(list)
        for r in self.state["resolved"]:
            if r.get("state") not in (None, "PUBLISHED"):
                continue
            owner = r.get("predicted_owner") or r.get("owner")
            if owner and isinstance(r.get("days_to_publish"), int):
                out[owner].append(r["days_to_publish"])
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
    """Median, kept as an int when the inputs are whole days.

    An even-length day count used to render as "42.0", which reads as a
    precision this measurement does not have. The clock is a floor derived from
    advisory dates, so a fractional day is meaningless.
    """
    if not xs:
        return None
    s = sorted(xs)
    n = len(s)
    mid = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
    return int(mid) if float(mid).is_integer() else round(mid, 1)


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
        out.append({
            "cna": owner,
            "outstanding": n,
            "oldest_days": max(ages) if ages else None,
            "median_days_public": _median(ages),
            "past_expectation": sum(1 for r in group if r.get("past_expectation")),
            "must_rows": sum(1 for r in group if r.get("rule") == RULE_MUST),
            "should_rows": sum(1 for r in group if r.get("rule") == RULE_SHOULD),
            # Raw scale context, so a CNA with thousands of published records is
            # not read the same way as one with fourteen. Deliberately NOT a
            # ratio: outstanding/published_12mo is arithmetically the exact
            # quantity RBP Policy v1.0 attached its withdrawn 5% and 50% sanction
            # triggers to, and publishing it against named CNAs while the v1.0
            # PDF still circulates would hand readers a threshold to apply that
            # the Program has retired. PLAN 2a already forbids a leaderboard, and
            # a rate column is a leaderboard whatever the caption says.
            "published_12mo": denom,
            "resolved_n": len(resolved),
            "median_days_to_publish": _median(resolved),
        })
    # Absolute count, never rate. Ranking by rate would put a five-person CNA
    # above Microsoft, and there is no threshold that would justify it.
    out.sort(key=lambda d: (-d["outstanding"], d["cna"]))
    return out


def summary(rows, cnas, today=None, undated_excluded=0, epoch_excluded=0):
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
        # Rows held back by the launch epoch. Disclosed, never silent.
        "epoch": EPOCH or None,
        "min_age_days": None,   # set by the caller; present so a diff can compare it
        "epoch_excluded": epoch_excluded,
        "oldest_days": max(ages) if ages else None,
        "median_days": _median(ages),
        "named_cnas": len(cnas),
        # The honest breadth signal. "N CNAs with a row named" implies spread;
        # this says how concentrated the naming actually is, which on live data
        # is the opposite of what the count suggests.
        "top_owner_share": _top_share(cnas),
        "must_rows": sum(1 for r in rows if r.get("rule") == RULE_MUST),
        "should_rows": sum(1 for r in rows if r.get("rule") == RULE_SHOULD),
        # The certainty split, published because without it the SHOULD count is
        # read as a measurement. It is not: an unmeasurable ordering falls to
        # SHOULD because SHOULD is the weaker claim, so the bucket mixes "a third
        # party demonstrably disclosed first" with "who disclosed first cannot be
        # seen from here". On live data that is 505 of 506 rows in the second
        # group, and the site was rendering the whole bucket as "a third party
        # disclosed", which is an assertion about third parties it cannot
        # support. Counted from rule_certainty, which annotate() already set
        # correctly; the defect was only ever in the display.
        "unmeasurable_rows": sum(1 for r in rows
                                 if r.get("rule_certainty") == "unmeasurable"),
        "candidate_rows": sum(1 for r in rows
                              if r.get("rule_certainty") == "candidate"),
        "age_buckets": _buckets(ages),
    }


def _top_share(cnas):
    """Fraction of named rows held by the single largest CNA."""
    counts = [c.get("outstanding", 0) for c in (cnas or [])]
    total = sum(counts)
    return round(max(counts, default=0) / total, 4) if total else None


def _buckets(ages):
    """Age bands. The lowest is open-ended downward rather than starting at the
    buffer, because the buffer is configurable: labelling it "7-30d" would
    misdescribe every row if the buffer is ever lowered."""
    b = collections.Counter()
    for d in ages:
        b["<7d" if d < 7 else "7-30d" if d < 30 else "30-90d" if d < 90
          else "90-180d" if d < 180 else "180d+"] += 1
    return dict(b)
