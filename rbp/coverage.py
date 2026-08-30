"""
CNA coverage: what slice of the CVE ecosystem do our feeds actually touch?

Authoritative (no inference): for every referenced ID that IS published in the
corpus, we know its real assigner. The set of those assigners = the CNAs our
downstream feeds surface. We rank all CNAs by recent published volume and report
how much of that universe the feeds cover, so the "top X% of CNAs" claim is
grounded in data, not vibes.
"""
from __future__ import annotations


# A CNA must be sighted at least this many times before this site counts it as
# observable. One incidental reference is not evidence that we read that CNA's
# output, and a gate keyed on a single sighting reopens on any stray row with no
# code change.
#
# DEFINED HERE, not in inference, since 2026-08-26. It is a coverage threshold:
# it decides what `cnas_effective` means, and `cnas_effective` is the launch
# gate. Inference borrowed it to decide whether to NAME a CNA, and while both
# uses exist they must stay the same number, so the publish-path module owns it
# and the off-path one imports it. The dependency used to point the other way,
# which meant coverage, the gate, and feedlab all reached into a module that no
# longer runs.
MIN_SIGHTINGS = 3

# How many years back the site looks, feeds and coverage alike.
#
# ONE DEFINITION, BECAUSE THEY HAD DRIFTED. `cli.run` defaulted the FEED window
# to two years (this year and last) while passing coverage a THREE year window,
# `(cyr - 2, cyr - 1, cyr)`. So the site measured its reach over 2024-2026 and
# read advisories only from 2025-2026: every 2024 CNA counted as covered was
# measured against ids the pipeline could not surface, and the launch gate sat
# on top of that.
#
# The cost of closing it is small and was measured rather than assumed on
# 2026-08-30: debian 18,152 -> 23,470 ids for +1.0s, alas 11,942 -> 16,294 for
# +0.0s. These feeds download in bulk and filter locally, so a wider window is
# more parsing, not more fetching.
#
# What it buys is the oldest evidence the site has. An uncapped sweep of the
# CSAF providers on 2026-08-29 found 422 reserved, publicly referenced ids the
# site did not hold, of which 104 were 2024-numbered and permanently outside the
# feed window, including every one over 700 days: CVE-2024-31884 at 971 days and
# CVE-2024-0234 at 968, against a then-oldest visible row of 572.
#
# Widening further is a judgement about relevance rather than cost. Three years
# is what coverage already claimed, so this makes the site honest about the
# window it was already reporting.
WINDOW_YEARS = 3


def window(today_year):
    """The year window, newest first. One caller in cli.run for both purposes."""
    return tuple(range(today_year - WINDOW_YEARS + 1, today_year + 1))


def _year(cid):
    try:
        return int(cid.split("-")[1])
    except (IndexError, ValueError, AttributeError):
        return None


def compute(corpus_df, refs, recent_years=(2024, 2025, 2026), top_n=50,
            sources=(), own_channels=None, corroborating=()):
    """Coverage, as three numbers rather than one.

    The single `pct_cnas` figure credited a CNA as covered on ONE sighting of one
    of its CVEs through any feed. Nothing required the site to read that CNA's own
    channel, or any channel that systematically carries its products, which is
    the property the launch gate exists to guarantee. The nine-feed weekly
    profile is distro and OSS package feeds, which never carry ICS or OT
    products, so the gate could clear while zero critical-infrastructure CNAs
    were measurable.

    So there are three, and they answer different questions:

        cnas_sighted      any published CVE of that CNA was seen, even once.
                          The old number, honestly relabelled. Weak: one stray
                          reference credits the CNA.
        cnas_effective    at least MIN_SIGHTINGS of its CVEs were seen, the same
                          floor at which inference is willing to NAME the CNA.
                          This is the gate figure.
        cnas_own_channel  that CNA's own advisory feed was ingested. Bounds what
                          can ever be read as 4.5.1.4, and nothing else.

    The gate was briefly built on own_channel, on the reasoning that it is the
    strict figure. It is strict, but it is also bounded by the number of
    hand-written owner-feed parsers, which is three, so a 50% gate on it had a
    ceiling of 0.7% and could never clear: a launch would have failed the gate
    check forever, and nothing measured that it could not be reached. The
    sighting floor is the honest reading of "we can see this CNA", it is the
    threshold the site already trusts enough to publish a name against, and it
    moves as feeds are added, which is the whole point of a gate.
    """
    pub = corpus_df[corpus_df["state"] == "PUBLISHED"].copy()
    pub = pub[pub["cve_id"].map(lambda c: _year(c) in recent_years)]
    vol = pub["assigner"].value_counts()
    total_vol = int(vol.sum())
    # value_counts() never emits a zero, so the old `(vol > 0).sum()` filter was
    # a no-op dressed as a guard.
    total_cnas = int(vol.size)

    assigner = dict(zip(corpus_df["cve_id"], corpus_df["assigner"]))
    pub_ids = set(pub["cve_id"])
    surfaced_ids = {c for c in refs if c in pub_ids}          # published CVEs we actually saw
    # Sightings per CNA, not a boolean. A single incidental reference used to
    # credit a CNA as covered, so one stray row could re-admit a CNA and any
    # gate built on this would silently reopen with no code change.
    sightings = {}
    for c in surfaced_ids:
        a = assigner.get(c)
        if a:
            sightings[a] = sightings.get(a, 0) + 1
    covered = {a for a in sightings if a}
    covered.discard("")

    # THE CORROBORATING EXCLUSION, ENFORCED. Round 7 H2.
    #
    # feedlab/README.md and FEEDS.md section 2 both say a corroborating feed is
    # "mergeable, and excluded from the coverage numerator ... It can strengthen a
    # row it did not find; it cannot credit a CNA as observable." Nothing read
    # that. The rule was written, tested against twelve scorecards, and enforced
    # by no code, so `mozilla` (verdict `corroborating`, 0 unpublished references
    # ever) contributed 605 sightings to the gate figure like any other feed.
    #
    # A written admissibility rule that no code reads is worse than no rule,
    # because the next scorecard is read as though its verdict has consequences.
    #
    # Applied to `effective` ONLY, not to `sightings`, `covered` or `observed_*`.
    # Those describe what this site actually saw and are honest as they stand;
    # narrowing them would make the site UNDER-report its own reach to satisfy a
    # rule about a different question. The rule is about crediting a CNA as
    # observable, and `cnas_effective` is the number that does that.
    #
    # Measured before enabling, against the 2026-08-27 baseline: excluding
    # `mozilla` moves the effective set from 141 to 141. It costs nothing today,
    # which is the only condition under which it is safe to turn on next to a
    # gate clearing by two.
    corrob = {f for f in (corroborating or ())}
    if corrob:
        gate_sightings = {}
        for c in surfaced_ids:
            if not ((refs.get(c, {}).get("sources") or set()) - corrob):
                continue      # seen only through feeds that cannot detect
            a = assigner.get(c)
            if a:
                gate_sightings[a] = gate_sightings.get(a, 0) + 1
    else:
        gate_sightings = sightings

    # "attributable volume" = full output of any touched CNA, an UPPER BOUND (one
    # sighting credits the CNA's whole volume). Report it as such, alongside the
    # honest OBSERVED coverage (distinct published CVEs actually surfaced / total).
    covered_vol = int(vol[[c for c in covered if c in vol.index]].sum())
    top = list(vol.head(top_n).index)
    top_covered = [c for c in top if c in covered]

    # THE DENOMINATOR IS THE PINNED ROSTER, not this count.
    #
    # `total_cnas` above is distinct assigners with a published CVE in the rolling
    # window. It moves as CNAs publish, shrinks as the window rolls, and steps
    # overnight on 1 January, so a percentage trended over it is weather rather
    # than progress, and the launch gate is a threshold on exactly that
    # percentage.
    #
    # The roster is larger (539 certified CNAs against 434 recent assigners), so
    # measuring honestly LOWERS the coverage figure. The 105 difference is CNAs
    # that published nothing in the window, and a CNA that published nothing is
    # still one whose advisories this site cannot read and which may hold reserved
    # IDs. Excluding them flattered the number.
    from . import roster as roster_mod
    ros = roster_mod.load()
    roster_index = roster_mod.index(ros)
    roster_total = ros["count"]

    # Gate figure: seen often enough that the site would be willing to name it.
    # Deliberately the SAME constant inference uses to decide whether to attach a
    # name, so the gate cannot clear on CNAs the site would refuse to name.
    effective = {a for a, n in gate_sightings.items() if a and n >= MIN_SIGHTINGS}

    # THE GATE FIGURE, from 2026-08-23. Top-N-by-volume measured on the SAME
    # sighting floor as `cnas_effective`, not on a single sighting.
    #
    # `top_covered` above credits a top-50 CNA on one stray reference, which is
    # the weakness this module's own docstring names, so it cannot be what a gate
    # is built on. Measured the difference on the live run before switching:
    # 37 of 50 on one sighting, 31 of 50 on three. The gate uses the 31.
    #
    # Why the gate moved here at all: the old threshold was a share of the whole
    # 539-CNA roster, and only 371 roster CNAs have published 3 CVEs in the
    # window, so no feed set can exceed 68.8% and the 50% figure was never
    # re-derived when the metric changed underneath it. Top-50-by-volume is
    # reachable, it moves as feeds are added, and it asks the question that
    # actually matters: can this site see the CNAs that issue most of the CVEs.
    top_effective = [c for c in top if c in effective]

    # Bounds 4.5.1.4 only: the CNA's own advisory channel was ingested this run.
    own_channels = own_channels or {}
    requested = set(sources or ())
    own_ingested = sorted(cna for cna, feeds in own_channels.items()
                          if feeds & requested)

    # Sighted and effective sets mapped onto roster names, so the numerator and the
    # denominator are drawn from the same list. Matching raw assigner strings
    # against roster short names without normalising undercounts exactly the CNAs
    # whose names carry punctuation (GitHub_M vs GitHub-M).
    def _on_roster(names):
        return {roster_index[roster_mod.normalise(n)] for n in names
                if roster_mod.normalise(n) in roster_index}

    sighted_on_roster = _on_roster(covered)
    effective_on_roster = _on_roster(effective)
    off_roster = sorted({n for n in covered
                         if roster_mod.normalise(n) not in roster_index})

    return {
        # The gate denominator. `total_assigners_in_window` is kept beside it so
        # the two are never confused and neither can be quoted as the other.
        "total_cnas": roster_total,
        "roster_source": ros.get("source"),
        "roster_fetched": ros.get("fetched"),
        "total_assigners_in_window": total_cnas,
        # Assigner strings in the corpus that match no roster entry, published in
        # full because the list is short and truncating it would hide the size of
        # the effect.
        #
        # These are real CNAs whose historical assigner name differs from their
        # current roster short name: `crafter` is `Crafter_CMS`, `facebook` is
        # `Meta`. Normalisation cannot bridge a rename, and adjudicating renames by
        # hand would be a map that is silently wrong the first time an org changes
        # name again. So they are excluded from the numerator, which UNDERSTATES
        # coverage by up to this many CNAs, and the count is published so the
        # understatement is visible rather than assumed away. Undercounting makes
        # the gate harder to clear, which is the safe direction to be wrong in.
        "off_roster": off_roster,
        "off_roster_n": len(off_roster),
        # launch._coverage_condition checks this. The denominator is now a pinned,
        # version-controlled list rather than a figure recounted from the corpus.
        "roster_pinned": True,
        "covered_cnas": len(sighted_on_roster),
        "pct_cnas": round(100 * len(sighted_on_roster) / max(roster_total, 1), 1),
        # Three separate integers, so a percentage is never trended over a
        # denominator that moved. The window is derived from the run date, so
        # both sides of the ratio shift overnight on 1 January.
        "cnas_sighted": len(sighted_on_roster),
        "cnas_effective": len(effective_on_roster),
        "pct_effective": round(100 * len(effective_on_roster) / max(roster_total, 1), 1),
        "min_sightings": MIN_SIGHTINGS,
        # Returned rather than discarded. inference refuses to name a CNA whose
        # advisories this site does not read, which is one sentence that survives
        # a hostile reading. Before this, one published artefact said "we do not
        # read this CNA" while another said "this CNA owns this row".
        "covered": sorted(covered),
        "sightings": sightings,
        "cnas_own_channel": len(own_ingested),
        "own_channel_cnas": own_ingested,
        "window": list(recent_years),
        "sources": sorted(requested),
        # Named, so the exclusion is auditable rather than a quiet subtraction.
        # Empty means the verdicts were unreadable and NOTHING was excluded,
        # which is the permissive direction and has to be visible.
        "corroborating_feeds": sorted(corrob),
        "pct_volume_attributable": round(100 * covered_vol / max(total_vol, 1), 1),
        "observed_pct": round(100 * len(surfaced_ids) / max(total_vol, 1), 2),
        "observed_ids": len(surfaced_ids),
        "total_pub": total_vol,
        "top_n": top_n,
        "top_covered": len(top_covered),
        # The gate numerator. Kept beside `top_covered` rather than replacing it,
        # so the strong figure and the weak one are never quoted as each other.
        "top_covered_effective": len(top_effective),
        "pct_top_effective": round(100 * len(top_effective) / max(top_n, 1), 1),
        "top_missed_effective": [c for c in top if c not in effective][:15],
        "top_missed": [c for c in top if c not in covered][:15],
        # NEAR THE FLOOR: sighted, and short of MIN_SIGHTINGS. Round 7 H3.
        #
        # `top_missed_effective` and `top_missed` are both published and the
        # difference between the two lists IS this set, but nothing said so and
        # nothing ranked it, so the cheapest headroom on the board was visible
        # only to someone who diffed two lists by hand.
        #
        # On 2026-08-27 the eight top-50 misses were not eight of a kind. Three of
        # them, `dell`, `TR-CERT` and `sap`, had exactly ONE sighting against a
        # floor of three: two more each and the gate goes 42 -> 45 of 50. The
        # other five had zero and are a parser apiece at FEEDS.md's rate of two to
        # three CNAs per working day.
        #
        # Published for every roster CNA, not only the top 50, because a CNA one
        # sighting short is the same cheap win wherever it sits, and `short_by`
        # is carried so the list can be read in priority order without recomputing
        # the floor. Whether this is ALLOWED to influence which parser gets
        # written next is a separate question and a live one: FEEDS.md section 4
        # sequences the tail by volume descending on the grounds that volume
        # maximises the chance of finding a real RBP, which is the mission rather
        # than the gate. Measuring it does not decide it.
        "near_floor": _near_floor(sightings, roster_index, roster_mod),
        "recent_years": list(recent_years),
    }


def _near_floor(sightings, roster_index, roster_mod):
    """Roster CNAs sighted at least once and short of MIN_SIGHTINGS.

    Sorted by how close they are first and by name second, so the ordering is
    stable across runs: sightings move, and a list that reshuffles every six
    hours cannot be diffed by whoever is deciding what to write next.
    """
    out = []
    for name, n in sightings.items():
        if not name or n <= 0 or n >= MIN_SIGHTINGS:
            continue
        key = roster_mod.normalise(name)
        if key not in roster_index:
            continue          # off-roster, excluded from the numerator anyway
        out.append({"cna": roster_index[key], "sightings": n,
                    "short_by": MIN_SIGHTINGS - n})
    return sorted(out, key=lambda r: (r["short_by"], r["cna"]))


def markdown(cov):
    # This section measures THIS TOOL's feed reach, not the CVE Program's completeness.
    L = ["\n## Feed reach (how much of the CVE ecosystem this tool observes)\n",
         "*This measures the tool's own coverage via its downstream feeds, NOT the health or "
         "completeness of the CVE Program.*\n",
         f"*Universe: {cov['total_pub']:,} CVEs published by {cov['total_cnas']} CNAs in "
         f"{cov['recent_years']} (a wider window than the RBP scan, to size the CNA landscape).*\n",
         f"- Feeds touch **{cov['covered_cnas']} of {cov['total_cnas']} CNAs "
         f"({cov['pct_cnas']}%)**.",
         f"- **Observed** reach (distinct published CVEs the tool actually surfaced ÷ total): "
         f"**{cov['observed_pct']}%** ({cov['observed_ids']:,} CVEs), the honest floor.",
         f"- Those CNAs account for {cov['pct_volume_attributable']}% of recent CVE volume, an "
         "*upper bound only* (touching a CNA once credits its entire output; bulk reporters dominate). "
         "Not a coverage claim.",
         f"- Of the **top {cov['top_n']} CNAs by volume**, the feeds touch **{cov['top_covered']}**.",
         ""]
    if cov["top_missed"]:
        L.append("High-volume CNAs *not* touched (expansion targets): "
                 + ", ".join(cov["top_missed"]) + "\n")
    return "\n".join(L)
