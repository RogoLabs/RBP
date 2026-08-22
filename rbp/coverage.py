"""
CNA coverage: what slice of the CVE ecosystem do our feeds actually touch?

Authoritative (no inference): for every referenced ID that IS published in the
corpus, we know its real assigner. The set of those assigners = the CNAs our
downstream feeds surface. We rank all CNAs by recent published volume and report
how much of that universe the feeds cover, so the "top X% of CNAs" claim is
grounded in data, not vibes.
"""
from __future__ import annotations


def _year(cid):
    try:
        return int(cid.split("-")[1])
    except (IndexError, ValueError, AttributeError):
        return None


def compute(corpus_df, refs, recent_years=(2024, 2025, 2026), top_n=50,
            sources=(), own_channels=None):
    """Coverage, as three numbers rather than one.

    The single `pct_cnas` figure credited a CNA as covered on ONE sighting of one
    of its CVEs through any feed. Nothing required the site to read that CNA's own
    channel, or any channel that systematically carries its products, which is
    the property the launch gate exists to guarantee. The nine-feed weekly
    profile is distro and OSS package feeds, which never carry ICS or OT
    products, so the gate could clear while zero critical-infrastructure CNAs
    were measurable.

    So: `cnas_sighted` is the old number, honestly relabelled.
    `cnas_own_channel` counts CNAs whose own advisory feed was actually ingested
    this run, which is the strict figure the gate should use.
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

    # "attributable volume" = full output of any touched CNA, an UPPER BOUND (one
    # sighting credits the CNA's whole volume). Report it as such, alongside the
    # honest OBSERVED coverage (distinct published CVEs actually surfaced / total).
    covered_vol = int(vol[[c for c in covered if c in vol.index]].sum())
    top = list(vol.head(top_n).index)
    top_covered = [c for c in top if c in covered]

    # Strict figure: the CNA's own advisory channel was ingested this run.
    own_channels = own_channels or {}
    requested = set(sources or ())
    own_ingested = sorted(cna for cna, feeds in own_channels.items()
                          if feeds & requested)

    return {
        "total_cnas": total_cnas,
        "covered_cnas": len(covered),
        "pct_cnas": round(100 * len(covered) / max(total_cnas, 1), 1),
        # Three separate integers, so a percentage is never trended over a
        # denominator that moved. The window is derived from the run date, so
        # both sides of the ratio shift overnight on 1 January.
        "cnas_sighted": len(covered),
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
        "pct_volume_attributable": round(100 * covered_vol / max(total_vol, 1), 1),
        "observed_pct": round(100 * len(surfaced_ids) / max(total_vol, 1), 2),
        "observed_ids": len(surfaced_ids),
        "total_pub": total_vol,
        "top_n": top_n,
        "top_covered": len(top_covered),
        "top_missed": [c for c in top if c not in covered][:15],
        "recent_years": list(recent_years),
    }


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
