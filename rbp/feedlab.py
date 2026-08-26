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


# The coverage window, which is WIDER than the feed-gather window. `cli.run`
# gathers {this year, last year} and measures coverage over three years, and the
# gate is the coverage figure, so the scorecard has to use the coverage window or
# its "marginal CNA" is marginal to a different denominator than the gate's.
def coverage_years(today=None):
    y = int((today or dt.date.today().isoformat())[:4])
    return (y - 2, y - 1, y)


def _cve_year(cid):
    try:
        return int(str(cid).split("-")[1])
    except (IndexError, ValueError, AttributeError):
        return None


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
    """detecting | corroborating | unmeasurable | reject, with the reason in words.

    `corroborating` is not a soft rejection. It means the feed may be merged and
    must be excluded from the coverage numerator, because crediting a CNA as
    observable on a feed that cannot surface an unpublished ID is how a launch
    gate clears while the site's actual claim gets weaker.

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
        return "corroborating", ("no marginal CNA, but it does reference "
                                 "unpublished ids, so it can strengthen a row it "
                                 "did not find")
    if not detects:
        return "corroborating", ("it crosses the sighting floor for "
                                 f"{marginal_cnas} new CNA(s) but has never "
                                 "referenced an unpublished id: a publication "
                                 "mirror, excluded from the coverage numerator")
    return "detecting", (f"{marginal_cnas} marginal CNA(s) and "
                         f"{lead['lead_n']} lead / {lead['unpublished_n']} "
                         "unpublished references")


def scorecard(name, years, corpus_df, base=None, rows=None, stats=None):
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
    # Recomputed on the COMBINED sightings, because a CNA at 2 sightings in the
    # baseline and 1 here is a CNA this feed makes observable.
    combined = dict(base_sight)
    for c, n in sight.items():
        combined[c] = combined.get(c, 0) + n
    new_effective = sorted(effective(combined) - base_effective)

    lead = disclosure_lead(rows, published, state)
    verdict, why = classify(len(new_effective), lead)

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
        except Exception as e:  # noqa: BLE001
            # Recorded, not skipped. A baseline missing a feed because it threw
            # is a baseline that makes every later candidate look better than it
            # is, and the whole point of a marginal number is what it is marginal
            # TO.
            failed[name] = str(e)[:160]
            print(f"  [{name}] FAILED: {e}", file=sys.stderr)
            continue
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
        "scored_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "ids": ids,
        "per_feed": per_feed,
        "sightings": sight,
        "effective": sorted(effective(sight)),
        "wall_seconds": round(wall, 1),
        "bytes": sum(f["stats"].get("bytes") or 0 for f in per_feed.values()),
        "health": {k: dict(v["stats"].get("health") or {}) for k, v in per_feed.items()},
    }


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
# stability, which accrues across runs and cannot be faked in one
# --------------------------------------------------------------------------

def record_fetch(name, ids, path=None):
    """Append one fetch's id count, so a later run can compute the swing.

    FEEDS.md asks for "ids on 3 fetches 24h apart". A single invocation cannot
    produce that number, and returning one anyway is how a scorecard field
    becomes decoration. So each run appends, and `stability` reports None until
    there are at least two.
    """
    # Working state, not a scorecard: it is one line per fetch and it
    # accrues, so it belongs beside the baseline rather than in the diff.
    path = path or os.path.join(STATE, f"{name}.fetches.json")
    hist = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            hist = json.load(fh)
    hist.append({"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                 "ids": len(ids)})
    write(hist, path)
    return hist


def stability(hist):
    """Widest swing between recorded fetches, as a fraction of the largest."""
    counts = [h["ids"] for h in (hist or []) if isinstance(h.get("ids"), int)]
    if len(counts) < 2:
        return None
    hi, lo = max(counts), min(counts)
    return {"fetches": len(counts), "min": lo, "max": hi,
            "swing_pct": round(100 * (hi - lo) / hi, 1) if hi else 0.0}


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
            except Exception as e:  # noqa: BLE001
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


def _render(card):
    d = card["disclosure"]
    L = [f"\n{card['feed']}  ({', '.join(str(y) for y in card['years'])})",
         f"  ids                    {card['ids']:,}"
         + (f"  ({card['ids_new']:,} not already seen)"
            if card["ids_new"] is not None else ""),
         f"  cnas reached           {card['cnas_reached']}",
         f"  cnas_new_effective     {card['cnas_new_effective']}"
         f"   <- the number that justifies the merge",
         f"    {', '.join(card['cnas_new_effective_names']) or '(none)'}",
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


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="python -m rbp.feedlab",
        description="Score one candidate feed against the corpus and the merged set.")
    ap.add_argument("--index", default=os.path.join(ROOT, "data", "index"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="record the merged set, once, before scoring")
    b.add_argument("--sources", default="", help="comma-separated; default is the weekly profile")
    b.add_argument("--years", default="2025,2026")

    s = sub.add_parser("score", help="score one candidate against the baseline")
    s.add_argument("name")
    s.add_argument("--years", default="2025,2026")
    s.add_argument("--no-write", action="store_true")

    a = sub.add_parser("audit",
                       help="score every merged feed against all the others, "
                            "offline, from the recorded baseline")
    a.add_argument("--years", default="2025,2026")

    c = sub.add_parser("probe-csaf",
                       help="probe .well-known/csaf for named CNAs; a hit is one "
                            "CSAF_PROVIDERS line, not a new parser")
    c.add_argument("--cnas", default="",
                   help="comma-separated roster short names; default is every "
                        "top-50 CNA the last run could not see")
    c.add_argument("--missed-from", default="",
                   help="a summary.json whose coverage.top_missed_effective "
                        "supplies the list")

    args = ap.parse_args(argv)
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

    corpus = _corpus(args.index)
    years = _years(args.years)

    if args.cmd == "baseline":
        from .cli import PROFILES
        srcs = [x for x in (args.sources or PROFILES["weekly"]).split(",") if x]
        base = build_baseline(srcs, years, corpus)
        write(base, BASELINE)
        write(baseline_summary(base), os.path.join(LAB, "_baseline.json"))
        print(f"baseline: {len(base['ids']):,} ids, {len(base['effective'])} "
              f"effective roster CNAs, {base['wall_seconds']}s, "
              f"{base['bytes'] / 1e6:.1f} MB")
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
        rows, stats = fetch(args.name, years)
        card = scorecard(args.name, years, corpus, base=base, rows=rows, stats=stats)
        card["stability"] = stability(record_fetch(
            args.name, {r["cve_id"] for r in rows if r.get("cve_id")}))
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
        cards = []
        for name, payload in sorted(per_feed.items()):
            other_ids = sorted({r["cve_id"] for n, p in per_feed.items()
                                if n != name for r in p["rows"]})
            other_sight = sightings_by_cna(other_ids, assigner, roster_index,
                                           eligible)
            others = {"feeds": [n for n in per_feed if n != name],
                      "scored_at": base.get("scored_at"), "ids": other_ids,
                      "sightings": other_sight,
                      "effective": sorted(effective(other_sight))}
            card = scorecard(name, set(base["years"]), corpus, base=others,
                             rows=payload["rows"], stats=payload["stats"])
            cards.append(card)
            write(card, os.path.join(LAB, f"{name}.json"))
            print(_render(card))
        write({"scored_at": dt.datetime.now(dt.timezone.utc)
                             .isoformat(timespec="seconds"),
               "baseline_scored_at": base.get("scored_at"),
               "note": ("each feed scored against ALL THE OTHERS, so these "
                        "marginal figures do not sum: two feeds that both "
                        "uniquely cover the same CNA each score 0"),
               "feeds": {c["feed"]: {"verdict": c["verdict"],
                                     "cnas_new_effective": c["cnas_new_effective"],
                                     "cnas_new_effective_names":
                                         c["cnas_new_effective_names"],
                                     "lead_n": c["disclosure"]["lead_n"],
                                     "unpublished_n": c["disclosure"]["unpublished_n"],
                                     "wall_seconds": c["wall_seconds"]}
                         for c in cards}},
              os.path.join(LAB, "_audit.json"))
        detecting = [c["feed"] for c in cards if c["verdict"] == "detecting"]
        corrob = [c["feed"] for c in cards if c["verdict"] == "corroborating"]
        rejected = [c["feed"] for c in cards if c["verdict"] == "reject"]
        print(f"detecting     {len(detecting)}: {', '.join(detecting) or '-'}")
        print(f"corroborating {len(corrob)}: {', '.join(corrob) or '-'}")
        print(f"reject        {len(rejected)}: {', '.join(rejected) or '-'}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
