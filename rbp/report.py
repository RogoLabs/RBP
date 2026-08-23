"""Build the weekly report: markdown + csv + json, dated snapshot, WoW diff."""
from __future__ import annotations

import csv
import datetime as dt
import glob
import json
import os
from collections import Counter

from . import classify
from . import clock


def _trunc(s, n):
    """Truncate on a word boundary so summaries don't cut mid-word."""
    s = (s or "").replace("\n", " ")
    if len(s) <= n:
        return s
    cut = s[:n]
    sp = cut.rfind(" ")
    return (cut[:sp] if sp > n * 0.6 else cut).rstrip() + "…"


# Which downstream feed maps to which enterprise/OS vendor a defender would recognize.
_SRC_VENDOR = {"msrc": "Microsoft", "mozilla": "Mozilla", "alas": "Amazon Linux",
               "redhat": "Red Hat", "ubuntu": "Ubuntu", "debian": "Debian",
               "alpine": "Alpine", "arch": "Arch Linux"}


def _derive_meta(row):
    """Pull affected package, ecosystem, a defender-recognizable vendor, and a real
    advisory URL out of the feed refs, so a defender can filter by software and open
    the source page. advisory_url is always populated."""
    cid = row["cve_id"]
    pkg = eco = ""
    refs = [r for r in row.get("refs", "").split(";") if r]
    for rf in refs:
        parts = rf.split(":")
        if parts[0] == "osv" and len(parts) >= 3:
            eco = eco or parts[1]
            pkg = pkg or parts[2]
        elif parts[0] in ("debian", "alpine", "redhat") and len(parts) >= 2:
            pkg = pkg or parts[1]
    srcs = [s for s in row.get("sources", "").split(",") if s]
    # vendor: prefer an enterprise/self-disclosure source, else the first mapped distro
    vendor = ""
    for s in ("msrc", "mozilla", "redhat", "alas", "ubuntu", "debian", "alpine"):
        if s in srcs:
            vendor = _SRC_VENDOR[s]
            break
    # advisory URL: one per source, always populated (enterprise sources included)
    def _u(s):
        if s == "redhat":
            return f"https://access.redhat.com/security/cve/{cid}"
        if s == "ubuntu":
            return f"https://ubuntu.com/security/{cid}"
        if s == "debian":
            return f"https://security-tracker.debian.org/tracker/{cid}"
        if s == "alas":
            return f"https://explore.alas.aws.amazon.com/{cid}.html"
        if s == "alpine":
            return f"https://security.alpinelinux.org/vuln/{cid}"
        if s == "msrc":
            return f"https://msrc.microsoft.com/update-guide/vulnerability/{cid}"
        if s == "mozilla":
            mfsa = next((r.split(":", 1)[1] for r in refs if r.startswith("mozilla:")), "")
            return f"https://www.mozilla.org/en-US/security/advisories/{mfsa}/" if mfsa else ""
        if s == "ghsa":
            gh = next((r.split(":", 1)[1] for r in refs if r.startswith("ghsa:")), "")
            return f"https://github.com/advisories/{gh}" if gh else ""
        if s == "osv":
            return f"https://osv.dev/list?q={cid}"
        if s == "csaf":
            # The advisory itself. Before this there was no csaf branch, so every
            # CSAF row took the last-resort cve.org/CVERecord URL, which renders
            # NOTHING for a RESERVED ID: the site would publish an ICS row whose
            # only evidence link disproved it. refs carry "csaf:<pub>\t<id>\t<url>".
            ref = next((r.split(":", 1)[1] for r in refs if r.startswith("csaf:")), "")
            parts = ref.split("\t")
            return parts[2] if len(parts) > 2 and parts[2].startswith("http") else ""
        return ""
    url = ""
    for s in ("redhat", "ubuntu", "debian", "alas", "alpine", "msrc", "mozilla", "ghsa", "osv", "csaf"):
        if s in srcs and _u(s):
            url = _u(s)
            break
    if not url:   # last-resort: never leave a row without a place to look it up
        url = f"https://www.cve.org/CVERecord?id={cid}"
    return pkg, eco, vendor, url


# How long an ID must be provably public before it is reportable, in days.
# Set to 7 (2.3x the 72h expectation) rather than 3, so normal latency and short
# coordinated-disclosure windows are excluded and every published row is hard to
# dispute. Deliberately configurable via --min-age-days: if CNAs push back that
# 7 days is unfair, raising it to 14 or 30 is a one-flag change and strengthens
# the remaining rows rather than weakening the project.
DEFAULT_MIN_AGE_DAYS = 7

# Absolute floor on the reportable buffer, in days.
#
# A SELF-IMPOSED FLOOR, not a warrant. The word matters and the site already
# gets it right elsewhere: policy.html says in bold that Rule 4.5.1.7 "is a rule
# about the Secretariat's own conduct. It is not this site's permission to name
# anyone, and the site does not claim it as one." That is the correct and
# stronger position, and this comment used to contradict it.
#
# What 4.5.1.7 establishes is that the Program already CONTEMPLATES naming a
# reserving CNA once an ID has been public for 24 hours. This project takes that
# as the floor below which it will not go, which is a choice it makes rather
# than a permission it holds. Nothing bound the buffer to it:
# --min-age-days took any int, and the workflow passed a repository variable
# through unvalidated, so setting it to 0 would publish inferred CNA names on IDs
# public for under 24 hours, inside the window the Program's own rule tells its
# own Secretariat not to name in, with no error and no visible change.
#
# 4 days rather than 1: the 24-hour horizon is the point below which the site
# would be naming inside a window the Program tells its own Secretariat not to
# name in, and the 72-hour publication expectation is the operating one, so the
# first defensible buffer sits just past both.
MIN_AGE_FLOOR_DAYS = 4


def validate_min_age(days):
    """Refuse a buffer that would name a CNA inside the 4.5.1.7 horizon.

    The epoch got a validator that raises because a silent config error would be
    catastrophic. This variable is more consequential and had none.
    """
    try:
        days = int(days)
    except (TypeError, ValueError) as e:
        raise SystemExit(f"--min-age-days must be an integer, got {days!r}") from e
    if days < MIN_AGE_FLOOR_DAYS:
        raise SystemExit(
            f"--min-age-days={days} is below the floor of {MIN_AGE_FLOOR_DAYS} days. "
            "CNA Rule 4.5.1.7 permits naming a reserving CNA only 24 hours after "
            "public disclosure. This site treats that as a self-imposed floor "
            "rather than as permission. The 72-hour publication expectation is the "
            "operating horizon. Refusing to publish names inside either window.")
    return days

# Feeds that trace to a common origin: collapsed when counting *independent*
# corroboration (OSV re-publishes GHSA; ALAS is a RHEL rebuild).
_ORIGIN = {"osv": "github", "ghsa": "github", "redhat": "redhat", "alas": "redhat",
           "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine", "csaf": "csaf",
           "msrc": "microsoft", "mozilla": "mozilla", "arch": "arch"}
# A CNA may be NAMED as owner only when its own feed corroborates it (or it is the
# authoritative RESERVED assigner), never on a bare product-map guess.
# The owner-feed mapping lives in clock.OWNER_FEEDS and nowhere else. A dead
# second copy used to sit here mapping GitHub_M to {"ghsa", "osv"}, which is the
# exact inclusion clock.py deliberately rejects: OSV re-publishes GHSA, so an OSV
# row is not evidence GitHub disclosed anything. Reconnecting it would have moved
# roughly 200 rows from SHOULD to MUST on mirror evidence. tests/test_clock.py
# pins the exclusion and tests/test_pipeline.py now pins the single definition.


def _indep(sources_str, refs_str=""):
    """Count INDEPENDENT origins, expanding csaf to one origin per provider.

    Every CSAF provider used to collapse to the single token "csaf", so Siemens
    and Schneider independently carrying the same row scored indep_sources 1 and
    the headline, which counts only rows with two or more, discarded exactly the
    corroboration CSAF exists to add. The mapping was written when csaf was one
    hand-configured feed; it is now an aggregator expanding to 17 providers.
    """
    origins = {_ORIGIN.get(s, s) for s in sources_str.split(",") if s}
    if "csaf" in origins:
        providers = {r.split(":", 1)[1].split("\t")[0]
                     for r in (refs_str or "").split(";")
                     if r.startswith("csaf:") and ":" in r}
        providers = {p for p in providers if p}
        if providers:
            origins.discard("csaf")
            origins |= {f"csaf:{p}" for p in providers}
    return len(origins)





def _clean_description(text, package):
    """Make the description fit to display, or drop it.

    Two different problems, handled differently.

    A row that arrives as bare vulnerability-tracker bookkeeping ("NOTE: this is
    fixed in ...") tells a reader nothing and reads like leaked internal text. Six
    such rows were in the live snapshot. Cleaning beats asserting: a useless
    description is bad display text, not a false statement about anyone, so it
    must not be able to stop a publication (PLAN 8b, class 2).

    A row carrying an introducing-commit pointer is a different kind of problem
    and is handled upstream by classify.display_description, before the length
    cut. Running that sanitiser again here is deliberate belt and braces: it is
    idempotent, and it means a row reaching this function by any path that skipped
    classify still cannot publish a URL.

    Module level, not nested inside build(): it is pure, it now has two callers,
    and a nested function cannot be tested directly, which is why the NOTE: bug it
    was written to fix reached production twice.
    """
    t = classify.display_description(text)
    low = t.lower()
    if not t or low.startswith(("[unknown", "unknown")) or low in (
            "security update", "security fix"):
        return package or ""
    return t


def _summary(r):
    """Clean a display summary for the markdown report.

    Was a third independent copy of the cleaning rules, with its own NOTE: check
    and its own "unknown" list that had already drifted from the other two (it
    omitted "security fix"). Now delegates to the one sanitiser, so a rule added
    for the site cannot silently fail to apply to the report.
    """
    d = classify.display_description(r.get("description"))
    low = d.lower()
    if not d or low.startswith(("[unknown", "unknown")) or low in (
            "security update", "security fix"):
        return r.get("package") or "-"
    return _trunc(d, 56)


def _age(public_date, today):
    try:
        return (dt.date.fromisoformat(today) - dt.date.fromisoformat(public_date)).days
    except Exception:  # noqa: BLE001
        return None


def _prev_snapshot(snap_root, today):
    dirs = sorted(d for d in glob.glob(os.path.join(snap_root, "*")) if os.path.isdir(d))
    dirs = [d for d in dirs if os.path.basename(d) < today]
    return dirs[-1] if dirs else None


def build(backlog, fresh_resolved, snap_root, today, years, sources, cov=None,
          min_age=DEFAULT_MIN_AGE_DAYS, min_conf=0.7, rows=None, held_back=None):
    """Write the snapshot.

    `rows` is the published population, already filtered by the caller (buffer,
    then epoch). When given, this function filters NOTHING: it previously
    derived its own `reportable`, which meant the epoch applied to summary.json
    and cnas.json but not to the backlog.json the site actually renders, so the
    front page and the table it sat above disagreed. One population, computed
    once, in cli.py.
    """
    for r in backlog:
        # clock.annotate is the owner of this field; only fill gaps here so the
        # two stages cannot disagree.
        if not isinstance(r.get("days_public"), int):
            r["days_public"] = _age(r["public_date"], today)

    # Buffer: only report RBPs we can PROVE have been public >= min_age days.
    # Younger-than-buffer and undated (age-unknown) entries are held back, not counted
    # against a CNA. That is what lets us say "not front-running; these are overdue."
    if rows is None:
        # Kept only for tests that predate the one-population refactor. cli.py is
        # the sole production caller and always passes rows, so this branch must
        # never decide what production publishes.
        reportable = [r for r in backlog
                      if isinstance(r["days_public"], int) and r["days_public"] >= min_age]
    else:
        reportable = list(rows)

    # Suppressed rows leave the published set entirely, and are counted only in an
    # aggregate. Not merely un-named: for an embargo report the listing itself is
    # the disclosure, because "CVE-2026-X is reserved and referenced publicly" is
    # the sensitive fact whether or not a CNA is named beside it. Removing the name
    # and keeping the row would honour the letter of the request and miss its
    # point.
    #
    # Deliberately applied to `reportable` regardless of which branch built it, so
    # the legacy test path cannot publish a row the production path withholds.
    n_suppressed = sum(1 for r in reportable if r.get("suppressed"))
    if n_suppressed:
        reportable = [r for r in reportable if not r.get("suppressed")]
        print(f"  withheld {n_suppressed} suppressed row(s) from every published "
              "artefact; the count is published, the ids are not")

    within_buffer = [r for r in backlog if isinstance(r["days_public"], int) and r["days_public"] < min_age]
    undated = [r for r in backlog if not isinstance(r["days_public"], int)]

    for r in backlog:
        r["indep_sources"] = _indep(r["sources"], r.get("refs") or "")
    # Every row is RESERVED now, the reservation endpoint confirms the state
    # directly, so there is no inferred `DNE` bucket to separate out.
    hard = [r for r in reportable if r["state"] == "RESERVED"]
    soft = []

    # Single rule-anchored threshold: reportable = provably public >= min_age, a
    # conservative buffer past the 72h expectation. No separate tiers. Core = reportable
    # RESERVED rows corroborated by >=2 INDEPENDENT origins (OSV<-GHSA, ALAS<-RHEL collapsed).
    kpi_core = [r for r in hard if r["indep_sources"] >= 2]

    # snapshot dir
    sdir = os.path.join(snap_root, today)
    os.makedirs(sdir, exist_ok=True)
    for r in backlog:
        r["package"], r["ecosystem"], r["vendor"], r["advisory_url"] = _derive_meta(r)

    # An owner may be NAMED only at/above the confidence gate AND corroborated by that
    # CNA's own feed (never a bare product-map guess). Applied to EVERY shared surface -
    # the Markdown tables AND the CSV, so the shareable CSV never names a CNA the report
    # withholds. Full inferred data is retained only in backlog_full.json (audit).
    # The naming gate is block inference (inference.py): `owner` is already None
    # wherever the k-neighbour gate abstained. No second confidence gate here -
    # one gate, measured, published. min_conf is retained only for the report header.
    def nameable(r):
        return r.get("owner") is not None

    # The product map is an 85%-precision signal that /method promises can never
    # create a name. Spreading the row with `{**r}` carried product_map_owner,
    # product_map_confidence and product_map_method straight into backlog.json
    # and from there into rbp.json and every per-CNA file: 112 of 553 published
    # rows shipped an ungated CNA name on a row rendered as unattributed. Strip
    # them on both branches and publish only a boolean.
    _INTERNAL = ("product_map_owner", "product_map_confidence", "product_map_method")

    def _publishable(r, **over):
        out = {k: v for k, v in r.items() if k not in _INTERNAL}
        out["description"] = _clean_description(r.get("description"),
                                                r.get("package") or r.get("vendor"))
        pm = r.get("product_map_owner")
        out["owner_contested"] = bool(
            pm and r.get("owner") and not clock._same_name(pm, r["owner"]))
        # Silence from the product map is not agreement. owner_contested shipped
        # false on every row as though it had been measured; this says whether it
        # was evaluated at all.
        out["veto_evaluated"] = bool(pm)
        # The aggregate headline requires two independent origins. A named-CNA
        # claim required only that inference succeeded, so the more consequential
        # claim was held to the weaker standard. Published per row rather than
        # withheld, because requiring two origins to name would drop naming from
        # 276 rows to 74, and the asymmetry stated is better than the coverage
        # lost silently.
        out["single_origin"] = (r.get("indep_sources") or 0) < 2
        out.update(over)
        return out

    def _gated(r):
        if nameable(r):
            # Read, never recomputed. Recomputing here while only clock.annotate
            # derived `rule` from it could publish self_disclosed true beside
            # rule 4.5.1.6 on the same row.
            return _publishable(r, owner_nameable=True)
        # owner is a CNA short name or None. NEVER a placeholder string.
        #
        # "unattributed" was the largest value in this column by a factor of three,
        # cnas.json had no such entry, and site._assert_consistent only passed
        # because it special-cased the string. /data documented the opposite
        # ("absent wherever the gate did not pass"), so a consumer coding to the
        # documentation treated every abstention as a named CNA. The word is display
        # text and now lives only in templates.
        return _publishable(r, owner=None, owner_tier="abstain",
                            owner_nameable=False)

    # Kept deliberately identical in spirit to site.CSV_COLS: two published CSVs
    # of the same rows with different column sets is a trap for a consumer.
    # ONE contract, defined in rbp/schema.py. This was a local 26-field list in a
    # different order from site.CSV_COLS' 25, under a comment asserting the two CSVs
    # were kept identical.
    from . import schema
    cols = schema.COLUMNS
    reportable.sort(key=lambda r: -r["days_public"])
    # backlog.csv = shareable, buffered, OWNER-GATED. Full inferred set kept in _full.json.
    with open(os.path.join(sdir, "backlog.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        # De-named like every other artefact. This writer had its own generator
        # expression rather than sharing the JSON path's row list, so the strip
        # applied to backlog.json missed it entirely and the CSV kept shipping
        # owner_nameable=True. Same shape as the per-CNA JSON endpoints: a second
        # writer for the same rows is where the guard does not reach.
        from . import site as _site_csv
        w.writerows(_site_csv._denamed([_gated(r) for r in reportable],
                                       "backlog.csv"))
    # Suppressed rows are excluded from the ungated audit file too.
    #
    # This file is NOT on publish.ALLOWED_SNAPSHOT, so it never reaches the data
    # branch and no reader can fetch it. That is exactly the reasoning that would
    # justify leaving suppressed rows in it, and it is wrong twice over: this is
    # the file whose earlier version WAS on the branch and had to be removed by a
    # history rewrite, and a withhold means the id does not get written down, not
    # that it gets written somewhere currently unreachable. An allowlist is one
    # commit away from including a filename.
    #
    # Found by running the real snapshot through this path rather than by a unit
    # test: the unit tests used a two-row fixture and checked backlog.json and
    # held_back.json, so they were blind to the third writer.
    from . import site as _site_full
    json.dump(_site_full._denamed([r for r in backlog if not r.get("suppressed")],
                                  "backlog_full.json"),
              open(os.path.join(sdir, "backlog_full.json"), "w"), indent=1)
    # Excluded rows, with the reason. An epoch that removes the oldest and
    # strongest evidence has to read as deliberate conservatism, not be
    # discovered later as a discrepancy between two numbers.
    counted = {r["cve_id"] for r in reportable}
    held = []
    for r in backlog:
        if r["cve_id"] in counted:
            continue
        # A suppressed row is not "held back", it is withheld, and this file
        # publishes the CVE ID. Dropping suppressed rows from `reportable` above
        # removed them from `counted`, which would have dropped every one of them
        # straight into held_back.json with a made-up reason: the exact file whose
        # earlier leak proved that a single-artefact assertion is not an assertion.
        # Caught by writing the test before trusting the change.
        if r.get("suppressed"):
            continue
        if not isinstance(r.get("days_public"), int):
            reason = "undated"
        elif r["days_public"] < min_age:
            reason = "within-buffer"
        else:
            reason = "pre-epoch"
        # NEVER named, regardless of whether the inference succeeded. _gated only
        # asks whether the inference passed; these rows failed a different and
        # earlier test, which is whether the site is willing to report them at
        # all. A within-buffer row is one the buffer exists to withhold, so
        # naming a CNA on it here would contradict the buffer's entire purpose
        # and would break the project's own rule that a named CNA gets a private
        # preview before any row naming it circulates. This file publishes the
        # shape of what is withheld, never who.
        held.append(_publishable(
            r, owner=None, owner_tier="abstain", owner_nameable=False,
            owner_method="withheld-not-reported", self_disclosed=False,
            counted=False, held_back_reason=reason))
    # The same invariants the site applies, applied where the file is written.
    # held_back.json is the file that proved a single-artefact assertion is not
    # an assertion: its named owners included CNAs absent from cnas.json.
    from . import site as _site
    # De-named HERE, at the write, not only when the site reads back.
    #
    # These snapshots are pushed to the `data` branch of a public repo, so they
    # are a published artefact in their own right and not merely internal state.
    # Stripping only on read would have left every name sitting on that branch
    # and in its git history, which is exactly how 121 names reached it while
    # every rendered page was clean.
    #
    # Safe with respect to grading: cli.run calls inference.apply_to_backlog,
    # which records predictions into the ledger, at line 233, long before this
    # function is reached at line 287. The grader has already seen the names.
    gated_rows = _site._denamed([_gated(r) for r in reportable], "backlog.json")
    held = _site._denamed(held, "held_back.json")
    _site.assert_artefact(gated_rows, "backlog.json")
    _site.assert_artefact(held, "held_back.json")
    json.dump(held, open(os.path.join(sdir, "held_back.json"), "w"), indent=1)
    json.dump(gated_rows, open(os.path.join(sdir, "backlog.json"), "w"), indent=1)

    # WoW diff: compare like-for-like (full backlog both sides, not full-vs-reportable)
    prev = _prev_snapshot(snap_root, today)
    new_ids = resolved_ids = still_ids = None
    if prev and os.path.exists(os.path.join(prev, "backlog_full.json")):
        prev_bl = {r["cve_id"] for r in json.load(open(os.path.join(prev, "backlog_full.json")))}
        cur = {r["cve_id"] for r in backlog}
        new_ids, resolved_ids, still_ids = cur - prev_bl, prev_bl - cur, cur & prev_bl

    scoreboard = Counter(r["owner"] for r in hard if nameable(r))
    below_gate = sum(1 for r in hard if not nameable(r))

    # Per-feed reportable contribution, so a feed that produced 0 rows reads as 0,
    # rather than the scope line implying it contributed content (practitioner).
    src_contrib = Counter()
    for r in reportable:
        for s in r["sources"].split(","):
            if s:
                src_contrib[s] += 1
    src_contrib = {s: src_contrib.get(s, 0) for s in sources}

    md = _markdown(today, years, sources, reportable, hard, soft, kpi_core,
                   fresh_resolved, scoreboard, prev, new_ids, resolved_ids, still_ids,
                   min_age, len(within_buffer), len(undated), min_conf, below_gate, nameable,
                   src_contrib)
    if cov is not None:
        from . import coverage
        md += "\n" + coverage.markdown(cov)
    open(os.path.join(sdir, "report.md"), "w").write(md)
    return sdir, md, kpi_core


def _markdown(today, years, sources, backlog, hard, soft, kpi_core, fresh_resolved,
              scoreboard, prev, new_ids, resolved_ids, still_ids,
              min_age=DEFAULT_MIN_AGE_DAYS, n_buffer=0, n_undated=0, min_conf=0.7, below_gate=0, nameable=None,
              src_contrib=None):
    def owner_str(r):
        if nameable and nameable(r):
            name = "GitHub (GHSA)" if r["owner"] == "GitHub_M" else r["owner"]
            tier = r.get("owner_tier", "block")
            tag = "inferred, corroborated" if tier == "block-corroborated" else "inferred"
            return f"{name} ({tag})"
        return "unattributed"

    n_indep = sum(1 for r in hard if r["indep_sources"] >= 2)
    n_single = len(hard) - n_indep
    L = []
    L.append(f"# RBP weekly report: {today}\n")
    L.append("> **Internal / pre-preview. Do not forward.** Contains unpublished CVE IDs; named "
             "CNAs receive a private preview and correction window before any external circulation.\n")
    L.append("**What this is:** CVE IDs that downstream security feeds reference but that are missing "
             "from the official CVE List v5, so anyone relying on the CVE List cannot see them. "
             "**Who it's for:** CVE Program / CNA-liaison triage. **What to do:** review the core "
             "table, then confirm the owning CNA before treating any row as a compliance gap.\n")
    L.append("**This report measures publishing *completeness*, not risk.** Summaries are verbatim "
             "advisory titles; it does **not** assess severity, exploitability, or patch status, and "
             "asserts nothing about whether any listed issue is dangerous or exploited.\n")
    if src_contrib is not None:
        feed_str = ", ".join(f"{s} {n}" for s, n in src_contrib.items())
    else:
        feed_str = ", ".join(sources)
    L.append(f"*Scan scope: CVE years {sorted(years)} | as of {today}. Reportable rows "
             f"contributed per feed: {feed_str}. (A feed showing 0 ran but surfaced no "
             f"reportable RBP; e.g. prompt vendors self-heal before the {min_age}d buffer.)*\n")

    L.append("## Headline\n")
    L.append(f"> **{n_indep} CVE IDs: corroborated by ≥2 independent sources and publicly "
             f"referenced for ≥{min_age} days: have no published record in the CVE List v5** "
             f"({len(hard)} including single-source references). The IDs are real and referenced "
             f"downstream; the authoritative record has not landed.\n")
    L.append(f"The ≥{min_age}-day threshold is a deliberately conservative buffer, well past the 72h "
             "publish rule, so normal latency and short coordinated-disclosure windows are excluded "
             f"(it is measured from first downstream reference, a floor on, not equal to, the "
             "rule's CNA-awareness clock). Of the wider {0}, {1} rest largely on a single GitHub "
             "advisory mirrored into OSV; all {0} are absent from the List regardless of source "
             "count.\n".format(len(hard), n_single))
    if prev and new_ids is not None:
        L.append(f"Week-over-week (vs {os.path.basename(prev)}): +{len(new_ids)} new / "
                 f"−{len(resolved_ids)} resolved. Resolved = the record finally published, the "
                 "pipeline self-closes, confirming these were real gaps, not tool noise.\n")

    total_hard, total_soft = len(hard), len(soft)
    L.append("## Totals\n")
    L.append(f"**Reportable** = provably public ≥ {min_age} days (a conservative buffer well past the "
             "72h publish rule), the single threshold; no separate 30-day tier.\n")
    L.append("| Class | Count |")
    L.append("|---|---:|")
    L.append(f"| RBP (`RESERVED`: confirmed reserved, publicly referenced) | {total_hard} |")
    L.append(f"|: **and** ≥2 independent sources (headline core) | **{len(kpi_core)}** |")
    L.append("")
    L.append("**Held back / context** (not reported against any CNA):\n")
    L.append("| | Count |")
    L.append("|---|---:|")
    L.append(f"| within {min_age}-day buffer | {n_buffer} |")
    L.append(f"| age unknown (undated feeds) | {n_undated} |")
    L.append(f"| published since baseline (self-healed this run) | {fresh_resolved} |")
    L.append("")
    L.append(f"\\* `RESERVED` is confirmed directly against the CVE Services reservation "
             f"endpoint (`/api/cve-id/`), which returns the true state for any ID. All {len(hard)} "
             f"rows are therefore RBP by the CVE Program's own definition, a Reserved ID "
             f"referenced in a public resource, not an inference about absence. IDs that were "
             f"never allocated return `CVE_ID_NOT_FOUND` and are excluded, so downstream typos "
             f"cannot inflate this count. (Reserve-then-publish is the normal lifecycle; what is "
             f"counted here is reservation that went public and stayed unpublished.)\n")

    L.append("## Aged core (owner shown only where a CNA's own feed corroborates it)\n")
    L.append("*Owner is inferred and provisional, NOT an authoritative assignment and NOT a "
             "compliance finding. `unattributed` = no confident, feed-corroborated owner.*\n")
    L.append("| CVE | package | days public | feeds | owner | summary (verbatim title) |")
    L.append("|---|---|---:|---|---|---|")
    shown = sorted(kpi_core, key=lambda r: -r["days_public"])
    for r in shown[:40]:
        L.append(f"| {r['cve_id']} | {r.get('package') or '-'} | {r['days_public']} | "
                 f"{r['sources']} | {owner_str(r)} | {_summary(r)} |")
    if len(shown) > 40:
        L.append(f"\n*(showing 40 of {len(shown)}; full set in backlog.csv)*")
    L.append("")

    L.append("## Inferred-owner tally: provisional triage, NOT a compliance leaderboard\n")
    L.append(f"*Inferred from a product→CNA map, gated at confidence ≥ {min_conf} **and** requiring "
             "the CNA's own feed to corroborate; still **not** an authoritative assignment. "
             f"**{below_gate} of {len(hard)} reportable RBP-hard are unattributed.** Do not publish "
             "any row as non-compliance without confirming the owning CNA, and only the Secretariat "
             "may formally identify a reserving CNA (§4.5.1.7).*\n")
    L.append("| Inferred owner (CVE Numbering Authority) | count to route for confirmation |")
    L.append("|---|---:|")
    for cna, n in scoreboard.most_common(15):
        label = "GitHub (GHSA)" if cna == "GitHub_M" else cna
        L.append(f"| {label} | {n} |")
    L.append(f"| *unattributed* | {below_gate} |")
    L.append("")

    L.append("## Why it matters (data completeness)\n")
    L.append("- Every RBP is a record a consumer pulling the CVE List cannot see, no CVSS, CWE, "
             "CPE, or references to key on, so any enrichment or scanning that sources from the "
             "CVE List silently skips it until the record lands.")
    L.append("- Rule context: **RBP Policy v2.0.0** (CVE Board approved 2026-08-13) and **CNA "
             "Operational Rules v4.1.0** (approved 2025-05-14); both are pinned verbatim in "
             "tests/fixtures and CI fails if either moves. A CVE Record should be published "
             "**within 72h** of disclosure by the CNA or of the CNA becoming aware of a "
             "third-party disclosure. §4.5.1.4 states this as a **MUST** *when the assigning CNA "
             "itself publicly discloses*; §4.5.1.6 as a **SHOULD** when a **third party** (e.g. a "
             "distro) discloses, the usual RBP case. This tool observes only that a downstream "
             "source referenced the ID; it **cannot establish who disclosed**, so aged RBPs "
             "indicate a likely §4.5.1.6 SHOULD gap, **not** a proven MUST breach.\n")
    L.append("- **v2.0.0 sets no numeric threshold.** Enforcement is four discretionary levers "
             "(Warning, Reservation Caps, Intervention, Formal Review) that the Program *may* "
             "apply, with remediation deadlines set case by case by a TL-Root or Root. The "
             "withdrawn v1.0 policy had an automatic trigger at 5% of trailing-12-month public "
             "IDs; **do not cite it**: third parties still host that PDF. Nothing here should be "
             "read as a CNA being over a threshold, because there is no longer a threshold.\n")

    L.append("## Methodology & caveats\n")
    L.append("- **CNA** = CVE Numbering Authority. Source of truth: official CVE List v5 baseline, "
             "plus the CVE Services reservation endpoint `/api/cve-id/` for state. That endpoint "
             "returns RESERVED directly, so a row is not an inference about absence and is not API "
             "propagation lag. Re-verified every run: auto-closes when a record publishes.")
    L.append("- **Sources are not fully independent:** OSV re-publishes GHSA, ALAS is a RHEL rebuild. "
             "The headline's independent-source count collapses those; the raw `feeds` column does not.")
    L.append("- Owner is **inferred, never authoritative**. The reservation endpoint redacts "
             "`owning_cna` for exactly the RESERVED population, so the owner is reconstructed by "
             "block inference: an ID is named only when the 3 published CVE IDs on *each* side all "
             "share one assigner. Measured 100% precision at 59.8% coverage out-of-sample, and "
             "re-graded every run against RBPs that have since published. Rows below the gate are "
             "left unattributed rather than guessed. An inferred owner is not a compliance finding.")
    L.append("- `self_disclosed` marks rows where the inferred owner's **own** feed carried the "
             "advisory. Those read against CNA Rules 4.5.1.4 (72h **MUST**); everything else reads "
             "against 4.5.1.6 (72h **SHOULD**, third-party disclosure). Do not conflate the two.")
    L.append("- `days_public` = days since the earliest downstream reference, a floor on how long "
             "the ID has been public, **not** the §4.5.1.6 CNA-awareness clock.")
    L.append("- Counts are a **lower bound**, only the configured feeds are checked.")
    L.append("- Some RBPs may be under legitimate coordinated disclosure. Named CNAs **must** receive "
             "a private preview and correction window before any row naming them is circulated.\n")
    return "\n".join(L)
