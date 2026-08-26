"""
The published data contract, defined once (review item 14).

Three problems this replaces.

**No envelope.** `data/rbp.json` was `json.dump(rows)`: a bare array with no
schema version, no generation time, no epoch, no buffer, no coverage and no floor
flag. Every caveat that makes the count safe to use lived in HTML and in a sibling
file a tool has no reason to fetch. Meanwhile the review queued eight
published-key changes against artefacts with no version field, so any consumer who
integrated in the meantime would have broken silently.

**Three column lists.** `site.CSV_COLS` had 25 fields, `report.build`'s local list
had 26 in a different order, and a code comment asserted the two CSVs were kept
identical. The fields missing from the shareable CSV were the audit fields: the
ones that let a reader check the rule call rather than take it on trust.

**Three absence conventions, none documented.** `""`, `null`, and the magic string
`"unattributed"` in the field that otherwise holds CNA short names. That string was
the largest value in the column by a factor of three, `cnas.json` had no such
entry, and `site._assert_consistent` only passed because it special-cased it. The
`/data` page documented the opposite ("absent wherever the gate did not pass"), so
a consumer coding to the documentation would have treated every abstention as a
named CNA.

So: `owner` is a CNA short name or `null`, never a placeholder. `owner_nameable`
is the marker. The word "unattributed" is display text and lives only in
templates.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess


# BUILD PROVENANCE. Every artefact says which code produced it.
#
# Review item 1, and it is item 1 because nothing else can be verified without
# it. A fifth of the adversarial review's blocker-grade output was spent on
# defects that did not exist, filed against a local build produced by an older
# revision and refuted by four reviewers who fetched origin/data and recomputed.
# The same thing happened during the de-naming: a test compared a freshly changed
# column contract against a site/ directory built by earlier code, and the
# failure looked like a bug in the contract.
#
# The failure mode is not "the artefact is wrong". It is "nobody can tell which
# code the artefact came from", which makes every verdict about the project
# provisional, including the favourable ones.
_UNKNOWN_COMMIT = "unknown"


def source_commit():
    """The commit this build came from, or 'unknown'.

    Order matters. GITHUB_SHA is authoritative in Actions and is present even
    when the checkout is shallow or detached. `git rev-parse` is the local
    fallback. Neither is allowed to raise: a build must not fail because it
    cannot describe itself, it must say so.
    """
    sha = (os.environ.get("GITHUB_SHA") or "").strip()
    if sha:
        return sha[:12]
    try:
        out = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"],
                             capture_output=True, text=True, timeout=10,
                             cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return _UNKNOWN_COMMIT


def source_dirty():
    """True when the working tree differs from the commit above.

    A dirty build is the one that produced the stale-artefact confusion, so the
    artefact says so rather than implying the commit describes it fully. Always
    False under Actions, where the tree is a clean checkout.
    """
    if os.environ.get("GITHUB_SHA"):
        return False
    try:
        out = subprocess.run(["git", "status", "--porcelain"],
                             capture_output=True, text=True, timeout=10,
                             cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return out.returncode == 0 and bool(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return False

# Bump on ANY published key rename, removal, or meaning change. Additive fields
# do not require a bump; a consumer pinning a major version must keep working.
#
# 1: first versioned artefact. Before this there was no version at all, which is
#    why the value starts here rather than at 0: a consumer that finds no
#    schema_version is reading a pre-contract artefact and should refuse it.
# v2, 2026-08-23: the owner columns were removed. A consumer pinned to v1 and
# indexing by position must fail loudly rather than silently read `sources` where
# it expected `owner`, which is the entire reason this constant exists.
SCHEMA_VERSION = 2

# --------------------------------------------------------------------------
# Writing an artefact. One implementation.
# --------------------------------------------------------------------------


def write_json(path, obj, indent=1):
    """Write one JSON artefact and CLOSE IT.

    Every artefact writer in this project was `json.dump(obj, open(p, "w"),
    indent=1)`: thirty of them, across six modules, none closing the handle and
    each repeating the indent. Both halves of that are worth fixing.

    THE HANDLE. It works on CPython, where the refcount drops to zero at the end
    of the statement and the file is flushed and closed there. That is a
    documented implementation detail rather than a language guarantee, and the
    failure mode if it ever stops holding is a truncated JSON artefact on the
    publish path, which is the single failure this project treats as unacceptable:
    a feed shrinking silently has bitten it twice, and a half-written rbp.json is
    the same shape of error with the site's own name on it. It also means the
    suite cannot be run under `-W error::ResourceWarning`.

    THE INDENT. Repeated thirty times, and already inconsistent: the classify
    cache was written with no indent at all while everything beside it used 1.

    Not atomic. A temp-file-and-rename would also protect against a crash
    mid-write leaving a partial file where the next step expects a whole one.
    That is a real improvement and a separate change: it needs the same directory
    for the temp file and a decision about what to do on Windows, and doing it
    here in one function is exactly what makes it a one-line change later.
    """
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=indent)


def write_text(path, text):
    """Write one text artefact and close it. See write_json."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# --------------------------------------------------------------------------
# THE DE-NAMING VOCABULARY. One definition, here, because four disagreed.
# --------------------------------------------------------------------------
#
# v1 publishes no attribution, and enforcing that means every writer and every
# guard has to agree on what "names a CNA" means. Before 2026-08-26 they did not:
#
#   site.NAME_FIELDS             9 row-level fields
#   site._LEDGER_NAMES           9 ledger fields
#   site._PER_CNA_KEYS           4 per-CNA table keys
#   cli._PER_CNA_KEYS            the same 4, a second copy
#   cli._CLOSURE_NAME_FIELDS     5 closure fields
#   publish._LEDGER_NAME_FIELDS  6 ledger fields
#
# Two of those were byte-identical duplicates of each other, and the whole point
# of the list is that "adding a new owner_* field cannot leak by being forgotten
# here". Forgotten in ONE of two copies is the same leak with an extra step.
#
# Defined in schema.py rather than in site.py or publish.py because schema has no
# internal imports, so every module can reach it without a cycle, and because
# what counts as a name is part of the published contract rather than a property
# of whoever happens to be writing the file.
#
# WHY THERE ARE STILL THREE LISTS. They are three different shapes, not three
# opinions about one shape:
#
#   ROW_NAME_FIELDS      fields on a published ROW
#   LEDGER_NAME_FIELDS   fields inside a ledger entry, which records a prediction
#                        and its later verdict, so it has `predicted`/`actual`
#                        where a row has `owner`
#   PER_CNA_KEYS         keys whose VALUES are mappings keyed by CNA. These leak
#                        by KEY rather than by value, so a field-name check
#                        cannot see them: stripping only the first list left
#                        `$.by_cna.GitHub_M` in a published precision.json.

# Fields on a published row that carry or qualify a name. `owner_tier` and
# `owner_method` hold no name of their own ("abstain",
# "block-k3-vetoed-by-product-map"); they are in here anyway, because they are an
# assertion that this site formed a view about who owns the row, and on a row
# published as unattributed that is a statement it has chosen not to make.
ROW_NAME_FIELDS = ("owner", "owner_tier", "owner_method", "owner_contested",
                   "predicted_owner", "product_map_owner",
                   "product_map_confidence", "product_map_method",
                   "owner_is_inferred")

# Fields inside a ledger entry. `actual` and `published_assigner` were missing
# once, and they are the two that carry an AUTHORITATIVE name rather than an
# inferred one, which makes publishing them a stronger claim than anything on a
# page rather than a weaker one.
# `owner_is_inferred` was on the row list and not this one until 2026-08-26, when
# the test below started asserting the owner_* family appears in both. It carries
# no name, being a boolean, and it is stripped for the same reason `owner_tier` is:
# on a row this site publishes as unattributed, recording that it formed a view is
# a statement it has chosen not to make, and a ledger on a public branch publishes
# it just as surely as a page does.
LEDGER_NAME_FIELDS = ("owner", "owner_tier", "owner_method", "owner_contested",
                      "owner_is_inferred", "predicted", "predicted_owner",
                      "actual", "assigner", "published_assigner",
                      "product_map_owner", "product_map_confidence",
                      "product_map_method")

# Keys whose values are per-CNA mappings. Stripped by STRUCTURE, because a
# per-CNA table is keyed by CNA and a mapping keyed by CNA is the thing that must
# not ship, whatever the key is called.
PER_CNA_KEYS = ("by_cna", "by_tier_cna", "largest_stratum", "misses")


# The one column contract. Order is part of it: a consumer indexing by position
# breaks silently on a reorder, so this list is the order and it does not change
# without a version bump.
#
# `refs` and `owner_method` are in here deliberately. They were missing from the
# shareable CSV, and they are the two fields that let a reader check the site's
# work: `owner_method` distinguishes a plausibility-checked name from an unchecked
# one, and `refs` is where the row came from.
COLUMNS = [
    # identity
    "cve_id", "state",
    # the clock
    "days_public", "hours_public", "public_date", "clock_known",
    "past_expectation",
    # the rule call, and its inputs
    "rule", "rule_strength", "rule_certainty", "rule_basis",
    "self_disclosed", "own_feed_date", "earliest_other_date",
    # attribution: ONE field, and it is always False under v1.
    #
    # `owner`, `owner_tier`, `owner_method` and `owner_contested` were here.
    # They are gone rather than emptied, because a column that is present and
    # always null invites a consumer to build against it and wait for it to
    # fill, and because an always-empty `owner` column in a published CSV is a
    # promise the site is not making. `owner_nameable` survives alone so that a
    # consumer has one documented field to branch on, and its documented value
    # is False.
    "owner_nameable", "veto_evaluated",
    # WHICH CLOCK, and how long it has run. See clock._ORIGIN_KIND.
    "clock_origin", "advisory_date", "advisory_days_public",
    # provenance
    "sources", "feed_count", "indep_sources", "single_origin", "refs",
    "advisory_url", "source_urls",
    # what it is
    "vendor", "package", "ecosystem", "description",
    # run integrity
    "state_verified_this_run",
]

# name -> (type, value when absent, meaning)
#
# Published on /data. The point is that "absent" has ONE documented spelling per
# field, so a consumer never has to guess whether "" and null mean the same thing.
FIELDS = {
    "cve_id": ("string", "never absent", "The CVE ID. Always present."),
    "state": ("string", "never absent",
              "Reservation state from the CVE Services endpoint. Always RESERVED "
              "in this file; the field exists so a consumer can assert it."),
    "days_public": ("integer|null", "null",
                    "Days since the earliest advisory this site can see. A FLOOR "
                    "on how long the ID has been public, never a measure of "
                    "lateness. null when no feed supplied a usable date."),
    "hours_public": ("integer|null", "null", "The same quantity in the rule's unit."),
    "public_date": ("date|null", "null", "Earliest advisory date this site saw."),
    "clock_known": ("boolean", "never absent",
                    "false when no feed supplied a date, in which case the row "
                    "cannot be aged at any threshold."),
    "past_expectation": ("boolean", "never absent",
                         "days_public exceeds the 72-hour expectation. Descriptive."),
    "rule": ("string", "never absent",
             "4.5.1.6 (SHOULD, third party disclosed) or 4.5.1.4 (MUST, the CNA "
             "itself disclosed)."),
    "rule_strength": ("string", "never absent", "MUST or SHOULD, matching `rule`."),
    "rule_certainty": ("string", "never absent",
                       "'candidate' where the disclosure ordering was measurable, "
                       "'unmeasurable' where it was not. An unmeasurable row is "
                       "filed under the WEAKER rule by default, so a 4.5.1.6 row "
                       "is not evidence that a third party disclosed first."),
    "rule_basis": ("string", "never absent",
                   "'inferred-owner' or 'unattributed': which of the two the rule "
                   "call rests on."),
    "self_disclosed": ("boolean", "never absent",
                       "The owning CNA's own advisory feed carried it. The only "
                       "route to a 4.5.1.4 reading."),
    "own_feed_date": ("date|null", "null",
                      "Earliest date from the inferred owner's OWN feed. Published "
                      "as a scalar so the rule call is checkable without parsing "
                      "nested JSON."),
    "earliest_other_date": ("date|null", "null",
                            "Earliest date from any other feed. With own_feed_date, "
                            "these two are the entire input to the rule call."),
    "owner_nameable": ("boolean", "never absent",
                       "ALWAYS false in v1: this site publishes no attribution. "
                       "The one field to branch on. `owner`, `owner_tier`, "
                       "`owner_method` and `owner_contested` were removed in "
                       "schema v2 rather than published as permanent nulls."),
    "clock_origin": ("string", "never absent",
                     "'advisory' if any feed that referenced this ID publishes "
                     "actual advisories, otherwise 'tracker'. The 72-hour "
                     "expectation runs from Public Disclosure, and a "
                     "distribution tracker entry is a public source under the "
                     "RBP definition but is NOT a Public Disclosure under "
                     "4.5.1.4 or 4.5.1.6. past_expectation is false on every "
                     "tracker-only row for that reason."),
    "advisory_date": ("date|null", "null",
                      "Earliest date from an advisory feed. null on "
                      "tracker-only rows. This, not public_date, is what may "
                      "start the 72-hour clock."),
    "advisory_days_public": ("integer|null", "null",
                             "Days since advisory_date. null on tracker-only "
                             "rows, where days_public is still reported: "
                             "'referenced for N days' is true of a tracker "
                             "entry, 'N days late' is not."),
    "veto_evaluated": ("boolean", "never absent",
                       "Whether a product-map verdict existed to contest the name "
                       "at all. false means silence, not agreement."),
    "sources": ("string", '""', "Comma-joined feed names that referenced this ID."),
    "source_urls": ("object", "{}",
                    "One advisory URL per feed that referenced this ID, keyed by "
                    "feed name. This is the evidence: each entry is a public page "
                    "naming an ID the CVE List has not published. Empty only for "
                    "feeds that publish no per-ID page. cve.org is never used as a "
                    "fallback, because it renders nothing for a RESERVED ID and a "
                    "link that disproves itself is worse than no link."),
    "feed_count": ("integer", "never absent", "Number of feeds, including mirrors."),
    "indep_sources": ("integer", "never absent",
                      "Number of INDEPENDENT origins, collapsing feeds that share "
                      "one (OSV re-publishes GHSA; ALAS is a RHEL rebuild). This "
                      "is the field to filter on for a defensible subset."),
    "single_origin": ("boolean", "never absent",
                      "true when indep_sources is 1, so the row rests on one "
                      "independent origin. Two thirds of rows are single-origin, "
                      "which is why the site's headline is the corroborated subset "
                      "rather than the total."),
    "refs": ("string", '""',
             "Semicolon-joined per-feed references. Truncated at 250 characters."),
    "advisory_url": ("string", "never absent",
                     "A place to look the ID up. Always populated."),
    "vendor": ("string", '""', "Defender-recognisable vendor, where derivable."),
    "package": ("string", '""', "Affected package, where derivable. Often empty."),
    "ecosystem": ("string", '""', "Package ecosystem, where derivable."),
    "description": ("string", '""',
                    "The upstream advisory's own summary, cut at the first sentence, "
                    "with URLs and tracker annotations removed. Not a title, and not "
                    "analysis by this site. Falls back to the package name where "
                    "nothing usable survived."),
    "state_verified_this_run": ("boolean", "true",
                                "false means the reservation endpoint could not be "
                                "reached for this row and it was carried forward "
                                "from the previous snapshot rather than dropped."),
}


def envelope(rows, summary, *, launched, snapshot_date, kind="backlog"):
    """Wrap a row set with everything a consumer needs to use it safely.

    The caveats are in the payload rather than only in HTML, because a tool has no
    reason to fetch the HTML and every reason to trust what it parsed.
    """
    cov = (summary or {}).get("coverage") or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        # Which code produced this file. See source_commit().
        "source_commit": source_commit(),
        "source_dirty": source_dirty(),
        "generated_at": summary.get("generated_at")
                        or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "snapshot_date": snapshot_date,
        "launched": bool(launched),
        "profile": cov.get("profile"),
        "min_age_days": summary.get("min_age_days"),
        "epoch": summary.get("epoch"),
        "counts": {
            "total": summary.get("total"),
            "corroborated": summary.get("corroborated"),
            "single_origin": summary.get("single_origin"),
            "undated_excluded": summary.get("undated_excluded"),
            "epoch_excluded": summary.get("epoch_excluded"),
            "unmeasurable_rule": summary.get("unmeasurable_rows"),
            "named": summary.get("named_cnas"),
        },
        "coverage": {
            "cnas_effective": cov.get("cnas_effective"),
            "cnas_sighted": cov.get("cnas_sighted"),
            "cnas_own_channel": cov.get("cnas_own_channel"),
            "total_cnas": cov.get("total_cnas"),
            "pct_effective": cov.get("pct_effective"),
            "min_sightings": cov.get("min_sightings"),
        },
        "caveats": {
            # Every one of these is true of every row in every payload. They are
            # here so a consumer cannot end up holding the numbers without them.
            "count_is_a_floor": True,
            "owner_is_inferred": True,
            "days_public_is_a_floor_not_lateness": True,
            "must_is_never_established": True,
            "rule_mostly_unmeasurable": True,
            "not_a_cna_scorecard": True,
        },
        "degraded": bool(summary.get("degraded")),
        "degraded_reasons": summary.get("degraded_reasons") or [],
        # Standing limits that fire every run by design, published separately
        # from `degraded` so a consumer can tell "this run was worse than usual"
        # from "this feed always stops at a page cap". The page and this payload
        # disagreed about `degraded` on the same build; tests/test_end_to_end.py
        # now asserts they cannot.
        "limitations": summary.get("limitations") or [],
        "columns": COLUMNS,
        "rows": rows,
    }
