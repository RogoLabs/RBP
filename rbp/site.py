"""
Static site build (PLAN.md phase 4).

Reads the newest snapshot plus both ledgers and renders rbptracker.org. No
network, no runtime API calls: every page is a file, and the data the tables
sort and filter is embedded as JSON so the browser never fetches anything.

Editorial stance, binding here and recorded in PLAN.md 2a: the site leads with
the COUNT. It is the dashboard the CVE Program should have published, so it
reads like an instrument panel rather than a campaign. The `owning_cna`
redaction is the immediate subhead, because it explains why the count had to be
assembled from outside. The Program's removed RBP metric gets its own section
lower down. The per-CNA page is reachable but never the lead, and it carries no
verdict, because RBP Policy v2.0.0 has no threshold for a CNA to be over.
"""
from __future__ import annotations

import csv
import datetime as dt
import glob
import hashlib
import io
import json
import os
import re
import shutil

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import clock
from . import launch as launch_mod

# Pre-launch posture. The dashboard is built and reachable either way, because
# the repo is public and the data files are served regardless; the gate is on
# what the front door presents, not on hiding anything.
#
#   not launched: / is the holding page, the dashboard lives at /overview.html
#                 and every dashboard page is noindex, so search engines do not
#                 index a count that is still built on partial CNA coverage.
#   launched:     / IS the dashboard.
#
# Flip with RBP_LAUNCHED=1, wired to a repository variable so it is a settings
# change rather than a commit. The launch gate is 50% CNA coverage (PLAN.md).
# Minimum coverage before the front door may become the dashboard, measured on
# cnas_effective: CNAs seen at least MIN_SIGHTINGS times, which is the same floor
# inference uses before it will attach a name to a row.
#
# This was briefly gated on cnas_own_channel instead, reasoning that it was the
# stricter figure. It is stricter, but it is bounded by the number of
# hand-written owner-feed parsers, which is three, so the ceiling was 3/434 =
# 0.7% against a 50% gate: the gate could never clear. A launch would have
# produced a red check forever, with nothing to distinguish a threshold that was
# merely distant from one that was unreachable. That was found by reading a
# summary artefact, not by a test, so test_gate_threshold_is_reachable now
# asserts the gate figure can in principle reach GATE_PCT.
#
# The objection that motivated own-channel still stands and is answered instead
# by the floor: a single stray sighting no longer credits a CNA as covered.
# THE GATE, re-derived 2026-08-23. Read this before changing the number.
#
# The old gate was `cnas_effective` >= 50% of the pinned 539-CNA roster. It was
# unreachable, and not by a little. Two ceilings, both measured:
#
#   28.2%  every CNA the nine feeds sight even once, promoted to the 3-sighting
#          floor. The ceiling on the CURRENT feed set. Tuning cannot pass 50%.
#   68.8%  roster CNAs that have published 3 CVEs in the window at all. Only 371
#          of 539 qualify; 128 published nothing. The ceiling on ANY feed set,
#          so 100% of the roster is arithmetically impossible and 80% would be
#          a stricter version of the same mistake.
#
# 50.0 was set when the gate figure was `cnas_sighted` over a corpus-derived
# denominator. The numerator later moved to `cnas_effective` and the denominator
# to the pinned roster, and nobody re-derived the threshold. It was a leftover
# from two metric changes that each made it harder to clear.
#
# The replacement asks a question that has an answer: of the 50 CNAs that issue
# the most CVEs, how many can this site actually see, on the same 3-sighting
# floor `cnas_effective` uses. Measured live at 31 of 50; the CSAF/MSRC
# promotion and the OSV ecosystem expansion together take it to 40 of 50.
#
# Deliberately NOT paired with a roster-share floor. That was offered and
# declined: the top-50 condition alone is the gate. The cost of that choice is
# that it clears at exactly 40/50 with no margin, so `_gate_status` reports the
# margin explicitly rather than letting a bare pass read as a comfortable one.
GATE_TOP_N_PCT = 80.0


def _validated_launched(raw):
    """Parse RBP_LAUNCHED strictly, the way the epoch is parsed.

    A bare truthiness test silently read `on`, `y` and `enabled` as
    not-launched, so a deliberate launch could look like a no-op and be
    debugged as a build problem.
    """
    raw = (raw or "").strip().lower()
    if raw in ("", "0", "false", "no"):
        return False
    if raw in ("1", "true", "yes"):
        return True
    raise SystemExit(
        f"RBP_LAUNCHED={raw!r} is not a recognised boolean. Use 1 or 0. "
        "Refusing to guess: a misread flag either publishes a site that should "
        "be held or holds one that should be published.")


LAUNCHED = _validated_launched(os.environ.get("RBP_LAUNCHED"))

# Build the LAUNCHED posture even below the coverage gate, for rehearsal only.
#
# Deliberately a second variable rather than a mode of RBP_LAUNCHED: bypassing the
# gate should take two explicit levers, so no single setting can both request a
# launch and waive the check on it. The workflow sets this only on a dry run, where
# the deploy job is skipped and the artefact is discarded.
REHEARSE = (os.environ.get("RBP_REHEARSE") or "").strip() in ("1", "true", "yes")

# The precision floor now lives in inference.MIN_GRADED, because whoever computes
# the number has to be the one that floors it. Split across two modules, the raw
# value reached summary.json while the floored one reached precision.json, and both
# published. Re-exported for the tests that reference it.
from . import inference as _inference

GRADER_MIN_N = _inference.MIN_GRADED

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TEMPLATES = os.path.join(ROOT, "templates")
STATIC = os.path.join(ROOT, "static")


def slug(name):
    """Filesystem-safe CNA name for /cna/<slug>.html."""
    return re.sub(r"[^a-z0-9]+", "-", (name or "unknown").lower()).strip("-") or "unknown"


def _snapshots(snap_root):
    return sorted(d for d in glob.glob(os.path.join(snap_root, "*")) if os.path.isdir(d))


def _read(path, default):
    """Tolerant read. Only for the two ledgers, where absence is a valid
    first-run state."""
    try:
        return json.load(open(path))
    except FileNotFoundError:
        return default
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"{path} exists but is unreadable: {e}. Refusing to "
                         "publish from a corrupt ledger.") from e


def _read_strict(path):
    """A snapshot artefact the pages assert numbers from.

    Previously these were tolerant, so a truncated backlog.json beside a good
    summary.json published a front page reading 553 above an empty table, an
    empty rbp.json, a header-only CSV, and per-CNA pages asserting rows above
    none of them. The step exited 0, so the artifact uploaded, the deploy ran,
    and the truncated snapshot became the next run's diff baseline.
    """
    try:
        return json.load(open(path))
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"cannot read {path}: {e}") from e


# The legacy placeholder. `owner` is now a CNA short name or None (schema v1), but
# snapshots written before that carry the string "unattributed" in the same field,
# and CI restores prior snapshots from the data branch for the week-over-week diff.
#
# Coerced on read rather than tolerated in the invariant. _assert_consistent
# deliberately no longer special-cases the string, so without this a stale snapshot
# reads as a row naming a CNA called "unattributed" that is absent from cnas.json,
# which is exactly what it said when this change first built. Version skew on a
# published artefact is an operational fact, not a bug to crash on; publishing the
# placeholder as though it were a CNA name is the bug.
_LEGACY_OWNER = "unattributed"


def _normalise_legacy(rows, source="snapshot"):
    """Bring a snapshot written under an older schema up to the current contract.

    Two coercions, both idempotent, so applying them to a current snapshot is a
    no-op and applying them to an old one makes it readable.
    """
    from . import classify
    owners = descs = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        if r.get("owner") == _LEGACY_OWNER:
            r["owner"] = None
            r.setdefault("owner_nameable", False)
            owners += 1
        # Descriptions written before the sanitiser existed still carry URLs and
        # tracker annotations, which assert_artefact refuses. Cleaning on read is
        # correct rather than lenient: the sanitiser is idempotent, so this cannot
        # weaken a current snapshot, and the alternative is a build that cannot
        # read its own history.
        d = r.get("description")
        if d:
            cleaned = classify.display_description(d)
            if cleaned != d:
                r["description"] = cleaned or (r.get("package") or "")
                descs += 1
    if owners:
        print(f"  note: {source}: coerced {owners} legacy {_LEGACY_OWNER!r} owner "
              "value(s) to null (predates schema v1)")
    if descs:
        # Naming the source matters. "sanitised 170 legacy description(s)" on a run
        # whose own snapshot is clean reads as the pipeline failing to sanitise;
        # every one of the 170 was in YESTERDAY's snapshot, read for the diff.
        print(f"  note: {source}: sanitised {descs} legacy description(s) on read "
              "(predates the description sanitiser)")
    return rows


def _gate_status(summary):
    """Is the launch gate cleared, on the effective coverage figure?

    Reported whether or not the flag is set, so /method can state the position
    truthfully at any time rather than only when someone tries to launch. All
    three coverage figures are returned, because a reader asking "can this site
    see my CNA" and a reader asking "could this site ever call my CNA a 4.5.1.4
    breach" are asking different questions with different answers.
    """
    cov = summary.get("coverage") or {}
    total = cov.get("total_cnas") or 0
    eff = cov.get("cnas_effective")
    sighted = cov.get("cnas_sighted", cov.get("covered_cnas"))
    top_n = cov.get("top_n") or 0
    top_eff = cov.get("top_covered_effective")
    floor = cov.get("min_sightings")

    # The gate reads top_covered_effective, NOT top_covered. A run produced
    # before that field existed must fail closed rather than fall back to the
    # one-sighting figure, which would clear the gate on a weaker measure than
    # the one it names.
    if not top_n or top_eff is None:
        return {"cleared": False, "pct": None, "required": GATE_TOP_N_PCT,
                "basis": f"top-{top_n or '?'}-by-volume at the {floor or '?'}-sighting floor",
                "reason": ("this snapshot does not report top-N coverage on the "
                           "sighting floor, so the gate cannot be evaluated")}

    pct = round(100 * top_eff / top_n, 1)
    needed = -(-int(GATE_TOP_N_PCT * top_n) // 100)      # ceil, in whole CNAs
    cleared = pct >= GATE_TOP_N_PCT
    margin = top_eff - needed
    return {
        "cleared": cleared,
        "pct": pct,
        "required": GATE_TOP_N_PCT,
        "basis": f"top-{top_n}-by-volume at the {floor or '?'}-sighting floor",
        "top_n": top_n,
        "top_effective": top_eff,
        "needed": needed,
        # Published because the gate was deliberately left without a second
        # condition, so it can clear by exactly one CNA. A bare "cleared: true"
        # would hide that; a margin of 0 says it out loud.
        "margin": margin,
        "top_missed": cov.get("top_missed_effective") or [],
        # Carried so the roster-share figures stay visible and quotable even
        # though they no longer gate anything. Removing them would make the
        # weaker number harder to find, not the site more honest.
        "roster_pct_effective": round(100 * eff / total, 1) if total and eff is not None else None,
        "effective": eff,
        "sighted": sighted,
        "total": total,
        "min_sightings": floor,
        "own_channel": cov.get("cnas_own_channel"),
        "profile": cov.get("profile"),
        "reason": (
            f"{top_eff} of the top {top_n} CNAs by volume are seen at least "
            f"{floor if floor is not None else '?'} times ({pct}%), "
            + (f"clearing the {GATE_TOP_N_PCT}% gate by {margin} CNA(s)" if cleared
               else f"below the {GATE_TOP_N_PCT}% gate, which needs {needed}")),
    }


def _assert_consistent(rows, summary, cnas):
    """One invariant, raised in one place, covering three separate defects:
    the epoch applied to some writers and not others, a truncated artefact, and
    an owner link pointing at a CNA page that was never generated."""
    total = summary.get("total")
    if total is not None and len(rows) != total:
        raise SystemExit(
            f"snapshot is inconsistent: backlog.json has {len(rows)} rows but "
            f"summary.json reports total={total}. The published population must "
            "be computed once. Refusing to publish contradictory numbers.")
    known = {c["cna"] for c in cnas}
    # No placeholder special-case. `owner` is a CNA short name or None, so this is
    # a plain truthiness test; the previous version only passed because it knew
    # about a magic string that the published field dictionary denied existed.
    named = [r for r in rows if r.get("owner")]
    orphans = sorted({r["owner"] for r in named} - known)
    if orphans:
        raise SystemExit(
            f"rows name CNAs absent from cnas.json: {orphans}. Every owner link "
            "would 404. Refusing to publish.")
    # No published artefact may name a CNA outside the covered set for the run
    # that named it. Before this, coverage.top_missed said "we do not read this
    # CNA" while a row said "this CNA owns this vulnerability".
    covered = set((summary.get("coverage") or {}).get("covered") or [])
    if covered:
        outside = sorted({r["owner"] for r in named if r["owner"] not in covered})
        if outside:
            raise SystemExit(
                f"rows name CNAs outside the covered set: {outside}. The site "
                "would simultaneously claim not to read these CNAs and to know "
                "what they own. Refusing to publish.")

    counted = sum(c.get("outstanding", 0) for c in cnas)
    if counted != len(named):
        raise SystemExit(
            f"per-CNA outstanding sums to {counted} but {len(named)} rows are "
            "named. The per-CNA cards would contradict their own tables.")


# A URL, by scheme. Deliberately not the bare substring "http": protocol names
# appear legitimately inside software identifiers (NIOHTTPRequestDecompressor,
# HTTPDecoder) and inside prose about a protocol ("unauthenticated HTTP endpoint").
_URL_IN_TEXT = re.compile(r"\b(?:https?|ftp|git)://|\bwww\.\w", re.I)


def assert_artefact(rows, label, cnas=None, covered=None):
    """Invariants every published artefact must satisfy, not just backlog.json.

    The one assertion that existed iterated a single-element tuple over a
    directory that had just gained a new file, which is exactly why the
    held_back.json leak shipped green. held_back's named owners included CNAs
    absent from cnas.json, so it published precisely the values the existing
    assertion refused.
    """
    known = {c["cna"] for c in (cnas or [])}
    problems = []
    for r in rows:
        if not isinstance(r, dict):
            problems.append(f"{label}: non-object row")
            continue
        cid = r.get("cve_id", "?")
        owner = r.get("owner")
        is_named = owner not in (None, "", "unattributed")

        if "owner_nameable" not in r:
            problems.append(f"{label}:{cid} has no owner_nameable field")
        if is_named and r.get("counted") is False:
            problems.append(f"{label}:{cid} names {owner} on an uncounted row")
        if is_named and known and owner not in known:
            problems.append(f"{label}:{cid} names {owner}, absent from cnas.json")
        if is_named and covered and owner not in covered:
            problems.append(f"{label}:{cid} names {owner}, outside the covered set")
        if any(k.startswith("product_map") for k in r):
            problems.append(f"{label}:{cid} carries an ungated product-map field")

        # Review item 4. A suppressed row is withheld because someone reported it
        # as wrong or under embargo, so its presence in ANY published artefact
        # defeats the lever. Class 1: publishing it is a false statement about, or
        # a disclosure concerning, a named third party. Blocks.
        if r.get("suppressed"):
            problems.append(
                f"{label}:{cid} is suppressed and must not appear in a published "
                "artefact at all")

        # Review item 18. A backstop, not a policy gate, and the distinction
        # matters under PLAN 8b. Cleaning happens deterministically upstream in
        # classify.display_description, so this can only fire if that sanitiser
        # has a bug or a new feed bypasses it. When it does fire the failure is a
        # disclosure harm (a pointer to vulnerable code on an unpublished CVE),
        # not an ugly string, so blocking is the correct direction. Contrast the
        # NOTE: guard this replaced, which blocked on cosmetics and froze a
        # publication over six harmless rows.
        # Match a URL SCHEME, not the substring "http". The first version of this
        # check was `"http" in desc.lower()`, which flagged 16 rows on
        # NIOHTTPRequestDecompressor, HTTPDecoder and "unauthenticated HTTP
        # tools/call" against 7 genuine URLs, and blocked the build on all 23. A
        # blocking guard with a sloppy pattern is the same class-1-on-class-2
        # mistake as the NOTE: guard, so a guard that CAN stop a publication has to
        # be precise about what it matches.
        desc = r.get("description") or ""
        if _URL_IN_TEXT.search(desc):
            problems.append(
                f"{label}:{cid} publishes a URL in its description: {desc[:80]!r}")
        if re.search(r"\bNOTE\s*:|\bDEBIANBUG", desc, re.I):
            problems.append(
                f"{label}:{cid} publishes a tracker annotation: {desc[:80]!r}")
        # Deliberately NOT asserted here: a low-quality description is bad
        # display text, not a false statement about a third party. Refusing to
        # publish over it would fail dark on data that is merely ugly, which is
        # the opposite of the rule these invariants exist to serve. It is cleaned
        # at the publishable boundary in report._publishable instead.
    if problems:
        raise SystemExit("refusing to publish:\n  " + "\n  ".join(problems[:25]))
    return len(rows)


def load(snap_root, data_dir):
    """Assemble the render context from the newest snapshot and the ledgers."""
    snaps = _snapshots(snap_root)
    if not snaps:
        raise SystemExit(f"no snapshots in {snap_root}; run the pipeline first")
    latest, prev = snaps[-1], (snaps[-2] if len(snaps) > 1 else None)

    rows = _normalise_legacy(_read_strict(os.path.join(latest, "backlog.json")),
                             source=f"{os.path.basename(latest)}/backlog.json")
    summary = _read_strict(os.path.join(latest, "summary.json"))
    cnas = _read_strict(os.path.join(latest, "cnas.json"))
    # Tolerant: a snapshot written before held_back.json existed is a valid input,
    # and an absent archive must not stop a publication.
    held_back = _normalise_legacy(_read(os.path.join(latest, "held_back.json"), []),
                                  source=f"{os.path.basename(latest)}/held_back.json")
    _assert_consistent(rows, summary, cnas)

    # The launch gate, enforced here but deliberately NOT by refusing to build.
    # A SystemExit in this function lands in the Build site step, and deploy is
    # `needs: build` with no `if:`, so the whole deploy job would be skipped and
    # Pages would serve the previous artefact indefinitely with no notification.
    # Worse, after a launch cleared on a manual `deep` run, every scheduled
    # `weekly` run would trip the refusal and the site would freeze permanently
    # four times a day while still serving a count and a six-hour cadence claim.
    #
    # So: fail CLOSED on the flag (ignore RBP_LAUNCHED and keep serving the
    # pre-launch page), and let a separate workflow step fail loud in CI. Never
    # fail dark on the publication itself.
    launched = LAUNCHED
    gate = _gate_status(summary)
    if launched and not gate["cleared"]:
        # REHEARSAL ESCAPE, and only that.
        #
        # The demotion is correct for a real run: a launch below coverage must serve
        # the pre-launch page rather than the dashboard. But it also made the launch
        # rehearsal impossible, which the first rehearsal proved by building the
        # holding page while every other lever said LAUNCHED. So the one thing
        # condition 9 exists to prevent, launch day being the first execution of the
        # launched code path, survived a green rehearsal.
        #
        # RBP_REHEARSE=1 skips the demotion. The workflow sets it only on a dry run,
        # where `deploy` is skipped, so the artefact is built and discarded. It is a
        # separate variable from RBP_LAUNCHED on purpose: someone who sets
        # RBP_LAUNCHED alone still gets the demotion, and bypassing the gate takes
        # two deliberate levers rather than one.
        if REHEARSE:
            print(f"REHEARSAL: {gate['reason']}, but RBP_REHEARSE=1, so the "
                  "LAUNCHED posture is being built anyway. This artefact must not "
                  "be published; the workflow only sets this on a dry run.")
        else:
            print(f"REFUSING TO LAUNCH: {gate['reason']}. "
                  "Serving the pre-launch page instead.")
            launched = False
    grader = _read(os.path.join(data_dir, "precision.json"),
                   {"graded": [], "predictions": {}, "history": []})
    resolutions = _read(os.path.join(data_dir, "resolutions.json"),
                        {"resolved": [], "open": {}})

    changes = _changes(rows, prev, latest)
    for c in cnas:
        c["slug"] = slug(c["cna"])

    _closures = resolutions.get("resolved", [])

    def _by_days_desc(rows):
        """Sort here, never in Jinja.

        The first attempt at this split left the sort in the template, and it
        crashed again in CI: filtering to PUBLISHED is not enough, because a
        published closure still carries days_to_publish None whenever the date
        arithmetic failed on an unparseable feed date. Jinja's sort calls
        sorted() with no key fallback and do_sort has no `default` parameter, so
        any None in the column is a build-killing TypeError. Sorting in Python
        with an explicit sentinel is the only version that cannot raise.
        """
        return sorted(rows,
                      key=lambda r: (r.get("days_to_publish") is None,
                                     -(r.get("days_to_publish") or 0)))

    _published_closures = _by_days_desc(
        [r for r in _closures if r.get("state", "PUBLISHED") == "PUBLISHED"])[:200]
    _rejected_closures = [r for r in _closures if r.get("state") == "REJECTED"][-200:]

    graded = grader.get("graded", [])

    # item 13: freshness measured, not asserted. The site claimed "Updated every
    # six hours" as static copy while nothing anywhere computed staleness, and a
    # scheduled workflow can stop silently (GitHub disables cron after 60 days of
    # repository inactivity, and cron is best-effort regardless).
    age_hours = None
    stamped = summary.get("generated_at")
    if stamped:
        try:
            then = dt.datetime.fromisoformat(stamped)
            if then.tzinfo is None:
                then = then.replace(tzinfo=dt.timezone.utc)
            age_hours = round((dt.datetime.now(dt.timezone.utc) - then).total_seconds() / 3600, 1)
        except ValueError:
            age_hours = None

    return {
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "snapshot_date": os.path.basename(latest),
        "snap_root": snap_root,
        "archive": None,          # filled by _write_data, read by /data
        "rows": rows,
        "summary": summary,
        "cnas": cnas,
        "changes": changes,
        # _gate_status' own docstring said "reported whether or not the flag is
        # set, so /method can state the position truthfully at any time", and then
        # it was never passed to a template, so no page could state it at all.
        # Same shape as days_public, self_disclosed, feed health, the epoch and
        # PAGES-at-import: computed in one stage, read in none.
        "gate": gate,
        # Review Part 2's nine conditions. Published, not just recorded, because
        # the panel's ask was that the commitment be "checkable from outside".
        # Coverage is condition 1 of 9, so `gate` and `launch` answer different
        # questions and the templates must not present either as the other.
        "launch": launch_mod.status(summary, gate),
        # The published contract, rendered on /data rather than described there.
        # The rows the epoch removes. Read from the snapshot rather than recomputed,
        # so the page shows exactly what the pipeline held back. Never carries an
        # owner: these rows are outside the reportable set, so they are outside the
        # set this site is willing to attribute.
        "held_back": held_back,
        "held_back_oldest": max((r.get("days_public") or 0 for r in held_back),
                                default=0),
        "schema_version": _schema.SCHEMA_VERSION,
        "columns": _schema.COLUMNS,
        "fields": _schema.FIELDS,
        # Split at the render boundary, not in the templates. Both states used
        # to share one list that the templates sorted on days_to_publish, which
        # is None for a rejection, and Jinja's sort filter calls sorted(), so one
        # published plus one rejected closure raised TypeError and killed the
        # whole build. changes.html is in PAGES, so that killed the pre-launch
        # build too, the artefact never uploaded, deploy was skipped, and the
        # next run re-derived the same rejection and failed identically. A
        # self-sustaining outage, latent only because resolved is currently 0.
        #
        # Below the crash threshold the render was worse than the crash: a lone
        # rejection printed under a "Resolved" heading with the prose "RBPs
        # attributed here that have since published" and a cell reading None. A
        # rule 4.5.3.5 rejection is the CNA complying with the rules.
        "resolutions_published": _published_closures,
        "resolutions_rejected": _rejected_closures,
        # Counted from the same lists that render, not from an untruncated
        # original, or the two diverge silently past the truncation point.
        "resolutions_n": len(_published_closures),
        "resolutions_rejected_n": len(_rejected_closures),
        "resolutions_tracked": len(resolutions.get("open", {})),
        # Read from the run's own accuracy block, NOT recomputed here.
        #
        # This block used to recompute precision with the floor applied, while
        # Grader.summary published the unfloored value into summary.json. Two files
        # from the same run then disagreed about the site's own accuracy:
        # summary.json said precision 1.0 at graded 1, precision.json said null with
        # below_floor true, and both were live. The floor now lives in
        # Grader.summary, and this reads what it produced.
        # Floored by inference.summarise_state, the one implementation of the rule.
        #
        # This block used to recompute precision with the floor applied while
        # Grader.summary published the unfloored value into summary.json. Two files
        # from the same run then disagreed about the site's own accuracy:
        # summary.json said precision 1.0 at graded 1, precision.json said null with
        # below_floor true, and both were live on the data branch.
        "grader": {
            **_inference.summarise_state(grader),
            "history": grader.get("history", [])[-30:],
        },
        "expectation_hours": clock.EXPECTATION_HOURS,
        "min_denominator": clock.MIN_DENOMINATOR,
        "rule_must": clock.RULE_MUST,
        "rule_should": clock.RULE_SHOULD,
        "owner_feeds": {k: sorted(v) for k, v in clock.OWNER_FEEDS.items()},
        "asset_v": _asset_versions(),
        "age_hours": age_hours,
        "stale": age_hours is not None and age_hours > 12,
        "very_stale": age_hours is not None and age_hours > 24,
        # The floor, for templates that explain why a figure is withheld. Sourced
        # from inference so there is exactly one definition of it.
        "precision_floor": _inference.MIN_GRADED,
        "launched": launched,
        "gate": gate,
        # Where the dashboard actually lives, so the nav and the logo point at
        # it in both postures.
        "home": "index.html" if launched else "overview.html",
    }


def _changes(rows, prev_dir, latest_dir):
    """Movement against the previous snapshot, in three buckets that are never
    merged.

    A set difference over two backlogs is NOT a publication event. A row leaves
    the set for at least six other reasons: a transient oracle error, a failed
    or truncated feed, a feed-profile change (one `deep` dispatch followed by the
    next `weekly` cron drops every CSAF-only row), a raised buffer, a revised
    `public_date`, and rejection. Labelling that difference "Published, and
    therefore resolved" asserted a fact about a CNA that the site had not
    checked, and the honest answer was already being computed and thrown away.

      published      verified PUBLISHED in the corpus, from the ledger.
      rejected       state REJECTED. Lawful under rule 4.5.3.5, and worse for a
                     defender than an open RBP, so it is never called resolved.
      no_longer_listed  unverified. The word "published" must not appear near it.

    Two snapshots taken under different feed profiles or buffers are not
    comparable at all, and saying so is better than showing a difference that
    means nothing.
    """
    empty = {"published": [], "rejected": [], "no_longer_listed": [], "new": [],
             "still_open": 0, "have_previous": False, "comparable": True,
             "incomparable_reason": None, "epoch_started": False,
             "dropped_by_epoch": 0}
    if not prev_dir:
        return empty

    # STRICT on the previous backlog when its directory exists. The tolerant read
    # turned a missing or corrupt previous backlog into an empty set, which makes
    # every current row "new" and every previous row "no longer listed" while
    # `comparable` stays True. A diff computed against nothing is the one output
    # that must never be published as a diff.
    prev_backlog = os.path.join(prev_dir, "backlog.json")
    prev_rows = (_normalise_legacy(_read_strict(prev_backlog),
                                   source=f"{os.path.basename(prev_dir)}/backlog.json "
                                          "(previous, for the diff)")
                 if os.path.exists(prev_backlog) else None)
    if prev_rows is None:
        return {**empty, "have_previous": True, "comparable": False,
                "previous_date": os.path.basename(prev_dir),
                "incomparable_reason":
                    "the previous snapshot has no backlog.json, so there is nothing "
                    "to diff against. Showing no movement rather than reporting "
                    "every row as new."}
    prev_sum = _read(os.path.join(prev_dir, "summary.json"), {})
    now_sum = _read(os.path.join(latest_dir, "summary.json"), {})

    # Refuse to diff snapshots that disagree on how they were produced.
    #
    # Keyed on PRESENCE, not truthiness. `epoch` is emitted as `EPOCH or None`, so
    # the None-to-date transition short-circuited `is not None` and the pair was
    # declared comparable on exactly the run where it is least comparable: launch
    # day, when every row moves. Reproduced by execution before this fix:
    # comparable True, no_longer_listed 150 of 150, which at live scale is ~500 CVE
    # IDs rendered as a comma-joined mono dump under "No longer listed, cause
    # unverified" on the first day anyone reads the site.
    #
    # The guard caught the harmless direction (unsetting the epoch) and missed the
    # one that will actually happen. Same hole a third time, after `min_age_days`
    # and the feed set.
    for key, label in (("min_age_days", "buffer"), ("epoch", "epoch")):
        in_prev, in_now = key in prev_sum, key in now_sum
        if in_prev and in_now and prev_sum.get(key) != now_sum.get(key):
            return {**empty, "have_previous": True, "comparable": False,
                    "previous_date": os.path.basename(prev_dir),
                    "epoch_started": (key == "epoch" and not prev_sum.get(key)
                                      and bool(now_sum.get(key))),
                    "incomparable_reason":
                        f"the {label} changed from {prev_sum.get(key)!r} to "
                        f"{now_sum.get(key)!r} between these snapshots"}
    a = set((prev_sum.get("feeds") or {}).get("requested") or [])
    b = set((now_sum.get("feeds") or {}).get("requested") or [])
    # Presence again, not truthiness: `if a and b` skipped the check whenever
    # either side was empty, which is precisely a run where every feed was dropped.
    if "feeds" in prev_sum and "feeds" in now_sum and a != b:
        return {**empty, "have_previous": True, "comparable": False,
                "previous_date": os.path.basename(prev_dir),
                "incomparable_reason":
                    "the feed set changed between these snapshots "
                    f"(added {sorted(b - a)}, dropped {sorted(a - b)})"}

    # `gone` is computed against the previous snapshot RESTRICTED to rows that are
    # still epoch-eligible, so an epoch change moves rows into the archive rather
    # than through the diff. Better than a comparability flag: the flag tells a
    # reader the diff is meaningless, this stops the meaningless diff existing.
    now_epoch = now_sum.get("epoch")
    before = {r["cve_id"] for r in prev_rows
              if not (now_epoch and (r.get("public_date") or "") < now_epoch)}
    dropped_by_epoch = len(prev_rows) - len(before)
    now = {r["cve_id"] for r in rows}
    by_id = {r["cve_id"]: r for r in rows}
    gone = before - now

    # The authoritative closures, written by the pipeline from the corpus.
    resolved = {r["cve_id"]: r for r in _read(os.path.join(latest_dir, "resolved.json"), [])}
    published = [resolved[c] for c in sorted(gone) if resolved.get(c, {}).get("state") == "PUBLISHED"]
    rejected = [resolved[c] for c in sorted(gone) if resolved.get(c, {}).get("state") == "REJECTED"]
    accounted = {r["cve_id"] for r in published + rejected}
    return {
        "new": [by_id[c] for c in sorted(now - before)],
        "published": published,
        "rejected": rejected,
        "no_longer_listed": sorted(gone - accounted),
        "still_open": len(now & before),
        "have_previous": True,
        "comparable": True,
        "incomparable_reason": None,
        "epoch_started": False,
        "dropped_by_epoch": dropped_by_epoch,
        "previous_date": os.path.basename(prev_dir),
    }


# --------------------------------------------------------------------------
# render
# --------------------------------------------------------------------------

def _asset_versions():
    """Short content hashes for the stylesheets, appended to their URLs.

    Without this a returning visitor keeps a cached stylesheet after a design
    change, which is exactly what happened during development: a dark-mode fix
    appeared to have no effect because the browser held the old file.
    """
    out = {}
    css = os.path.join(STATIC, "css")
    if os.path.isdir(css):
        for name in sorted(os.listdir(css)):
            if name.endswith(".css"):
                data = open(os.path.join(css, name), "rb").read()
                out[name] = hashlib.sha256(data).hexdigest()[:10]
    return out


def _env():
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["commafy"] = lambda n: f"{n:,}" if isinstance(n, (int, float)) else n
    # One decimal, not two. Two decimals on a 223-row base implies a precision of
    # one part in ten thousand from a measurement that cannot support one part in
    # a hundred. The raw ratio stays in the JSON for anyone who wants it.
    env.filters["pct"] = lambda x: "n/a" if x is None else f"{100 * x:.1f}%"
    env.filters["slug"] = slug

    def sortnum(rows, attribute, reverse=True):
        """Sort on a possibly-null numeric attribute without raising.

        Jinja's built-in sort calls sorted() with no key fallback, and do_sort
        has no `default` parameter, so a single None in the column raises
        TypeError inside the Build site step. That took the whole site down twice
        during this review: once on days_to_publish for a rejected closure, and
        it was latent on days_public for an undated row. Nulls sort last in both
        directions, because a missing value is not a small value.
        """
        return sorted(
            rows,
            key=lambda r: (r.get(attribute) is None,
                           -(r.get(attribute) or 0) if reverse else (r.get(attribute) or 0)),
        )

    env.filters["sortnum"] = sortnum
    return env


# Columns for the public CSV. Deliberately the gated view: an ungated owner
# column in a shareable file was a real defect in the previous engine.
# `rule_strength` never travels without `rule_certainty`. clock.py states the
# rule that the qualifier must accompany the strength wherever it appears, and it
# was in no template and no CSV, so a consumer could not reconstruct it at all.
# `indep_sources` ships too: 314 of 553 rows showed feed_count >= 2 with
# indep_sources == 1, all of them GHSA plus its own OSV mirror.
# The published column contract lives in rbp/schema.py, once. This was a 25-field
# list here and a 26-field list in a different order in report.build, under a
# comment claiming the two CSVs were identical.
from . import schema as _schema

CSV_COLS = _schema.COLUMNS


def _write_data(out, ctx):
    launched = ctx["launched"]
    # Every published row set, not only the one the old test looked at.
    covered = set((ctx["summary"].get("coverage") or {}).get("covered") or [])
    assert_artefact(ctx["rows"], "rbp.json", ctx["cnas"], covered)
    d = os.path.join(out, "data")
    os.makedirs(d, exist_ok=True)

    # Wrapped, not bare. `rbp.json` was json.dump(rows): an array with no schema
    # version, no generation time, no epoch, no buffer, no coverage and no floor
    # flag, so every caveat that makes the count safe to use lived in HTML a tool
    # has no reason to fetch.
    env = _schema.envelope(ctx["rows"], ctx["summary"], launched=launched,
                           snapshot_date=ctx["snapshot_date"])
    json.dump(env, open(os.path.join(d, "rbp.json"), "w"), indent=1)
    json.dump(ctx["summary"], open(os.path.join(d, "summary.json"), "w"), indent=1)
    json.dump(ctx["cnas"], open(os.path.join(d, "cnas.json"), "w"), indent=1)
    json.dump(ctx["grader"], open(os.path.join(d, "precision.json"), "w"), indent=1)

    # The closure record. resolved.json and held_back.json were computed, rendered
    # and then withheld from consumers entirely: neither reached the data branch or
    # site/data. The resolved rows are the only public evidence the pipeline closes,
    # and the held-back count is the filter that removes the oldest and strongest
    # rows, so withholding both left a consumer unable to check either.
    # The archive, published rather than computed and withheld. The oldest row is
    # this project's single strongest piece of evidence and the epoch would have
    # deleted it from the site with no home anywhere.
    assert_artefact(ctx["held_back"], "held-back.json", ctx["cnas"], covered)
    json.dump(_schema.envelope(ctx["held_back"], ctx["summary"], launched=launched,
                               snapshot_date=ctx["snapshot_date"], kind="held-back"),
              open(os.path.join(d, "held-back.json"), "w"), indent=1)

    json.dump(_schema.envelope(ctx["resolutions_published"], ctx["summary"],
                               launched=launched, snapshot_date=ctx["snapshot_date"],
                               kind="resolved"),
              open(os.path.join(d, "resolved.json"), "w"), indent=1)

    # A CSV sidecar, so the column contract is machine-readable beside the file
    # rather than only prose on /data.
    json.dump({"schema_version": _schema.SCHEMA_VERSION,
               "columns": _schema.COLUMNS,
               "fields": {k: {"type": t, "absent": a, "meaning": m}
                          for k, (t, a, m) in _schema.FIELDS.items()}},
              open(os.path.join(d, "rbp.csv.meta.json"), "w"), indent=1)

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLS, extrasaction="ignore")
    w.writeheader()
    w.writerows(ctx["rows"])
    open(os.path.join(d, "rbp.csv"), "w").write(buf.getvalue())

    # THE DATED ARCHIVE (Part 2 condition 7).
    #
    # /data/rbp.json is the only target a citation could use, and it changes every
    # six hours. After the epoch flip its numbers change entirely, so anything cited
    # before launch resolves afterwards to a file that no longer says what was cited.
    #
    # Every retained snapshot is now also published at a dated path, so a citation
    # can point at /data/2026-08-22/rbp.json and keep meaning what it meant. Written
    # from the snapshot on disk rather than from the current context, so a dated file
    # is that day's numbers and not today's wearing that day's name.
    #
    # HONESTY ABOUT "IMMUTABLE": it is not. A withhold request removes a row from
    # every published artefact including these, which is the whole point of the
    # suppression lever. So the archive is STABLE rather than immutable: a figure can
    # go down if someone asks for a row to be withheld, and /data says so rather than
    # promising permanence this project deliberately does not offer.
    arch_root = os.path.join(d, "archive")
    archive = []
    for snap in _snapshots(ctx["snap_root"]):
        date = os.path.basename(snap)
        rows_path = os.path.join(snap, "backlog.json")
        sum_path = os.path.join(snap, "summary.json")
        if not (os.path.exists(rows_path) and os.path.exists(sum_path)):
            continue
        try:
            snap_rows = _normalise_legacy(json.load(open(rows_path)),
                                          source=f"archive/{date}")
            snap_sum = json.load(open(sum_path))
        except Exception:  # noqa: BLE001
            continue
        # Validated against ITS OWN covered set and cnas.json, not today's.
        #
        # The first version passed the current snapshot's, which fails the moment a
        # CNA named in an older snapshot is absent from today's cnas.json, or falls
        # outside today's covered set because a feed moved. Reproduced immediately in
        # CI: the archive refused to publish a historical row that was correct when
        # it was written.
        #
        # A historical artefact has to be judged by the rules that applied when it
        # was produced, and the site published its own covered set alongside it for
        # exactly that reason. Checking it against today's is a category error, and
        # the version that fails closed on correct history is still failing.
        try:
            snap_cnas = json.load(open(os.path.join(snap, "cnas.json")))
        except Exception:  # noqa: BLE001
            snap_cnas = []
        snap_covered = set((snap_sum.get("coverage") or {}).get("covered") or [])
        assert_artefact(snap_rows, f"archive/{date}/rbp.json", snap_cnas, snap_covered)
        dd = os.path.join(arch_root, date)
        os.makedirs(dd, exist_ok=True)
        json.dump(_schema.envelope(snap_rows, snap_sum, launched=launched,
                                   snapshot_date=date, kind="backlog"),
                  open(os.path.join(dd, "rbp.json"), "w"), indent=1)
        archive.append({
            "date": date,
            "url": f"data/archive/{date}/rbp.json",
            "rows": len(snap_rows),
            "epoch": snap_sum.get("epoch"),
            "min_age_days": snap_sum.get("min_age_days"),
            "corroborated": snap_sum.get("corroborated"),
        })
    archive_index = sorted(archive, key=lambda a: a["date"], reverse=True)
    json.dump({"schema_version": _schema.SCHEMA_VERSION,
               "stable_not_immutable": True,
               "note": ("A withhold request removes a row from every published "
                        "artefact including these, so a figure can go down. This "
                        "archive is stable, not immutable."),
               "snapshots": archive_index},
              open(os.path.join(d, "archive.json"), "w"), indent=1)
    _archive_index = archive_index

    # One file per CNA, so anyone can pull just their own rows.
    per = os.path.join(d, "cna")
    if launched:
        os.makedirs(per, exist_ok=True)
    for c in (ctx["cnas"] if launched else []):
        mine = [r for r in ctx["rows"] if r.get("owner") == c["cna"]]
        json.dump({"cna": c["cna"], "summary": c, "rows": mine},
                  open(os.path.join(per, f"{c['slug']}.json"), "w"), indent=1)

    # Returned so /data can render the citable routes. The pages render AFTER the
    # data files for exactly this reason.
    return _archive_index


# Page targets depend on the EFFECTIVE posture, which is not the same as the
# environment flag: the launch gate can demote a requested launch. Computing this
# at import time meant the demotion never reached the page targets, so a launch
# attempted below gate still wrote the dashboard to index.html. That is precisely
# the outcome the gate exists to prevent.
_PAGE_TEMPLATES = [
    ("index.html", None),
    ("cves.html", "cves.html"),
    ("cnas.html", "cnas.html"),
    ("method.html", "method.html"),
    ("policy.html", "policy.html"),
    ("data.html", "data.html"),
    ("changes.html", "changes.html"),
    # A permanent home for the rows the epoch removes. Published whether or not an
    # epoch is set, so the archive exists BEFORE the day it is needed rather than
    # being designed on launch day, which is the sequencing item 6 insists on:
    # design the zero state, publish the archive, then set the epoch.
    ("backlog-at-launch.html", "backlog-at-launch.html"),
]


def pages_for(launched):
    """Template to output filename, for the given effective posture."""
    return [(t, ("index.html" if launched else "overview.html") if o is None else o)
            for t, o in _PAGE_TEMPLATES]


def build(out, snap_root, data_dir):
    ctx = load(snap_root, data_dir)
    env = _env()
    os.makedirs(out, exist_ok=True)

    if os.path.isdir(STATIC):
        shutil.copytree(STATIC, os.path.join(out, "static"), dirs_exist_ok=True)

    launched = ctx["launched"]
    # The archive index is built by _write_data, which runs after the pages. /data
    # needs it while rendering, so the data files are written first and the list is
    # put back into the context before the templates run.
    ctx["archive"] = _write_data(out, ctx)
    pages = pages_for(launched)
    for template, target in pages:
        # `page_file` is the page's own path, for a per-page og:url and canonical.
        # A single hard-coded root og:url on all seven pages meant every paste
        # unfurled as the front page regardless of what was actually shared.
        html = env.get_template(template).render(
            **ctx, page=target,
            page_file="" if target == "index.html" else target)
        open(os.path.join(out, target), "w").write(html)

    if not launched:
        # GitHub Pages cannot set X-Robots-Tag, and a meta tag cannot cover the
        # JSON and CSV under data/. robots.txt is the only lever that reaches them.
        open(os.path.join(out, "robots.txt"), "w").write(
            "# Pre-launch. The count is built on partial CNA coverage and is not\n"
            "# ready to be indexed or cited. See PLAN.md launch gate.\n"
            "User-agent: *\nDisallow: /\n")
    # /.well-known/security.txt (RFC 9116). The site names organisations and
    # invites embargo reports, so the one machine-readable place a security team
    # looks for a contact route must not be empty. Expires is required by the RFC.
    wk = os.path.join(out, ".well-known")
    os.makedirs(wk, exist_ok=True)
    _expires = (dt.datetime.now(dt.timezone.utc)
                + dt.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    open(os.path.join(wk, "security.txt"), "w").write(
        "# rbptracker.org\n"
        "# This site lists reserved CVE IDs that appear in public advisories.\n"
        "# To have a listed row withheld, open a withhold request giving the\n"
        "# CVE ID and nothing else. No reason, no detail, no confirmation that a\n"
        "# vulnerability exists. It is withheld on the next build, which runs\n"
        "# every six hours. Requests are public so the count can be audited; the\n"
        "# private routes below reach a person instead, within five business days.\n"
        "Contact: https://github.com/RogoLabs/RBP/issues/new?labels=withhold\n"
        "Contact: https://github.com/RogoLabs/RBP/security/advisories/new\n"
        "Contact: mailto:rbp@rogolabs.net\n"
        f"Expires: {_expires}\n"
        "Preferred-Languages: en\n"
        "Canonical: https://rbptracker.org/.well-known/security.txt\n"
        "Policy: https://rbptracker.org/method.html\n")

    # The holding page, always written, at a permanent route.
    #
    # It used to be copied over index.html only in the `not launched` branch, so
    # flipping RBP_LAUNCHED would have DELETED it, and with it the three paragraphs
    # that do the site's framing work: the glossary provenance ("That is not our
    # term. It is the CVE Program's own"), the full 4.5.1.7 quotation, and the
    # narrow ask with its own safety reasoning. A grep of the built dashboard
    # returned zero occurrences of "unblind" and zero of "glossary"; the only
    # surviving ask was one line of footer small print. Launch day would have
    # quietly destroyed the most careful copy on the site.
    #
    # So it lives at /about-this-count.html in both postures, and pre-launch it is
    # ALSO the front door.
    landing = os.path.join(ROOT, "placeholder.html")
    if not os.path.exists(landing):
        raise SystemExit("placeholder.html missing; cannot build the front door")
    shutil.copyfile(landing, os.path.join(out, "about-this-count.html"))
    if not launched:
        # Kept as a standalone file rather than a template: it shares nothing
        # with the dashboard by design, and it must not link into it before launch.
        shutil.copyfile(landing, os.path.join(out, "index.html"))

    # Per-CNA detail. This is the page a CNA lands on when someone sends them
    # the link, so it carries the full row list and the method caveats rather
    # than a summary line.
    #
    # Withheld entirely until launch. report.py states the project's own rule
    # that a named CNA gets a private preview before any row naming it
    # circulates, and a six-hourly public deploy of these pages breaks that rule
    # on every run. The noindex meta tag is not sufficient: the pages are still
    # fetchable and linkable.
    written_cna = 0
    cna_dir = os.path.join(out, "cna")
    if launched:
        os.makedirs(cna_dir, exist_ok=True)
    tpl = env.get_template("cna.html")
    for c in (ctx["cnas"] if launched else []):
        mine = [r for r in ctx["rows"] if r.get("owner") == c["cna"]]
        # Keyed on the TRACKED owner. reconcile sets `owner` to the post-transfer
        # assigner, so keying on it gave a CNA-LR that published someone else's
        # overdue record under 4.5.1.5 a resolution history it never had, while
        # clock.by_owner keyed the median tile on the tracked owner. The same
        # page showed two different parties' data.
        resolved = [r for r in ctx["resolutions_published"]
                    if (r.get("predicted_owner") or r.get("owner")) == c["cna"]]
        # already ordered by _by_days_desc; the template must not re-sort
        html = tpl.render(**ctx, page="cna", cna=c, cna_rows=mine,
                          cna_resolved=resolved,
                          page_file=f"cna/{c['slug']}.html")
        open(os.path.join(cna_dir, f"{c['slug']}.html"), "w").write(html)
        written_cna += 1

    posture = "LAUNCHED, / is the dashboard" if launched else \
              "pre-launch, / is the holding page and the dashboard is /overview.html"
    # Report what was written, not what was available. Printing the available
    # count while withholding the pages is the same class of untruth the review
    # found elsewhere on this site.
    print(f"site: {len(pages)} pages + {written_cna} CNA pages -> {out}"
          + ("" if launched else
             f" ({len(ctx['cnas'])} CNA pages withheld until launch)"))
    print(f"      {posture}")
    return ctx
