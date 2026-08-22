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
GATE_PCT = 50.0


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

# Minimum graded predictions before a production precision figure is shown at
# all. With n=1 the site rendered "100.00%" in a headline tile, which is a
# stronger claim than the leave-one-out figure it sits beside.
GRADER_MIN_N = 20

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
    if not total or eff is None:
        return {"cleared": False, "pct": None, "required": GATE_PCT,
                "reason": "coverage was not measured in this snapshot"}
    pct = round(100 * eff / total, 1)
    floor = cov.get("min_sightings")
    return {
        "cleared": pct >= GATE_PCT,
        "pct": pct,
        "required": GATE_PCT,
        "effective": eff,
        "min_sightings": floor,
        "own_channel": cov.get("cnas_own_channel"),
        "sighted": sighted,
        "total": total,
        "profile": cov.get("profile"),
        "reason": (f"coverage is {pct}% of {total} CNAs seen at least "
                   f"{floor if floor is not None else '?'} times, below the "
                   f"{GATE_PCT}% gate"),
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
    named = [r for r in rows if r.get("owner") and r["owner"] != "unattributed"]
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

    rows = _read_strict(os.path.join(latest, "backlog.json"))
    summary = _read_strict(os.path.join(latest, "summary.json"))
    cnas = _read_strict(os.path.join(latest, "cnas.json"))
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
        "grader": {
            "graded": len(graded),
            "correct": sum(1 for g in graded if g.get("correct")),
            # Below the floor this is None and the templates render a sentence
            # rather than a metric tile. The project already applies exactly this
            # discipline to other people's numbers via MIN_DENOMINATOR; applying
            # it to its own claim is the same rule.
            "precision": (sum(1 for g in graded if g.get("correct")) / len(graded)
                          if len(graded) >= GRADER_MIN_N else None),
            "below_floor": len(graded) < GRADER_MIN_N,
            "outstanding": len(grader.get("predictions", {})),
            "misses": [g for g in graded if not g.get("correct")][-25:],
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
        # item 11: a precision figure needs a minimum n before it is a figure at
        # all. `pct` renders two decimals, so the first graded case published
        # "100.00%" in a headline tile and on every per-CNA page.
        "precision_floor": GRADER_MIN_N,
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
             "incomparable_reason": None}
    if not prev_dir:
        return empty

    prev_rows = _read(os.path.join(prev_dir, "backlog.json"), [])
    prev_sum = _read(os.path.join(prev_dir, "summary.json"), {})
    now_sum = _read(os.path.join(latest_dir, "summary.json"), {})

    # Refuse to diff snapshots that disagree on how they were produced.
    for key, label in (("min_age_days", "buffer"), ("epoch", "epoch")):
        if prev_sum.get(key) is not None and prev_sum.get(key) != now_sum.get(key):
            return {**empty, "have_previous": True, "comparable": False,
                    "previous_date": os.path.basename(prev_dir),
                    "incomparable_reason":
                        f"the {label} changed from {prev_sum.get(key)!r} to "
                        f"{now_sum.get(key)!r} between these snapshots"}
    a = set((prev_sum.get("feeds") or {}).get("requested") or [])
    b = set((now_sum.get("feeds") or {}).get("requested") or [])
    if a and b and a != b:
        return {**empty, "have_previous": True, "comparable": False,
                "previous_date": os.path.basename(prev_dir),
                "incomparable_reason":
                    "the feed set changed between these snapshots "
                    f"(added {sorted(b - a)}, dropped {sorted(a - b)})"}

    before = {r["cve_id"] for r in prev_rows}
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
    env.filters["pct"] = lambda x: "n/a" if x is None else f"{100 * x:.2f}%"
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
CSV_COLS = ["cve_id", "state", "days_public", "past_expectation",
            "rule", "rule_strength", "rule_certainty", "rule_basis",
            "owner", "owner_tier", "owner_method", "owner_nameable",
            "owner_contested", "veto_evaluated", "single_origin",
            "self_disclosed", "package", "vendor", "public_date",
            "feed_count", "indep_sources", "sources", "clock_known",
            "advisory_url", "description"]


def _write_data(out, ctx):
    launched = ctx["launched"]
    # Every published row set, not only the one the old test looked at.
    covered = set((ctx["summary"].get("coverage") or {}).get("covered") or [])
    assert_artefact(ctx["rows"], "rbp.json", ctx["cnas"], covered)
    d = os.path.join(out, "data")
    os.makedirs(d, exist_ok=True)

    json.dump(ctx["rows"], open(os.path.join(d, "rbp.json"), "w"), indent=1)
    json.dump(ctx["summary"], open(os.path.join(d, "summary.json"), "w"), indent=1)
    json.dump(ctx["cnas"], open(os.path.join(d, "cnas.json"), "w"), indent=1)
    json.dump(ctx["grader"], open(os.path.join(d, "precision.json"), "w"), indent=1)

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLS, extrasaction="ignore")
    w.writeheader()
    w.writerows(ctx["rows"])
    open(os.path.join(d, "rbp.csv"), "w").write(buf.getvalue())

    # One file per CNA, so anyone can pull just their own rows.
    per = os.path.join(d, "cna")
    if launched:
        os.makedirs(per, exist_ok=True)
    for c in (ctx["cnas"] if launched else []):
        mine = [r for r in ctx["rows"] if r.get("owner") == c["cna"]]
        json.dump({"cna": c["cna"], "summary": c, "rows": mine},
                  open(os.path.join(per, f"{c['slug']}.json"), "w"), indent=1)


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
    pages = pages_for(launched)
    for template, target in pages:
        html = env.get_template(template).render(**ctx, page=target)
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
        "# To report that a listed row is under embargo, use the private route\n"
        "# below and send the CVE ID and the word embargo. Nothing else: no\n"
        "# detail, no confirmation that a vulnerability exists. It is withheld\n"
        "# on the next build, which runs every six hours.\n"
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
        html = tpl.render(**ctx, page="cna", cna=c, cna_rows=mine, cna_resolved=resolved)
        open(os.path.join(cna_dir, f"{c['slug']}.html"), "w").write(html)
        written_cna += 1

    _write_data(out, ctx)
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
