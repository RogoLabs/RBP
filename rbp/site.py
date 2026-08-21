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
LAUNCHED = os.environ.get("RBP_LAUNCHED", "").strip().lower() in ("1", "true", "yes")

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


def prune_snapshots(snap_root, keep=2, keep_monthly=True):
    """Keep the current snapshot, the previous one, and one per month.

    An unbounded public log of every row ever named, including names later
    withdrawn, is a standing liability that grows four times a day and that no
    correction on the site can reach. The diff only ever needs the previous
    snapshot; the monthly archive is for the historical record.
    """
    snaps = _snapshots(snap_root)
    if len(snaps) <= keep:
        return []
    recent = set(snaps[-keep:])
    monthly = set()
    if keep_monthly:
        by_month = {}
        for d in snaps:
            by_month[os.path.basename(d)[:7]] = d      # last of each month wins
        monthly = set(by_month.values())
    dropped = []
    for d in snaps:
        if d in recent or d in monthly:
            continue
        shutil.rmtree(d, ignore_errors=True)
        dropped.append(os.path.basename(d))
    return dropped


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
    counted = sum(c.get("outstanding", 0) for c in cnas)
    if counted != len(named):
        raise SystemExit(
            f"per-CNA outstanding sums to {counted} but {len(named)} rows are "
            "named. The per-CNA cards would contradict their own tables.")


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
        "launched": LAUNCHED,
        # Where the dashboard actually lives, so the nav and the logo point at
        # it in both postures.
        "home": "index.html" if LAUNCHED else "overview.html",
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
            "owner", "owner_tier", "owner_nameable", "owner_contested",
            "self_disclosed", "package", "vendor", "public_date",
            "feed_count", "indep_sources", "sources", "clock_known",
            "advisory_url", "description"]


def _write_data(out, ctx):
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
    if LAUNCHED:
        os.makedirs(per, exist_ok=True)
    for c in (ctx["cnas"] if LAUNCHED else []):
        mine = [r for r in ctx["rows"] if r.get("owner") == c["cna"]]
        json.dump({"cna": c["cna"], "summary": c, "rows": mine},
                  open(os.path.join(per, f"{c['slug']}.json"), "w"), indent=1)


PAGES = [
    ("index.html", "index.html" if LAUNCHED else "overview.html"),
    ("cves.html", "cves.html"),
    ("cnas.html", "cnas.html"),
    ("method.html", "method.html"),
    ("policy.html", "policy.html"),
    ("data.html", "data.html"),
    ("changes.html", "changes.html"),
]


def build(out, snap_root, data_dir):
    ctx = load(snap_root, data_dir)
    env = _env()
    os.makedirs(out, exist_ok=True)

    if os.path.isdir(STATIC):
        shutil.copytree(STATIC, os.path.join(out, "static"), dirs_exist_ok=True)

    for template, target in PAGES:
        html = env.get_template(template).render(**ctx, page=target)
        open(os.path.join(out, target), "w").write(html)

    if not LAUNCHED:
        # GitHub Pages cannot set X-Robots-Tag, and a meta tag cannot cover the
        # JSON and CSV under data/. robots.txt is the only lever that reaches them.
        open(os.path.join(out, "robots.txt"), "w").write(
            "# Pre-launch. The count is built on partial CNA coverage and is not\n"
            "# ready to be indexed or cited. See PLAN.md launch gate.\n"
            "User-agent: *\nDisallow: /\n")
        # The holding page becomes the front door. Kept as a standalone file
        # rather than a template: it shares nothing with the dashboard by
        # design, and it must not link into it before launch.
        landing = os.path.join(ROOT, "placeholder.html")
        if os.path.exists(landing):
            shutil.copyfile(landing, os.path.join(out, "index.html"))
        else:
            raise SystemExit("placeholder.html missing; cannot build pre-launch front door")

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
    if LAUNCHED:
        os.makedirs(cna_dir, exist_ok=True)
    tpl = env.get_template("cna.html")
    for c in (ctx["cnas"] if LAUNCHED else []):
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
    posture = "LAUNCHED, / is the dashboard" if LAUNCHED else \
              "pre-launch, / is the holding page and the dashboard is /overview.html"
    # Report what was written, not what was available. Printing the available
    # count while withholding the pages is the same class of untruth the review
    # found elsewhere on this site.
    print(f"site: {len(PAGES)} pages + {written_cna} CNA pages -> {out}"
          + ("" if LAUNCHED else
             f" ({len(ctx['cnas'])} CNA pages withheld until launch)"))
    print(f"      {posture}")
    return ctx
