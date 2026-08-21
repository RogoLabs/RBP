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
    try:
        return json.load(open(path))
    except Exception:  # noqa: BLE001
        return default


def load(snap_root, data_dir):
    """Assemble the render context from the newest snapshot and the ledgers."""
    snaps = _snapshots(snap_root)
    if not snaps:
        raise SystemExit(f"no snapshots in {snap_root}; run the pipeline first")
    latest, prev = snaps[-1], (snaps[-2] if len(snaps) > 1 else None)

    rows = _read(os.path.join(latest, "backlog.json"), [])
    summary = _read(os.path.join(latest, "summary.json"), {})
    cnas = _read(os.path.join(latest, "cnas.json"), [])
    grader = _read(os.path.join(data_dir, "precision.json"),
                   {"graded": [], "predictions": {}, "history": []})
    resolutions = _read(os.path.join(data_dir, "resolutions.json"),
                        {"resolved": [], "open": {}})

    changes = _changes(rows, prev)
    for c in cnas:
        c["slug"] = slug(c["cna"])

    graded = grader.get("graded", [])
    live_precision = (sum(1 for g in graded if g.get("correct")) / len(graded)
                      if graded else None)

    return {
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "snapshot_date": os.path.basename(latest),
        "rows": rows,
        "summary": summary,
        "cnas": cnas,
        "changes": changes,
        "resolutions": resolutions.get("resolved", [])[-200:],
        "resolutions_n": len(resolutions.get("resolved", [])),
        "resolutions_tracked": len(resolutions.get("open", {})),
        "grader": {
            "graded": len(graded),
            "correct": sum(1 for g in graded if g.get("correct")),
            "precision": live_precision,
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
        "launched": LAUNCHED,
        # Where the dashboard actually lives, so the nav and the logo point at
        # it in both postures.
        "home": "index.html" if LAUNCHED else "overview.html",
    }


def _changes(rows, prev_dir):
    """New, resolved and still-open against the previous snapshot.

    Resolved rows matter as much as new ones. A tracker that only ever
    accumulates reads as a grudge; one that visibly closes rows reads as an
    instrument, and the closures are the strongest evidence the open rows are
    real.
    """
    if not prev_dir:
        return {"new": [], "resolved": [], "still_open": 0, "have_previous": False}
    before = {r["cve_id"] for r in _read(os.path.join(prev_dir, "backlog.json"), [])}
    now = {r["cve_id"] for r in rows}
    by_id = {r["cve_id"]: r for r in rows}
    return {
        "new": [by_id[c] for c in sorted(now - before)],
        "resolved": sorted(before - now),
        "still_open": len(now & before),
        "have_previous": True,
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
    return env


# Columns for the public CSV. Deliberately the gated view: an ungated owner
# column in a shareable file was a real defect in the previous engine.
CSV_COLS = ["cve_id", "days_public", "past_expectation", "rule", "rule_strength",
            "owner", "owner_tier", "self_disclosed", "package", "vendor",
            "public_date", "feed_count", "sources", "advisory_url", "description"]


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
    cna_dir = os.path.join(out, "cna")
    os.makedirs(cna_dir, exist_ok=True)
    tpl = env.get_template("cna.html")
    for c in (ctx["cnas"] if LAUNCHED else []):
        mine = [r for r in ctx["rows"] if r.get("owner") == c["cna"]]
        resolved = [r for r in ctx["resolutions"] if r.get("owner") == c["cna"]]
        html = tpl.render(**ctx, page="cna", cna=c, cna_rows=mine, cna_resolved=resolved)
        open(os.path.join(cna_dir, f"{c['slug']}.html"), "w").write(html)

    _write_data(out, ctx)
    posture = "LAUNCHED, / is the dashboard" if LAUNCHED else \
              "pre-launch, / is the holding page and the dashboard is /overview.html"
    print(f"site: {len(PAGES)} pages + {len(ctx['cnas'])} CNA pages -> {out}")
    print(f"      {posture}")
    return ctx
