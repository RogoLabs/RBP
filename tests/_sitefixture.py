"""
A real built site, from a synthetic snapshot, for the tests that assert on output.

WHY THIS EXISTS. `tests/test_copy.py`, `tests/test_schema.py` and
`tests/test_suppress.py` assert against the RENDERED site, which is right: "a rule
that holds in the source and not in the output protects nothing". All three found
that site by looking for `./site` on disk and calling `pytest.skip` when it was
absent. `site/` is gitignored, so on any CI runner it is always absent.

Measured on 2026-08-24, run 32744122341: the runner reported `662 passed, 56
skipped` where a developer machine reports `707 passed, 11 skipped`. Same 718
collected. **44 tests passed locally and skipped in CI**, and `deploy.yml`'s
`test` job is the one that gates a four-times-daily publication, so the copy
assertions, the published-JSON schema assertions and seven suppression assertions
were protecting nothing in the pipeline. Locally they ran against whatever stale
build happened to be sitting in the working tree, which is worse than not running.

It is the failure this repository keeps meeting from a new direction: *the test
passes* and *the test works* are different claims. A skip is the quietest possible
way for the second to be false.

So the site is BUILT, hermetically, in both postures, from a fixture snapshot. No
network, no corpus, no data branch. The machinery already existed twice over in
`tests/test_end_to_end.py` and `tests/render/conftest.py`; this is the shared
version, and `tests/render` now uses it too rather than keeping a third copy.

WHAT THE FIXTURE HAS TO BE. Not minimal. Every assertion downstream is of the form
"the output says X", and a fixture that renders half the pages, or renders tables
with no rows in them, satisfies those assertions vacuously. `assert_renders`
below fails the build if the fixture stops producing the pages and tables the
assertions are about, and `tests/test_sitefixture.py` mutation-tests that guard.
"""
from __future__ import annotations

import importlib
import json
import re
import pathlib

# Content chosen to be hostile to layout and long enough to be realistic, because
# tests/render measures reflow against this same fixture and a table of short
# words cannot tell whether `overflow-wrap: anywhere` is still there.
_LONG_PACKAGE = ("org.apache.some-extremely-long-artifact-coordinate/"
                 "spring-boot-starter-data-elasticsearch")
_LONG_DESC = ("A specially crafted request to the administrative interface allows an "
              "unauthenticated remote attacker to bypass the access-control check and "
              "read arbitrary files outside the configured document root, including "
              "credentials for downstream services.")
_LONG_SOURCES = "osv,ghsa,debian,ubuntu,alpine,redhat,alas,csaf,msrc,samsung"
_LONG_REF = "osv:Packagist:codingms/additional-tca-with-a-deliberately-long-suffix"

# The launch epoch. Set so `backlog-at-launch.html` renders its table at all: it
# is `{% if summary.epoch and held_back %}`, and without an epoch that whole page
# is prose and its .rbp table is never rendered or laid out.
EPOCH = "2026-08-01"

SNAPSHOT_DATE = "2026-08-20"
PREV_DATE = "2026-08-19"


def _row(n, public_date="2026-08-05", days=19):
    """One backlog row, in the shape report.build writes."""
    return {
        "cve_id": f"CVE-2025-{30000 + n}",
        "state": "RESERVED",
        "owner": None,
        "owner_tier": "abstain",
        "owner_method": "block-k3-abstain",
        "public_date": public_date,
        "sources": _LONG_SOURCES if n % 3 == 0 else "osv,ghsa",
        "feed_count": 10 if n % 3 == 0 else 2,
        # PER-FEED DATES AND URLS FOR EVERY SOURCE THE ROW CLAIMS, not just osv.
        #
        # This was `{"osv": public_date}` with no `source_urls` at all, and the
        # consequence was invisible: `chips()` renders a source with no URL as a
        # non-link <span>, so no row in any render test had ever produced a single
        # <a> in the list. The front page's whole evidence layer -- the feed chips
        # and the per-feed "open advisory" links -- was unrendered, which makes any
        # assertion about those links vacuous rather than failing.
        #
        # Caught by test_every_advisory_link_names_its_own_row, which asserts it
        # found links before it asserts anything about them.
        "dates": {src: public_date
                  for src in (_LONG_SOURCES if n % 3 == 0 else "osv,ghsa").split(",")},
        "source_urls": {
            src: f"https://example.invalid/{src}/CVE-2025-{30000 + n}"
            for src in (_LONG_SOURCES if n % 3 == 0 else "osv,ghsa").split(",")},
        "refs": _LONG_REF,
        "description": _LONG_DESC if n % 2 == 0 else "Cross-Site Scripting (XSS)",
        "veto_evaluated": False,
        "days_public": days + n,
        "clock_known": True,
        "hours_public": (days + n) * 24,
        "past_expectation": True,
        # A MUST row carries the evidence MUST requires. The fixture used to
        # set rule_strength MUST on every fifth row while leaving
        # disclosure_order "unmeasurable" and self_disclosed False, which is a
        # state the pipeline cannot produce: 4.5.1.4 is claimed only where the
        # owning CNA's own feed carried the advisory FIRST. An incoherent fixture
        # makes the invariant that forbids it untestable.
        "disclosure_order": "owner-first" if n % 5 == 0 else "unmeasurable",
        "self_disclosed": n % 5 == 0,
        "rule": "4.5.1.4" if n % 5 == 0 else "4.5.1.6",
        "rule_strength": "MUST" if n % 5 == 0 else "SHOULD",
        "rule_basis": "unattributed",
        "rule_certainty": "unmeasurable",
        # DELIBERATELY STILL HERE, and no longer produced by the pipeline.
        #
        # `indep_sources` and `single_origin` were removed from the row schema at
        # v3 on 2026-08-27. This fixture keeps writing them so that it simulates a
        # PRE-v3 snapshot, which is what every snapshot on the data branch is: the
        # site rebuilds all of them on every run, so the read-path strip in
        # site._normalise_legacy is exercised end to end here rather than only
        # against a hand-built row.
        "indep_sources": 2 if n % 4 == 0 else 1,
        "package": _LONG_PACKAGE if n % 2 == 0 else "codingms/additional-tca",
        "ecosystem": "Packagist",
        "vendor": "",
        "advisory_url": f"https://osv.dev/list?q=CVE-2025-{30000 + n}",
        "owner_contested": False,
        "single_origin": n % 4 != 0,
        "owner_nameable": False,
    }


# THE AGES HAVE TO CROSS THE 90-DAY BOUNDARY, and they did not.
#
# `days_public` ran 19 to 78 across all 60 rows, so every one of them was under 90
# days. The front page defaults to the last 90 days, which meant the default
# filter hid NOTHING in any render test: the notice that announces the default
# never rendered, and a test asserting the default is announced would have passed
# against a page where the question never arose.
#
# Caught by test_the_default_view_is_announced_and_reversible, which asserts the
# notice is visible rather than asserting something about it if it happens to be.
#
# Every tenth row is aged past a year. That is the shape of the real data, where
# the oldest rows are a small, old cluster and the bulk is recent, and it is the
# shape the default view exists to deal with.
def _spread(n):
    return 19 + (400 if n % 10 == 0 else 0)


ROWS = [_row(n, days=_spread(n)) for n in range(60)]

# Pre-epoch, so backlog-at-launch.html has something to render.
HELD_BACK = [_row(500 + n, public_date="2025-03-19", days=519) for n in range(12)]

# The previous snapshot, so changes.html renders its diff rather than the "no
# previous run" branch. ROWS[:4] are absent from it, so they are `new`; the six
# 9xx rows are absent from ROWS, so they are `gone` and split into published,
# rejected and no-longer-listed by RESOLVED below.
GONE = [_row(900 + n) for n in range(6)]
PREV_ROWS = ROWS[4:] + GONE

RESOLVED = (
    [{"cve_id": r["cve_id"], "state": "PUBLISHED", "first_public": "2026-08-05",
      "published": "2026-08-18", "days_to_publish": 13} for r in GONE[:2]]
    + [{"cve_id": r["cve_id"], "state": "REJECTED", "first_public": "2026-08-05",
        "published": "2026-08-18", "days_to_publish": None} for r in GONE[2:4]]
)


def summary(rows, date=SNAPSHOT_DATE):
    """The run summary the site renders from.

    Coverage is deliberately ABOVE the gate, so the LAUNCHED build is not demoted
    by `site.load` into serving the holding page. A fixture that cannot clear the
    gate makes every launched-posture writer unreachable, which is the exact trap
    the end-to-end harness fell into before it built both postures.
    """
    return {
        "date": date, "expectation_hours": 72,
        "total": len(rows), "past_expectation": len(rows),
        "clock_unknown": 0, "undated_excluded": 0, "epoch": EPOCH,
        "epoch_excluded": len(HELD_BACK), "min_age_days": 7,
        "oldest_days": 519, "median_days": 42, "named_cnas": 0,
        "must_rows": sum(1 for r in rows if r["rule_strength"] == "MUST"),
        "should_rows": sum(1 for r in rows if r["rule_strength"] != "MUST"),
        "unmeasurable_rows": len(rows), "candidate_rows": 0,
        "age_buckets": {"30d+": len(rows)},
        "corroborated": sum(1 for r in rows if not r["single_origin"]),
        "single_origin": sum(1 for r in rows if r["single_origin"]),
        "generated_at": "2026-08-20T00:00:00+00:00",
        "source_commit": "0" * 12, "source_dirty": False,
        # The concentration reading on /method, which is `{% if ... is not none %}`
        # in the template. Omitted, the whole paragraph is skipped and
        # test_no_page_leads_with_a_single_cna_share can only ever fail: the half
        # of it that checks the reading is ON /method has nothing to find. Live
        # value on 2026-08-20 was 0.9633, and a figure near 1.0 is the point,
        # because the assertion exists to keep a one-entrant leaderboard off the
        # front page rather than to hide it.
        "top_owner_share": 0.9633,
        "inference": {"k": 3, "run_coverage": 0.5,
                      "leave_one_out": {"precision": 0.99, "coverage": 0.6,
                                        "decided": 22413},
                      "live": {"graded": 0, "correct": 0, "precision": None,
                               "below_floor": True, "outstanding": 1,
                               "by_tier": {}}},
        "feeds": {"requested": ["osv", "ghsa"], "failures": [], "attempts": 3,
                  "truncated": [], "detail": {}},
        "coverage": {"total_cnas": 539, "cnas_effective": 117,
                     "cnas_sighted": 152, "cnas_own_channel": 2,
                     "min_sightings": 3, "pct_cnas": 28.2, "pct_effective": 21.7,
                     "observed_pct": 12.5, "profile": "weekly",
                     "roster_pinned": True, "covered": [],
                     "top_n": 50, "top_covered_effective": 45,
                     "top_covered": 47, "pct_top_effective": 90.0,
                     "top_missed_effective": []},
    }


def write_snapshots(root):
    """The two dated snapshots and the ledgers, as the pipeline would leave them."""
    snaps = pathlib.Path(root) / "snapshots"

    prev = snaps / PREV_DATE
    prev.mkdir(parents=True, exist_ok=True)
    (prev / "backlog.json").write_text(json.dumps(PREV_ROWS))
    (prev / "summary.json").write_text(json.dumps(summary(PREV_ROWS, date=PREV_DATE)))
    (prev / "cnas.json").write_text("[]")

    latest = snaps / SNAPSHOT_DATE
    latest.mkdir(parents=True, exist_ok=True)
    (latest / "backlog.json").write_text(json.dumps(ROWS))
    (latest / "summary.json").write_text(json.dumps(summary(ROWS)))
    (latest / "cnas.json").write_text("[]")
    (latest / "resolved.json").write_text(json.dumps(RESOLVED))
    (latest / "held_back.json").write_text(json.dumps(HELD_BACK))

    data = pathlib.Path(root) / "data"
    data.mkdir(exist_ok=True)
    # The resolution ledger drives two more .rbp tables on /changes. Left empty,
    # both are `{% if %}`-ed away.
    (data / "resolutions.json").write_text(json.dumps({"open": {}, "resolved": RESOLVED}))
    return snaps, data


def build(root, launched):
    """Build the site into `root/site-<posture>` and return its path.

    RBP_LAUNCHED is set around the build and `rbp.site` is reloaded, because that
    module captures the posture at import. Reloaded again on the way out, so a
    fixture cannot leave the rest of the session looking at a launched module.
    """
    import pytest
    from rbp import site as _site

    root = pathlib.Path(root)
    snaps, data = write_snapshots(root)
    out = root / ("site-launched" if launched else "site-prelaunch")

    mp = pytest.MonkeyPatch()
    mp.setenv("RBP_LAUNCHED", "1" if launched else "")
    site = importlib.reload(_site)
    try:
        site.build(str(out), str(snaps), str(data))
    finally:
        mp.undo()
        importlib.reload(_site)
    assert_renders(out, launched)
    return out


# What the fixture must actually produce. Each entry was a real way to leave a
# downstream assertion vacuous while the suite stayed green.
# The page set as of 2026-08-26. Eight pages became four: the list is the front
# door, cves / changes / data / backlog-at-launch were removed with their content
# folded into the slide-over panel, and /status was added to carry the per-run
# health that used to be a banner above the count on every page.
# about-this-count is the holding page, written in both postures.
REQUIRED_PAGES = ("about-this-count.html", "method.html", "policy.html",
                  "status.html")
# The list page renders its rows from an embedded JSON island rather than
# server-side <table> markup, so "did the table render" is now "did the row data
# reach the page". Checked in assert_renders below.
REQUIRED_TABLES = ("method.html",)


def assert_renders(out, launched):
    """Fail loudly if the fixture stops exercising what the assertions are about.

    A synthetic fixture buys hermeticity and can lose fixture blindness, which is
    this project's most expensive recurring bug: no fixture produced a degraded
    run, so `False == False` passed. These are the specific ways this one could
    go quiet.
    """
    out = pathlib.Path(out)
    have = {p.name for p in out.glob("*.html")}
    missing = [p for p in REQUIRED_PAGES if p not in have]
    assert not missing, f"the fixture build produced no {missing}; have {sorted(have)}"
    # Keyed on OVERVIEW, not on index.html. Both postures write an index.html:
    # pre-launch it is a copy of the holding page. So "index.html exists" is true
    # of a demoted build too, and a launched build that the coverage gate quietly
    # demoted would have passed this check while serving the holding page. The
    # dashboard's filename is the thing that actually moves.
    if launched:
        assert "index.html" in have and "overview.html" not in have, (
            "this build still has an overview.html, so it is PRE-LAUNCH: either "
            "the posture lever did not take or the coverage gate demoted it, and "
            "every launched-posture assertion below is being made against the "
            f"holding page. Have {sorted(have)}")
    else:
        assert "overview.html" in have, (
            f"no overview.html in the pre-launch build. Have {sorted(have)}")
    if not launched:
        assert (out / "robots.txt").exists(), "pre-launch built no robots.txt"
    for page in REQUIRED_TABLES:
        assert "<table" in (out / page).read_text(), (
            f"{page} rendered no table, so every assertion about its rows, its "
            "columns and its layout is vacuous")
    # The list page carries its rows as a JSON island. An empty island is the
    # same failure as a table that did not render: every assertion about rows
    # becomes vacuous while the page still looks fine.
    front = out / ("index.html" if launched else "overview.html")
    body = front.read_text()
    m = re.search(r'<script id="rows" type="application/json">(.*?)</script>',
                  body, re.S)
    assert m, f"{front.name} carries no row data island"
    assert json.loads(m.group(1)), (
        f"{front.name} rendered zero rows, so the list is empty and every "
        "assertion about it proves nothing")
    assert (out / "data" / "rbp.json").exists(), "the build published no rbp.json"
    rows = json.loads((out / "data" / "rbp.json").read_text())
    body = rows.get("rows") if isinstance(rows, dict) else rows
    assert body, "rbp.json carries no rows; the schema assertions prove nothing"
