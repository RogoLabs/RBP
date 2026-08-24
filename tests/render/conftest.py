"""
The browser-backed render tests (PLAN.md 8e).

WHY A BROWSER AT ALL. Half of accessibility is answerable from source text and is
covered offline in tests/test_a11y.py. The other half is layout, and a four-persona
panel established by measurement that the source-level version of these checks
cannot see the defects that actually shipped:

  - at 375px the card layout IS correctly active and the document still overflowed
    926px, because style.css sets `white-space: nowrap` at 768px and the card
    layout never reset it;
  - at exactly 768px, where the collision is worst, `scrollWidth - clientWidth` on
    the document is **0** and the obvious assertion passes, because
    `.tablewrap { overflow-x: auto }` absorbs the overflow before the document
    sees it, while hiding roughly three quarters of every row behind a nested
    scrollbar.

So `scrollWidth <= clientWidth` is necessary and not sufficient, and the check that
does catch 768 needs the cascade, specificity resolution and media-query evaluation
run for real. That is the definition of a browser. A CSS parser was evaluated and
rejected on measurement rather than on taste.

WHERE THIS RUNS. `render` is a job in ci.yml, which fires on push and pull_request.
It is NOT in `deploy.yml` at all, so it cannot appear in `deploy.needs`, there is no
skip cascade, and the publish path is byte-for-byte unchanged. Per-tick browser
coverage is given up deliberately: three experiments agreed that after
`overflow-wrap: anywhere` and `min-width: 0`, document overflow no longer varies
with feed data, so a scheduled tick has nothing new to render.

THE FIXTURE IS SYNTHETIC AND MUST STAY THAT WAY. CI has no `snapshots/` and no data
branch on the commit path, and building this from real data would either add a
network dependency to a layout test or make the local run and the CI run measure
different documents. What a synthetic fixture buys in hermeticity it can lose in
fixture blindness, which is this project's most expensive recurring bug: no fixture
produced a degraded run, so `False == False` passed. The defence is
tests/render/test_mutations.py, which reintroduces each defect into the live page
and asserts the corresponding check reports it. If the fixture is too small or too
short to overflow, those tests fail rather than the fixture quietly making every
other assertion vacuous.
"""
from __future__ import annotations

import functools
import http.server
import json
import os
import pathlib
import socketserver
import threading

import pytest

ROOT = pathlib.Path(__file__).parent.parent.parent

# Turns every skip in this package into a failure. The `render` job sets it, so a
# job that installed nothing, downloaded no browser, or silently collected zero
# tests reports red instead of green. A browser job that skips itself is worse
# than no browser job, because it looks like coverage.
REQUIRED = os.environ.get("RBP_RENDER_TESTS") == "1"


def _unavailable(reason):
    if REQUIRED:
        pytest.fail(f"RBP_RENDER_TESTS=1 but {reason}")
    pytest.skip(reason)


# --------------------------------------------------------------------------
# the fixture site
# --------------------------------------------------------------------------

# Content chosen to be hostile to layout, because content is what pushes a page
# sideways. Long unbroken tokens (package coordinates, ecosystem names, source
# lists, URLs) are the class that `overflow-wrap: anywhere` exists to handle, and
# a fixture full of short words cannot tell whether that rule is still there.
_LONG_PACKAGE = "org.apache.some-extremely-long-artifact-coordinate/spring-boot-starter-data-elasticsearch"
_LONG_DESC = ("A specially crafted request to the administrative interface allows an "
              "unauthenticated remote attacker to bypass the access-control check and "
              "read arbitrary files outside the configured document root, including "
              "credentials for downstream services.")
_LONG_SOURCES = "osv,ghsa,debian,ubuntu,alpine,redhat,alas,csaf,msrc,samsung"
_LONG_REF = "osv:Packagist:codingms/additional-tca-with-a-deliberately-long-suffix"


# The launch epoch. Set so that `backlog-at-launch.html` renders its table at
# all: it is `{% if summary.epoch and held_back %}`, and without an epoch that
# whole page is prose and the .rbp table inside it is never laid out. The same
# reasoning covers the prior snapshot below, for changes.html.
EPOCH = "2026-08-01"


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
        "dates": {"osv": public_date},
        "refs": _LONG_REF,
        "description": _LONG_DESC if n % 2 == 0 else "Cross-Site Scripting (XSS)",
        "veto_evaluated": False,
        "days_public": days + n,
        "clock_known": True,
        "hours_public": (days + n) * 24,
        "past_expectation": True,
        "disclosure_order": "unmeasurable",
        "self_disclosed": False,
        "rule": "4.5.1.6",
        "rule_strength": "MUST" if n % 5 == 0 else "SHOULD",
        "rule_basis": "unattributed",
        "rule_certainty": "unmeasurable",
        "indep_sources": 2 if n % 4 == 0 else 1,
        "package": _LONG_PACKAGE if n % 2 == 0 else "codingms/additional-tca",
        "ecosystem": "Packagist",
        "vendor": "",
        "advisory_url": f"https://osv.dev/list?q=CVE-2025-{30000 + n}",
        "owner_contested": False,
        "single_origin": n % 4 != 0,
        "owner_nameable": False,
    }


# 60 rows. Enough that the table is a real table and the page scrolls vertically
# (so the vertical scrollbar is in play when the horizontal one is measured), and
# few enough that the width sweep across every page stays inside a CI minute.
ROWS = [_row(n) for n in range(60)]

# Pre-epoch, so backlog-at-launch.html has something to render. Days public in
# the hundreds, which is what that page is about.
HELD_BACK = [_row(500 + n, public_date="2025-03-19", days=519) for n in range(12)]

# The previous snapshot, so changes.html renders its diff rather than the
# "no previous run" branch. ROWS[:4] are absent from it, so they are `new`; the
# six 9xx rows are absent from ROWS, so they are `gone` and split into published,
# rejected and no-longer-listed by resolved.json below.
GONE = [_row(900 + n) for n in range(6)]
PREV_ROWS = ROWS[4:] + GONE

# The authoritative closures. `gone` minus these is "no longer listed, cause
# unverified", which is a deliberately different claim and a different table.
RESOLVED = (
    [{"cve_id": r["cve_id"], "state": "PUBLISHED", "first_public": "2026-08-05",
      "published": "2026-08-18", "days_to_publish": 13} for r in GONE[:2]]
    + [{"cve_id": r["cve_id"], "state": "REJECTED", "first_public": "2026-08-05",
        "published": "2026-08-18", "days_to_publish": None} for r in GONE[2:4]]
)


def _summary(rows, date="2026-08-20"):
    """The run summary the site renders from.

    Coverage is deliberately ABOVE the gate. The launched posture is where the
    front-door dashboard lives, and a fixture that cannot clear the gate is
    demoted by site.load and renders the holding page instead: eight pages of
    layout coverage would silently become one. Same trap as the end-to-end
    harness, which built the pre-launch posture only and left every writer gated
    on `launched` unreached.
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


@pytest.fixture(scope="session")
def site_dir(tmp_path_factory):
    """Build the real site, in the LAUNCHED posture, into a temp directory.

    Launched rather than pre-launch, because launched is the posture with the
    dashboard on the front door and therefore the most layout to measure. The
    pre-launch holding page is still covered: it is written to
    /about-this-count.html in BOTH postures, so one build reaches every template.
    """
    import importlib
    from rbp import site as _site

    root = tmp_path_factory.mktemp("render")
    snaps = root / "snapshots"

    prev = snaps / "2026-08-19"
    prev.mkdir(parents=True)
    (prev / "backlog.json").write_text(json.dumps(PREV_ROWS))
    (prev / "summary.json").write_text(json.dumps(
        _summary(PREV_ROWS, date="2026-08-19")))
    (prev / "cnas.json").write_text("[]")

    latest = snaps / "2026-08-20"
    latest.mkdir(parents=True)
    (latest / "backlog.json").write_text(json.dumps(ROWS))
    (latest / "summary.json").write_text(json.dumps(_summary(ROWS)))
    (latest / "cnas.json").write_text("[]")
    (latest / "resolved.json").write_text(json.dumps(RESOLVED))
    (latest / "held_back.json").write_text(json.dumps(HELD_BACK))

    data = root / "data"
    data.mkdir()
    # The resolution ledger drives two more .rbp tables on /changes. Left empty,
    # both are `{% if %}`-ed away and the widest tables on that page are never
    # laid out at any width in the sweep.
    (data / "resolutions.json").write_text(json.dumps(
        {"open": {}, "resolved": RESOLVED}))

    mp = pytest.MonkeyPatch()
    mp.setenv("RBP_LAUNCHED", "1")
    site = importlib.reload(_site)
    out = root / "site"
    try:
        site.build(str(out), str(snaps), str(data))
    finally:
        mp.undo()
        importlib.reload(_site)

    # Fixture-blindness guards. Each of these was a real way to make the whole
    # sweep vacuous while every assertion still passed.
    index = (out / "index.html").read_text()
    assert "overview.html" not in index or "holding" not in index.lower(), (
        "the fixture was demoted to the pre-launch posture, so the dashboard "
        "template was never rendered")
    tables = {p.name: p.read_text().count('<table') for p in out.glob("*.html")}
    assert tables.get("cves.html"), "the primary data table did not render"
    assert tables.get("changes.html"), (
        "changes.html rendered no table, so its four .rbp tables and their "
        "inline min-width:0 were never laid out")
    assert tables.get("backlog-at-launch.html"), (
        "backlog-at-launch.html rendered no table; the epoch or held_back "
        "fixture stopped reaching it")
    assert tables.get("method.html"), (
        "method.html rendered no table, so the table-sm rules that had 1,656px "
        "of overflow at 375px are uncovered")
    return out


@pytest.fixture(scope="session")
def server(site_dir):
    """Serve the built tree over HTTP.

    file:// would do for layout, and would be wrong for the `?v=` check: that
    check exists because two reviewers silently measured the wrong document, and
    the only way to be sure the browser rendered the bytes on disk is to serve
    them and read back what it actually fetched.
    """
    handler = functools.partial(_QuietHandler, directory=str(site_dir))
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_a):  # noqa: D102
        pass


# --------------------------------------------------------------------------
# the browser
# --------------------------------------------------------------------------

@pytest.fixture(scope="session")
def _playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _unavailable("playwright is not installed; see requirements-browser.txt")
    with sync_playwright() as pw:
        yield pw


@pytest.fixture(scope="session")
def browser(_playwright):
    try:
        b = _playwright.chromium.launch()
    except Exception as e:  # noqa: BLE001
        _unavailable(f"chromium would not launch ({e}); "
                     "run `playwright install --with-deps chromium`")
    try:
        yield b
    finally:
        b.close()


@pytest.fixture
def page(browser, server):
    """A page with every off-origin request blocked.

    base.html preconnects to fonts.googleapis.com and loads a webfont. On a CI
    runner that is a network dependency inside a layout measurement, and a slow
    or failed font fetch changes text metrics, which changes what overflows. So
    the sweep runs against the site's own bytes and nothing else, and a fallback
    font is what a reader with a blocked CDN sees anyway.
    """
    context = browser.new_context(viewport={"width": 1280, "height": 900})
    context.route("**/*", lambda route: (
        route.continue_() if route.request.url.startswith(server)
        else route.abort()))
    pg = context.new_page()
    try:
        yield pg
    finally:
        context.close()
