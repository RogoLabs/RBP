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

THE FIXTURE IS SYNTHETIC AND MUST STAY THAT WAY, and it is now shared. CI has no
`snapshots/` and no data branch on the commit path, and building this from real
data would either add a network dependency to a layout test or make the local run
and the CI run measure different documents. It lives in tests/_sitefixture.py,
because three other modules needed the same thing and were skipping themselves in
CI for want of it.

What a synthetic fixture buys in hermeticity it can lose in fixture blindness,
which is this project's most expensive recurring bug: no fixture produced a
degraded run, so `False == False` passed. Two defences. `_sitefixture.assert_renders`
fails the build if the fixture stops producing the pages and tables the assertions
are about. And tests/render/test_mutations.py reintroduces each defect into the
live page and requires the corresponding check to report it, so a fixture too small
or too short to overflow fails rather than quietly making every other assertion
vacuous.
"""
from __future__ import annotations

import functools
import http.server
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

# THE FIXTURE LIVES IN tests/_sitefixture.py, not here.
#
# It was written here first and then needed by three more modules, so it moved to
# the shared one rather than becoming a second copy. tests/test_copy.py,
# tests/test_schema.py and tests/test_suppress.py all used to find the site by
# looking for `./site` on disk and skipping when it was absent, which is always,
# on every CI runner. 44 of their tests never ran in CI.


@pytest.fixture(scope="session")
def site_dir(built_site_launched):
    """The LAUNCHED build.

    Launched rather than pre-launch, because it is the posture with the dashboard
    on the front door and therefore the most layout to measure. The pre-launch
    holding page is still covered: it is written to /about-this-count.html in BOTH
    postures, so one build reaches every template.
    """
    return built_site_launched


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
    def log_message(self, *_a):
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
    except Exception as e:
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
