"""
The document under test is the document on disk (PLAN.md 8e).

"the served `?v=` hash asserted against the file on disk, because two reviewers
silently measured the wrong document."

That is the whole reason this file exists. A layout measurement is only worth the
confidence that the bytes measured are the bytes that ship, and there are three
ways for that to be false without anything erroring: a stale copy in the served
tree, a `?v=` that no longer matches its file so a cached stylesheet is reused,
and a stylesheet that 404s and leaves the page rendering unstyled. An unstyled
page has no `min-width`, no `nowrap` and no breakpoints, so it passes every
overflow assertion in this package.
"""
from __future__ import annotations

import pathlib
import urllib.request

from _measure import LIST_PAGE, asset_versions, file_hash, page_paths

REPO_CSS = pathlib.Path(__file__).parent.parent.parent / "static" / "css"


def test_the_served_css_is_byte_identical_to_the_repository(site_dir):
    """The build copies static/ into the artefact. If that copy ever went stale
    or partial, every test here would be measuring a stylesheet nobody reviewed."""
    served = sorted(p.name for p in (site_dir / "static" / "css").glob("*.css"))
    repo = sorted(p.name for p in REPO_CSS.glob("*.css"))
    assert served == repo, f"served {served}, repository has {repo}"
    for name in repo:
        assert (site_dir / "static" / "css" / name).read_bytes() == \
            (REPO_CSS / name).read_bytes(), f"{name} differs from the repository"


def test_every_page_versions_every_stylesheet_it_loads(site_dir):
    """A `?v=` missing from one page is a page that serves a cached stylesheet
    after a deploy, which is a layout defect that only some readers see."""
    expected = {p.name: file_hash(p) for p in (site_dir / "static" / "css").glob("*.css")}
    assert expected, "the built site serves no stylesheets at all"
    for name in page_paths(site_dir):
        html = (site_dir / name).read_text()
        if "static/css/" not in html:
            continue
        got = asset_versions(html)
        assert set(got) == set(expected), (
            f"{name} links {sorted(got)}, the tree holds {sorted(expected)}")
        for css, v in got.items():
            assert v == expected[css], (
                f"{name} asks for {css}?v={v}, but the file on disk hashes to "
                f"{expected[css]}: readers would keep a cached stylesheet")


def test_the_browser_fetched_the_versioned_stylesheets_and_got_them(page, server,
                                                                    site_dir):
    """Asserted from the network log, not from the markup.

    The markup is what the page ASKS for. This is what it GOT, which is the only
    version of the question that can catch a 404, a redirect to an error page, or
    an off-origin request the route blocker aborted.
    """
    expected = {n: file_hash(p) for n, p in
                ((p.name, p) for p in (site_dir / "static" / "css").glob("*.css"))}
    seen = {}
    page.on("response", lambda r: seen.__setitem__(r.url, r.status))
    page.goto(f"{server}/{LIST_PAGE}", wait_until="load")
    for css, v in expected.items():
        url = f"{server}/static/css/{css}?v={v}"
        assert url in seen, (
            f"the browser never fetched {css}?v={v}; it fetched "
            f"{sorted(u for u in seen if '.css' in u)}")
        assert seen[url] == 200, f"{css} came back {seen[url]}"


def test_the_page_actually_has_the_stylesheet_applied(page, server):
    """The last false-green: a stylesheet that loads but matches nothing.

    Checked against a value that only the project's own CSS can produce, so an
    unstyled page, a wrong stylesheet, or a cascade that failed to reach the
    table all read as a failure rather than as a page with no overflow.
    """
    page.goto(f"{server}/{LIST_PAGE}", wait_until="load")
    applied = page.evaluate("""() => {
        const row = document.querySelector('.rbprow');
        // The wait, which is the one value in a row wearing a project-only token
        // (--rbp-age). It replaced the age rail as the probe here when the rows
        // stopped being cards: the rail was a 12px strip at the card edge and
        // there is no card any more.
        const age = row && row.querySelector('.agenum');
        const bar = document.querySelector('.distbar i b');
        const chip = document.querySelector('.chip');
        return {
          hasRow: !!row,
          ageColor: age ? getComputedStyle(age).color : null,
          barBg: bar ? getComputedStyle(bar).backgroundColor : null,
          chipRadius: chip ? getComputedStyle(chip).borderRadius : null,
        };
    }""")
    assert applied["hasRow"], "no .rbprow on the list page"
    # Values only the project's own stylesheet produces. An unstyled page, a
    # wrong stylesheet, or a cascade that failed to reach the rows all read as a
    # failure here rather than as a page with no overflow.
    assert applied["ageColor"] not in (None, "", "rgb(0, 0, 0)"), (
        "the wait carries no project colour, so rbp.css is not in effect and every "
        "layout measurement in this package is meaningless")
    assert applied["barBg"] not in (None, "rgba(0, 0, 0, 0)"), (
        "the distribution bars have no fill, so either rbp.css is not in effect or "
        "render() never drew them")
    assert applied["chipRadius"] and applied["chipRadius"].startswith("999"), (
        "the source chips are unstyled")


def test_the_served_tree_is_what_the_http_server_returns(server, site_dir):
    """Belt and braces on the fixture itself: the directory asserted about above
    is the directory being served."""
    html = urllib.request.urlopen(f"{server}/{LIST_PAGE}", timeout=10).read().decode()
    assert html == (site_dir / LIST_PAGE).read_text()
