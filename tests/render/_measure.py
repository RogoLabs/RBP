"""
What the browser is asked, and what the answers mean.

Kept out of conftest.py so the test modules can import it by name rather than
importing the conftest, and so tests/render/test_mutations.py can run exactly the
same predicates against a page it has deliberately broken. A check whose only
caller is the passing case is a check nobody has watched fail.
"""
from __future__ import annotations

import hashlib
import pathlib
import re



# --------------------------------------------------------------------------
# the pages under test
# --------------------------------------------------------------------------

# The page carrying the row list. It was cves.html; since 2026-08-26 the list IS
# the front door, so it is index.html launched and overview.html pre-launch. Named
# once here rather than hardcoded in four files, which is how the render suite
# ended up pointing at a deleted page.
LIST_PAGE = "index.html"


def page_paths(site_dir):
    """Every HTML page the build produced, discovered rather than listed.

    A hand-written list is how a new page ships uncovered, which is the same
    shape as the per-CNA JSON endpoints sitting outside `assert_artefact` because
    nobody added them to an allowlist.
    """
    return sorted(p.name for p in site_dir.glob("*.html"))


# One evaluate() per width, returning everything the checks need. Split into
# several round trips it would be several layout flushes and several chances for
# the viewport and the measurement to disagree.
MEASURE_JS = r"""
() => {
  const de = document.documentElement;
  const tables = [...document.querySelectorAll('table')].map(t => {
    const cs = getComputedStyle(t);
    const head = t.querySelector('thead');
    const cell = t.querySelector('tbody td') || t.querySelector('td');
    const wrap = t.closest('.tablewrap') || t.parentElement;
    const wcs = wrap ? getComputedStyle(wrap) : null;
    return {
      cls: t.className || '',
      theadDisplay: head ? getComputedStyle(head).display : null,
      cellWhiteSpace: cell ? getComputedStyle(cell).whiteSpace : null,
      minWidth: cs.minWidth,
      tableScrollWidth: t.scrollWidth,
      wrapClientWidth: wrap ? wrap.clientWidth : null,
      wrapScrollWidth: wrap ? wrap.scrollWidth : null,
      wrapOverflowX: wcs ? wcs.overflowX : null,
    };
  });
  // THE ROW LAYOUT, which replaced the table on 2026-08-26. Same questions:
  // has the breakpoint fired, and is anything refusing to wrap.
  const rows = [...document.querySelectorAll('.rbprow')].map(r => {
    const sum = r.querySelector('summary');
    const cs = sum ? getComputedStyle(sum) : null;
    const cols = cs ? cs.gridTemplateColumns.trim().split(/\s+/).length : 0;
    const desc = r.querySelector('.rdesc');
    const age = r.querySelector('.agebox');
    return {
      cols,
      stacked: cols <= 2,
      descWhiteSpace: desc ? getComputedStyle(desc).whiteSpace : null,
      scrollWidth: r.scrollWidth,
      clientWidth: r.clientWidth,
      ageLeft: age ? Math.round(age.getBoundingClientRect().left) : null,
      bodyWidth: (() => { const b = r.querySelector('.rowbody');
                          return b ? Math.round(b.getBoundingClientRect().width) : null; })(),
    };
  });
  return {
    scrollWidth: de.scrollWidth,
    clientWidth: de.clientWidth,
    innerWidth: window.innerWidth,
    tables,
    rows,
  };
}
"""


def measure(pg, width, height=900):
    """Set the viewport and read the layout back."""
    pg.set_viewport_size({"width": width, "height": height})
    return pg.evaluate(MEASURE_JS)


def document_overflow(m):
    """Horizontal PAGE scroll, in px. Necessary, and famously not sufficient."""
    return m["scrollWidth"] - m["clientWidth"]


# `nested_overflow()` WAS HERE, and `row_overflow()` below is what replaced it.
#
# It measured content hidden inside a `.tablewrap` scroll container, which is
# the measurement the panel's investigation turned on: at exactly 768px the
# document overflow read 0 while the wrapper hid ~74% of every row, so a reader
# could not tell "the page fits" from "the page fits because the data is off
# screen inside a box".
#
# Its only in-scope subject was `table.rbp`, now deleted. The tables that remain
# are `table.table-sm`, which is DESIGNED to scroll inside its own box below
# 768 because a three-column figure table reads worse as stacked cards, so an
# assertion over what is left would fire on a recorded decision rather than on a
# defect.
#
# `row_overflow()` asks the identical question of the row layout that replaced
# the table, and until this commit it had never been called from anywhere.


# `card_mode_disagreements()` AND `rbp_tables_in_card_mode()` WERE HERE.
#
# Both filtered `m["tables"]` down to `t.classList.contains('rbp')` and asked
# whether that component's thead and cells agreed about which layout was
# running. The component rendered on no page and has been deleted, so both
# would have gone on returning an empty list forever while their callers
# reported green over zero tables.
#
# That is the exact shape this package's docstring calls the project's most
# expensive recurring bug, so they are deleted rather than left to pass
# vacuously. `rows_not_stacked()` below is the equivalent question for the row
# layout that replaced the table, and it has a live subject.


def asset_versions(html):
    """The `?v=` hashes the served HTML asks the browser to fetch."""
    return dict(re.findall(r"static/css/([A-Za-z0-9_.-]+\.css)\?v=([0-9a-f]+)", html))


def file_hash(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()[:10]


# --------------------------------------------------------------------------
# the ROW layout, which replaced the table
# --------------------------------------------------------------------------

def row_overflow(m):
    """Rows whose content is wider than the row itself.

    The row equivalent of the nested scrollbar: the page can fit while the row's
    own content is clipped or pushed, and a reader sees a truncated line rather
    than a horizontal scrollbar telling them so.
    """
    return [{"cols": r["cols"], "hidden_px": r["scrollWidth"] - r["clientWidth"]}
            for r in m.get("rows", [])
            if r["clientWidth"] and r["scrollWidth"] - r["clientWidth"] > 1]


def rows_not_stacked(m, boundary):
    """Rows still in the desktop three-column layout below the boundary.

    The direct descendant of the 768px collision: a breakpoint that did not
    fire, leaving the age box beside the content instead of under it and
    squeezing the column that carries the evidence.
    """
    if m["innerWidth"] > boundary:
        return []
    return [r for r in m.get("rows", []) if not r["stacked"]]


def rows_refusing_to_wrap(m):
    """Row text set to `nowrap`, which is what pushed the page 926px sideways at
    375px when the card layout was active and style.css's rule was never reset."""
    return [r for r in m.get("rows", []) if r["descWhiteSpace"] == "nowrap"]


def rows_squeezed(m, floor=120):
    """Rows whose content column has been crushed below a readable width.

    At 768px the old table hid roughly three quarters of every row while the
    document reported no overflow at all. This is that measurement for the grid:
    the page fits, and the column carrying the CVE ID and its sources does not.
    """
    return [r for r in m.get("rows", [])
            if r["bodyWidth"] is not None and r["bodyWidth"] < floor]
