"""
The shared site fixture, and the guard against this whole class coming back.

WHAT HAPPENED. `tests/test_copy.py`, `tests/test_schema.py` and
`tests/test_suppress.py` assert against the RENDERED site, and all three found it
by looking for `./site` on disk and calling `pytest.skip` when it was absent.
`site/` is gitignored, so it is absent on every runner. Measured on run
32744122341: CI reported `662 passed, 56 skipped` where a developer machine
reported `707 passed, 11 skipped`, same 718 collected. 44 tests passed locally and
skipped in CI, in the job that gates a four-times-daily publication.

Two failures, and the second is worse than the first. In CI they did not run. On a
developer machine they ran against whatever stale build happened to be in the
working tree, which is not the commit under test and can be arbitrarily old.

The fix is that the site is built. This file keeps it honest, because a shared
fixture is a single point through which every one of those 44 assertions can be
made vacuous at once.
"""
from __future__ import annotations

import pathlib

import re

import pytest

import _sitefixture

TESTS = pathlib.Path(__file__).parent
ROOT = TESTS.parent


def _code_lines(path):
    """Every source line that is not a comment and not inside a docstring.

    Uses `ast` to find the docstring spans rather than looking for quote
    characters, because this file's own prose quotes the code it forbids.
    """
    import ast
    body = path.read_text()
    tree = ast.parse(body)
    doc_spans = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            doc_spans.append((node.lineno, node.end_lineno))
    lines = body.splitlines()
    out = []
    for i, line in enumerate(lines, 1):
        if any(a <= i <= b for a, b in doc_spans):
            continue
        if line.lstrip().startswith("#"):
            continue
        out.append(line)
    return out


# --------------------------------------------------------------------------
# the class regression guard
# --------------------------------------------------------------------------

def test_no_test_reaches_for_a_built_site_on_disk():
    """The regression that matters, and it is about the SUITE rather than any one
    test. Anything gated on `ROOT / "site"` is a test that does not run where it
    is needed and runs against a stale artefact where it is not."""
    offenders = []
    for path in sorted(TESTS.rglob("test_*.py")) + sorted(TESTS.rglob("conftest.py")):
        if path.name == "test_sitefixture.py":
            continue
        # Parsed, not grepped. The first version of this guard skipped any line
        # containing a triple quote and matched the DOCSTRINGS that explain what
        # the old code used to do, so writing down the history of the bug
        # reported the bug. A source-text check that cannot tell code from prose
        # is the same mistake as the one that matched `<th` inside `<thead>`.
        for line in _code_lines(path):
            if re.search(r'ROOT\s*/\s*"site"', line):
                offenders.append(f"{path.relative_to(ROOT)}: {line.strip()}")
    assert not offenders, (
        "these reach for a built site on disk instead of the built_site "
        "fixture:\n  " + "\n  ".join(offenders))


def test_nothing_skips_itself_for_want_of_a_built_site():
    """The message that used to appear 38 times in a CI log, phrased as a helpful
    instruction to a developer who was never going to read it."""
    offenders = []
    for path in sorted(TESTS.rglob("*.py")):
        if path.name == "test_sitefixture.py":
            continue
        body = path.read_text()
        for marker in ("site not built", "no local snapshot"):
            if f'pytest.skip("{marker}' in body or f"pytest.skip(f'{marker}" in body:
                offenders.append(f"{path.relative_to(ROOT)}: {marker}")
    assert not offenders, "these still skip rather than build:\n  " + "\n  ".join(offenders)


# --------------------------------------------------------------------------
# the fixture cannot go quiet
# --------------------------------------------------------------------------

def test_both_postures_build_and_differ_in_the_right_way(built_site,
                                                         built_site_launched):
    """Pre-launch serves the holding page at / with the dashboard at /overview;
    launched serves the dashboard at /. Several writers are gated on `launched`,
    so a fixture that only ever built one posture could not reach them."""
    assert (built_site / "overview.html").exists()
    assert (built_site / "robots.txt").exists(), "pre-launch must disallow indexing"
    assert "Disallow: /" in (built_site / "robots.txt").read_text()

    assert (built_site_launched / "index.html").exists()
    assert not (built_site_launched / "robots.txt").exists(), (
        "the launched build is still telling crawlers to go away")
    # The holding page survives the flip, at a permanent route, in both.
    for site in (built_site, built_site_launched):
        assert (site / "about-this-count.html").exists()


def test_the_render_guard_catches_a_missing_page(tmp_path):
    """assert_renders is the single thing standing between a shrinking fixture and
    44 silently vacuous assertions, so it is watched failing rather than trusted."""
    fake = tmp_path / "site"
    (fake / "data").mkdir(parents=True)
    (fake / "data" / "rbp.json").write_text('{"rows": [{"cve_id": "CVE-2025-1"}]}')
    (fake / "overview.html").write_text("<table></table>")
    with pytest.raises(AssertionError, match="produced no"):
        _sitefixture.assert_renders(fake, launched=False)


def test_the_render_guard_catches_a_list_that_rendered_no_rows(tmp_path,
                                                              built_site):
    """The subtler half, and it moved with the redesign.

    The list page carries its rows as a JSON island rather than server-side
    <table> markup, so the way it goes quiet is an EMPTY ISLAND, not a missing
    table. The page still renders, the command bar still shows, and every
    assertion about rows becomes vacuous. Same failure, new shape.
    """
    import shutil
    fake = tmp_path / "site"
    shutil.copytree(built_site, fake)
    front = fake / "overview.html"
    body = front.read_text()
    front.write_text(re.sub(
        r'(<script id="rows" type="application/json">).*?(</script>)',
        r"\g<1>[]\g<2>", body, flags=re.S))
    with pytest.raises(AssertionError, match="rendered zero rows"):
        _sitefixture.assert_renders(fake, launched=False)


def test_the_render_guard_catches_an_empty_data_endpoint(tmp_path, built_site):
    """rbp.json with no rows makes every schema assertion about row shape pass
    over an empty list."""
    import shutil
    fake = tmp_path / "site"
    shutil.copytree(built_site, fake)
    (fake / "data" / "rbp.json").write_text('{"rows": []}')
    with pytest.raises(AssertionError, match="carries no rows"):
        _sitefixture.assert_renders(fake, launched=False)


def test_the_render_guard_catches_the_wrong_posture(tmp_path, built_site):
    """A launched build demoted by the coverage gate looks exactly like a
    pre-launch build, and would take every launched-posture assertion with it.
    The fixture's coverage figures sit above the gate for this reason."""
    import shutil
    fake = tmp_path / "site"
    shutil.copytree(built_site, fake)
    with pytest.raises(AssertionError, match="PRE-LAUNCH"):
        _sitefixture.assert_renders(fake, launched=True)


def test_the_fixture_carries_the_fields_the_templates_gate_on():
    """Each of these is `{% if %}`-ed in a template, so omitting one deletes a
    section and makes the assertions about it unsatisfiable rather than false.
    `top_owner_share` was omitted, and test_no_page_leads_with_a_single_cna_share
    could only ever fail: the half checking the reading is ON /method had nothing
    to find."""
    s = _sitefixture.summary(_sitefixture.ROWS)
    assert s["top_owner_share"] is not None
    assert s["epoch"], "no epoch, so backlog-at-launch.html renders no table"
    assert _sitefixture.HELD_BACK, "nothing held back, so that page is prose only"
    assert _sitefixture.RESOLVED, "no closures, so two .rbp tables on /changes vanish"
    assert s["coverage"]["pct_top_effective"] >= 80.0, (
        "the fixture no longer clears the gate, so the launched build is demoted")


def test_every_posture_lever_is_listed_here():
    """The list is hand-written and the failure mode is silent.

    A new lever that nobody adds here is a variable the suite inherits from the
    operator's shell, and the symptom is a test that passes on CI and fails on one
    machine, or worse the reverse. `RBP_WITHHOLD` was added on 2026-08-26 and would
    have silently dropped rows from every fixture build on any machine that had it
    set.

    Derived from the source, so adding a lever without listing it fails here rather
    than at whatever downstream assertion happens to notice first.
    """
    import pathlib as _p
    import re as _re
    root = _p.Path(__file__).parent.parent
    found = set()
    for src in (root / "rbp").glob("*.py"):
        found |= set(_re.findall(r'environ(?:\.get)?[(\[]\s*"(RBP_[A-Z_]+)"',
                                 src.read_text()))
    missing = found - set(_sitefixture.POSTURE_VARS)
    assert not missing, (
        f"{sorted(missing)} change what the site publishes and are not cleared "
        "for the suite, so the tests inherit them from whoever is running them")


def test_no_test_imports_the_ambiguous_conftest_module():
    """`import conftest` resolves to whichever conftest.py pytest collected first.

    There are two, `tests/conftest.py` and `tests/render/conftest.py`, neither in
    a package, so pytest imports both under the top-level module name `conftest`
    and the second to arrive does not get its own name: it loses. This file did
    `import conftest` and read `POSTURE_VARS` off it, which resolved correctly
    when this file was run alone and to the render conftest on a full-suite run.

    So the guard that exists to catch an unlisted posture lever failed with
    `AttributeError` on every full run and passed in isolation. That is the shape
    that gets called flaky and reruns rather than fixed, and the thing it was
    guarding is a variable that silently drops rows from every fixture build.

    The constant lives in `_sitefixture` now, which is a unique module name.
    Shared test state belongs in a uniquely-named module, never in `conftest`.
    """
    offenders = []
    for path in sorted(TESTS.rglob("test_*.py")) + sorted(TESTS.rglob("conftest.py")):
        for line in _code_lines(path):
            if re.match(r"\s*(import\s+conftest|from\s+conftest\s+import)\b", line):
                offenders.append(f"{path.relative_to(ROOT)}: {line.strip()}")
    assert not offenders, (
        "`conftest` is not a stable module name, there are two of them and they "
        "shadow each other. Put shared state in a uniquely-named module and "
        "import that:\n  " + "\n  ".join(offenders))
