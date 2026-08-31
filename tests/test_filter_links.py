"""A filtered view is meant to be citable, asserted on the source that makes it so.

THE OTHER HALF IS tests/render/test_filters.py, and it is the half that measures.
Whether a <select> keeps a value it has no <option> for is a DOM behaviour, and the
answer is that it does not: `value` reads back "" and `selectedIndex` becomes -1,
silently, so the filter stops applying and every row renders. Only a browser sees
that.

This file exists because the browser suite is on the commit path and cannot stop a
publish, and two of the three defects below are the kind you do not want shipping
for one tick: `/?src=mozilla&age=any` rendered all 1,672 rows rather than none,
and `?q=<img src=x onerror=...>` executed on the page. So the structure that makes
the behaviour possible is asserted here, offline, where it gates the publication.
Structural is weaker than measured. Neither replaces the other.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).parent.parent
TEMPLATES = ROOT / "templates"
CSS = ROOT / "static" / "css" / "rbp.css"

LIST = TEMPLATES / "list.html"


def _src():
    return LIST.read_text()


def _function(src, name):
    """One function body, by brace matching.

    Regex to the opening brace and count from there. A line-based or lazy-regex
    version stops at the first `}` inside the function, which for every function
    that matters here is an object literal or an `if`.
    """
    m = re.search(rf"function {re.escape(name)}\s*\([^)]*\)\s*\{{", src)
    assert m, f"{name}() is not in list.html any more; this test is reading a dead page"
    depth, i = 0, m.end() - 1
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():i + 1]
        i += 1
    raise AssertionError(f"unbalanced braces reading {name}()")


def _object_keys(src, name):
    """The TOP-LEVEL keys of an object literal.

    Brace-counted, and keys are read only at depth 1. A lazy regex over the
    literal picks up the keys of nested objects, and a greedy one runs off the end
    of the file and returns words out of the comments, which is what the first
    version of this helper did.
    """
    m = re.search(rf"var {re.escape(name)} = \{{", src)
    assert m, f"no {name} object literal in list.html"
    depth, shallow = 0, []
    for ch in src[m.end() - 1:]:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        elif depth == 1:
            shallow.append(ch)
    keys = set(re.findall(r"(\w+)\s*:", "".join(shallow)))
    assert keys, f"no keys parsed out of {name}"
    return keys


def _code(src):
    """The page's script with its `//` comment lines dropped.

    Only whole-line comments, which is every comment on this page and keeps the
    helper from having to know about `//` inside a string.
    """
    return "\n".join(ln for ln in src.splitlines()
                     if not ln.lstrip().startswith("//"))


def test_no_value_from_the_url_reaches_innerhtml_unescaped():
    """The empty state is the one place the page draws text the reader supplied.

    It was `'<div class="empty"><b>Nothing matches ' + describeFilters() + ...`,
    and describeFilters interpolates `els.q.value` and `els.src.value`, both read
    straight from the query string. So `?q=<img src=x onerror=...>` matched no
    rows, the empty state rendered the tag, and the handler ran. Measured on
    2026-08-28.

    Discovered from the innerHTML assignments rather than checked against a list of
    them, because the failure mode is someone ADDING one. The RHS is taken up to
    the first `;`, which is exact for every assignment on this page today and
    over-reads rather than under-reads if that stops being true.
    """
    src = _src()
    sinks = re.findall(r"\.innerHTML\s*=\s*([^;]*);", src, re.S)
    assert sinks, "no innerHTML assignments found; this test has stopped reading the page"

    for rhs in sinks:
        assert "describeFilters()" not in rhs or "esc(describeFilters())" in rhs, (
            "describeFilters() reaches innerHTML unescaped. It carries the reader's "
            f"own filter text out of the query string: {rhs.strip()[:120]}")
        raw = [m for m in re.findall(r"(?<!esc\()els\.\w+\.value", rhs)]
        assert not raw, (
            f"a control's value is concatenated into innerHTML unescaped ({raw}), "
            "and both text filters are read from the URL")


def test_every_control_reads_the_url_through_its_own_setter():
    """`els` and the URL readers are one list, iterated from `els`.

    Two lists is how `minage` outlived its rename: the clear-filters handler kept
    clearing a control that no longer existed, so "Clear filters" left the age
    filter on. A control in `els` with no reader now throws on load, which the
    render suite catches, rather than quietly ceasing to be linkable.
    """
    src = _src()
    controls = _object_keys(src, "els")
    readers = _object_keys(src, "FROM_URL")
    assert controls == readers, (
        f"the controls and their URL readers have drifted: only in els {controls - readers}, "
        f"only in FROM_URL {readers - controls}. A control with no reader stops being "
        "linkable; a reader with no control is dead code that reads as coverage")

    body = _function(src, "readUrl")
    assert "FROM_URL[k](" in body, (
        "readUrl no longer goes through FROM_URL, so it is assigning query-string "
        "values straight onto the controls again")
    stray = [rhs.strip() for rhs in
             re.findall(r"els(?:\.\w+|\[\w+\])\.value\s*=\s*([^;]+);", body)
             if rhs.strip() != "DEFAULT_AGE"]
    assert not stray, (
        f"readUrl assigns {stray} directly to a control. A select discards a value "
        "it has no option for, which is the whole defect: the filter stops applying "
        "and every row renders. DEFAULT_AGE is exempt because it is one of the "
        "control's own options")


def test_a_value_from_the_url_can_never_be_silently_discarded():
    """A control takes a value it does not offer, or it stops being linkable.

    THE REPORTED CASE WAS `src`, and it is now fixed by construction rather than
    by a guard. Its options were built from the slugs in today's rows, so a feed
    contributing nothing had no option, and assigning a <select> a value it has no
    <option> for neither throws nor sticks: `value` reads back "" and the filter
    stops applying, so `/?src=mozilla&age=any` rendered all 1,672 rows rather than
    none. Two of thirteen live feeds were in that state.

    `src` is a hidden input now, which cannot discard a value at all, and the
    visible controls are drawn from the CONFIGURED feed list rather than from the
    rows, so a quiet feed has a control whether or not it contributed anything.
    What is asserted here is that it stays that way: a <select> would bring the
    defect straight back.

    `age` and `sort` are still selects and still need the guard. `age` because
    `?age=45+` is a bound a reader can construct that the control does not offer;
    `sort` because an unknown grouping is a typo rather than a view, so it falls
    back to the default instead of being added.
    """
    src = _src()

    assert not re.search(r'<select[^>]*\bid="src"', src), (
        "#src is a <select> again. A select silently discards a value it has no "
        "option for, which is the whole defect: the filter stops applying and "
        "every row renders for a URL that asked for one feed")
    assert re.search(r'<input[^>]*\btype="hidden"[^>]*\bid="src"', src), (
        "#src is no longer the hidden input that holds the chosen feed, so "
        "whatever holds it now needs its own version of this test")

    # The unknown slug still has to become a control the reader can see, or the
    # filter is applied with nothing on the page saying so.
    body = _function(src, "setSrc")
    assert "extra.push" in body, (
        "setSrc() no longer records a slug that is in neither the configured list "
        "nor the rows, so a URL naming a retired feed filters invisibly")

    for name in ("setAge", "setSort"):
        body = _function(src, name)
        assert "hasOption" in body, (
            f"{name}() assigns to a select without checking the option exists, so a "
            "value from the URL can be discarded silently and the filter dropped")


def test_a_feed_slug_from_the_url_is_never_looked_up_on_names_directly():
    """`NAMES[v] || v` is fine for a slug out of the data and wrong for one out of
    a URL: NAMES is a plain object, so `NAMES["constructor"]` is a function rather
    than undefined and `?src=constructor` labelled a control with the source of
    Object. One lookup, guarded, at the one place slugs arrive from outside.
    """
    src = _code(_src())
    lookups = src.count("NAMES[")
    assert lookups == 1, (
        f"{lookups} direct NAMES[...] lookups; there should be exactly one, inside "
        "feedName(), so an inherited property cannot be read as a display name")
    assert "hasOwnProperty.call(NAMES" in src, (
        "feedName() no longer guards the lookup with hasOwnProperty")


def test_the_empty_state_wraps_what_the_reader_typed():
    """The measured version is in tests/render, at 1280 and at 375. This is the
    structural one, because it gates the publication.

    400 unbroken characters in the filter scrolled the document sideways by
    2,466px at 1280 wide, and 80 did it at 375. `overflow-wrap: anywhere` existed
    for `.mono, code, pre` and only below 768px; nothing covered this box, which is
    the one that draws the reader's own text.
    """
    css = CSS.read_text()
    m = re.search(r"\n\.empty\{([^}]*)\}", css)
    assert m, ".empty rule not found in rbp.css"
    assert "overflow-wrap" in m.group(1), (
        "the empty state declares no wrapping, so a long pasted filter value makes "
        "the page scroll sideways at every width")
