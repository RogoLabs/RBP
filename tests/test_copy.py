"""
The copy and citation pass (review item 11).

"Every item here is a place where the site's public surfaces contradict each other
or omit what cuts against them, on a project whose entire authority rests on
quoting accurately."

Every policy quotation was already pinned by tests/test_policy.py and none of the
historical claims were, which is backwards: the historical claims are the
contested ones. These pin the claims and the copy rules.

Asserted against RENDERED pages where possible, not templates, because a rule that
holds in the source and not in the output protects nothing.
"""
from __future__ import annotations

import html
import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).parent.parent
TEMPLATES = ROOT / "templates"
PLACEHOLDER = ROOT / "placeholder.html"


def _text(path):
    """Tags stripped, whitespace collapsed, entities resolved."""
    raw = pathlib.Path(path).read_text()
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", raw)))


@pytest.fixture(scope="module")
def built():
    """The rendered site, if it has been built. These assertions are about output."""
    out = ROOT / "site"
    if not (out / "overview.html").exists():
        pytest.skip("site not built; run `python -m rbp.cli build --out site`")
    return out


# --------------------------------------------------------------------------
# contradictions between one page and another
# --------------------------------------------------------------------------

def test_no_template_says_the_table_was_public_for_about_a_year():
    """index.html said "after about a year public" while policy.html, one click
    away, labelled that figure a correction: "closer to four months than a year"."""
    for tpl in list(TEMPLATES.glob("*.html")) + [PLACEHOLDER]:
        body = re.sub(r"\{#.*?#\}", "", tpl.read_text(), flags=re.S)
        assert "about a year" not in body, (
            f"{tpl.name} still claims the RBP table was public for about a year; "
            "policy.html corrects this to closer to four months")


def test_no_page_claims_to_fill_the_gap_left_by_the_archived_series():
    """index.html said the Metrics page reports "nothing on the overlap between
    them, which is the gap this site fills" while policy.html said "The two are not
    comparable and this site does not replace it". /policy is canonical."""
    for tpl in list(TEMPLATES.glob("*.html")) + [PLACEHOLDER]:
        body = tpl.read_text()
        assert "gap this site fills" not in body, tpl.name
        assert "this site fills" not in body, tpl.name


def test_the_advisory_title_column_is_gone_everywhere():
    """`<th>Advisory title</th>` shipped on three pages while data.html retracted
    exactly that word: the field is a summary, often a body rather than a title."""
    for tpl in TEMPLATES.glob("*.html"):
        assert ">Advisory title<" not in tpl.read_text(), tpl.name


def test_the_meta_description_makes_no_absolute_claim(built):
    """The one string search engines and link previews quote verbatim. It began
    "Every CVE ID that is reserved..." on a run at 27.9% effective CNA coverage.
    "Every" is the absolute the holding page was corrected to remove."""
    for page in ("overview.html", "cves.html", "method.html"):
        raw = (built / page).read_text()
        m = re.search(r'<meta name="description" content="([^"]*)"', raw)
        assert m, page
        desc = m.group(1)
        assert not desc.lower().startswith("every"), desc
        assert "Program's own term" in desc or "own term" in desc, desc


# --------------------------------------------------------------------------
# quote the clauses that cut against the site
# --------------------------------------------------------------------------

COUNTER_QUOTES = [
    "incident response",
    "short delays",
    "resource constraints",
    "volume, complexity",
    "volume, history",
]


@pytest.mark.parametrize("phrase", COUNTER_QUOTES)
def test_the_front_page_quotes_the_clauses_that_cut_against_it(built, phrase):
    """The front page quoted the policy's "does not condone any unnecessary,
    intentional, or routine delay" and omitted, from the same paragraph, every
    clause that softens it. /policy already states this project's own standard:
    "quoting only the discretionary parts would be selective." It was broken on the
    section that governs the headline."""
    assert phrase in _text(built / "overview.html"), (
        f"the front page omits the policy's {phrase!r} clause")


def test_counter_quotes_are_filed_under_the_sections_they_occupy(built):
    """Two of the four are not in Timely Publication. Misfiling them would be the
    exact error tests/test_policy.py exists to prevent."""
    text = _text(built / "overview.html")
    for heading in ("Timely Publication", "Notification and Remediation", "Enforcement"):
        assert heading in text, heading
    # Ordering: the volume/complexity clause belongs to Notification and
    # Remediation, so that heading must precede it.
    assert text.index("Notification and Remediation") < text.index("volume, complexity")
    assert text.index("Enforcement") < text.index("volume, history")


def test_the_counter_quotes_are_verbatim_against_the_pinned_policy():
    """The site's authority rests on quoting accurately, so these are checked
    against the pinned document rather than against memory."""
    policy = json.loads(
        (ROOT / "tests" / "fixtures" / "rbp_policy_v2.json").read_text())["full_text"]
    flat = re.sub(r"\s+", " ", policy)
    for quote in [
        "recognizing that such publication may, at times, coincide with ongoing "
        "vulnerability or incident response activities",
        "internal processes may necessitate short delays",
        "no later than the deadline stated by their TL-Root or Root (which may "
        "account for factors such as volume, complexity, and resource constraints)",
        "may take further action depending on the",
    ]:
        assert quote in flat, f"not in RBP Policy v2.0.0: {quote!r}"


def test_the_front_page_answers_the_counter_quotes_rather_than_only_listing_them(built):
    """The review's ask was to quote them AND answer them in the same breath with
    the buffer, the median and the 180d+ bucket, then state the sentence they
    license."""
    text = _text(built / "overview.html")
    assert "only deadline that binds a specific row is one a Root set privately" in text
    assert "never calls a single row overdue" in text


# --------------------------------------------------------------------------
# historical claims: pinned, because these are the contested ones
# --------------------------------------------------------------------------

def test_the_issue_numbers_and_dates_are_pinned(built):
    """#835 withdrew the v1.0 PDF; #842 commented out the table thirteen days
    later. Both numbers and both dates appear on the site and neither was pinned."""
    text = _text(built / "overview.html") + _text(built / "policy.html")
    assert "842" in text and "835" in text
    assert "7 February 2022" in text
    assert "February 2021" in text
    assert "Q3" in text and "2021" in text


def test_the_three_item_restructuring_is_described_not_asserted(built):
    """"Item 2 of three" only exculpates if a reader can see what items 1 and 3
    were. The first draft of this asserted them from memory and was wrong; they
    come from cve-website#842 and are now named with the issue linked."""
    text = _text(built / "overview.html")
    assert "item 2 of a three-item" in text
    assert "issue" in text and "842" in text
    # Item 1 and item 3, from the issue body.
    assert "Reserved IDs tables" in text or "Published Records" in text
    assert "quarterly to annual" in text


def test_the_n_a_final_column_fact_is_on_both_front_doors(built):
    """The most exculpatory fact available: the series had stopped being populated
    before anyone commented it out. It was on /policy only, which nobody can reach
    pre-launch."""
    assert "N/A" in _text(built / "overview.html")
    assert "N/A" in _text(built / "policy.html")
    assert "N/A" in _text(built / "index.html"), "missing from the holding page"


def test_the_flow_versus_stock_distinction_is_on_the_holding_page():
    """The holding page is the only page anyone can reach pre-launch, so it is
    where good faith is cheapest to establish. It implied this site publishes the
    Program's archived metric, which /policy retracts on a page nobody can reach."""
    text = _text(PLACEHOLDER)
    assert "flow" in text and "stock" in text
    assert "not comparable" in text
    assert "minority of CNAs" in text, "the coverage bound is missing"


def test_the_ask_is_anchored_on_the_in_force_document():
    """Asking for the return of a v1.0-era quarterly table under a policy that
    withdrew the arithmetic that table scored is answerable with "that was v1.0".
    v2.0.0 names "Program metrics and audits" as its own identification channel."""
    for path in (PLACEHOLDER, ROOT / "site" / "overview.html"):
        if not pathlib.Path(path).exists():
            continue
        assert "metrics and audits" in _text(path), path


# --------------------------------------------------------------------------
# claims stated as completed facts
# --------------------------------------------------------------------------

def test_no_built_page_states_an_interval_as_a_completed_fact(built):
    """A grep guard for the class, not just the instance that was found."""
    banned = ["about a year", "for over a year", "for more than a year public"]
    for page in built.glob("*.html"):
        text = _text(page).lower()
        for phrase in banned:
            assert phrase not in text, f"{page.name}: {phrase!r}"


# --------------------------------------------------------------------------
# the framing assets must survive launch
# --------------------------------------------------------------------------

def test_the_holding_page_survives_launch_at_a_permanent_route(built):
    """placeholder.html was copied over index.html ONLY in the not-launched
    branch, so flipping RBP_LAUNCHED would have deleted it and with it the three
    paragraphs doing the site's framing work: the glossary provenance ("That is
    not our term. It is the CVE Program's own"), the full 4.5.1.7 quotation, and
    the narrow ask with its own safety reasoning.

    A grep of the built dashboard returned zero occurrences of "unblind" and zero
    of "glossary"; the only surviving ask was one line of footer small print.
    Launch day would have quietly destroyed the most careful copy on the site."""
    about = built / "about-this-count.html"
    assert about.exists(), "the holding page has no permanent route"
    text = _text(about)
    assert "not our term" in text, "the glossary-provenance paragraph is missing"
    assert "glossary" in text.lower()
    assert "4.5.1.7" in text, "the naming-warrant quotation is missing"
    assert "unblind" in text.lower(), "the narrow ask is missing"


def test_the_about_route_exists_in_both_postures(tmp_path, monkeypatch):
    """Asserted by building BOTH postures, because "it works pre-launch" is
    exactly what was true before and exactly what was not the problem."""
    import importlib
    from rbp import site as site_mod

    snaps = tmp_path / "snapshots" / "2026-08-20"
    snaps.mkdir(parents=True)
    (tmp_path / "data").mkdir()
    (snaps / "backlog.json").write_text("[]")
    (snaps / "cnas.json").write_text("[]")
    (snaps / "summary.json").write_text(json.dumps({
        "total": 0, "past_expectation": 0, "oldest_days": None, "median_days": None,
        "named_cnas": 0, "must_rows": 0, "should_rows": 0, "clock_unknown": 0,
        "unmeasurable_rows": 0, "candidate_rows": 0, "undated_excluded": 0,
        "min_age_days": 7, "age_buckets": {},
        "inference": {"k": 3, "run_coverage": 0.0,
                      "leave_one_out": {"precision": 0.99, "coverage": 0.6,
                                        "decided": 0},
                      "live": {"graded": 0, "correct": 0, "precision": None,
                               "outstanding": 0, "by_tier": {}}},
        "feeds": {"requested": [], "failures": [], "attempts": 0, "truncated": [],
                  "detail": {}},
        "coverage": {"total_cnas": 10, "cnas_effective": 6, "cnas_own_channel": 1,
                     "cnas_sighted": 8, "min_sightings": 3, "pct_cnas": 80.0,
                     "pct_effective": 60.0, "observed_pct": 1.0, "profile": "weekly"},
    }))

    for launched in (False, True):
        monkeypatch.setenv("RBP_LAUNCHED", "1" if launched else "")
        importlib.reload(site_mod)
        out = tmp_path / ("post" if launched else "pre")
        site_mod.build(str(out), str(tmp_path / "snapshots"), str(tmp_path / "data"))
        assert (out / "about-this-count.html").exists(), (
            f"about route missing with launched={launched}")
    monkeypatch.delenv("RBP_LAUNCHED", raising=False)
    importlib.reload(site_mod)
